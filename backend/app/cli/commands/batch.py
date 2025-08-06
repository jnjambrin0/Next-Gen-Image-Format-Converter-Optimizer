"""
Batch Command
Batch image conversion with parallel processing
"""

import asyncio
from pathlib import Path
from typing import List, Optional, Annotated
from glob import glob

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, MofNCompleteColumn
from rich.table import Table

from app.cli.config import get_config
from app.cli.utils.validation import validate_input_file
from app.cli.utils.errors import handle_api_error
from app.cli.utils.history import record_command
from app.cli.ui.themes import get_theme_manager
from app.cli.ui.tables import SmartTable, ColumnType, create_batch_summary_table
from app.cli.utils.emoji import get_emoji, get_format_emoji, format_with_emoji
from app.cli.utils.terminal import should_use_emoji
from app.cli.utils.progress import InterruptableProgress, create_multi_progress

# Import SDK client
from app.cli.utils import setup_sdk_path
setup_sdk_path()
from image_converter.async_client import AsyncImageConverterClient
from image_converter.models import BatchRequest, OutputFormat as SDKOutputFormat

app = typer.Typer(no_args_is_help=True)

# Initialize themed console
theme_manager = get_theme_manager()
config = get_config()
console = theme_manager.create_console(config.theme)


@app.command(name="convert")
def batch_convert(
    pattern: Annotated[
        str,
        typer.Argument(help="File pattern or glob (e.g., *.jpg, images/*.png)")
    ],
    format: Annotated[
        str,
        typer.Option("-f", "--format", help="Output format for all files")
    ],
    output_dir: Annotated[
        Optional[Path],
        typer.Option("-o", "--output-dir", help="Output directory (default: same as input)")
    ] = None,
    quality: Annotated[
        Optional[int],
        typer.Option("-q", "--quality", min=1, max=100, help="Quality for lossy formats")
    ] = None,
    preset: Annotated[
        Optional[str],
        typer.Option("-p", "--preset", help="Optimization preset to apply")
    ] = None,
    parallel: Annotated[
        int,
        typer.Option("--parallel", "-j", help="Number of parallel conversions")
    ] = 4,
    recursive: Annotated[
        bool,
        typer.Option("-r", "--recursive", help="Process directories recursively")
    ] = False,
    skip_errors: Annotated[
        bool,
        typer.Option("--skip-errors", help="Continue on conversion errors")
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would be converted without doing it")
    ] = False,
):
    """
    Convert multiple images in batch
    
    Examples:
      img batch convert "*.jpg" -f webp
      img batch convert "photos/*.png" -f avif -q 85 -o converted/
      img batch convert "**/*.jpg" -f jpeg --preset web -r
    """
    # Find matching files
    if recursive and "**" not in pattern:
        pattern = f"**/{pattern}"
    
    files = glob(pattern, recursive=recursive)
    valid_files = [Path(f) for f in files if validate_input_file(Path(f))]
    
    if not valid_files:
        error_msg = format_with_emoji("No valid image files found matching: " + pattern, "error")
        console.print(f"[error]{error_msg}[/error]")
        raise typer.Exit(1)
    
    found_msg = format_with_emoji(f"Found {len(valid_files)} images to convert", "info")
    console.print(f"[info]{found_msg}[/info]")
    
    # Create output directory if specified
    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
    
    if dry_run:
        # Show what would be done
        table = Table(title="Batch Conversion Preview", show_header=True)
        table.add_column("Input File", style="cyan")
        table.add_column("Output File", style="green")
        
        for file in valid_files[:10]:  # Show first 10
            if output_dir:
                out_file = output_dir / file.with_suffix(f".{format}").name
            else:
                out_file = file.with_suffix(f".{format}")
            table.add_row(str(file), str(out_file))
        
        if len(valid_files) > 10:
            table.add_row("...", f"... ({len(valid_files) - 10} more files)")
        
        console.print(table)
        console.print(f"\n[yellow]Dry run complete. {len(valid_files)} files would be converted.[/yellow]")
        raise typer.Exit(0)
    
    # Run async batch conversion
    asyncio.run(_run_batch_conversion(
        files=valid_files,
        format=format,
        output_dir=output_dir,
        quality=quality,
        preset=preset,
        parallel=parallel,
        skip_errors=skip_errors
    ))


async def _run_batch_conversion(
    files: List[Path],
    format: str,
    output_dir: Optional[Path],
    quality: Optional[int],
    preset: Optional[str],
    parallel: int,
    skip_errors: bool
):
    """Run batch conversion asynchronously"""
    config = get_config()
    
    # Initialize async client
    async with AsyncImageConverterClient(
            host=config.api_host,
            port=config.api_port,
        api_key=config.api_key,
        timeout=config.api_timeout
    ) as client:
        
        # Prepare batch files
        batch_files = []
        for file in files:
            with open(file, 'rb') as f:
                batch_files.append({
                    'filename': file.name,
                    'data': f.read()
                })
        
        # Create batch request
        batch_request = BatchRequest(
            output_format=SDKOutputFormat(format.lower()),
            quality=quality or config.default_quality,
            preset_id=preset or config.default_preset,
            max_parallel=parallel,
            skip_errors=skip_errors
        )
        
        # Start batch job
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            MofNCompleteColumn(),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            # Create batch job
            task = progress.add_task("Creating batch job...", total=len(files))
            
            try:
                job = await client.create_batch(batch_files, batch_request)
                job_id = job.job_id
                
                progress.update(task, description=f"Processing batch {job_id[:8]}...")
                
                # Monitor progress
                completed = 0
                failed = 0
                
                while True:
                    status = await client.get_batch_status(job_id)
                    
                    new_completed = status.completed_count
                    new_failed = status.failed_count
                    
                    if new_completed > completed:
                        progress.update(task, advance=new_completed - completed)
                        completed = new_completed
                    
                    if new_failed > failed:
                        failed = new_failed
                    
                    if status.status in ["completed", "failed", "cancelled"]:
                        break
                    
                    await asyncio.sleep(1)
                
                # Download results
                if status.status == "completed" or (status.status == "failed" and skip_errors):
                    progress.update(task, description="Downloading results...")
                    
                    results = await client.download_batch_results(job_id)
                    
                    # Save converted files
                    success_count = 0
                    for idx, (file, result) in enumerate(zip(files, results)):
                        if result and result.get('data'):
                            if output_dir:
                                out_file = output_dir / file.with_suffix(f".{format}").name
                            else:
                                out_file = file.with_suffix(f".{format}")
                            
                            with open(out_file, 'wb') as f:
                                f.write(result['data'])
                            success_count += 1
                
                # Show summary with SmartTable
                summary_table = SmartTable(
                    title="Batch Conversion Summary",
                    console=console,
                    show_statistics=True
                )
                summary_table.add_column("Metric", ColumnType.TEXT, width=20)
                summary_table.add_column("Value", ColumnType.TEXT, width=15)
                summary_table.add_column("Status", ColumnType.STATUS, width=10)
                
                summary_table.add_row("Total Files", str(len(files)), "info")
                summary_table.add_row("Succeeded", str(completed), "success" if completed > 0 else "warning")
                if failed > 0:
                    summary_table.add_row("Failed", str(failed), "error")
                summary_table.add_row("Output Format", format.upper(), "info")
                
                console.print()
                console.print(summary_table.render())
                
                complete_msg = format_with_emoji("Batch conversion complete!", "success")
                console.print(f"\n[success]{complete_msg}[/success]")
                
                # Record in history
                record_command(f"batch convert {pattern} -f {format}", success=True)
                
            except Exception as e:
                handle_api_error(e, console)
                record_command(f"batch convert {pattern} -f {format}", success=False)
                raise typer.Exit(1)


@app.command(name="status")
def batch_status(
    job_id: Annotated[
        str,
        typer.Argument(help="Batch job ID to check")
    ],
    watch: Annotated[
        bool,
        typer.Option("-w", "--watch", help="Watch status until completion")
    ] = False,
):
    """
    Check batch job status
    
    Examples:
      img batch status abc123
      img batch status abc123 --watch
    """
    config = get_config()
    
    async def check_status():
        async with AsyncImageConverterClient(
            host=config.api_host,
            port=config.api_port,
            api_key=config.api_key
        ) as client:
            
            while True:
                try:
                    status = await client.get_batch_status(job_id)
                    
                    # Display status
                    console.clear()
                    console.print(f"[bold cyan]Batch Job Status[/bold cyan]")
                    console.print(f"ID: {status.job_id}")
                    console.print(f"Status: [yellow]{status.status}[/yellow]")
                    console.print(f"Progress: {status.completed_count}/{status.total_count}")
                    
                    if status.failed_count > 0:
                        console.print(f"Failed: [red]{status.failed_count}[/red]")
                    
                    if status.status in ["completed", "failed", "cancelled"] or not watch:
                        break
                    
                    await asyncio.sleep(2)
                    
                except Exception as e:
                    handle_api_error(e, console)
                    raise typer.Exit(1)
    
    asyncio.run(check_status())


@app.command(name="cancel")
def batch_cancel(
    job_id: Annotated[
        str,
        typer.Argument(help="Batch job ID to cancel")
    ],
    force: Annotated[
        bool,
        typer.Option("-f", "--force", help="Force cancel without confirmation")
    ] = False,
):
    """
    Cancel a batch job
    
    Examples:
      img batch cancel abc123
      img batch cancel abc123 --force
    """
    if not force:
        if not typer.confirm(f"Cancel batch job {job_id}?"):
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit(0)
    
    config = get_config()
    
    async def cancel_job():
        async with AsyncImageConverterClient(
            host=config.api_host,
            port=config.api_port,
            api_key=config.api_key
        ) as client:
            try:
                await client.cancel_batch(job_id)
                console.print(f"[green]✓[/green] Batch job {job_id} cancelled")
            except Exception as e:
                handle_api_error(e, console)
                raise typer.Exit(1)
    
    asyncio.run(cancel_job())


@app.callback()
def batch_callback():
    """Batch conversion operations"""
    pass