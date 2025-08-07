"""
Convert Command
Single image conversion with rich progress and options
"""

import sys
import time
from pathlib import Path
from typing import Optional, Annotated
import asyncio

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from app.cli.config import get_config
from app.cli.utils.validation import validate_input_file, validate_output_path
from app.cli.utils.progress import create_progress_bar, InterruptableProgress, progress_context
from app.cli.utils.errors import handle_api_error
from app.cli.utils.history import record_command
from app.cli.ui.themes import get_theme_manager
from app.cli.utils.emoji import get_emoji, get_format_emoji
from app.cli.utils.terminal import get_terminal_detector, should_use_emoji
from app.cli.utils.profiler import cli_profiler, profile_command

# Import SDK client
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / "sdks" / "python"))
from image_converter.client import ImageConverterClient
from image_converter.models import ConversionRequest, OutputFormat as SDKOutputFormat

app = typer.Typer(no_args_is_help=True)

# Initialize themed console
theme_manager = get_theme_manager()
config = get_config()
console = theme_manager.create_console(config.theme)


@app.command(name="file")
def convert_file(
    input_path: Annotated[
        Path,
        typer.Argument(help="Input image file path", exists=True)
    ],
    format: Annotated[
        str,
        typer.Option("-f", "--format", help="Output format (webp, avif, jpeg, png, etc.)")
    ],
    output_path: Annotated[
        Optional[Path],
        typer.Option("-o", "--output", help="Output file path")
    ] = None,
    quality: Annotated[
        Optional[int],
        typer.Option("-q", "--quality", min=1, max=100, help="Quality for lossy formats (1-100)")
    ] = None,
    preset: Annotated[
        Optional[str],
        typer.Option("-p", "--preset", help="Use optimization preset")
    ] = None,
    width: Annotated[
        Optional[int],
        typer.Option("-w", "--width", help="Resize to width (maintains aspect ratio)")
    ] = None,
    height: Annotated[
        Optional[int],
        typer.Option("-h", "--height", help="Resize to height (maintains aspect ratio)") 
    ] = None,
    keep_metadata: Annotated[
        bool,
        typer.Option("--keep-metadata", help="Preserve image metadata")
    ] = False,
    optimize: Annotated[
        bool,
        typer.Option("--optimize", help="Apply automatic optimization")
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Preview operation without converting")
    ] = False,
    profile: Annotated[
        bool,
        typer.Option("--profile", help="Enable performance profiling")
    ] = False,
    profile_output: Annotated[
        Optional[Path],
        typer.Option("--profile-output", help="Save profile to JSON file")
    ] = None,
):
    """
    Convert a single image to a different format
    
    Examples:
      img convert file photo.jpg -f webp
      img convert file image.png -f avif -q 90 -o output.avif
      img convert file large.jpg -f jpeg -w 1920 --optimize
    """
    # Validate input
    if not validate_input_file(input_path):
        console.print(f"[red]Error: Invalid or unsupported input file: {input_path}[/red]")
        raise typer.Exit(1)
    
    # Generate output path if not provided
    if not output_path:
        output_path = input_path.with_suffix(f".{format.lower()}")
    
    # Validate output path
    if not validate_output_path(output_path):
        console.print(f"[red]Error: Invalid output path: {output_path}[/red]")
        raise typer.Exit(1)
    
    # Check if output exists and confirm overwrite
    config = get_config()
    if output_path.exists() and config.confirm_destructive and not dry_run:
        if not typer.confirm(f"Output file exists. Overwrite {output_path}?"):
            console.print("[yellow]Conversion cancelled[/yellow]")
            raise typer.Exit(0)
    
    # Show operation preview with emoji if supported
    if should_use_emoji():
        console.print(f"\n[bold cyan]{get_emoji('convert')} Converting:[/bold cyan] {input_path.name}")
        console.print(f"[bold green]{get_emoji('success')} To:[/bold green] {output_path.name} ({get_format_emoji(format)} {format.upper()})")
    else:
        console.print(f"\n[bold cyan]Converting:[/bold cyan] {input_path.name}")
        console.print(f"[bold green]To:[/bold green] {output_path.name} ({format.upper()})")
    
    if dry_run:
        # Show what would be done with themed table
        table = Table(title="Conversion Preview", show_header=False, style="primary")
        table.add_column("Setting", style="secondary")
        table.add_column("Value", style="info")
        
        table.add_row("Input", str(input_path))
        table.add_row("Output", str(output_path))
        table.add_row("Format", f"{get_format_emoji(format) if should_use_emoji() else ''} {format.upper()}")
        if quality:
            table.add_row("Quality", str(quality))
        if preset:
            table.add_row("Preset", preset)
        if width or height:
            table.add_row("Resize", f"{width or 'auto'} x {height or 'auto'}")
        table.add_row("Keep Metadata", "Yes" if keep_metadata else "No")
        table.add_row("Optimize", "Yes" if optimize else "No")
        
        console.print(table)
        console.print(f"\n[warning]{get_emoji('warning') if should_use_emoji() else ''} Dry run complete. No files were modified.[/warning]")
        raise typer.Exit(0)
    
    # Enable profiling if requested
    if profile:
        cli_profiler.enable(output_path=profile_output, show_summary=True)
    
    # Perform conversion
    conversion_start = time.time()
    
    try:
        # Initialize client
        client = ImageConverterClient(
            host=config.api_host,
            port=config.api_port,
            api_key=config.api_key,
            timeout=config.api_timeout
        )
        
        # Read input file
        with open(input_path, 'rb') as f:
            image_data = f.read()
        
        # Create conversion request
        request = ConversionRequest(
            output_format=SDKOutputFormat(format.lower()),
            quality=quality or config.default_quality,
            preset_id=preset or config.default_preset,
            width=width,
            height=height,
            preserve_metadata=keep_metadata or config.preserve_metadata,
            optimize_level=2 if optimize else None
        )
        
        # Show enhanced progress with interruption support
        import tempfile
        import os
        
        with InterruptableProgress(
            description="Converting image",
            total=100,
            show_emoji=should_use_emoji(),
            console=console,
            show_speed=True
        ) as progress:
            task = progress.add_task("Converting...", total=100)
            
            # Create temp file for SDK (it expects file path)
            with tempfile.NamedTemporaryFile(suffix=input_path.suffix, delete=False) as tmp_input:
                tmp_input.write(image_data)
                tmp_input_path = tmp_input.name
            
            try:
                # Perform conversion (SDK expects file path)
                output_data, result = client.convert_image(
                    image_path=tmp_input_path,
                    output_format=format.lower(),
                    quality=quality,
                    strip_metadata=not keep_metadata,
                    preset_id=preset
                )
                
                progress.update(task, advance=50, description="Processing...")
                
                # Write output file
                with open(output_path, 'wb') as f:
                    f.write(output_data)
                
                progress.update(task, advance=50, description="Saving...")
            finally:
                # Clean up temp file
                if os.path.exists(tmp_input_path):
                    os.unlink(tmp_input_path)
            
            if progress.interrupted:
                console.print(f"\n[error]{get_emoji('error') if should_use_emoji() else ''} Conversion interrupted by user[/error]")
                raise typer.Exit(1)
        
        # Track conversion metrics if profiling
        conversion_time = time.time() - conversion_start
        if profile:
            with cli_profiler.profile_operation("convert_file"):
                cli_profiler.track_conversion(
                    input_size=len(image_data),
                    output_size=len(output_data),
                    duration=conversion_time,
                    input_format=input_path.suffix.strip('.'),
                    output_format=format,
                    memory_used=0  # Would need to track actual memory
                )
        
        # Show results with emojis and theming
        input_size = len(image_data) / 1024
        output_size = len(output_data) / 1024
        reduction = ((input_size - output_size) / input_size) * 100 if input_size > 0 else 0
        
        if should_use_emoji():
            console.print(f"\n[success]{get_emoji('success')} Conversion complete![/success]")
        else:
            console.print(f"\n[success]Conversion complete![/success]")
            
        # Create results table
        results_table = Table(show_header=False, box=None)
        results_table.add_column("Metric", style="dim")
        results_table.add_column("Value", style="info")
        
        results_table.add_row("Input Size", f"{input_size:.1f} KB")
        results_table.add_row("Output Size", f"{output_size:.1f} KB")
        results_table.add_row(
            "Size Reduction", 
            f"[{'success' if reduction > 0 else 'warning'}]{reduction:+.1f}%[/{'success' if reduction > 0 else 'warning'}]"
        )
        results_table.add_row("Saved to", f"[primary]{output_path}[/primary]")
        
        console.print(results_table)
        
        # Record in history
        record_command(f"convert {input_path} -f {format} -o {output_path}", success=True)
        
    except Exception as e:
        handle_api_error(e, console)
        record_command(f"convert {input_path} -f {format} -o {output_path}", success=False)
        raise typer.Exit(1)


@app.command(name="stdin")
def convert_stdin(
    format: Annotated[
        str,
        typer.Option("-f", "--format", help="Output format")
    ],
    output: Annotated[
        Optional[Path],
        typer.Option("-o", "--output", help="Output file (or stdout if not specified)")
    ] = None,
    quality: Annotated[
        Optional[int],
        typer.Option("-q", "--quality", min=1, max=100, help="Quality for lossy formats")
    ] = None,
):
    """
    Convert image from stdin
    
    Examples:
      cat image.jpg | img convert stdin -f webp > output.webp
      cat photo.png | img convert stdin -f avif -o result.avif
    """
    try:
        # Read from stdin
        if sys.stdin.isatty():
            console.print("[red]Error: No input data. Pipe an image to this command.[/red]")
            raise typer.Exit(1)
        
        image_data = sys.stdin.buffer.read()
        
        # Initialize client
        config = get_config()
        client = ImageConverterClient(
            host=config.api_host,
            port=config.api_port,
            api_key=config.api_key,
            timeout=config.api_timeout
        )
        
        # Create conversion request
        request = ConversionRequest(
            output_format=SDKOutputFormat(format.lower()),
            quality=quality or config.default_quality
        )
        
        # Create temp file for SDK
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(suffix='.tmp', delete=False) as tmp_input:
            tmp_input.write(image_data)
            tmp_input_path = tmp_input.name
        
        try:
            # Perform conversion (SDK expects file path)
            output_data, result = client.convert_image(
                image_path=tmp_input_path,
                output_format=format.lower(),
                quality=quality,
                strip_metadata=True
            )
        finally:
            # Clean up temp file
            if os.path.exists(tmp_input_path):
                os.unlink(tmp_input_path)
        
        # Output result
        if output:
            with open(output, 'wb') as f:
                f.write(output_data)
            console.print(f"[green]✓[/green] Saved to: [cyan]{output}[/cyan]", file=sys.stderr)
        else:
            # Write to stdout
            sys.stdout.buffer.write(output_data)
        
    except Exception as e:
        handle_api_error(e, console)
        raise typer.Exit(1)


@app.callback()
def convert_callback():
    """Convert images to different formats"""
    pass