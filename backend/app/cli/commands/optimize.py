"""
Optimize Command
Intelligent image optimization with presets and auto-detection
"""

import time
from pathlib import Path
from typing import Optional, Annotated
import asyncio

import typer
from rich.console import Console
from rich.table import Table

from app.cli.config import get_config
from app.cli.utils.validation import validate_input_file, validate_output_path
from app.cli.utils.errors import handle_api_error
from app.cli.utils.history import record_command
from app.cli.ui.themes import get_theme_manager
from app.cli.ui.preview import show_image_comparison
from app.cli.utils.emoji import get_emoji, format_with_emoji, get_quality_stars
from app.cli.utils.terminal import should_use_emoji
from app.cli.utils.progress import InterruptableProgress, SpinnerStyle
from app.cli.utils.profiler import cli_profiler

# Import SDK client
from app.cli.utils import setup_sdk_path
setup_sdk_path()
from image_converter.client import ImageConverterClient
from image_converter.models import OptimizationRequest

app = typer.Typer(no_args_is_help=True)

# Initialize themed console
theme_manager = get_theme_manager()
config = get_config()
console = theme_manager.create_console(config.theme)


@app.command(name="auto")
def optimize_auto(
    input_path: Annotated[
        Path,
        typer.Argument(help="Input image file path", exists=True)
    ],
    preset: Annotated[
        Optional[str],
        typer.Option("-p", "--preset", help="Optimization preset (web, print, archive, thumbnail)")
    ] = "balanced",
    output: Annotated[
        Optional[Path],
        typer.Option("-o", "--output", help="Output file path")
    ] = None,
    quality_target: Annotated[
        Optional[int],
        typer.Option("-q", "--quality", min=1, max=100, help="Target quality (1-100)")
    ] = None,
    max_size: Annotated[
        Optional[str],
        typer.Option("--max-size", help="Maximum file size (e.g., 100KB, 2MB)")
    ] = None,
    preview: Annotated[
        bool,
        typer.Option("--preview", help="Show before/after preview in terminal")
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show optimization plan without executing")
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
    Automatically optimize image with intelligent settings
    
    Examples:
      img optimize auto photo.jpg
      img optimize auto image.png --preset web
      img optimize auto large.jpg --max-size 500KB
      img optimize auto image.jpg -q 85 --preview
    """
    # Validate input
    if not validate_input_file(input_path):
        error_msg = format_with_emoji(f"Invalid or unsupported input file: {input_path}", "error")
        console.print(f"[error]{error_msg}[/error]")
        raise typer.Exit(1)
    
    # Generate output path if not provided
    if not output:
        output = input_path.parent / f"{input_path.stem}_optimized{input_path.suffix}"
    
    # Validate output path
    if not validate_output_path(output):
        error_msg = format_with_emoji(f"Invalid output path: {output}", "error")
        console.print(f"[error]{error_msg}[/error]")
        raise typer.Exit(1)
    
    # Show operation preview
    title = format_with_emoji("Optimization Settings", "optimize")
    console.print(f"\n[primary]{title}[/primary]")
    
    settings_table = Table(show_header=False, box=None)
    settings_table.add_column("Setting", style="secondary")
    settings_table.add_column("Value", style="info")
    
    settings_table.add_row("Input", str(input_path))
    settings_table.add_row("Output", str(output))
    settings_table.add_row("Preset", f"{get_emoji('settings')} {preset}" if should_use_emoji() else preset)
    if quality_target:
        settings_table.add_row("Target Quality", get_quality_stars(quality_target))
    if max_size:
        settings_table.add_row("Max Size", max_size)
    
    console.print(settings_table)
    
    if dry_run:
        info_msg = format_with_emoji("Dry run complete. No files were modified.", "info")
        console.print(f"\n[warning]{info_msg}[/warning]")
        raise typer.Exit(0)
    
    # Enable profiling if requested
    if profile:
        cli_profiler.enable(output_path=profile_output, show_summary=True)
    
    # Perform optimization
    optimization_start = time.time()
    
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
        
        input_size = len(image_data) / 1024  # KB
        
        # Parse max size if provided
        max_size_bytes = None
        if max_size:
            if max_size.upper().endswith('KB'):
                max_size_bytes = int(float(max_size[:-2]) * 1024)
            elif max_size.upper().endswith('MB'):
                max_size_bytes = int(float(max_size[:-2]) * 1024 * 1024)
            else:
                max_size_bytes = int(max_size)
        
        # Create optimization request
        request = OptimizationRequest(
            preset=preset,
            target_quality=quality_target,
            max_file_size=max_size_bytes,
            auto_optimize=True
        )
        
        # Show progress with theme support
        with InterruptableProgress(
            description="Optimizing image",
            total=100,
            show_emoji=should_use_emoji(),
            spinner_style=SpinnerStyle.STAR,
            console=console
        ) as progress:
            task = progress.add_task("Analyzing image...", total=100)
            
            # Perform optimization
            result = client.convert_image(
                image_data=image_data,
                request=request,
                input_filename=input_path.name
            )
            
            progress.update(task, advance=50, description="Applying optimizations...")
            
            # Write output file
            with open(output, 'wb') as f:
                f.write(result.output_data)
            
            progress.update(task, advance=50, description="Saving optimized image...")
            
            if progress.interrupted:
                error_msg = format_with_emoji("Optimization interrupted by user", "cancelled")
                console.print(f"\n[error]{error_msg}[/error]")
                raise typer.Exit(1)
        
        # Track optimization metrics if profiling
        optimization_time = time.time() - optimization_start
        if profile:
            with cli_profiler.profile_operation("optimize_auto"):
                cli_profiler.track_conversion(
                    input_size=len(image_data),
                    output_size=len(result.output_data),
                    duration=optimization_time,
                    input_format=input_path.suffix.strip('.'),
                    output_format=output.suffix.strip('.') if output else input_path.suffix.strip('.'),
                    memory_used=0  # Would need to track actual memory
                )
        
        # Calculate results
        output_size = len(result.output_data) / 1024  # KB
        reduction = ((input_size - output_size) / input_size) * 100 if input_size > 0 else 0
        
        # Show results
        success_msg = format_with_emoji("Optimization complete!", "success")
        console.print(f"\n[success]{success_msg}[/success]")
        
        # Results table
        results_table = Table(title="Optimization Results", show_header=True)
        results_table.add_column("Metric", style="dim")
        results_table.add_column("Before", style="warning")
        results_table.add_column("After", style="success")
        results_table.add_column("Improvement", style="info")
        
        results_table.add_row(
            "File Size",
            f"{input_size:.1f} KB",
            f"{output_size:.1f} KB",
            f"{reduction:+.1f}%"
        )
        
        if hasattr(result, 'quality_score'):
            results_table.add_row(
                "Quality",
                "-",
                get_quality_stars(result.quality_score),
                f"{result.quality_score}%"
            )
        
        console.print(results_table)
        
        # Show preview if requested
        if preview and output.exists():
            try:
                show_image_comparison(input_path, output, console)
            except Exception:
                # Preview might fail in some terminals
                pass
        
        # Record in history
        record_command(f"optimize auto {input_path} --preset {preset}", success=True)
        
    except Exception as e:
        handle_api_error(e, console)
        record_command(f"optimize auto {input_path} --preset {preset}", success=False)
        raise typer.Exit(1)


@app.command(name="analyze")
def optimize_analyze(
    input_path: Annotated[
        Path,
        typer.Argument(help="Image file to analyze", exists=True)
    ],
):
    """
    Analyze image and suggest optimizations
    
    Examples:
      img optimize analyze photo.jpg
      img optimize analyze large-image.png
    """
    if not validate_input_file(input_path):
        error_msg = format_with_emoji(f"Invalid or unsupported input file: {input_path}", "error")
        console.print(f"[error]{error_msg}[/error]")
        raise typer.Exit(1)
    
    analyzing_msg = format_with_emoji(f"Analyzing {input_path.name}...", "analyzing")
    console.print(f"\n[info]{analyzing_msg}[/info]")
    
    try:
        # Initialize client
        config = get_config()
        client = ImageConverterClient(
            host=config.api_host,
            port=config.api_port,
            api_key=config.api_key
        )
        
        # Read file
        with open(input_path, 'rb') as f:
            image_data = f.read()
        
        # Analyze image
        analysis = client.analyze_image(image_data, input_path.name)
        
        # Display analysis results
        analysis_table = Table(title="Image Analysis", show_header=True)
        analysis_table.add_column("Property", style="cyan")
        analysis_table.add_column("Value", style="green")
        analysis_table.add_column("Recommendation", style="yellow")
        
        file_size = len(image_data) / 1024
        analysis_table.add_row(
            "File Size",
            f"{file_size:.1f} KB",
            "Consider optimization" if file_size > 500 else "Good"
        )
        
        if hasattr(analysis, 'format'):
            analysis_table.add_row(
                "Format",
                f"{get_format_emoji(analysis.format)} {analysis.format.upper()}" if should_use_emoji() else analysis.format.upper(),
                "Modern format" if analysis.format in ['webp', 'avif'] else "Consider WebP/AVIF"
            )
        
        if hasattr(analysis, 'dimensions'):
            analysis_table.add_row(
                "Dimensions",
                f"{analysis.dimensions[0]}x{analysis.dimensions[1]}",
                "Resize for web" if analysis.dimensions[0] > 2000 else "Good"
            )
        
        console.print(analysis_table)
        
        # Optimization suggestions
        suggestions = [
            format_with_emoji("Use 'img optimize auto' for automatic optimization", "tip"),
            format_with_emoji("Try '--preset web' for web-optimized output", "tip"),
            format_with_emoji("Use '--max-size' to set file size limit", "tip"),
        ]
        
        console.print("\n[primary]Optimization Suggestions:[/primary]")
        for suggestion in suggestions:
            console.print(f"  • {suggestion}")
        
    except Exception as e:
        handle_api_error(e, console)
        raise typer.Exit(1)


@app.callback()
def optimize_callback():
    """Intelligent image optimization"""
    pass