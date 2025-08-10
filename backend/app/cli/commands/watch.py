"""
Watch Mode Command
Monitor directories and automatically convert images
"""

import signal
import sys
from pathlib import Path
from typing import Annotated, Any, List, Optional

import typer
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from app.cli.config import get_config
from app.cli.productivity.watcher import (DirectoryWatcher, FileEvent,
                                          ResourceLimits, WatcherStatus)
from app.cli.utils.errors import handle_error

# Import SDK for conversions
try:
    from sdks.python.image_converter_sdk import ImageConverterClient

    SDK_AVAILABLE = True
    SDK_IMPORT_ERROR = None
except ImportError as e:
    ImageConverterClient = None
    SDK_AVAILABLE = False
    SDK_IMPORT_ERROR = str(e)


# Create Typer app
app = typer.Typer(
    name="watch",
    help="Monitor directories for automatic image conversion",
    no_args_is_help=True,
)

# Console for output
console = Console()


class WatchModeProcessor:
    """Process files in watch mode using sandboxed conversions"""

    def __init__(
        self,
        output_format: str,
        output_dir: Optional[Path] = None,
        quality: int = 85,
        preset: Optional[str] = None,
    ) -> None:
        self.output_format = output_format
        self.output_dir = output_dir
        self.quality = quality
        self.preset = preset

        # Initialize SDK client if available
        config = get_config()
        self.client = None
        self.client_error = None

        if not SDK_AVAILABLE:
            self.client_error = (
                "Image Converter SDK not installed. "
                "Install it with: pip install -e sdks/python/"
            )
            if SDK_IMPORT_ERROR:
                self.client_error += f"\nImport error: {SDK_IMPORT_ERROR}"
        elif ImageConverterClient:
            try:
                self.client = ImageConverterClient(
                    host=config.api_host, port=config.api_port, api_key=config.api_key
                )
            except Exception as e:
                self.client_error = f"Failed to initialize SDK client: {e}"

    def process_file(self, file_event: FileEvent) -> None:
        """Process a file event"""
        if not self.client:
            error_msg = self.client_error or "Image converter client not available"
            raise RuntimeError(error_msg)

        input_path = file_event.path

        # Determine output path
        if self.output_dir:
            output_name = input_path.stem + f".{self.output_format}"
            output_path = self.output_dir / output_name
        else:
            output_path = input_path.parent / (
                input_path.stem + f".{self.output_format}"
            )

        # Skip if output already exists and is newer
        if output_path.exists():
            if output_path.stat().st_mtime > input_path.stat().st_mtime:
                return

        try:
            # Use SDK to convert (which enforces sandboxing)
            # SDK expects file paths, not bytes
            _, result = self.client.convert_image(
                image_path=str(input_path),
                output_format=self.output_format,
                quality=self.quality,
                preset_id=self.preset,
            )

            # Save output
            if hasattr(result, "output_path"):
                # Move from temp to final location
                import shutil

                shutil.move(result.output_path, str(output_path))
        except Exception as e:
            # Log error but don't stop watching
            console.print(f"[red]Error processing {input_path.name}: {e}[/red]")


class WatchDisplay:
    """Display for watch mode status"""

    def __init__(self) -> None:
        self.layout = self._create_layout()
        self.status_table = Table(show_header=False, box=None)
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            expand=True,
        )

    def _create_layout(self) -> Layout:
        """Create display layout"""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="status", size=10),
            Layout(name="progress", size=3),
            Layout(name="footer", size=3),
        )
        return layout

    def update(self, watcher: DirectoryWatcher) -> None:
        """Update display with current status"""
        status = watcher.get_status()

        # Update header
        header = Panel(
            f"[bold cyan]Watch Mode[/bold cyan] - Monitoring: {status['directory']}",
            style="cyan",
        )
        self.layout["header"].update(header)

        # Update status table
        self.status_table = Table(show_header=False, box=None, expand=True)
        self.status_table.add_column("Label", style="cyan")
        self.status_table.add_column("Value", style="white")

        stats = status["stats"]
        self.status_table.add_row("Status", f"[bold]{status['status']}[/bold]")
        self.status_table.add_row("Files Processed", str(stats["files_processed"]))
        self.status_table.add_row("Files Failed", f"[red]{stats['files_failed']}[/red]")
        self.status_table.add_row("Files Skipped", str(stats["files_skipped"]))
        self.status_table.add_row("Total Events", str(stats["total_events"]))
        self.status_table.add_row("Queue Size", f"{stats['queue_size']}")
        self.status_table.add_row("Active Workers", str(stats["active_workers"]))
        self.status_table.add_row("Uptime", stats["uptime"])

        self.layout["status"].update(Panel(self.status_table, title="Statistics"))

        # Update progress
        if status["status"] == "processing":
            self.layout["progress"].update(self.progress)
        else:
            self.layout["progress"].update(Panel("[dim]Waiting for changes...[/dim]"))

        # Update footer
        resources = status["resources"]
        footer_text = (
            f"Memory: {resources['memory_mb']:.1f} MB | "
            f"CPU: {resources['cpu_percent']:.1f}% | "
            f"Press Ctrl+C to stop"
        )
        self.layout["footer"].update(Panel(footer_text, style="dim"))

        return self.layout


@app.command()
def start(
    directory: Annotated[Path, typer.Argument(help="Directory to watch")],
    format: Annotated[
        str, typer.Option("-f", "--format", help="Output format")
    ] = "webp",
    output_dir: Annotated[
        Optional[Path],
        typer.Option(
            "-o", "--output-dir", help="Output directory (default: same as input)"
        ),
    ] = None,
    filter: Annotated[
        Optional[List[str]],
        typer.Option("--filter", help="File patterns to include (e.g., *.jpg)"),
    ] = None,
    exclude: Annotated[
        Optional[List[str]], typer.Option("--exclude", help="File patterns to exclude")
    ] = None,
    quality: Annotated[
        int, typer.Option("-q", "--quality", help="Output quality (1-100)")
    ] = 85,
    preset: Annotated[
        Optional[str], typer.Option("--preset", help="Optimization preset")
    ] = None,
    workers: Annotated[
        int, typer.Option("--workers", help="Max concurrent conversions")
    ] = 5,
    max_files: Annotated[
        int, typer.Option("--max-files", help="Max files in queue")
    ] = 100,
    debounce: Annotated[
        int, typer.Option("--debounce", help="Debounce delay in milliseconds")
    ] = 500,
    no_display: Annotated[
        bool, typer.Option("--no-display", help="Disable status display")
    ] = False,
):
    """
    Start watching a directory for image files to convert

    Examples:
        img watch ./photos -f webp
        img watch . --filter "*.jpg" "*.png" -f avif --quality 90
        img watch ./input -o ./output --preset web
    """
    # Check SDK availability first
    if not SDK_AVAILABLE:
        console.print("[red]Error: Image Converter SDK is not installed[/red]")
        console.print("[yellow]To install the SDK, run:[/yellow]")
        console.print("  pip install -e sdks/python/")
        if SDK_IMPORT_ERROR:
            console.print(f"[dim]Import error: {SDK_IMPORT_ERROR}[/dim]")
        raise typer.Exit(1)

    # Validate directory
    if not directory.exists():
        console.print(f"[red]Error: Directory '{directory}' does not exist[/red]")
        raise typer.Exit(1)

    if not directory.is_dir():
        console.print(f"[red]Error: '{directory}' is not a directory[/red]")
        raise typer.Exit(1)

    # Create output directory if specified
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    # Set up resource limits
    limits = ResourceLimits(
        max_files=max_files,
        max_concurrent=workers,
        debounce_ms=debounce,
        max_events_per_second=10,
        max_memory_mb=512,
        max_cpu_percent=80,
    )

    # Default filters if none specified
    if not filter:
        filter = ["*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.tiff", "*.tif"]

    # Create processor
    processor = WatchModeProcessor(
        output_format=format, output_dir=output_dir, quality=quality, preset=preset
    )

    # Create watcher
    watcher = DirectoryWatcher(
        directory=directory,
        filters=filter,
        excludes=exclude or [],
        limits=limits,
        process_callback=processor.process_file,
    )

    # Set up signal handlers
    def signal_handler(sig, frame) -> None:
        console.print("\n[yellow]Stopping watch mode...[/yellow]")
        watcher.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start watching
    console.print(f"[green]Starting watch mode on {directory}[/green]")
    console.print(f"[dim]Output format: {format}, Quality: {quality}[/dim]")
    console.print(f"[dim]Filters: {', '.join(filter)}[/dim]")
    if exclude:
        console.print(f"[dim]Excludes: {', '.join(exclude)}[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        watcher.start()

        if no_display:
            # Simple mode - just wait
            while watcher.status != WatcherStatus.STOPPED:
                import time

                time.sleep(1)
        else:
            # Interactive display mode
            display = WatchDisplay()

            with Live(
                display.update(watcher), refresh_per_second=1, console=console
            ) as live:
                while watcher.status != WatcherStatus.STOPPED:
                    import time

                    time.sleep(0.5)
                    live.update(display.update(watcher))

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping watch mode...[/yellow]")
        watcher.stop()
    except Exception as e:
        handle_error(e, "Watch mode failed")
        watcher.stop()
        raise typer.Exit(1)
    finally:
        # Show final stats
        status = watcher.get_status()
        stats = status["stats"]

        console.print("\n[bold]Final Statistics:[/bold]")
        console.print(f"  Files processed: {stats['files_processed']}")
        console.print(f"  Files failed: [red]{stats['files_failed']}[/red]")
        console.print(f"  Files skipped: {stats['files_skipped']}")
        console.print(f"  Total events: {stats['total_events']}")
        console.print(f"  Runtime: {stats['uptime']}")


@app.command()
def test(
    directory: Annotated[Path, typer.Argument(help="Directory to test")],
    filter: Annotated[
        Optional[List[str]], typer.Option("--filter", help="File patterns to include")
    ] = None,
):
    """
    Test which files would be processed (dry run)
    """
    if not directory.exists() or not directory.is_dir():
        console.print(f"[red]Error: Invalid directory '{directory}'[/red]")
        raise typer.Exit(1)

    # Default filters
    if not filter:
        filter = ["*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.tiff", "*.tif"]

    # Find matching files
    import fnmatch

    matched_files = []

    for path in directory.rglob("*"):
        if path.is_file():
            for pattern in filter:
                if fnmatch.fnmatch(path.name, pattern):
                    matched_files.append(path)
                    break

    if not matched_files:
        console.print("[yellow]No matching files found[/yellow]")
        return

    # Display results
    console.print(f"[green]Found {len(matched_files)} matching files:[/green]")

    table = Table(show_header=True)
    table.add_column("File", style="cyan")
    table.add_column("Size", style="yellow")
    table.add_column("Modified", style="dim")

    for file in matched_files[:20]:  # Show first 20
        size_mb = file.stat().st_size / 1024 / 1024
        modified = file.stat().st_mtime
        from datetime import datetime

        mod_time = datetime.fromtimestamp(modified).strftime("%Y-%m-%d %H:%M")

        table.add_row(str(file.relative_to(directory)), f"{size_mb:.2f} MB", mod_time)

    if len(matched_files) > 20:
        table.add_row("...", "...", "...")
        table.add_row(f"[dim]And {len(matched_files) - 20} more files[/dim]", "", "")

    console.print(table)


if __name__ == "__main__":
    app()
