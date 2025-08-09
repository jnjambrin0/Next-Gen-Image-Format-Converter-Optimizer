"""
from typing import Any
Formats Command
List and manage supported image formats
"""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command(name="list")
def formats_list() -> None:
    """
    List all supported image formats

    Examples:
      img formats list
    """
    # Implementation will query the formats API endpoint
    table = Table(title="Supported Image Formats", show_header=True)
    table.add_column("Format", style="cyan")
    table.add_column("Input", style="green")
    table.add_column("Output", style="yellow")
    table.add_column("Description", style="dim")

    # Sample data - will be fetched from API
    formats = [
        ("JPEG", "✓", "✓", "Joint Photographic Experts Group"),
        ("PNG", "✓", "✓", "Portable Network Graphics"),
        ("WebP", "✓", "✓", "Modern web image format"),
        ("AVIF", "✓", "✓", "AV1 Image File Format"),
        ("HEIF", "✓", "✓", "High Efficiency Image Format"),
    ]

    for fmt, inp, out, desc in formats:
        table.add_row(fmt, inp, out, desc)

    console.print(table)


@app.command(name="info")
def formats_info(
    format_name: str,
) -> None:
    """
    Show detailed information about a format

    Examples:
      img formats info webp
      img formats info avif
    """
    console.print(f"[cyan]Format: {format_name.upper()}[/cyan]")

    # Sample info - will be fetched from API
    info_table = Table(show_header=False, box=None)
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="green")

    info_table.add_row("MIME Type", f"image/{format_name.lower()}")
    info_table.add_row("Supports Transparency", "Yes")
    info_table.add_row(
        "Supports Animation", "Yes" if format_name.lower() in ["webp", "gif"] else "No"
    )
    info_table.add_row("Compression", "Lossy/Lossless")
    info_table.add_row("Browser Support", "Modern browsers")

    console.print(info_table)


@app.callback()
def formats_callback() -> None:
    """Manage supported formats"""
