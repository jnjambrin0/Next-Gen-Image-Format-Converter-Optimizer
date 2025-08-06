"""
Formats Command
List and manage supported image formats
"""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command(name="list")
def formats_list():
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


@app.callback()
def formats_callback():
    """Manage supported formats"""
    pass