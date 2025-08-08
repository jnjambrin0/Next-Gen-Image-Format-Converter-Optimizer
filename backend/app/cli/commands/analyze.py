"""
Analyze Command
Image analysis and information extraction
"""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command(name="info")
def analyze_info(
    input_path: str,
):
    """
    Show detailed image information

    Examples:
      img analyze info photo.jpg
    """
    console.print(f"[cyan]Analyzing {input_path}...[/cyan]")
    # Implementation will use the analyze API endpoint


@app.command(name="preview")
def analyze_preview(
    input_path: str,
    mode: str = "ansi",
):
    """
    Preview image in terminal

    Examples:
      img analyze preview photo.jpg
      img analyze preview photo.jpg --mode ascii
    """
    console.print(f"[cyan]Generating preview for {input_path}...[/cyan]")
    # Implementation will use the preview module
    from app.cli.ui.preview import create_ascii_preview
    from pathlib import Path

    try:
        preview = create_ascii_preview(Path(input_path), mode=mode)
        console.print(preview)
    except Exception as e:
        console.print(f"[red]Error generating preview: {e}[/red]")


@app.callback()
def analyze_callback():
    """Analyze image properties"""
    pass
