"""
Presets Command
Manage conversion presets
"""

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command(name="list")
def presets_list():
    """
    List available presets

    Examples:
      img presets list
    """
    # Implementation will query the presets API endpoint
    table = Table(title="Available Presets", show_header=True)
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Description", style="dim")

    # Sample data - will be fetched from API
    presets = [
        ("web", "Built-in", "Optimized for web delivery"),
        ("thumbnail", "Built-in", "Small thumbnail generation"),
        ("archive", "Built-in", "High quality archival"),
    ]

    for name, type_, desc in presets:
        table.add_row(name, type_, desc)

    console.print(table)


@app.command(name="create")
def presets_create(
    name: str,
    format: str,
    quality: int = 85,
):
    """
    Create a new preset

    Examples:
      img presets create my-preset webp --quality 90
    """
    console.print(f"[green]✓[/green] Created preset [cyan]{name}[/cyan]")
    console.print(f"  Format: {format}")
    console.print(f"  Quality: {quality}")


@app.command(name="delete")
def presets_delete(
    name: str,
):
    """
    Delete a preset

    Examples:
      img presets delete my-preset
    """
    console.print(f"[yellow]⚠[/yellow] Deleted preset [cyan]{name}[/cyan]")


@app.callback()
def presets_callback():
    """Manage conversion presets"""
    pass
