"""
from typing import Any
CLI Branding utilities
Logo display and branding consistency for CLI
"""

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from app.cli import __version__


def get_logo_ascii() -> str:
    """
    Returns ASCII art version of the IC logo
    Based on the shield logo with 'ic' text
    """
    return """
    ╭─────────────╮
   ╱               ╲
  ╱                 ╲
 │    ██  ████████   │
 │    ██  ██         │
 │    ██  ██         │
 │    ██  ██         │
 │    ██  ████████   │
 │                   │
 │     ████████      │
 │    ██      ██     │
 │   ██        ██    │
 │  ██          ██   │
 │  ████████████████ │
  ╲                 ╱
   ╲_______________╱
"""


def get_simple_logo() -> str:
    """Simplified logo for smaller displays"""
    return """
 ╭─────╮
 │ 🛡️ IC │
 ╰─────╯
"""


def show_cli_banner(console: Console = None, show_version: bool = True) -> None:
    """
    Display the CLI banner with logo and branding
    """
    if not console:
        console = Console()

    # Logo text with styling
    logo_text = Text()
    logo_text.append("🛡️ ", style="bright_cyan")
    logo_text.append("IC", style="bold bright_cyan")
    logo_text.append(" Image Converter", style="bold white")

    # Version info
    version_info = Text()
    if show_version:
        version_info.append(f"v{__version__}", style="dim")
        version_info.append(" • ", style="dim")
    version_info.append("Privacy-First Local Processing", style="italic green")

    # Create panel
    banner_content = Text()
    banner_content.append(logo_text)
    banner_content.append("\n")
    banner_content.append(version_info)

    panel = Panel(
        Align.center(banner_content),
        border_style="bright_cyan",
        padding=(1, 2),
        title="[bold bright_cyan]Image Converter CLI[/bold bright_cyan]",
        title_align="center",
    )

    console.print(panel)
    console.print()


def show_version_info(console: Console = None) -> None:
    """
    Display detailed version information with branding
    """
    if not console:
        console = Console()

    # Create version table
    from rich.table import Table

    table = Table(title="🛡️ IC Image Converter", title_style="bold bright_cyan")
    table.add_column("Component", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Status", style="yellow")

    table.add_row("CLI", __version__, "✅ Active")
    table.add_row("Backend", "1.0.0", "✅ Connected")
    table.add_row("Security", "Multi-layer", "🛡️ Enabled")
    table.add_row("Privacy", "100% Local", "🔒 Protected")

    console.print(table)
    console.print()


def show_success_message(message: str, console: Console = None) -> None:
    """Show success message with branding"""
    if not console:
        console = Console()

    success_panel = Panel(
        f"🛡️ [green]✓[/green] {message}", border_style="green", padding=(0, 1)
    )
    console.print(success_panel)


def show_error_message(message: str, console: Console = None) -> None:
    """Show error message with branding"""
    if not console:
        console = Console()

    error_panel = Panel(f"🛡️ [red]✗[/red] {message}", border_style="red", padding=(0, 1))
    console.print(error_panel)
