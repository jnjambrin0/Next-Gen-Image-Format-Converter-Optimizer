"""
Main CLI Application
Core Typer application with command groups and global configuration
"""

import sys
from pathlib import Path
from typing import Optional, Annotated
from enum import Enum

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from app.cli import __version__
from app.cli.commands import convert, batch, optimize, analyze, formats, presets, chain
from app.cli.plugins import loader as plugin_loader
from app.cli.utils import aliases, errors, i18n
from app.cli.utils.branding import (
    show_cli_banner,
    show_version_info,
    show_success_message,
    show_error_message,
)
from app.cli.config import CLIConfig, get_config, update_config
from app.cli.ui.themes import get_theme_manager
from app.cli.utils.terminal import get_terminal_detector

# Initialize theme manager and console
theme_manager = get_theme_manager()
console = None  # Will be initialized with theme

# Create main Typer app with custom help
app = typer.Typer(
    name="img",
    help="🛡️ IC Professional Image Converter CLI - Next-gen format conversion & optimization",
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
    add_completion=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

# State management for verbose mode
state = {"verbose": False, "debug": False, "language": "en"}


class OutputFormat(str, Enum):
    """Output format options for global flag"""

    json = "json"
    table = "table"
    plain = "plain"
    rich = "rich"


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        Optional[bool], typer.Option("--version", "-v", help="Show CLI version")
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", help="Enable verbose output")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", help="Enable debug mode with detailed errors")
    ] = False,
    output: Annotated[
        OutputFormat, typer.Option("--output", "-O", help="Output format for results")
    ] = OutputFormat.rich,
    language: Annotated[
        Optional[str],
        typer.Option("--lang", "-L", help="Language code (en, es, fr, de, zh, ja)"),
    ] = None,
):
    """
    Image Converter CLI - Professional image format conversion & optimization

    Use 'img COMMAND --help' for more information on specific commands.

    [bold green]Quick Start:[/bold green]

    Convert single image:
      [cyan]img convert input.jpg -f webp -o output.webp[/cyan]

    Batch conversion:
      [cyan]img batch *.png -f avif --quality 85[/cyan]

    Optimize images:
      [cyan]img optimize photo.jpg --preset web[/cyan]

    [bold yellow]Common Shortcuts:[/bold yellow]
      • img c → img convert
      • img b → img batch
      • img o → img optimize
    """
    global console  # Declare global at the beginning

    # Load user configuration first
    config = get_config()

    # Initialize console with theme if not already initialized
    if not console:
        theme_manager.set_current_theme(config.theme)
        console = theme_manager.create_console()

    if version:
        show_version_info(console)
        raise typer.Exit()

    # Update global state
    state["verbose"] = verbose
    state["debug"] = debug
    state["output_format"] = output.value

    # Set language if specified
    if language:
        state["language"] = language
        i18n.set_language(language)

    # Load plugins
    if config.plugins_enabled:
        try:
            plugin_loader.load_plugins(app)
        except Exception as e:
            if state["debug"]:
                console.print(f"[yellow]Warning: Failed to load plugins: {e}[/yellow]")

    # Apply aliases
    if config.aliases_enabled:
        try:
            aliases.apply_aliases(app)
        except Exception as e:
            if state["debug"]:
                console.print(f"[yellow]Warning: Failed to apply aliases: {e}[/yellow]")

    # If no command was invoked and no version flag, show branded help
    if ctx.invoked_subcommand is None and not version:
        show_cli_banner(console)
        console.print(ctx.get_help())
        raise typer.Exit()


# Add command groups
app.add_typer(
    convert.app, name="convert", help="Convert single images", no_args_is_help=True
)
app.add_typer(
    batch.app, name="batch", help="Batch conversion operations", no_args_is_help=True
)
app.add_typer(
    optimize.app,
    name="optimize",
    help="Intelligent image optimization",
    no_args_is_help=True,
)
app.add_typer(
    analyze.app, name="analyze", help="Analyze image properties", no_args_is_help=True
)
app.add_typer(
    formats.app, name="formats", help="Manage supported formats", no_args_is_help=True
)
app.add_typer(
    presets.app, name="presets", help="Manage conversion presets", no_args_is_help=True
)
app.add_typer(
    chain.app, name="chain", help="Chain operations and piping", no_args_is_help=True
)


# Add shortcuts (these will be handled by alias system)
# Register common shortcuts programmatically
@app.command("c", hidden=True)
def convert_shortcut(
    ctx: typer.Context,
):
    """Shortcut for 'convert' command"""
    # Forward to convert command
    convert.app.invoke(ctx)


@app.command("b", hidden=True)
def batch_shortcut(
    ctx: typer.Context,
):
    """Shortcut for 'batch' command"""
    # Forward to batch command
    batch.app.invoke(ctx)


@app.command("o", hidden=True)
def optimize_shortcut(
    ctx: typer.Context,
):
    """Shortcut for 'optimize' command"""
    # Forward to optimize command
    optimize.app.invoke(ctx)


# Configuration management commands
@app.command()
def config(
    action: Annotated[str, typer.Argument(help="Action: show, set, get, reset, theme")],
    key: Annotated[
        Optional[str], typer.Argument(help="Configuration key or theme name")
    ] = None,
    value: Annotated[Optional[str], typer.Argument(help="Configuration value")] = None,
):
    """
    Manage CLI configuration

    Examples:
      img config show              # Show all configuration
      img config get api_url       # Get specific value
      img config set api_url http://localhost:8000
      img config reset             # Reset to defaults
      img config theme             # List available themes
      img config theme dark        # Set theme to dark
    """
    global console

    # Ensure console is initialized
    if not console:
        config_obj = get_config()
        theme_manager.set_current_theme(config_obj.theme)
        console = theme_manager.create_console()

    config_obj = get_config()

    if action == "show":
        table = Table(title="CLI Configuration", show_header=True)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Description", style="dim")

        for field_name, field in config_obj.__fields__.items():
            value = getattr(config_obj, field_name)
            description = field.description or ""
            table.add_row(field_name, str(value), description)

        console.print(table)

    elif action == "get" and key:
        if hasattr(config_obj, key):
            value = getattr(config_obj, key)
            console.print(f"[cyan]{key}[/cyan] = [green]{value}[/green]")
        else:
            console.print(f"[red]Unknown configuration key: {key}[/red]")
            raise typer.Exit(1)

    elif action == "set" and key and value:
        if hasattr(config_obj, key):
            # Update configuration
            setattr(config_obj, key, value)
            update_config(config_obj)
            console.print(
                f"[green]✓[/green] Set [cyan]{key}[/cyan] = [green]{value}[/green]"
            )
        else:
            console.print(f"[red]Unknown configuration key: {key}[/red]")
            raise typer.Exit(1)

    elif action == "reset":
        # Reset to defaults
        default_config = CLIConfig()
        update_config(default_config)
        console.print("[green]✓[/green] Configuration reset to defaults")

    elif action == "theme":
        if key:
            # Set theme
            if theme_manager.set_current_theme(key):
                config_obj.theme = key
                update_config(config_obj)
                # Reinitialize console with new theme
                new_console = theme_manager.create_console()
                new_console.print(f"[green]✓[/green] Theme set to [cyan]{key}[/cyan]")
                # Update global console
                console = new_console
            else:
                console.print(f"[red]Unknown theme: {key}[/red]")
                console.print(
                    "Available themes: dark, light, high_contrast, colorblind_safe, minimal"
                )
                raise typer.Exit(1)
        else:
            # List themes
            themes = theme_manager.list_themes()
            table = Table(title="Available Themes", show_header=True)
            table.add_column("Name", style="cyan")
            table.add_column("Type", style="green")
            table.add_column("Description", style="dim")
            table.add_column("Current", style="yellow")

            current_theme = config_obj.theme
            for theme_name, theme in themes.items():
                is_current = "✓" if theme_name == current_theme else ""
                table.add_row(
                    theme.name, theme.type.value, theme.description, is_current
                )

            console.print(table)

    else:
        console.print("[red]Invalid action or missing arguments[/red]")
        console.print("Use: img config show|get|set|reset|theme")
        raise typer.Exit(1)


@app.command()
def aliases(
    action: Annotated[
        Optional[str], typer.Argument(help="Action: list, add, remove")
    ] = "list",
    name: Annotated[Optional[str], typer.Argument(help="Alias name")] = None,
    command: Annotated[Optional[str], typer.Argument(help="Command to alias")] = None,
):
    """
    Manage command aliases

    Examples:
      img aliases                    # List all aliases
      img aliases add conv convert   # Create alias 'conv' for 'convert'
      img aliases remove conv        # Remove alias
    """
    if action == "list":
        alias_list = aliases.list_aliases()
        if alias_list:
            table = Table(title="Command Aliases", show_header=True)
            table.add_column("Alias", style="cyan")
            table.add_column("Command", style="green")

            for alias, cmd in alias_list.items():
                table.add_row(alias, cmd)

            console.print(table)
        else:
            console.print("[yellow]No aliases configured[/yellow]")

    elif action == "add" and name and command:
        aliases.add_alias(name, command)
        console.print(
            f"[green]✓[/green] Added alias [cyan]{name}[/cyan] → [green]{command}[/green]"
        )

    elif action == "remove" and name:
        if aliases.remove_alias(name):
            console.print(f"[green]✓[/green] Removed alias [cyan]{name}[/cyan]")
        else:
            console.print(f"[red]Alias not found: {name}[/red]")
            raise typer.Exit(1)

    else:
        console.print("[red]Invalid action or missing arguments[/red]")
        raise typer.Exit(1)


@app.command()
def plugins(
    action: Annotated[
        Optional[str], typer.Argument(help="Action: list, info, enable, disable")
    ] = "list",
    name: Annotated[Optional[str], typer.Argument(help="Plugin name")] = None,
):
    """
    Manage CLI plugins

    Examples:
      img plugins              # List all plugins
      img plugins info myplug  # Show plugin details
      img plugins enable myplug
      img plugins disable myplug
    """
    if action == "list":
        plugin_list = plugin_loader.list_plugins()
        if plugin_list:
            table = Table(title="Installed Plugins", show_header=True)
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("Description", style="dim")

            for plugin in plugin_list:
                status = "✓ Enabled" if plugin["enabled"] else "✗ Disabled"
                table.add_row(
                    plugin["name"], plugin["version"], status, plugin["description"]
                )

            console.print(table)
        else:
            console.print("[yellow]No plugins installed[/yellow]")
            console.print(
                "\n[dim]Plugins should be placed in ~/.image-converter/plugins/[/dim]"
            )

    elif action == "info" and name:
        info = plugin_loader.get_plugin_info(name)
        if info:
            console.print(f"\n[bold cyan]{info['name']}[/bold cyan] v{info['version']}")
            console.print(f"[dim]{info['description']}[/dim]\n")
            console.print(
                f"[yellow]Status:[/yellow] {'Enabled' if info['enabled'] else 'Disabled'}"
            )
            console.print(f"[yellow]Author:[/yellow] {info.get('author', 'Unknown')}")
            console.print(f"[yellow]Path:[/yellow] {info.get('path', 'N/A')}")
        else:
            console.print(f"[red]Plugin not found: {name}[/red]")
            raise typer.Exit(1)

    elif action == "enable" and name:
        if plugin_loader.enable_plugin(name):
            console.print(f"[green]✓[/green] Enabled plugin [cyan]{name}[/cyan]")
        else:
            console.print(f"[red]Failed to enable plugin: {name}[/red]")
            raise typer.Exit(1)

    elif action == "disable" and name:
        if plugin_loader.disable_plugin(name):
            console.print(f"[green]✓[/green] Disabled plugin [cyan]{name}[/cyan]")
        else:
            console.print(f"[red]Failed to disable plugin: {name}[/red]")
            raise typer.Exit(1)

    else:
        console.print("[red]Invalid action or missing arguments[/red]")
        raise typer.Exit(1)


@app.command()
def tui():
    """
    Launch interactive Terminal UI mode

    Provides a full-featured terminal interface with:
    • File browser for image selection
    • Visual conversion settings
    • Real-time progress tracking
    • Results table with statistics
    """
    from app.cli.ui.tui import launch_tui

    try:
        console.print("[cyan]Launching Interactive Mode...[/cyan]")
        launch_tui()
    except ImportError:
        console.print("[red]Error: Textual library not installed[/red]")
        console.print("Install with: pip install textual")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error launching TUI: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def history(
    action: Annotated[
        Optional[str], typer.Argument(help="Action: show, clear, undo, redo")
    ] = "show",
    count: Annotated[
        Optional[int], typer.Option("--count", "-n", help="Number of entries")
    ] = 10,
):
    """
    Manage command history for undo/redo

    Examples:
      img history              # Show recent history
      img history show -n 20   # Show last 20 commands
      img history undo         # Undo last operation
      img history redo         # Redo last undone operation
      img history clear        # Clear all history
    """
    from app.cli.utils.history import HistoryManager

    history_mgr = HistoryManager()

    if action == "show":
        entries = history_mgr.get_history(count)
        if entries:
            table = Table(title="Command History", show_header=True)
            table.add_column("#", style="dim")
            table.add_column("Command", style="cyan")
            table.add_column("Timestamp", style="green")
            table.add_column("Status", style="yellow")

            for idx, entry in enumerate(entries, 1):
                status = "✓" if entry.get("success") else "✗"
                table.add_row(str(idx), entry["command"], entry["timestamp"], status)

            console.print(table)
        else:
            console.print("[yellow]No command history found[/yellow]")

    elif action == "undo":
        result = history_mgr.undo()
        if result:
            console.print(f"[green]✓[/green] Undone: [cyan]{result['command']}[/cyan]")
        else:
            console.print("[yellow]Nothing to undo[/yellow]")

    elif action == "redo":
        result = history_mgr.redo()
        if result:
            console.print(f"[green]✓[/green] Redone: [cyan]{result['command']}[/cyan]")
        else:
            console.print("[yellow]Nothing to redo[/yellow]")

    elif action == "clear":
        history_mgr.clear_history()
        console.print("[green]✓[/green] Command history cleared")

    else:
        console.print("[red]Invalid action[/red]")
        raise typer.Exit(1)


# Error handling
# Note: Typer doesn't have exception_handler attribute
# This would need to be implemented differently
def handle_exceptions(e: Exception):
    """Global exception handler with helpful suggestions"""
    if state.get("debug"):
        # In debug mode, show full traceback
        console.print_exception()
    else:
        # Show user-friendly error with suggestions
        error_handler = errors.ErrorHandler()
        error_handler.handle(e, console)

    raise typer.Exit(1)


if __name__ == "__main__":
    app()
