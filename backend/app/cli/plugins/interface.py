"""
Plugin Interface
Base interface for CLI plugins
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict

import typer


class CLIPlugin(ABC):
    """Base class for CLI plugins"""

    @abstractmethod
    def plugin_info(self) -> Dict[str, Any]:
        """
        Return plugin information

        Returns: Dict[str, Any] with keys: name, version, description, author
        """

    @abstractmethod
    def register(self, app: typer.Typer) -> None:
        """
        Register plugin commands with the CLI app

        Args:
            app: The main Typer application
        """

    def on_load(self) -> None:
        """Called when plugin is loaded (optional)"""

    def on_unload(self) -> None:
        """Called when plugin is unloaded (optional)"""


# Example plugin template
PLUGIN_TEMPLATE = '''"""
Example CLI Plugin
Template for creating custom CLI plugins
"""

import typer
from app.cli.plugins.interface import CLIPlugin


class ExamplePlugin(CLIPlugin):
    """Example plugin implementation"""
    
    def plugin_info(self) -> None:
        return {
            "name": "example",
            "version": "1.0.0",
            "description": "Example plugin for Image Converter CLI",
            "author": "Your Name"
        }
    
    def register(self, app: typer.Typer) -> None:
        """Register plugin commands"""
        
        @app.command()
        def example_command(
            arg: str = typer.Argument(help="Example argument")
        ):
            """Example command added by plugin"""
            typer.echo(f"Example plugin command called with: {arg}")
        
        # You can add multiple commands, groups, etc.
        example_group = typer.Typer()
        
        @example_group.command()
        def subcommand() -> None:
            """Example subcommand"""
            typer.echo("Subcommand executed")
        
        app.add_typer(example_group, name="example-group")


# Required: Create plugin instance
plugin = ExamplePlugin()

# Required: Export these functions
def plugin_info() -> None:
    return plugin.plugin_info()

def register(app) -> None:
    plugin.register(app)
'''


def create_plugin_template(path: Path) -> None:
    """Create a plugin template file"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(PLUGIN_TEMPLATE)
    return path
