"""
Plugin Interface
Base interface for CLI plugins
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import typer


class CLIPlugin(ABC):
    """Base class for CLI plugins"""

    @abstractmethod
    def plugin_info(self) -> Dict[str, Any]:
        """
        Return plugin information

        Returns:
            Dict with keys: name, version, description, author
        """
        pass

    @abstractmethod
    def register(self, app: typer.Typer):
        """
        Register plugin commands with the CLI app

        Args:
            app: The main Typer application
        """
        pass

    def on_load(self):
        """Called when plugin is loaded (optional)"""
        pass

    def on_unload(self):
        """Called when plugin is unloaded (optional)"""
        pass


# Example plugin template
PLUGIN_TEMPLATE = '''"""
Example CLI Plugin
Template for creating custom CLI plugins
"""

import typer
from app.cli.plugins.interface import CLIPlugin


class ExamplePlugin(CLIPlugin):
    """Example plugin implementation"""
    
    def plugin_info(self):
        return {
            "name": "example",
            "version": "1.0.0",
            "description": "Example plugin for Image Converter CLI",
            "author": "Your Name"
        }
    
    def register(self, app: typer.Typer):
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
        def subcommand():
            """Example subcommand"""
            typer.echo("Subcommand executed")
        
        app.add_typer(example_group, name="example-group")


# Required: Create plugin instance
plugin = ExamplePlugin()

# Required: Export these functions
def plugin_info():
    return plugin.plugin_info()

def register(app):
    plugin.register(app)
'''


def create_plugin_template(path: Path):
    """Create a plugin template file"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(PLUGIN_TEMPLATE)
    return path
