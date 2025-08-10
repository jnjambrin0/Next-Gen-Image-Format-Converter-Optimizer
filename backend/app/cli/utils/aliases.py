"""
Command Aliases Management
Handles user-defined command aliases
"""

import json
from typing import Any, Dict, Optional

import typer

from app.cli.config import get_aliases_file


class AliasManager:
    """Manages command aliases"""

    def __init__(self) -> None:
        self.aliases_file = get_aliases_file()
        self.aliases = self._load_aliases()

    def _load_aliases(self) -> Dict[str, str]:
        """Load aliases from file"""
        if self.aliases_file.exists():
            try:
                with open(self.aliases_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return self._get_default_aliases()
        return self._get_default_aliases()

    def _get_default_aliases(self) -> Dict[str, str]:
        """Get default aliases"""
        return {
            # Short aliases for main commands
            "c": "convert",
            "b": "batch",
            "o": "optimize",
            "a": "analyze",
            "f": "formats",
            "p": "presets",
            # Common command patterns
            "conv": "convert",
            "opt": "optimize",
            "info": "analyze info",
            "ls": "formats list",
        }

    def _save_aliases(self) -> None:
        """Save aliases to file"""
        self.aliases_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.aliases_file, "w") as f:
            json.dump(self.aliases, f, indent=2)

    def add_alias(self, alias: str, command: str) -> bool:
        """Add a new alias"""
        self.aliases[alias] = command
        self._save_aliases()
        return True

    def remove_alias(self, alias: str) -> bool:
        """Remove an alias"""
        if alias in self.aliases:
            del self.aliases[alias]
            self._save_aliases()
            return True
        return False

    def get_alias(self, alias: str) -> Optional[str]:
        """Get command for an alias"""
        return self.aliases.get(alias)

    def list_aliases(self) -> Dict[str, str]:
        """List all aliases"""
        return self.aliases.copy()


# Global alias manager
_alias_manager = AliasManager()


def apply_aliases(app: typer.Typer) -> None:
    """Apply aliases to a Typer app"""
    aliases = _alias_manager.list_aliases()

    for alias, command in aliases.items():
        # Skip if alias already exists as a command
        if alias not in ["c", "b", "o"]:  # These are handled in main.py
            # Dynamic alias creation would go here
            # This is complex with Typer and requires runtime modification
            pass


def add_alias(alias: str, command: str) -> bool:
    """Add a command alias"""
    return _alias_manager.add_alias(alias, command)


def remove_alias(alias: str) -> bool:
    """Remove a command alias"""
    return _alias_manager.remove_alias(alias)


def list_aliases() -> Dict[str, str]:
    """List all command aliases"""
    return _alias_manager.list_aliases()


def resolve_alias(command: str) -> str:
    """Resolve an alias to its full command"""
    return _alias_manager.get_alias(command) or command
