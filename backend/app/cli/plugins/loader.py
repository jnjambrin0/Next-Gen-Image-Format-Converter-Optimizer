"""
Plugin Loader
Discovers and loads CLI plugins
"""

import importlib.util
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer

from app.cli.config import get_plugins_dir


class PluginLoader:
    """Loads and manages CLI plugins"""

    def __init__(self):
        self.plugins_dir = get_plugins_dir()
        self.loaded_plugins: Dict[str, Any] = {}
        self.plugin_registry: Dict[str, Dict] = {}
        self._load_registry()

    def _load_registry(self):
        """Load plugin registry"""
        registry_file = self.plugins_dir / "registry.json"
        if registry_file.exists():
            try:
                with open(registry_file, "r") as f:
                    self.plugin_registry = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.plugin_registry = {}
        else:
            self.plugin_registry = {}

    def _save_registry(self):
        """Save plugin registry"""
        registry_file = self.plugins_dir / "registry.json"
        with open(registry_file, "w") as f:
            json.dump(self.plugin_registry, f, indent=2)

    def discover_plugins(self) -> List[Path]:
        """Discover available plugins"""
        plugins = []

        # Look for Python plugin files
        for plugin_file in self.plugins_dir.glob("*.py"):
            if plugin_file.name != "__init__.py":
                plugins.append(plugin_file)

        # Look for plugin directories with __init__.py
        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_dir():
                init_file = plugin_dir / "__init__.py"
                if init_file.exists():
                    plugins.append(plugin_dir)

        return plugins

    def load_plugin(self, plugin_path: Path) -> Optional[Any]:
        """Load a single plugin"""
        try:
            # Determine plugin name
            if plugin_path.is_file():
                plugin_name = plugin_path.stem
                module_path = plugin_path
            else:
                plugin_name = plugin_path.name
                module_path = plugin_path / "__init__.py"

            # Load the module
            spec = importlib.util.spec_from_file_location(plugin_name, module_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Check for required plugin interface
                if hasattr(module, "plugin_info") and hasattr(module, "register"):
                    self.loaded_plugins[plugin_name] = module

                    # Update registry
                    info = module.plugin_info()
                    self.plugin_registry[plugin_name] = {
                        "name": info.get("name", plugin_name),
                        "version": info.get("version", "0.0.0"),
                        "description": info.get("description", ""),
                        "author": info.get("author", "Unknown"),
                        "enabled": True,
                        "path": str(plugin_path),
                    }

                    return module

        except Exception as e:
            # Plugin failed to load
            print(f"Failed to load plugin {plugin_path}: {e}")

        return None

    def load_all_plugins(self, app: typer.Typer):
        """Load all enabled plugins"""
        plugins = self.discover_plugins()

        for plugin_path in plugins:
            plugin_name = (
                plugin_path.stem if plugin_path.is_file() else plugin_path.name
            )

            # Check if plugin is enabled
            if plugin_name in self.plugin_registry:
                if not self.plugin_registry[plugin_name].get("enabled", True):
                    continue

            # Load the plugin
            module = self.load_plugin(plugin_path)
            if module and hasattr(module, "register"):
                # Register plugin with the app
                module.register(app)

        # Save updated registry
        self._save_registry()

    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin"""
        if name in self.plugin_registry:
            self.plugin_registry[name]["enabled"] = True
            self._save_registry()
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin"""
        if name in self.plugin_registry:
            self.plugin_registry[name]["enabled"] = False
            self._save_registry()
            return True
        return False

    def get_plugin_info(self, name: str) -> Optional[Dict]:
        """Get plugin information"""
        return self.plugin_registry.get(name)

    def list_plugins(self) -> List[Dict]:
        """List all plugins"""
        return list(self.plugin_registry.values())


# Global plugin loader
_plugin_loader = PluginLoader()


def load_plugins(app: typer.Typer):
    """Load all enabled plugins into the app"""
    _plugin_loader.load_all_plugins(app)


def list_plugins() -> List[Dict]:
    """List all available plugins"""
    return _plugin_loader.list_plugins()


def get_plugin_info(name: str) -> Optional[Dict]:
    """Get information about a specific plugin"""
    return _plugin_loader.get_plugin_info(name)


def enable_plugin(name: str) -> bool:
    """Enable a plugin"""
    return _plugin_loader.enable_plugin(name)


def disable_plugin(name: str) -> bool:
    """Disable a plugin"""
    return _plugin_loader.disable_plugin(name)
