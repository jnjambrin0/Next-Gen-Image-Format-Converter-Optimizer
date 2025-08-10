"""
Unit tests for plugin system
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from app.cli.plugins.interface import CLIPlugin
from app.cli.plugins.loader import PluginLoader


class TestPluginInterface:
    """Test plugin interface"""

    def test_plugin_interface_abstract(self):
        """Test that CLIPlugin is abstract"""
        with pytest.raises(TypeError):
            CLIPlugin()

    def test_plugin_implementation(self):
        """Test plugin implementation"""

        class TestPlugin(CLIPlugin):
            def plugin_info(self):
                return {
                    "name": "test",
                    "version": "1.0.0",
                    "description": "Test plugin",
                    "author": "Test Author",
                }

            def register(self, app):
                pass

        plugin = TestPlugin()
        info = plugin.plugin_info()

        assert info["name"] == "test"
        assert info["version"] == "1.0.0"
        assert info["description"] == "Test plugin"
        assert info["author"] == "Test Author"


class TestPluginLoader:
    """Test plugin loader"""

    @pytest.fixture
    def temp_plugin_dir(self):
        """Create temporary plugin directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir) / "plugins"
            plugin_dir.mkdir()
            yield plugin_dir

    def test_plugin_loader_init(self, temp_plugin_dir):
        """Test plugin loader initialization"""
        with patch("app.cli.plugins.loader.get_plugins_dir") as mock_get_dir:
            mock_get_dir.return_value = temp_plugin_dir

            loader = PluginLoader()

            assert loader.plugins_dir == temp_plugin_dir
            assert loader.loaded_plugins == {}
            assert loader.plugin_registry == {}

    def test_discover_plugins_empty(self, temp_plugin_dir):
        """Test discovering plugins in empty directory"""
        with patch("app.cli.plugins.loader.get_plugins_dir") as mock_get_dir:
            mock_get_dir.return_value = temp_plugin_dir

            loader = PluginLoader()
            plugins = loader.discover_plugins()

            assert plugins == []

    def test_discover_plugins_with_files(self, temp_plugin_dir):
        """Test discovering plugin files"""
        with patch("app.cli.plugins.loader.get_plugins_dir") as mock_get_dir:
            mock_get_dir.return_value = temp_plugin_dir

            # Create test plugin files
            (temp_plugin_dir / "test_plugin.py").write_text("# Test plugin")
            (temp_plugin_dir / "__init__.py").write_text("")
            (temp_plugin_dir / "another_plugin.py").write_text("# Another plugin")

            loader = PluginLoader()
            plugins = loader.discover_plugins()

            assert len(plugins) == 2
            assert any("test_plugin.py" in str(p) for p in plugins)
            assert any("another_plugin.py" in str(p) for p in plugins)

    def test_discover_plugins_with_directories(self, temp_plugin_dir):
        """Test discovering plugin directories"""
        with patch("app.cli.plugins.loader.get_plugins_dir") as mock_get_dir:
            mock_get_dir.return_value = temp_plugin_dir

            # Create plugin directory with __init__.py
            plugin_subdir = temp_plugin_dir / "complex_plugin"
            plugin_subdir.mkdir()
            (plugin_subdir / "__init__.py").write_text("# Complex plugin")

            loader = PluginLoader()
            plugins = loader.discover_plugins()

            assert len(plugins) == 1
            assert "complex_plugin" in str(plugins[0])

    def test_load_plugin_valid(self, temp_plugin_dir):
        """Test loading a valid plugin"""
        with patch("app.cli.plugins.loader.get_plugins_dir") as mock_get_dir:
            mock_get_dir.return_value = temp_plugin_dir

            # Create a valid plugin file
            plugin_content = """
def plugin_info():
    return {
        "name": "test",
        "version": "1.0.0",
        "description": "Test plugin",
        "author": "Test"
    }

def register(app):
    pass
"""
            plugin_file = temp_plugin_dir / "test_plugin.py"
            plugin_file.write_text(plugin_content)

            loader = PluginLoader()
            module = loader.load_plugin(plugin_file)

            assert module is not None
            assert "test_plugin" in loader.loaded_plugins
            assert "test_plugin" in loader.plugin_registry

    def test_load_plugin_invalid(self, temp_plugin_dir):
        """Test loading an invalid plugin"""
        with patch("app.cli.plugins.loader.get_plugins_dir") as mock_get_dir:
            mock_get_dir.return_value = temp_plugin_dir

            # Create an invalid plugin file (missing required functions)
            plugin_content = """
# Invalid plugin - missing required functions
print("This is not a valid plugin")
"""
            plugin_file = temp_plugin_dir / "invalid_plugin.py"
            plugin_file.write_text(plugin_content)

            loader = PluginLoader()
            module = loader.load_plugin(plugin_file)

            assert module is None
            assert "invalid_plugin" not in loader.loaded_plugins

    def test_enable_disable_plugin(self, temp_plugin_dir):
        """Test enabling and disabling plugins"""
        with patch("app.cli.plugins.loader.get_plugins_dir") as mock_get_dir:
            mock_get_dir.return_value = temp_plugin_dir

            loader = PluginLoader()
            loader.plugin_registry = {"test_plugin": {"name": "test", "enabled": True}}

            # Disable plugin
            assert loader.disable_plugin("test_plugin") == True
            assert loader.plugin_registry["test_plugin"]["enabled"] == False

            # Enable plugin
            assert loader.enable_plugin("test_plugin") == True
            assert loader.plugin_registry["test_plugin"]["enabled"] == True

            # Try to enable non-existent plugin
            assert loader.enable_plugin("non_existent") == False

    def test_list_plugins(self, temp_plugin_dir):
        """Test listing plugins"""
        with patch("app.cli.plugins.loader.get_plugins_dir") as mock_get_dir:
            mock_get_dir.return_value = temp_plugin_dir

            loader = PluginLoader()
            loader.plugin_registry = {
                "plugin1": {"name": "Plugin 1", "enabled": True},
                "plugin2": {"name": "Plugin 2", "enabled": False},
            }

            plugins = loader.list_plugins()

            assert len(plugins) == 2
            assert {"name": "Plugin 1", "enabled": True} in plugins
            assert {"name": "Plugin 2", "enabled": False} in plugins

    def test_get_plugin_info(self, temp_plugin_dir):
        """Test getting plugin information"""
        with patch("app.cli.plugins.loader.get_plugins_dir") as mock_get_dir:
            mock_get_dir.return_value = temp_plugin_dir

            loader = PluginLoader()
            loader.plugin_registry = {
                "test_plugin": {
                    "name": "Test Plugin",
                    "version": "1.0.0",
                    "enabled": True,
                }
            }

            info = loader.get_plugin_info("test_plugin")
            assert info["name"] == "Test Plugin"
            assert info["version"] == "1.0.0"

            # Non-existent plugin
            info = loader.get_plugin_info("non_existent")
            assert info is None
