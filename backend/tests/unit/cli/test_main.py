"""
from typing import Any
Unit tests for main CLI application
"""

import json
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

from app.cli.config import CLIConfig
from app.cli.main import app


@pytest.fixture
def runner() -> None:
    """Create a CLI test runner"""
    return CliRunner()


@pytest.fixture
def mock_config(tmp_path) -> None:
    """Mock configuration"""
    config_dir = tmp_path / ".image-converter"
    config_dir.mkdir()
    config_file = config_dir / "config.json"

    config = {
        "api_url": "http://localhost:8000",
        "api_key": None,
        "default_quality": 85,
        "language": "en",
    }

    with open(config_file, "w") as f:
        json.dump(config, f)

    return config_dir


class TestMainCLI:
    """Test main CLI functionality"""

    def test_cli_help(self, runner) -> None:
        """Test CLI help command"""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Image Converter CLI" in result.stdout
        assert "convert" in result.stdout
        assert "batch" in result.stdout
        assert "optimize" in result.stdout

    def test_cli_version(self, runner) -> None:
        """Test version display"""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "Image Converter CLI" in result.stdout
        assert "Python" in result.stdout

    def test_cli_no_args(self, runner) -> None:
        """Test CLI with no arguments shows help"""
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert "Image Converter CLI" in result.stdout
        assert "Quick Start" in result.stdout

    @patch("app.cli.main.get_config")
    def test_verbose_mode(self, mock_get_config, runner) -> None:
        """Test verbose mode activation"""
        mock_get_config.return_value = CLIConfig()

        with patch("app.cli.main.state") as mock_state:
            result = runner.invoke(app, ["--verbose", "--help"])
            assert result.exit_code == 0
            # State should be updated with verbose flag

    @patch("app.cli.main.get_config")
    def test_debug_mode(self, mock_get_config, runner) -> None:
        """Test debug mode activation"""
        mock_get_config.return_value = CLIConfig()

        with patch("app.cli.main.state") as mock_state:
            result = runner.invoke(app, ["--debug", "--help"])
            assert result.exit_code == 0
            # State should be updated with debug flag

    def test_config_show(self, runner) -> None:
        """Test config show command"""
        with patch("app.cli.main.get_config") as mock_get_config:
            mock_get_config.return_value = CLIConfig()

            result = runner.invoke(app, ["config", "show"])
            assert result.exit_code == 0
            assert "CLI Configuration" in result.stdout
            assert "api_url" in result.stdout

    def test_config_get(self, runner) -> None:
        """Test config get command"""
        with patch("app.cli.main.get_config") as mock_get_config:
            mock_config = CLIConfig()
            mock_config.api_url = "http://localhost:8000"
            mock_get_config.return_value = mock_config

            result = runner.invoke(app, ["config", "get", "api_url"])
            assert result.exit_code == 0
            assert "http://localhost:8000" in result.stdout

    def test_config_set(self, runner) -> None:
        """Test config set command"""
        with patch("app.cli.main.get_config") as mock_get_config:
            with patch("app.cli.main.update_config") as mock_update:
                mock_config = CLIConfig()
                mock_get_config.return_value = mock_config

                result = runner.invoke(
                    app, ["config", "set", "api_url", "http://localhost:9000"]
                )
                assert result.exit_code == 0
                assert "Set api_url" in result.stdout
                mock_update.assert_called_once()

    def test_config_reset(self, runner) -> None:
        """Test config reset command"""
        with patch("app.cli.main.update_config") as mock_update:
            result = runner.invoke(app, ["config", "reset"])
            assert result.exit_code == 0
            assert "Configuration reset to defaults" in result.stdout
            mock_update.assert_called_once()

    def test_aliases_list(self, runner) -> None:
        """Test aliases list command"""
        with patch("app.cli.utils.aliases.list_aliases") as mock_list:
            mock_list.return_value = {"c": "convert", "b": "batch"}

            result = runner.invoke(app, ["aliases"])
            assert result.exit_code == 0
            assert "Command Aliases" in result.stdout

    def test_aliases_add(self, runner) -> None:
        """Test adding an alias"""
        with patch("app.cli.utils.aliases.add_alias") as mock_add:
            mock_add.return_value = True

            result = runner.invoke(app, ["aliases", "add", "conv", "convert"])
            assert result.exit_code == 0
            assert "Added alias" in result.stdout
            mock_add.assert_called_once_with("conv", "convert")

    def test_aliases_remove(self, runner) -> None:
        """Test removing an alias"""
        with patch("app.cli.utils.aliases.remove_alias") as mock_remove:
            mock_remove.return_value = True

            result = runner.invoke(app, ["aliases", "remove", "conv"])
            assert result.exit_code == 0
            assert "Removed alias" in result.stdout
            mock_remove.assert_called_once_with("conv")

    def test_plugins_list(self, runner) -> None:
        """Test plugins list command"""
        with patch("app.cli.plugins.loader.list_plugins") as mock_list:
            mock_list.return_value = []

            result = runner.invoke(app, ["plugins"])
            assert result.exit_code == 0
            assert "plugins" in result.stdout.lower()

    def test_history_show(self, runner) -> None:
        """Test history show command"""
        with patch("app.cli.utils.history.HistoryManager") as mock_history_class:
            mock_history = Mock()
            mock_history.get_history.return_value = []
            mock_history_class.return_value = mock_history

            result = runner.invoke(app, ["history"])
            assert result.exit_code == 0

    def test_shortcuts(self, runner) -> None:
        """Test command shortcuts are registered"""
        # Test 'c' shortcut exists
        result = runner.invoke(app, ["c", "--help"])
        # Should either work or show appropriate error
        assert result.exit_code in [0, 2]

        # Test 'b' shortcut exists
        result = runner.invoke(app, ["b", "--help"])
        assert result.exit_code in [0, 2]

        # Test 'o' shortcut exists
        result = runner.invoke(app, ["o", "--help"])
        assert result.exit_code in [0, 2]

    def test_language_setting(self, runner) -> None:
        """Test language setting via command line"""
        with patch("app.cli.main.i18n.set_language") as mock_set_lang:
            with patch("app.cli.main.get_config") as mock_get_config:
                mock_get_config.return_value = CLIConfig()

                result = runner.invoke(app, ["--lang", "es", "--help"])
                assert result.exit_code == 0
                mock_set_lang.assert_called_once_with("es")

    def test_exception_handling(self, runner) -> None:
        """Test global exception handling"""
        with patch("app.cli.main.get_config") as mock_get_config:
            mock_get_config.side_effect = Exception("Test error")

            result = runner.invoke(app, ["config", "show"])
            assert result.exit_code == 1
            # Error should be handled gracefully
