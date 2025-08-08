"""
Unit tests for theme management system
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from app.cli.ui.themes import ThemeManager, Theme, ThemeType, get_theme_manager


class TestTheme:
    """Test Theme class"""

    def test_theme_creation(self):
        """Test creating a theme"""
        theme = Theme(
            name="Test Theme",
            type=ThemeType.DARK,
            colors={"primary": "#00D9FF"},
            styles={"info": {"color": "cyan", "bold": True}},
            description="Test theme",
        )

        assert theme.name == "Test Theme"
        assert theme.type == ThemeType.DARK
        assert theme.colors["primary"] == "#00D9FF"
        assert theme.styles["info"]["bold"] is True

    def test_theme_to_rich_theme(self):
        """Test converting to Rich theme"""
        theme = Theme(
            name="Test",
            type=ThemeType.DARK,
            colors={},
            styles={
                "info": {"color": "cyan", "bold": True},
                "error": {"color": "red", "underline": True},
            },
        )

        rich_theme = theme.to_rich_theme()
        assert rich_theme is not None
        assert "info" in rich_theme.styles
        assert "error" in rich_theme.styles

    def test_theme_serialization(self):
        """Test theme serialization"""
        theme = Theme(
            name="Test",
            type=ThemeType.LIGHT,
            colors={"primary": "#000000"},
            styles={"test": {"color": "blue"}},
        )

        # To dict
        theme_dict = theme.to_dict()
        assert theme_dict["name"] == "Test"
        assert theme_dict["type"] == ThemeType.LIGHT

        # From dict
        new_theme = Theme.from_dict(theme_dict)
        assert new_theme.name == theme.name
        assert new_theme.type == theme.type


class TestThemeManager:
    """Test ThemeManager class"""

    @pytest.fixture
    def temp_config_dir(self, tmp_path):
        """Create temporary config directory"""
        config_dir = tmp_path / "test_config"
        config_dir.mkdir()
        (config_dir / "themes").mkdir()
        return config_dir

    def test_theme_manager_init(self, temp_config_dir):
        """Test theme manager initialization"""
        manager = ThemeManager(config_dir=temp_config_dir)

        assert manager.config_dir == temp_config_dir
        assert manager.themes_dir == temp_config_dir / "themes"
        assert manager.themes_dir.exists()

    def test_built_in_themes(self):
        """Test built-in themes are available"""
        manager = ThemeManager()

        # Check all built-in themes exist
        for theme_type in [
            ThemeType.DARK,
            ThemeType.LIGHT,
            ThemeType.HIGH_CONTRAST,
            ThemeType.COLORBLIND_SAFE,
            ThemeType.MINIMAL,
        ]:
            assert theme_type in manager.THEMES
            theme = manager.THEMES[theme_type]
            assert isinstance(theme, Theme)

    def test_get_theme(self, temp_config_dir):
        """Test getting themes"""
        manager = ThemeManager(config_dir=temp_config_dir)

        # Get built-in theme
        dark_theme = manager.get_theme("dark")
        assert dark_theme is not None
        assert dark_theme.type == ThemeType.DARK

        # Non-existent theme
        missing = manager.get_theme("nonexistent")
        assert missing is None

    def test_list_themes(self, temp_config_dir):
        """Test listing all themes"""
        manager = ThemeManager(config_dir=temp_config_dir)

        themes = manager.list_themes()
        assert len(themes) >= 5  # At least the built-in themes
        assert "dark" in themes
        assert "light" in themes

    def test_set_current_theme(self, temp_config_dir):
        """Test setting current theme"""
        manager = ThemeManager(config_dir=temp_config_dir)

        # Set valid theme
        result = manager.set_current_theme("light")
        assert result is True
        assert manager.get_current_theme().type == ThemeType.LIGHT

        # Set invalid theme
        result = manager.set_current_theme("invalid")
        assert result is False

    def test_save_custom_theme(self, temp_config_dir):
        """Test saving custom theme"""
        manager = ThemeManager(config_dir=temp_config_dir)

        custom_theme = Theme(
            name="Custom",
            type=ThemeType.DARK,
            colors={"primary": "#FF0000"},
            styles={"custom": {"color": "red"}},
        )

        # Save theme
        result = manager.save_custom_theme(custom_theme)
        assert result is True

        # Check file was created
        theme_file = temp_config_dir / "themes" / "custom.json"
        assert theme_file.exists()

        # Load and verify
        with open(theme_file) as f:
            saved_data = json.load(f)
        assert saved_data["name"] == "Custom"

    def test_load_custom_themes(self, temp_config_dir):
        """Test loading custom themes from disk"""
        # Create a custom theme file
        theme_data = {
            "name": "TestCustom",
            "type": "dark",
            "colors": {"primary": "#123456"},
            "styles": {"test": {"color": "blue"}},
        }

        theme_file = temp_config_dir / "themes" / "testcustom.json"
        with open(theme_file, "w") as f:
            json.dump(theme_data, f)

        # Create manager and check theme is loaded
        manager = ThemeManager(config_dir=temp_config_dir)

        custom_theme = manager.get_theme("testcustom")
        assert custom_theme is not None
        assert custom_theme.name == "TestCustom"

    def test_delete_custom_theme(self, temp_config_dir):
        """Test deleting custom theme"""
        manager = ThemeManager(config_dir=temp_config_dir)

        # Save a custom theme
        custom_theme = Theme(name="ToDelete", type=ThemeType.DARK, colors={}, styles={})
        manager.save_custom_theme(custom_theme)

        # Delete it
        result = manager.delete_custom_theme("ToDelete")
        assert result is True

        # Verify it's gone
        assert manager.get_theme("todelete") is None
        theme_file = temp_config_dir / "themes" / "todelete.json"
        assert not theme_file.exists()

    def test_create_console(self, temp_config_dir):
        """Test creating console with theme"""
        manager = ThemeManager(config_dir=temp_config_dir)

        # Create console with default theme
        console = manager.create_console()
        assert console is not None

        # Create console with specific theme
        console = manager.create_console("light")
        assert console is not None
        assert manager.get_current_theme().type == ThemeType.LIGHT

    @patch.dict("os.environ", {"COLORFGBG": "0;15"})
    def test_detect_terminal_theme_light(self, temp_config_dir):
        """Test detecting light terminal theme"""
        manager = ThemeManager(config_dir=temp_config_dir)

        detected = manager.detect_terminal_theme()
        assert detected == ThemeType.LIGHT

    @patch.dict("os.environ", {"COLORFGBG": "15;0"})
    def test_detect_terminal_theme_dark(self, temp_config_dir):
        """Test detecting dark terminal theme"""
        manager = ThemeManager(config_dir=temp_config_dir)

        detected = manager.detect_terminal_theme()
        assert detected == ThemeType.DARK

    @patch.dict("os.environ", {"TERMINAL_THEME": "light"})
    def test_detect_terminal_theme_env(self, temp_config_dir):
        """Test detecting theme from environment variable"""
        manager = ThemeManager(config_dir=temp_config_dir)

        detected = manager.detect_terminal_theme()
        assert detected == ThemeType.LIGHT


class TestThemeManagerSingleton:
    """Test theme manager singleton"""

    def test_get_theme_manager_singleton(self):
        """Test getting singleton instance"""
        manager1 = get_theme_manager()
        manager2 = get_theme_manager()

        assert manager1 is manager2  # Same instance
