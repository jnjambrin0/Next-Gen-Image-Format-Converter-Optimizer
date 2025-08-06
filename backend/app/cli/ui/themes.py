"""
Theme Management System
Customizable color themes for terminal output
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

from rich.console import Console
from rich.theme import Theme as RichTheme
from rich.style import Style


class ThemeType(str, Enum):
    """Built-in theme types"""
    DARK = "dark"
    LIGHT = "light"
    HIGH_CONTRAST = "high_contrast"
    COLORBLIND_SAFE = "colorblind_safe"
    DRACULA = "dracula"
    MONOKAI = "monokai"
    SOLARIZED_DARK = "solarized_dark"
    SOLARIZED_LIGHT = "solarized_light"
    MINIMAL = "minimal"


@dataclass
class Theme:
    """Theme configuration"""
    name: str
    type: ThemeType
    colors: Dict[str, str]
    styles: Dict[str, Dict[str, Any]]
    description: str = ""
    author: str = ""
    version: str = "1.0.0"
    
    def to_rich_theme(self) -> RichTheme:
        """Convert to Rich Theme object"""
        style_dict = {}
        for name, style_def in self.styles.items():
            style_kwargs = {}
            if "color" in style_def:
                style_kwargs["color"] = style_def["color"]
            if "bgcolor" in style_def:
                style_kwargs["bgcolor"] = style_def["bgcolor"]
            if "bold" in style_def:
                style_kwargs["bold"] = style_def["bold"]
            if "italic" in style_def:
                style_kwargs["italic"] = style_def["italic"]
            if "underline" in style_def:
                style_kwargs["underline"] = style_def["underline"]
            if "dim" in style_def:
                style_kwargs["dim"] = style_def["dim"]
            
            style_dict[name] = Style(**style_kwargs)
        
        return RichTheme(style_dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Theme":
        """Create from dictionary"""
        data["type"] = ThemeType(data.get("type", ThemeType.DARK))
        return cls(**data)


class ThemeManager:
    """Manages CLI themes"""
    
    # Built-in themes
    THEMES = {
        ThemeType.DARK: Theme(
            name="Dark",
            type=ThemeType.DARK,
            colors={
                "primary": "#00D9FF",
                "secondary": "#FF6AC1",
                "success": "#50FA7B",
                "warning": "#FFB86C",
                "error": "#FF5555",
                "info": "#8BE9FD",
                "background": "#282A36",
                "foreground": "#F8F8F2",
            },
            styles={
                "info": {"color": "cyan", "bold": True},
                "warning": {"color": "yellow", "bold": True},
                "error": {"color": "red", "bold": True},
                "success": {"color": "green", "bold": True},
                "primary": {"color": "bright_cyan"},
                "secondary": {"color": "bright_magenta"},
                "dim": {"color": "bright_black"},
                "highlight": {"color": "bright_yellow", "bold": True},
                "progress.description": {"color": "bright_blue"},
                "progress.percentage": {"color": "bright_cyan"},
                "progress.bar": {"color": "bright_magenta"},
                "table.header": {"color": "bright_cyan", "bold": True},
                "table.row": {"color": "white"},
                "table.footer": {"color": "bright_black", "italic": True},
                "json.key": {"color": "bright_blue"},
                "json.string": {"color": "bright_green"},
                "json.number": {"color": "bright_yellow"},
                "json.null": {"color": "bright_red"},
                "json.bool": {"color": "bright_magenta"},
            },
            description="Default dark theme with vibrant colors",
            author="Image Converter CLI",
        ),
        
        ThemeType.LIGHT: Theme(
            name="Light",
            type=ThemeType.LIGHT,
            colors={
                "primary": "#0969DA",
                "secondary": "#8250DF",
                "success": "#1A7F37",
                "warning": "#9A6700",
                "error": "#CF222E",
                "info": "#0550AE",
                "background": "#FFFFFF",
                "foreground": "#1F2328",
            },
            styles={
                "info": {"color": "blue", "bold": True},
                "warning": {"color": "yellow", "bold": True},
                "error": {"color": "red", "bold": True},
                "success": {"color": "green", "bold": True},
                "primary": {"color": "blue"},
                "secondary": {"color": "magenta"},
                "dim": {"color": "bright_black"},
                "highlight": {"color": "yellow", "bold": True},
                "progress.description": {"color": "blue"},
                "progress.percentage": {"color": "cyan"},
                "progress.bar": {"color": "magenta"},
                "table.header": {"color": "blue", "bold": True},
                "table.row": {"color": "black"},
                "table.footer": {"color": "bright_black", "italic": True},
                "json.key": {"color": "blue"},
                "json.string": {"color": "green"},
                "json.number": {"color": "yellow"},
                "json.null": {"color": "red"},
                "json.bool": {"color": "magenta"},
            },
            description="Light theme for bright terminals",
            author="Image Converter CLI",
        ),
        
        ThemeType.HIGH_CONTRAST: Theme(
            name="High Contrast",
            type=ThemeType.HIGH_CONTRAST,
            colors={
                "primary": "#FFFFFF",
                "secondary": "#FFFF00",
                "success": "#00FF00",
                "warning": "#FFA500",
                "error": "#FF0000",
                "info": "#00FFFF",
                "background": "#000000",
                "foreground": "#FFFFFF",
            },
            styles={
                "info": {"color": "bright_cyan", "bold": True},
                "warning": {"color": "bright_yellow", "bold": True},
                "error": {"color": "bright_red", "bold": True},
                "success": {"color": "bright_green", "bold": True},
                "primary": {"color": "bright_white", "bold": True},
                "secondary": {"color": "bright_yellow", "bold": True},
                "dim": {"color": "white"},
                "highlight": {"color": "bright_yellow", "bold": True, "underline": True},
                "progress.description": {"color": "bright_white", "bold": True},
                "progress.percentage": {"color": "bright_cyan", "bold": True},
                "progress.bar": {"color": "bright_green"},
                "table.header": {"color": "bright_white", "bold": True, "underline": True},
                "table.row": {"color": "bright_white"},
                "table.footer": {"color": "white", "italic": True},
                "json.key": {"color": "bright_cyan", "bold": True},
                "json.string": {"color": "bright_green", "bold": True},
                "json.number": {"color": "bright_yellow", "bold": True},
                "json.null": {"color": "bright_red", "bold": True},
                "json.bool": {"color": "bright_magenta", "bold": True},
            },
            description="Maximum contrast for accessibility",
            author="Image Converter CLI",
        ),
        
        ThemeType.COLORBLIND_SAFE: Theme(
            name="Colorblind Safe",
            type=ThemeType.COLORBLIND_SAFE,
            colors={
                "primary": "#0173B2",
                "secondary": "#DE8F05",
                "success": "#029E73",
                "warning": "#CC78BC",
                "error": "#ECE133",
                "info": "#56B4E9",
                "background": "#1E1E1E",
                "foreground": "#D4D4D4",
            },
            styles={
                "info": {"color": "#56B4E9"},
                "warning": {"color": "#CC78BC"},
                "error": {"color": "#ECE133", "bold": True},
                "success": {"color": "#029E73"},
                "primary": {"color": "#0173B2"},
                "secondary": {"color": "#DE8F05"},
                "dim": {"color": "#808080"},
                "highlight": {"color": "#DE8F05", "bold": True},
                "progress.description": {"color": "#56B4E9"},
                "progress.percentage": {"color": "#0173B2"},
                "progress.bar": {"color": "#029E73"},
                "table.header": {"color": "#0173B2", "bold": True},
                "table.row": {"color": "#D4D4D4"},
                "table.footer": {"color": "#808080", "italic": True},
                "json.key": {"color": "#0173B2"},
                "json.string": {"color": "#029E73"},
                "json.number": {"color": "#DE8F05"},
                "json.null": {"color": "#CC78BC"},
                "json.bool": {"color": "#56B4E9"},
            },
            description="Optimized for colorblind users",
            author="Image Converter CLI",
        ),
        
        ThemeType.MINIMAL: Theme(
            name="Minimal",
            type=ThemeType.MINIMAL,
            colors={
                "primary": "white",
                "secondary": "white",
                "success": "white",
                "warning": "white",
                "error": "white",
                "info": "white",
                "background": "black",
                "foreground": "white",
            },
            styles={
                "info": {"color": "white"},
                "warning": {"color": "white", "bold": True},
                "error": {"color": "white", "bold": True, "underline": True},
                "success": {"color": "white", "italic": True},
                "primary": {"color": "white"},
                "secondary": {"color": "white"},
                "dim": {"color": "white", "dim": True},
                "highlight": {"color": "white", "bold": True},
                "progress.description": {"color": "white"},
                "progress.percentage": {"color": "white"},
                "progress.bar": {"color": "white"},
                "table.header": {"color": "white", "underline": True},
                "table.row": {"color": "white"},
                "table.footer": {"color": "white", "dim": True},
                "json.key": {"color": "white", "bold": True},
                "json.string": {"color": "white"},
                "json.number": {"color": "white"},
                "json.null": {"color": "white", "dim": True},
                "json.bool": {"color": "white", "italic": True},
            },
            description="Minimal theme for CI/CD environments",
            author="Image Converter CLI",
        ),
    }
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize theme manager"""
        self.config_dir = config_dir or Path.home() / ".image-converter"
        self.themes_dir = self.config_dir / "themes"
        self.themes_dir.mkdir(parents=True, exist_ok=True)
        
        self._current_theme: Optional[Theme] = None
        self._custom_themes: Dict[str, Theme] = {}
        
        # Load custom themes
        self._load_custom_themes()
    
    def _load_custom_themes(self):
        """Load custom themes from configuration directory"""
        for theme_file in self.themes_dir.glob("*.json"):
            try:
                with open(theme_file, "r") as f:
                    theme_data = json.load(f)
                    theme = Theme.from_dict(theme_data)
                    self._custom_themes[theme.name.lower()] = theme
            except Exception:
                # Ignore invalid theme files
                pass
    
    def get_theme(self, name: str) -> Optional[Theme]:
        """Get theme by name"""
        # Check built-in themes
        for theme_type in ThemeType:
            if theme_type.value == name.lower():
                return self.THEMES[theme_type]
        
        # Check custom themes
        return self._custom_themes.get(name.lower())
    
    def list_themes(self) -> Dict[str, Theme]:
        """List all available themes"""
        themes = {}
        
        # Add built-in themes
        for theme_type, theme in self.THEMES.items():
            themes[theme_type.value] = theme
        
        # Add custom themes
        themes.update(self._custom_themes)
        
        return themes
    
    def set_current_theme(self, name: str) -> bool:
        """Set the current theme"""
        theme = self.get_theme(name)
        if theme:
            self._current_theme = theme
            return True
        return False
    
    def get_current_theme(self) -> Theme:
        """Get current theme (default to dark if not set)"""
        if not self._current_theme:
            self._current_theme = self.THEMES[ThemeType.DARK]
        return self._current_theme
    
    def save_custom_theme(self, theme: Theme) -> bool:
        """Save a custom theme"""
        try:
            theme_file = self.themes_dir / f"{theme.name.lower()}.json"
            with open(theme_file, "w") as f:
                json.dump(theme.to_dict(), f, indent=2)
            self._custom_themes[theme.name.lower()] = theme
            return True
        except Exception:
            return False
    
    def delete_custom_theme(self, name: str) -> bool:
        """Delete a custom theme"""
        if name.lower() in self._custom_themes:
            theme_file = self.themes_dir / f"{name.lower()}.json"
            if theme_file.exists():
                theme_file.unlink()
            del self._custom_themes[name.lower()]
            return True
        return False
    
    def create_console(self, theme_name: Optional[str] = None) -> Console:
        """Create a Rich console with the specified theme"""
        if theme_name:
            self.set_current_theme(theme_name)
        
        theme = self.get_current_theme()
        return Console(theme=theme.to_rich_theme())
    
    def detect_terminal_theme(self) -> ThemeType:
        """Attempt to detect terminal background and suggest theme"""
        # This is a placeholder - actual detection would require terminal queries
        # For now, check environment variables
        if os.environ.get("COLORFGBG"):
            # Parse COLORFGBG to detect light/dark
            fgbg = os.environ["COLORFGBG"].split(";")
            if len(fgbg) >= 2:
                bg = int(fgbg[-1])
                # Common light background colors are 7 (white) or 15 (bright white)
                if bg in [7, 15]:
                    return ThemeType.LIGHT
        
        # Check for common terminal theme indicators
        if os.environ.get("TERMINAL_THEME") == "light":
            return ThemeType.LIGHT
        
        # Default to dark theme
        return ThemeType.DARK


# Singleton instance
_theme_manager: Optional[ThemeManager] = None


def get_theme_manager() -> ThemeManager:
    """Get the singleton theme manager instance"""
    global _theme_manager
    if _theme_manager is None:
        _theme_manager = ThemeManager()
    return _theme_manager