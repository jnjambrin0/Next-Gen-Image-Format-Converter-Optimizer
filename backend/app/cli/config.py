"""
CLI Configuration Management
Handles CLI-specific configuration with local storage
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class CLIConfig(BaseModel):
    """CLI Configuration Model"""

    # API Connection
    api_url: str = Field(default="http://localhost:8000", description="API server URL")
    api_host: str = Field(default="localhost", description="API server host")
    api_port: int = Field(default=8000, description="API server port")
    api_key: Optional[str] = Field(
        default=None, description="API key for authentication"
    )
    api_timeout: int = Field(default=30, description="API request timeout in seconds")

    # CLI Behavior
    default_output_format: str = Field(
        default="rich", description="Default output format (rich, json, plain)"
    )
    confirm_destructive: bool = Field(
        default=True, description="Confirm before destructive operations"
    )
    show_progress: bool = Field(
        default=True, description="Show progress bars for operations"
    )

    # Features
    aliases_enabled: bool = Field(default=True, description="Enable command aliases")
    plugins_enabled: bool = Field(default=True, description="Enable plugin loading")
    history_enabled: bool = Field(
        default=True, description="Enable command history for undo/redo"
    )
    history_size: int = Field(
        default=100, description="Maximum history entries to keep"
    )

    # Language
    language: str = Field(
        default="en", description="Interface language (en, es, fr, de, zh, ja)"
    )

    # UI/Theme Settings
    theme: str = Field(
        default="dark",
        description="Terminal theme (dark, light, high_contrast, colorblind_safe, minimal)",
    )
    emoji_enabled: bool = Field(default=True, description="Enable emoji in output")
    syntax_highlighting: bool = Field(
        default=True, description="Enable syntax highlighting for code/JSON output"
    )

    # Defaults for conversion
    default_quality: int = Field(
        default=85, description="Default quality for lossy formats (1-100)"
    )
    default_preset: Optional[str] = Field(
        default=None, description="Default optimization preset"
    )
    preserve_metadata: bool = Field(
        default=False, description="Preserve image metadata by default"
    )

    class Config:
        json_encoders = {Path: str}


class ConfigManager:
    """Manages CLI configuration persistence"""

    def __init__(self):
        self.config_dir = Path.home() / ".image-converter"
        self.config_file = self.config_dir / "config.json"
        self._ensure_config_dir()

    def _ensure_config_dir(self):
        """Ensure configuration directory exists"""
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        (self.config_dir / "aliases").mkdir(exist_ok=True)
        (self.config_dir / "history").mkdir(exist_ok=True)
        (self.config_dir / "plugins").mkdir(exist_ok=True)
        (self.config_dir / "cache").mkdir(exist_ok=True)
        (self.config_dir / "themes").mkdir(exist_ok=True)

    def load_config(self) -> CLIConfig:
        """Load configuration from disk"""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    data = json.load(f)
                    return CLIConfig(**data)
            except (json.JSONDecodeError, ValueError):
                # Invalid config, return defaults
                return CLIConfig()
        return CLIConfig()

    def save_config(self, config: CLIConfig):
        """Save configuration to disk"""
        with open(self.config_file, "w") as f:
            json.dump(config.dict(), f, indent=2)

    def reset_config(self):
        """Reset configuration to defaults"""
        default_config = CLIConfig()
        self.save_config(default_config)
        return default_config

    def get_config_value(self, key: str) -> Any:
        """Get a specific configuration value"""
        config = self.load_config()
        return getattr(config, key, None)

    def set_config_value(self, key: str, value: Any):
        """Set a specific configuration value"""
        config = self.load_config()
        if hasattr(config, key):
            setattr(config, key, value)
            self.save_config(config)
            return True
        return False


# Global config manager instance
_config_manager = ConfigManager()


def get_config() -> CLIConfig:
    """Get current CLI configuration"""
    return _config_manager.load_config()


def update_config(config: CLIConfig):
    """Update CLI configuration"""
    _config_manager.save_config(config)


def reset_config():
    """Reset configuration to defaults"""
    return _config_manager.reset_config()


def get_config_dir() -> Path:
    """Get configuration directory path"""
    return _config_manager.config_dir


def get_cache_dir() -> Path:
    """Get cache directory path"""
    return _config_manager.config_dir / "cache"


def get_plugins_dir() -> Path:
    """Get plugins directory path"""
    return _config_manager.config_dir / "plugins"


def get_history_dir() -> Path:
    """Get history directory path"""
    return _config_manager.config_dir / "history"


def get_aliases_file() -> Path:
    """Get aliases file path"""
    return _config_manager.config_dir / "aliases" / "aliases.json"


def get_themes_dir() -> Path:
    """Get themes directory path"""
    return _config_manager.config_dir / "themes"
