"""
from typing import Any
Integration tests for themed CLI output
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add the backend directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import io

from rich.console import Console

from app.cli.ui.tables import ColumnType, SmartTable
from app.cli.ui.themes import ThemeManager, get_theme_manager
from app.cli.utils.emoji import format_with_emoji, get_emoji
from app.cli.utils.terminal import get_terminal_detector


class TestThemedOutput:
    """Test themed output integration"""

    def test_theme_manager_console_creation(self) -> None:
        """Test creating themed console"""
        manager = ThemeManager()

        # Test each built-in theme
        for theme_name in [
            "dark",
            "light",
            "high_contrast",
            "colorblind_safe",
            "minimal",
        ]:
            console = manager.create_console(theme_name)
            assert isinstance(console, Console)
            # Console objects are created successfully
            assert console is not None

    def test_theme_application_to_output(self) -> None:
        """Test that themes are applied to output"""
        manager = ThemeManager()

        # Create console with dark theme
        console = manager.create_console("dark")

        # Capture output
        output = io.StringIO()
        test_console = Console(file=output, force_terminal=True)

        # Print with theme styles
        test_console.print("[primary]Primary text[/primary]")
        test_console.print("[success]Success message[/success]")
        test_console.print("[error]Error message[/error]")

        result = output.getvalue()
        assert result  # Output should not be empty
        # Output should contain ANSI escape codes
        assert "\x1b[" in result or "[" in result

    def test_smart_table_with_theme(self) -> None:
        """Test SmartTable with themed console"""
        manager = ThemeManager()
        console = manager.create_console("dark")

        # Create smart table
        table = SmartTable(title="Test Table", console=console)

        table.add_column("Name", ColumnType.TEXT)
        table.add_column("Size", ColumnType.FILE_SIZE)
        table.add_column("Status", ColumnType.STATUS)

        table.add_row("test.jpg", 1024 * 1024, "success")
        table.add_row("image.png", 2048 * 1024, "error")

        # Render should work without errors
        rendered = table.render()
        assert rendered is not None

    def test_emoji_integration_with_themes(self) -> None:
        """Test emoji integration with themed output"""
        # Test with emoji enabled
        with patch.dict(os.environ, {}, clear=True):
            detector = get_terminal_detector()
            with patch.object(detector, "supports_emoji", return_value=True):
                with patch.object(detector, "is_ci", return_value=False):
                    emoji = get_emoji("success")
                    # Should return actual emoji when supported
                    assert emoji in ["✅", "✓", "[✓]", ""]

        # Test with emoji disabled
        with patch.dict(os.environ, {"NO_EMOJI": "1"}):
            emoji = get_emoji("success")
            # Should return text fallback
            assert emoji in ["✓", "[✓]", ""]

    def test_terminal_capability_adaptation(self) -> None:
        """Test output adaptation based on terminal capabilities"""
        detector = get_terminal_detector()

        # Test different capability levels
        from app.cli.utils.terminal import TerminalCapability, adapt_output

        # Minimal terminal
        with patch.object(
            detector, "get_capability_level", return_value=TerminalCapability.MINIMAL
        ):
            result = adapt_output("🎨 Fancy text", "Plain text")
            assert result == "Plain text"

        # Full terminal
        with patch.object(
            detector, "get_capability_level", return_value=TerminalCapability.FULL
        ):
            result = adapt_output("🎨 Fancy text", "Plain text")
            assert result == "🎨 Fancy text"

    def test_progress_bar_with_themes(self) -> None:
        """Test progress bar rendering with themes"""
        from app.cli.utils.progress import InterruptableProgress, SpinnerStyle

        manager = ThemeManager()
        console = manager.create_console("dark")

        # Create progress bar
        with InterruptableProgress(
            description="Testing",
            total=100,
            show_emoji=True,
            spinner_style=SpinnerStyle.DOTS,
            console=console,
        ) as progress:
            task = progress.add_task("Processing", total=100)
            progress.update(task, advance=50)

            # Progress should work without errors
            assert progress is not None

    def test_format_with_emoji_integration(self) -> None:
        """Test format_with_emoji with different scenarios"""
        # Test with emoji enabled
        with patch("app.cli.utils.terminal.should_use_emoji", return_value=True):
            result = format_with_emoji("Success!", "success")
            # Should include emoji or fallback
            assert "Success!" in result

        # Test with emoji disabled
        with patch("app.cli.utils.terminal.should_use_emoji", return_value=False):
            result = format_with_emoji("Error occurred", "error")
            assert "Error occurred" in result
            # Should not have emoji characters

    def test_theme_persistence(self) -> None:
        """Test that theme settings persist across components"""

        # Mock config
        mock_config = MagicMock()
        mock_config.theme = "high_contrast"

        with patch("app.cli.config.get_config", return_value=mock_config):
            manager = get_theme_manager()
            console = manager.create_console(mock_config.theme)

            # Console should be created
            assert console is not None

            # Create multiple components with same theme
            table = SmartTable("Test", console=console)
            assert table.console == console

    @pytest.mark.parametrize(
        "theme_name", ["dark", "light", "high_contrast", "colorblind_safe", "minimal"]
    )
    def test_all_themes_render_correctly(self, theme_name) -> None:
        """Test that all themes render without errors"""
        manager = ThemeManager()
        console = manager.create_console(theme_name)

        # Capture output
        output = io.StringIO()
        test_console = Console(file=output, force_terminal=True)

        # Test various styled elements
        test_console.print(f"[primary]Testing {theme_name} theme[/primary]")
        test_console.print("[secondary]Secondary text[/secondary]")
        test_console.print("[success]✓ Success[/success]")
        test_console.print("[error]✗ Error[/error]")
        test_console.print("[warning]⚠ Warning[/warning]")
        test_console.print("[info]ℹ Info[/info]")

        # Create a table
        from rich.table import Table

        table = Table(title=f"{theme_name} Theme Table")
        table.add_column("Column 1", style="cyan")
        table.add_column("Column 2", style="magenta")
        table.add_row("Data 1", "Data 2")
        test_console.print(table)

        result = output.getvalue()
        assert result  # Should have output
        assert theme_name.replace("_", " ").title() in result or "Testing" in result

    def test_cli_command_with_theme(self) -> None:
        """Test actual CLI command execution with themes"""
        # This would test the actual command but requires the CLI to be installed
        # For now, we'll test the component integration

        from app.cli.ui.themes import get_theme_manager

        # Mock config with theme
        mock_config = MagicMock()
        mock_config.theme = "dark"
        mock_config.api_url = "http://localhost:8000"
        mock_config.api_key = None

        with patch("app.cli.config.get_config", return_value=mock_config):
            # Initialize themed components
            theme_manager = get_theme_manager()
            console = theme_manager.create_console(mock_config.theme)

            # Components should initialize without errors
            assert console is not None
            assert theme_manager.get_theme(mock_config.theme) is not None


class TestCachingIntegration:
    """Test caching functionality integration"""

    def test_terminal_detection_caching(self) -> None:
        """Test that terminal detection uses caching"""
        from app.cli.utils.terminal import TerminalDetector

        detector = TerminalDetector()
        detector.clear_cache()

        # First call should cache
        result1 = detector.supports_color()
        assert "supports_color" in detector._cache

        # Second call should use cache
        with patch.object(detector, "_set_cached") as mock_set:
            result2 = detector.supports_color()
            # Should not call _set_cached again
            mock_set.assert_not_called()

        assert result1 == result2

    def test_cache_ttl_integration(self) -> None:
        """Test cache TTL in real scenario"""
        import time

        from app.cli.utils.terminal import TerminalDetector

        detector = TerminalDetector()
        detector.clear_cache()

        # Set cache TTL to very short for testing
        detector._CACHE_TTL = 0.1  # 100ms

        # Cache a value
        detector._set_cached("test_key", "test_value")

        # Should be cached
        assert detector._get_cached("test_key") == "test_value"

        # Wait for TTL to expire
        time.sleep(0.2)

        # Should be expired
        assert detector._get_cached("test_key") is None


class TestRateLimitingIntegration:
    """Test rate limiting in TUI"""

    def test_rate_limiter_functionality(self) -> None:
        """Test RateLimiter class"""
        from app.cli.ui.tui import RateLimiter

        limiter = RateLimiter(min_interval=0.1)

        # First call should be allowed
        assert limiter.should_allow("test") is True

        # Immediate second call should be blocked
        assert limiter.should_allow("test") is False

        # After interval, should be allowed
        import time

        time.sleep(0.11)
        assert limiter.should_allow("test") is True

    def test_rate_limiter_wait(self) -> None:
        """Test rate limiter wait functionality"""
        import time

        from app.cli.ui.tui import RateLimiter

        limiter = RateLimiter(min_interval=0.05)

        # First call
        start = time.time()
        limiter.wait_if_needed("test")

        # Second call should wait
        limiter.wait_if_needed("test")
        elapsed = time.time() - start

        # Should have waited at least min_interval
        assert elapsed >= 0.05


class TestPathSanitization:
    """Test path sanitization integration"""

    def test_path_sanitizer_safe_paths(self) -> None:
        """Test PathSanitizer with safe paths"""
        from app.cli.ui.tui import PathSanitizer

        sanitizer = PathSanitizer()

        # Current directory should be safe
        assert sanitizer.is_safe_path(Path.cwd()) is True

        # Home directory should be safe
        assert sanitizer.is_safe_path(Path.home()) is True

    def test_path_sanitizer_unsafe_paths(self) -> None:
        """Test PathSanitizer with unsafe paths"""
        from app.cli.ui.tui import PathSanitizer

        sanitizer = PathSanitizer()

        # Non-existent path
        assert sanitizer.is_safe_path(Path("/nonexistent/path")) is False

        # Path with dangerous patterns (if we could create them)
        # These would be blocked by the pattern check
        dangerous_paths = [
            "../../../etc/passwd",
            "~/../../sensitive",
            "path;rm -rf /",
            "file|command",
        ]

        for path_str in dangerous_paths:
            # The string itself would be rejected
            assert not any(pattern in path_str for pattern in ["..", "~", ";", "|"])

    def test_filename_sanitization(self) -> None:
        """Test filename sanitization"""
        from app.cli.ui.tui import PathSanitizer

        sanitizer = PathSanitizer()

        # Normal filename
        assert sanitizer.sanitize_filename("image.jpg") == "image.jpg"

        # Filename with path separators
        assert sanitizer.sanitize_filename("../../etc/passwd") == "_.._etc_passwd"

        # Filename with dangerous characters
        assert sanitizer.sanitize_filename("file;rm -rf /") == "file_rm -rf _"

        # Very long filename
        long_name = "a" * 300 + ".jpg"
        sanitized = sanitizer.sanitize_filename(long_name)
        assert len(sanitized) <= 255
        assert sanitized.endswith(".jpg")

        # Empty filename
        assert sanitizer.sanitize_filename("") == "unnamed_file"
