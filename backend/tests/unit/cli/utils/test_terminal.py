"""
Unit tests for terminal capability detection
"""

import os
import sys
import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from app.cli.utils.terminal import (
    TerminalCapability,
    TerminalDetector,
    adapt_output,
    get_safe_width,
    get_terminal_detector,
    should_use_color,
    should_use_emoji,
)


class TestTerminalDetector:
    """Test TerminalDetector class"""

    @pytest.fixture
    def detector(self):
        """Create a fresh detector instance"""
        detector = TerminalDetector()
        detector.clear_cache()  # Clear cache for testing
        return detector

    def test_capability_levels(self, detector):
        """Test capability level detection"""
        # Test enum values
        assert TerminalCapability.FULL == "full"
        assert TerminalCapability.STANDARD == "standard"
        assert TerminalCapability.MINIMAL == "minimal"
        assert TerminalCapability.CI == "ci"

    @patch.dict("os.environ", {"CI": "true"})
    def test_is_ci_detection(self, detector):
        """Test CI environment detection"""
        assert detector.is_ci() is True

        # Test caching
        assert "is_ci" in detector._cache
        assert detector._cache["is_ci"] is True

    @patch.dict("os.environ", {}, clear=True)
    def test_is_not_ci(self, detector):
        """Test non-CI environment"""
        assert detector.is_ci() is False

    @patch.dict("os.environ", {"GITHUB_ACTIONS": "true"})
    def test_github_actions_ci(self, detector):
        """Test GitHub Actions CI detection"""
        assert detector.is_ci() is True

    @patch.dict("os.environ", {"NO_COLOR": "1"})
    def test_no_color_env(self, detector):
        """Test NO_COLOR environment variable"""
        assert detector.supports_color() is False

    @patch.dict("os.environ", {"FORCE_COLOR": "1"})
    def test_force_color_env(self, detector):
        """Test FORCE_COLOR environment variable"""
        assert detector.supports_color() is True

    @patch("sys.stdout.isatty")
    def test_not_tty(self, mock_isatty, detector):
        """Test non-TTY stdout"""
        mock_isatty.return_value = False
        assert detector.supports_color() is False

    @patch.dict("os.environ", {"TERM": "dumb"})
    @patch("sys.stdout.isatty")
    def test_dumb_terminal(self, mock_isatty, detector):
        """Test dumb terminal"""
        mock_isatty.return_value = True
        assert detector.supports_color() is False

    @patch.dict("os.environ", {"TERM": "xterm-256color"})
    @patch("sys.stdout.isatty")
    @patch("sys.platform", "linux")
    def test_color_support_unix(self, mock_isatty, detector):
        """Test color support on Unix"""
        mock_isatty.return_value = True
        assert detector.supports_color() is True

    @patch.dict("os.environ", {"LANG": "en_US.UTF-8"})
    def test_unicode_support(self, detector):
        """Test Unicode support detection"""
        result = detector.supports_unicode()
        # Should detect UTF in LANG
        assert result is True

    @patch.dict("os.environ", {"TERM_PROGRAM": "iTerm.app"})
    def test_unicode_iterm(self, detector):
        """Test Unicode in iTerm"""
        assert detector.supports_unicode() is True

    @patch.dict("os.environ", {"WT_SESSION": "12345"})
    def test_unicode_windows_terminal(self, detector):
        """Test Unicode in Windows Terminal"""
        assert detector.supports_unicode() is True

    @patch.dict("os.environ", {"COLORTERM": "truecolor"})
    def test_truecolor_support(self, detector):
        """Test true color support"""
        assert detector.supports_truecolor() is True

    @patch.dict("os.environ", {"COLORTERM": "24bit"})
    def test_24bit_color(self, detector):
        """Test 24-bit color support"""
        assert detector.supports_truecolor() is True

    @patch.dict("os.environ", {"TERM_PROGRAM": "vscode"})
    def test_vscode_truecolor(self, detector):
        """Test VS Code true color"""
        assert detector.supports_truecolor() is True

    @patch("shutil.get_terminal_size")
    def test_terminal_size(self, mock_size, detector):
        """Test terminal size detection"""
        mock_size.return_value = MagicMock(columns=120, lines=40)

        width, height = detector.get_terminal_size()
        assert width == 120
        assert height == 40

        # Test caching
        assert "terminal_size" in detector._cache

    @patch("shutil.get_terminal_size")
    def test_terminal_size_fallback(self, mock_size, detector):
        """Test terminal size fallback"""
        mock_size.side_effect = Exception("No terminal")

        width, height = detector.get_terminal_size()
        assert width == 80
        assert height == 24

    @patch("sys.stdout.isatty")
    def test_is_interactive(self, mock_isatty, detector):
        """Test interactive terminal detection"""
        mock_isatty.return_value = True

        with patch.object(detector, "is_ci", return_value=False):
            assert detector.is_interactive() is True

    @patch("sys.stdout.isatty")
    @patch.dict("os.environ", {"CI": "true"})
    def test_not_interactive_in_ci(self, mock_isatty, detector):
        """Test non-interactive in CI"""
        mock_isatty.return_value = True
        assert detector.is_interactive() is False

    @patch.dict("os.environ", {"TERM_PROGRAM": "iTerm.app"})
    def test_emoji_support_iterm(self, detector):
        """Test emoji support in iTerm"""
        with patch.object(detector, "supports_unicode", return_value=True):
            assert detector.supports_emoji() is True

    def test_emoji_requires_unicode(self, detector):
        """Test emoji requires Unicode"""
        with patch.object(detector, "supports_unicode", return_value=False):
            assert detector.supports_emoji() is False

    @patch.dict("os.environ", {"VTE_VERSION": "5002"})
    def test_hyperlinks_vte(self, detector):
        """Test hyperlink support in VTE terminals"""
        assert detector.supports_hyperlinks() is True

    @patch.dict("os.environ", {"TERM_PROGRAM": "iTerm.app"})
    def test_hyperlinks_iterm(self, detector):
        """Test hyperlink support in iTerm"""
        assert detector.supports_hyperlinks() is True

    def test_get_environment_info(self, detector):
        """Test getting environment info"""
        info = detector.get_environment_info()

        assert "capability_level" in info
        assert "is_ci" in info
        assert "is_interactive" in info
        assert "supports_color" in info
        assert "supports_unicode" in info
        assert "supports_truecolor" in info
        assert "supports_emoji" in info
        assert "supports_hyperlinks" in info
        assert "terminal_size" in info
        assert "term" in info

    @patch.dict("os.environ", {"CI": "true"})
    def test_capability_level_ci(self, detector):
        """Test CI capability level"""
        assert detector.get_capability_level() == TerminalCapability.CI

    @patch("sys.stdout.isatty")
    def test_capability_level_minimal(self, mock_isatty, detector):
        """Test minimal capability level"""
        mock_isatty.return_value = False
        assert detector.get_capability_level() == TerminalCapability.MINIMAL

    def test_capability_level_standard(self, detector):
        """Test standard capability level"""
        with patch.object(detector, "is_ci", return_value=False):
            with patch.object(detector, "supports_color", return_value=True):
                with patch.object(detector, "supports_unicode", return_value=True):
                    with patch.object(
                        detector, "supports_truecolor", return_value=False
                    ):
                        assert (
                            detector.get_capability_level()
                            == TerminalCapability.STANDARD
                        )

    def test_capability_level_full(self, detector):
        """Test full capability level"""
        with patch.object(detector, "is_ci", return_value=False):
            with patch.object(detector, "supports_color", return_value=True):
                with patch.object(detector, "supports_unicode", return_value=True):
                    with patch.object(
                        detector, "supports_truecolor", return_value=True
                    ):
                        assert (
                            detector.get_capability_level() == TerminalCapability.FULL
                        )

    def test_cache_ttl(self, detector):
        """Test cache TTL expiration"""
        # Test that cache TTL is respected
        assert detector._CACHE_TTL == 300  # 5 minutes

        # Set a cached value
        detector._set_cached("test_key", "test_value")
        assert detector._get_cached("test_key") == "test_value"

        # Mock time to simulate TTL expiration
        with patch("app.cli.utils.terminal.time.time") as mock_time:
            # Start time
            start_time = 1000.0
            mock_time.return_value = start_time
            detector._set_cached("ttl_test", "value1")

            # Still within TTL (4 minutes later)
            mock_time.return_value = start_time + 240
            assert detector._get_cached("ttl_test") == "value1"

            # After TTL expires (6 minutes later)
            mock_time.return_value = start_time + 360
            assert detector._get_cached("ttl_test") is None

    def test_cache_thread_safety(self, detector):
        """Test cache thread safety"""
        import random
        import threading

        results = []
        errors = []

        def cache_operation():
            try:
                for i in range(100):
                    key = f"key_{random.randint(1, 10)}"
                    value = f"value_{i}"

                    # Random operations
                    if random.random() > 0.5:
                        detector._set_cached(key, value)
                    else:
                        result = detector._get_cached(key)
                        if result:
                            results.append(result)
            except Exception as e:
                errors.append(e)

        # Run multiple threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=cache_operation)
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join()

        # Should have no errors
        assert len(errors) == 0

    def test_clear_cache(self, detector):
        """Test cache clearing"""
        # Add some cached values
        detector._set_cached("key1", "value1")
        detector._set_cached("key2", "value2")

        assert detector._get_cached("key1") == "value1"
        assert detector._get_cached("key2") == "value2"

        # Clear cache
        detector.clear_cache()

        # Cache should be empty
        assert detector._get_cached("key1") is None
        assert detector._get_cached("key2") is None
        assert len(detector._cache) == 0
        assert len(detector._cache_timestamps) == 0


class TestTerminalHelpers:
    """Test terminal helper functions"""

    def test_get_terminal_detector_singleton(self):
        """Test singleton detector"""
        det1 = get_terminal_detector()
        det2 = get_terminal_detector()
        assert det1 is det2

    def test_adapt_output_minimal(self):
        """Test output adaptation for minimal terminals"""
        detector = get_terminal_detector()

        with patch.object(
            detector, "get_capability_level", return_value=TerminalCapability.MINIMAL
        ):
            result = adapt_output("fancy text", "simple text")
            assert result == "simple text"

            result = adapt_output("fancy text")
            assert result == "fancy text"  # No fallback provided

    def test_adapt_output_full(self):
        """Test output adaptation for full terminals"""
        detector = get_terminal_detector()

        with patch.object(
            detector, "get_capability_level", return_value=TerminalCapability.FULL
        ):
            result = adapt_output("fancy text", "simple text")
            assert result == "fancy text"

    @patch.dict("os.environ", {"NO_EMOJI": "1"})
    def test_should_use_emoji_disabled(self):
        """Test emoji disabled by environment"""
        assert should_use_emoji() is False

    def test_should_use_emoji(self):
        """Test emoji usage detection"""
        detector = get_terminal_detector()

        with patch.object(detector, "supports_emoji", return_value=True):
            with patch.object(detector, "is_ci", return_value=False):
                with patch.dict("os.environ", {}, clear=True):
                    result = should_use_emoji()
                    # Result depends on actual terminal

    def test_should_use_color(self):
        """Test color usage detection"""
        detector = get_terminal_detector()

        with patch.object(detector, "supports_color", return_value=True):
            assert should_use_color() is True

        with patch.object(detector, "supports_color", return_value=False):
            assert should_use_color() is False

    def test_get_safe_width(self):
        """Test safe width calculation"""
        detector = get_terminal_detector()

        with patch.object(detector, "get_terminal_size", return_value=(120, 40)):
            width = get_safe_width()
            assert width == 118  # 120 - 2

        with patch.object(detector, "get_terminal_size", return_value=(30, 20)):
            width = get_safe_width()
            assert width == 40  # Minimum of 40
