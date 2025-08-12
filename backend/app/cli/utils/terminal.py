"""
Terminal Capability Detection
Detect terminal features and adapt output accordingly
"""

import os
import shutil
import sys
import threading
import time
from enum import Enum
from typing import Any, Dict, Optional, Tuple


class TerminalCapability(str, Enum):
    """Terminal capability levels"""

    FULL = "full"  # Full color, Unicode, rich features
    STANDARD = "standard"  # Basic colors, limited Unicode
    MINIMAL = "minimal"  # No colors, ASCII only
    CI = "ci"  # CI/CD environment


class TerminalDetector:
    """Detect terminal capabilities and environment with caching"""

    # Cache TTL in seconds (5 minutes)
    _CACHE_TTL = 300

    def __init__(self) -> None:
        self._cache: Dict[str, Any] = {}
        self._cache_timestamps: Dict[str, float] = {}
        self._cache_lock = threading.Lock()

    def get_capability_level(self) -> TerminalCapability:
        """Determine terminal capability level"""
        if self.is_ci():
            return TerminalCapability.CI

        if not self.supports_color():
            return TerminalCapability.MINIMAL

        if self.supports_unicode() and self.supports_truecolor():
            return TerminalCapability.FULL

        return TerminalCapability.STANDARD

    def _get_cached(self, key: str) -> Any:
        """Get cached value if still valid"""
        with self._cache_lock:
            if key in self._cache and key in self._cache_timestamps:
                if time.time() - self._cache_timestamps[key] < self._CACHE_TTL:
                    return self._cache[key]
        return None

    def _set_cached(self, key: str, value: Any) -> Any:
        """Set cached value with timestamp"""
        with self._cache_lock:
            self._cache[key] = value
            self._cache_timestamps[key] = time.time()
        return value

    def clear_cache(self) -> None:
        """Clear all cached values (useful for testing)"""
        with self._cache_lock:
            self._cache.clear()
            self._cache_timestamps.clear()

    def is_ci(self) -> bool:
        """Check if running in CI/CD environment"""
        cached = self._get_cached("is_ci")
        if cached is not None:
            return cached

        ci_env_vars = [
            "CI",
            "CONTINUOUS_INTEGRATION",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "JENKINS_URL",
            "CIRCLECI",
            "TRAVIS",
            "BUILDKITE",
            "DRONE",
            "TEAMCITY_VERSION",
        ]

        result = any(os.environ.get(var) for var in ci_env_vars)
        return self._set_cached("is_ci", result)

    def supports_color(self) -> bool:
        """Check if terminal supports color output"""
        cached = self._get_cached("supports_color")
        if cached is not None:
            return cached

        # Check NO_COLOR environment variable (https://no-color.org/)
        if os.environ.get("NO_COLOR"):
            return self._set_cached("supports_color", False)

        # Check FORCE_COLOR environment variable
        if os.environ.get("FORCE_COLOR"):
            return self._set_cached("supports_color", True)

        # Check if stdout is a TTY
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return self._set_cached("supports_color", False)

        # Check TERM environment variable
        term = os.environ.get("TERM", "")
        if term == "dumb":
            return self._set_cached("supports_color", False)

        # Check platform-specific indicators
        if sys.platform == "win32":
            # Windows 10+ supports ANSI colors
            result = self._check_windows_color_support()
        else:
            # Unix-like systems generally support color if TERM is set
            result = bool(term)

        return self._set_cached("supports_color", result)

    def _check_windows_color_support(self) -> bool:
        """Check Windows color support"""
        if sys.platform != "win32":
            return False

        try:
            import ctypes
            import ctypes.wintypes

            # Check Windows version
            kernel32 = ctypes.windll.kernel32
            kernel32.GetConsoleMode.argtypes = [
                ctypes.wintypes.HANDLE,
                ctypes.POINTER(ctypes.wintypes.DWORD),
            ]
            kernel32.GetConsoleMode.restype = ctypes.wintypes.BOOL

            # Get stdout handle
            STD_OUTPUT_HANDLE = -11
            handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

            mode = ctypes.wintypes.DWORD()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                return bool(mode.value & 0x0004)
        except Exception:
            pass

        # Check for modern terminals on Windows
        if os.environ.get("WT_SESSION"):  # Windows Terminal
            return True
        if os.environ.get("TERM_PROGRAM") == "vscode":  # VS Code terminal
            return True

        return False

    def supports_unicode(self) -> bool:
        """Check if terminal supports Unicode characters"""
        cached = self._get_cached("supports_unicode")
        if cached is not None:
            return cached

        # Check locale settings
        try:
            import locale

            encoding = locale.getpreferredencoding()
            result = "utf" in encoding.lower()
        except Exception:
            result = False

        # Check LANG environment variable
        if not result:
            lang = os.environ.get("LANG", "")
            result = "utf" in lang.lower() or "UTF" in lang

        # Check specific terminal programs known to support Unicode
        term_program = os.environ.get("TERM_PROGRAM", "")
        if term_program in ["iTerm.app", "vscode", "Terminal.app"]:
            result = True

        # Windows Terminal supports Unicode
        if os.environ.get("WT_SESSION"):
            result = True

        return self._set_cached("supports_unicode", result)

    def supports_truecolor(self) -> bool:
        """Check if terminal supports 24-bit true color"""
        cached = self._get_cached("supports_truecolor")
        if cached is not None:
            return cached

        # Check COLORTERM environment variable
        colorterm = os.environ.get("COLORTERM", "")
        if colorterm in ["truecolor", "24bit"]:
            return self._set_cached("supports_truecolor", True)

        # Check for specific terminals known to support true color
        term_program = os.environ.get("TERM_PROGRAM", "")
        if term_program in ["iTerm.app", "vscode"]:
            return self._set_cached("supports_truecolor", True)

        # Windows Terminal supports true color
        if os.environ.get("WT_SESSION"):
            return self._set_cached("supports_truecolor", True)

        return self._set_cached("supports_truecolor", False)

    def get_terminal_size(self) -> Tuple[int, int]:
        """Get terminal width and height"""
        cached = self._get_cached("terminal_size")
        if cached is not None:
            return cached

        try:
            size = shutil.get_terminal_size(fallback=(80, 24))
            result = (size.columns, size.lines)
        except Exception:
            result = (80, 24)

        return self._set_cached("terminal_size", result)

    def is_interactive(self) -> bool:
        """Check if terminal is interactive"""
        cached = self._get_cached("is_interactive")
        if cached is not None:
            return cached

        result = (
            hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and not self.is_ci()
        )

        return self._set_cached("is_interactive", result)

    def supports_emoji(self) -> bool:
        """Check if terminal likely supports emoji"""
        cached = self._get_cached("supports_emoji")
        if cached is not None:
            return cached

        # Emoji requires Unicode support
        if not self.supports_unicode():
            return self._set_cached("supports_emoji", False)

        # Check for known good terminals
        term_program = os.environ.get("TERM_PROGRAM", "")
        if term_program in ["iTerm.app", "vscode", "Terminal.app"]:
            return self._set_cached("supports_emoji", True)

        # Windows Terminal supports emoji
        if os.environ.get("WT_SESSION"):
            return self._set_cached("supports_emoji", True)

        # Conservative default
        return self._set_cached("supports_emoji", False)

    def supports_hyperlinks(self) -> bool:
        """Check if terminal supports hyperlinks"""
        cached = self._get_cached("supports_hyperlinks")
        if cached is not None:
            return cached

        # Check for terminals known to support OSC 8 hyperlinks
        term_program = os.environ.get("TERM_PROGRAM", "")
        if term_program in ["iTerm.app", "vscode"]:
            return self._set_cached("supports_hyperlinks", True)

        # Windows Terminal supports hyperlinks
        if os.environ.get("WT_SESSION"):
            return self._set_cached("supports_hyperlinks", True)

        # Check for specific terminal versions
        vte_version = os.environ.get("VTE_VERSION", "")
        if vte_version and int(vte_version[:4]) >= 5000:  # VTE 0.50.0+
            return self._set_cached("supports_hyperlinks", True)

        return self._set_cached("supports_hyperlinks", False)

    def get_environment_info(self) -> Dict[str, Any]:
        """Get comprehensive terminal environment information"""
        return {
            "capability_level": self.get_capability_level().value,
            "is_ci": self.is_ci(),
            "is_interactive": self.is_interactive(),
            "supports_color": self.supports_color(),
            "supports_unicode": self.supports_unicode(),
            "supports_truecolor": self.supports_truecolor(),
            "supports_emoji": self.supports_emoji(),
            "supports_hyperlinks": self.supports_hyperlinks(),
            "terminal_size": self.get_terminal_size(),
            "term": os.environ.get("TERM", "unknown"),
            "term_program": os.environ.get("TERM_PROGRAM", "unknown"),
            "colorterm": os.environ.get("COLORTERM", "unknown"),
            "lang": os.environ.get("LANG", "unknown"),
        }


# Singleton instance
_detector: Optional[TerminalDetector] = None


def get_terminal_detector() -> TerminalDetector:
    """Get the singleton terminal detector instance"""
    global _detector
    if _detector is None:
        _detector = TerminalDetector()
    return _detector


def adapt_output(text: str, fallback: str = "") -> str:
    """Adapt output based on terminal capabilities"""
    detector = get_terminal_detector()

    if detector.get_capability_level() == TerminalCapability.MINIMAL:
        return fallback if fallback else text

    return text


def should_use_emoji() -> bool:
    """Check if emoji should be used in output"""
    # Check environment variable override
    if os.environ.get("NO_EMOJI"):
        return False

    detector = get_terminal_detector()
    return detector.supports_emoji() and not detector.is_ci()


def should_use_color() -> bool:
    """Check if color should be used in output"""
    detector = get_terminal_detector()
    return detector.supports_color()


def get_safe_width() -> int:
    """Get safe terminal width for output"""
    detector = get_terminal_detector()
    width, _ = detector.get_terminal_size()
    # Leave some margin for safety
    return max(40, width - 2)
