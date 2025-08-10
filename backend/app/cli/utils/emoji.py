"""
Emoji Mappings and Management
Contextual emoji for better visual scanning
"""

import os
from enum import Enum
from typing import Dict, Optional

from app.cli.config import get_config
from app.cli.utils.terminal import should_use_emoji


class EmojiCategory(str, Enum):
    """Emoji categories"""

    FORMAT = "format"
    STATUS = "status"
    PROGRESS = "progress"
    ACTION = "action"
    QUALITY = "quality"
    WARNING = "warning"


# Emoji mappings
EMOJI_MAP = {
    # File formats
    "jpeg": "📷",
    "jpg": "📷",
    "png": "🖼️",
    "gif": "🎬",
    "webp": "🌐",
    "avif": "🚀",
    "heif": "📱",
    "heic": "📱",
    "bmp": "🎨",
    "tiff": "📊",
    "jxl": "✨",
    "webp2": "🌟",
    "jp2": "🗾",
    "svg": "📐",
    "ico": "🔷",
    "raw": "📸",
    # Status indicators
    "success": "✅",
    "error": "❌",
    "warning": "⚠️",
    "info": "ℹ️",
    "question": "❓",
    "pending": "⏳",
    "running": "🔄",
    "complete": "✔️",
    "failed": "✖️",
    "skipped": "⏭️",
    "cancelled": "🚫",
    # Progress indicators
    "start": "🚀",
    "processing": "⚙️",
    "converting": "🔄",
    "optimizing": "⚡",
    "analyzing": "🔍",
    "downloading": "📥",
    "uploading": "📤",
    "saving": "💾",
    "loading": "📂",
    "complete_progress": "🎉",
    # Actions
    "convert": "🔄",
    "optimize": "⚡",
    "analyze": "🔍",
    "batch": "📦",
    "preview": "👁️",
    "settings": "⚙️",
    "help": "❓",
    "exit": "🚪",
    "save": "💾",
    "load": "📂",
    "delete": "🗑️",
    "copy": "📋",
    "paste": "📌",
    "undo": "↩️",
    "redo": "↪️",
    # Quality indicators
    "high_quality": "⭐⭐⭐⭐⭐",
    "good_quality": "⭐⭐⭐⭐",
    "medium_quality": "⭐⭐⭐",
    "low_quality": "⭐⭐",
    "poor_quality": "⭐",
    # File operations
    "file": "📄",
    "folder": "📁",
    "archive": "🗜️",
    "lock": "🔒",
    "unlock": "🔓",
    # Performance
    "fast": "🚀",
    "slow": "🐌",
    "memory": "🧠",
    "cpu": "💻",
    "disk": "💿",
    # UI elements
    "menu": "☰",
    "close": "❌",
    "minimize": "➖",
    "maximize": "➕",
    "checkbox_checked": "☑️",
    "checkbox_unchecked": "☐",
    "radio_selected": "🔘",
    "radio_unselected": "⚪",
    # Miscellaneous
    "clock": "🕐",
    "calendar": "📅",
    "email": "📧",
    "link": "🔗",
    "bug": "🐛",
    "fire": "🔥",
    "star": "⭐",
    "heart": "❤️",
    "thumbs_up": "👍",
    "thumbs_down": "👎",
    "checkmark": "✓",
    "cross": "✗",
    "arrow_right": "→",
    "arrow_left": "←",
    "arrow_up": "↑",
    "arrow_down": "↓",
}

# Text-only fallbacks for when emoji are disabled
TEXT_FALLBACK = {
    # File formats
    "jpeg": "[JPEG]",
    "jpg": "[JPG]",
    "png": "[PNG]",
    "gif": "[GIF]",
    "webp": "[WEBP]",
    "avif": "[AVIF]",
    "heif": "[HEIF]",
    "heic": "[HEIC]",
    "bmp": "[BMP]",
    "tiff": "[TIFF]",
    "jxl": "[JXL]",
    "webp2": "[WEBP2]",
    "jp2": "[JP2]",
    "svg": "[SVG]",
    "ico": "[ICO]",
    "raw": "[RAW]",
    # Status indicators
    "success": "[OK]",
    "error": "[ERROR]",
    "warning": "[WARN]",
    "info": "[INFO]",
    "question": "[?]",
    "pending": "[...]",
    "running": "[RUN]",
    "complete": "[DONE]",
    "failed": "[FAIL]",
    "skipped": "[SKIP]",
    "cancelled": "[CANCEL]",
    # Progress indicators
    "start": "[START]",
    "processing": "[PROC]",
    "converting": "[CONV]",
    "optimizing": "[OPT]",
    "analyzing": "[ANLZ]",
    "downloading": "[DL]",
    "uploading": "[UL]",
    "saving": "[SAVE]",
    "loading": "[LOAD]",
    "complete_progress": "[COMPLETE]",
    # Actions
    "convert": ">>",
    "optimize": "++",
    "analyze": "??",
    "batch": "[]",
    "preview": "o",
    "settings": "*",
    "help": "?",
    "exit": "X",
    "save": "S",
    "load": "L",
    "delete": "D",
    "copy": "C",
    "paste": "P",
    "undo": "<",
    "redo": ">",
    # Quality indicators
    "high_quality": "*****",
    "good_quality": "****",
    "medium_quality": "***",
    "low_quality": "**",
    "poor_quality": "*",
    # File operations
    "file": "-",
    "folder": "+",
    "archive": "#",
    "lock": "L",
    "unlock": "U",
    # Performance
    "fast": ">>",
    "slow": "<<",
    "memory": "M",
    "cpu": "C",
    "disk": "D",
    # UI elements
    "menu": "=",
    "close": "X",
    "minimize": "-",
    "maximize": "+",
    "checkbox_checked": "[X]",
    "checkbox_unchecked": "[ ]",
    "radio_selected": "(o)",
    "radio_unselected": "( )",
    # Miscellaneous
    "clock": "@",
    "calendar": "#",
    "email": "@",
    "link": "&",
    "bug": "!",
    "fire": "!",
    "star": "*",
    "heart": "<3",
    "thumbs_up": "+1",
    "thumbs_down": "-1",
    "checkmark": "v",
    "cross": "x",
    "arrow_right": ">",
    "arrow_left": "<",
    "arrow_up": "^",
    "arrow_down": "v",
}


def get_emoji(key: str, fallback: Optional[str] = None) -> str:
    """
    Get emoji or fallback text based on configuration

    Args:
        key: Emoji key from EMOJI_MAP
        fallback: Optional custom fallback text

    Returns:
        Emoji character or fallback text
    """
    config = get_config()

    # Check if emoji should be used
    if not should_use_emoji() or not config.emoji_enabled:
        # Use text fallback
        if fallback:
            return fallback
        return TEXT_FALLBACK.get(key, "")

    # Return emoji
    return EMOJI_MAP.get(key, fallback or "")


def format_with_emoji(text: str, emoji_key: str) -> str:
    """
    Format text with optional emoji prefix

    Args:
        text: Text to format
        emoji_key: Emoji key from EMOJI_MAP

    Returns:
        Formatted text with or without emoji
    """
    emoji = get_emoji(emoji_key)
    if emoji:
        return f"{emoji} {text}"
    return text


def get_format_emoji(format_name: str) -> str:
    """
    Get emoji for image format

    Args:
        format_name: Image format name

    Returns:
        Format emoji or fallback
    """
    return get_emoji(format_name.lower(), f"[{format_name.upper()}]")


def get_status_emoji(status: str) -> str:
    """
    Get emoji for status indicator

    Args:
        status: Status type (success, error, warning, etc.)

    Returns:
        Status emoji or fallback
    """
    return get_emoji(status.lower())


def get_quality_stars(quality: int) -> str:
    """
    Get star rating for quality level

    Args:
        quality: Quality percentage (0-100)

    Returns:
        Star rating string
    """
    if quality >= 90:
        return get_emoji("high_quality", "*****")
    elif quality >= 75:
        return get_emoji("good_quality", "****")
    elif quality >= 60:
        return get_emoji("medium_quality", "***")
    elif quality >= 40:
        return get_emoji("low_quality", "**")
    else:
        return get_emoji("poor_quality", "*")


def format_file_size_with_emoji(size_bytes: int) -> str:
    """
    Format file size with appropriate emoji

    Args:
        size_bytes: File size in bytes

    Returns:
        Formatted file size with emoji
    """
    size_mb = size_bytes / (1024 * 1024)

    if size_mb < 1:
        emoji = get_emoji("fast")
        size_str = f"{size_bytes / 1024:.1f} KB"
    elif size_mb < 10:
        emoji = get_emoji("file")
        size_str = f"{size_mb:.1f} MB"
    elif size_mb < 100:
        emoji = get_emoji("folder")
        size_str = f"{size_mb:.0f} MB"
    else:
        emoji = get_emoji("slow")
        size_str = f"{size_mb:.0f} MB"

    if emoji:
        return f"{emoji} {size_str}"
    return size_str


def format_duration_with_emoji(seconds: float) -> str:
    """
    Format duration with appropriate emoji

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration with emoji
    """
    if seconds < 1:
        emoji = get_emoji("fast")
        duration = f"{seconds*1000:.0f}ms"
    elif seconds < 10:
        emoji = get_emoji("clock")
        duration = f"{seconds:.1f}s"
    elif seconds < 60:
        emoji = get_emoji("processing")
        duration = f"{seconds:.0f}s"
    else:
        emoji = get_emoji("slow")
        minutes = seconds / 60
        duration = f"{minutes:.1f}m"

    if emoji:
        return f"{emoji} {duration}"
    return duration


def strip_emoji(text: str) -> str:
    """
    Remove all emoji from text

    Args:
        text: Text containing emoji

    Returns:
        Text with emoji removed
    """
    import re

    # Remove emoji using regex pattern
    emoji_pattern = re.compile(
        "["
        "\U0001f600-\U0001f64f"  # emoticons
        "\U0001f300-\U0001f5ff"  # symbols & pictographs
        "\U0001f680-\U0001f6ff"  # transport & map symbols
        "\U0001f1e0-\U0001f1ff"  # flags (iOS)
        "\U00002500-\U00002bef"  # chinese char
        "\U00002702-\U000027b0"
        "\U00002702-\U000027b0"
        "\U000024c2-\U0001f251"
        "\U0001f926-\U0001f937"
        "\U00010000-\U0010ffff"
        "\u2640-\u2642"
        "\u2600-\u2b55"
        "\u200d"
        "\u23cf"
        "\u23e9"
        "\u231a"
        "\ufe0f"  # dingbats
        "\u3030"
        "]+",
        flags=re.UNICODE,
    )
    return emoji_pattern.sub("", text).strip()
