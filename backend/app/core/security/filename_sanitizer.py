"""
Filename sanitization utilities for secure file handling.
"""

import os
import re
from typing import List, Optional


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize a filename to prevent path traversal and other security issues.

    Args:
        filename: The filename to sanitize
        max_length: Maximum allowed length for the filename

    Returns:
        Sanitized filename safe for filesystem use
    """
    # Remove any path components
    filename = os.path.basename(filename)

    # Remove dangerous characters
    # Keep only alphanumeric, spaces, dots, hyphens, and underscores
    filename = re.sub(r"[^\w\s.-]", "_", filename)

    # Remove multiple dots to prevent extension confusion
    filename = re.sub(r"\.+", ".", filename)

    # Remove leading/trailing dots and spaces
    filename = filename.strip(". ")

    # Prevent empty filename
    if not filename:
        filename = "unnamed_file"

    # Split name and extension
    name_parts = filename.rsplit(".", 1)
    name = name_parts[0]
    ext = name_parts[1] if len(name_parts) > 1 else ""

    # Truncate name if too long (preserve extension)
    if ext:
        max_name_length = max_length - len(ext) - 1  # -1 for the dot
        if len(name) > max_name_length:
            name = name[:max_name_length]
        filename = f"{name}.{ext}"
    else:
        if len(filename) > max_length:
            filename = filename[:max_length]

    # Final safety check - no path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        filename = filename.replace("..", "_").replace("/", "_").replace("\\", "_")

    return filename


def is_safe_filename(filename: str) -> bool:
    """
    Check if a filename is safe (no path traversal attempts).

    Args:
        filename: The filename to check

    Returns:
        True if the filename is safe, False otherwise
    """
    # Check for path traversal patterns
    dangerous_patterns = [
        "..",
        "/",
        "\\",
        "\x00",  # Null byte
        "\n",
        "\r",
    ]

    for pattern in dangerous_patterns:
        if pattern in filename:
            return False

    # Check if it's just a filename (no path)
    if os.path.basename(filename) != filename:
        return False

    return True


def get_safe_extension(
    filename: str, allowed_extensions: Optional[List[str]] = None
) -> str:
    """
    Extract and validate file extension.

    Args:
        filename: The filename to extract extension from
        allowed_extensions: List of allowed extensions (with dots, e.g., ['.jpg', '.png'])

    Returns:
        Safe extension or empty string if invalid
    """
    # Default allowed image extensions if none provided
    if allowed_extensions is None:
        allowed_extensions = [
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".webp",
            ".avif",
            ".heif",
            ".heic",
            ".bmp",
            ".tiff",
            ".jxl",
            ".webp2",
        ]

    # Get extension
    _, ext = os.path.splitext(filename.lower())

    # Validate extension
    if ext in allowed_extensions:
        return ext

    return ""
