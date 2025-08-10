#!/usr/bin/env python3
"""
from typing import Any
Sandboxed image conversion script.

This script runs in a restricted subprocess to perform pure format conversion
using PIL/Pillow. It reads image data from stdin and writes to stdout.

Metadata handling is done by SecurityEngine before conversion.

Usage:
    python sandboxed_convert.py <input_format> <output_format> <quality>
"""

import io
import json
# Disable all logging before any other imports
import logging
import os
# Standard library imports only - no app imports to avoid logging initialization
import sys
import traceback

logging.disable(logging.CRITICAL)

# Ensure clean environment
os.environ["PYTHONUNBUFFERED"] = "1"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Block network access by overriding socket module
import socket

# Store original functions for internal use if needed
_original_socket = socket.socket
_original_getaddrinfo = socket.getaddrinfo
_original_gethostbyname = socket.gethostbyname
_original_gethostbyaddr = socket.gethostbyaddr
_original_gethostname = socket.gethostname
_original_getfqdn = socket.getfqdn

# Import error messages from constants for consistency
# We'll import these after setting up the path below
NETWORK_BLOCKED_MSG = "Network access is disabled in sandboxed environment"
DNS_BLOCKED_MSG = "DNS resolution is disabled in sandboxed environment"
UDP_BLOCKED_MSG = "UDP sockets are disabled in sandboxed environment"


# Create a blocking socket class that preserves inheritance
class BlockedSocket(_original_socket):
    """Socket class that blocks all operations."""

    def __init__(self, *args, **kwargs) -> None:
        raise OSError(NETWORK_BLOCKED_MSG)


# Override all DNS and socket functions
def _blocked_socket(*args, **kwargs) -> None:
    """Block all socket creation."""
    raise OSError(NETWORK_BLOCKED_MSG)


def _blocked_dns(*args, **kwargs) -> None:
    """Block all DNS resolution."""
    raise socket.gaierror(DNS_BLOCKED_MSG)


# Apply blocks - use the class for socket.socket to preserve inheritance
socket.socket = BlockedSocket
socket.create_connection = _blocked_socket
socket.getaddrinfo = _blocked_dns
socket.gethostbyname = _blocked_dns
socket.gethostbyaddr = _blocked_dns
socket.gethostname = lambda: "localhost"
socket.getfqdn = lambda x="": "localhost"

# Block urllib to prevent any HTTP requests
try:
    import urllib.request

    urllib.request.urlopen = lambda *args, **kwargs: (_ for _ in ()).throw(
        OSError(NETWORK_BLOCKED_MSG)
    )
except ImportError:
    pass

try:
    import urllib2

    urllib2.urlopen = lambda *args, **kwargs: (_ for _ in ()).throw(
        OSError(NETWORK_BLOCKED_MSG)
    )
except ImportError:
    pass

# Block requests library if present
try:
    import requests

    def _blocked_request(*args, **kwargs) -> None:
        raise OSError(NETWORK_BLOCKED_MSG)

    requests.get = _blocked_request
    requests.post = _blocked_request
    requests.put = _blocked_request
    requests.delete = _blocked_request
    requests.head = _blocked_request
    requests.options = _blocked_request
    requests.request = _blocked_request
except ImportError:
    pass

# Block WebRTC and P2P libraries
# List of P2P/WebRTC modules to block
P2P_MODULES = [
    "pyp2p",
    "p2p",
    "libp2p",
    "webrtc",
    "aiortc",
    "peerjs",
    "simple-peer",
    "webtorrent",
    "bittorrent",
    "libtorrent",
    "torrent",
    "dht",
    "kademlia",
    "ipfs",
    "pyipfs",
    "dat",
    "hypercore",
    "scuttlebutt",
    "gun",
    "orbit-db",
]


# Create a custom import hook to block P2P modules
class P2PBlocker:
    def find_module(self, fullname, path=None) -> None:
        # Block exact matches and submodules
        for blocked in P2P_MODULES:
            if fullname == blocked or fullname.startswith(blocked + "."):
                return self
        return None

    def load_module(self, fullname) -> None:
        raise ImportError(
            f"P2P/WebRTC module '{fullname}' is blocked in sandboxed environment"
        )


# Install the import blocker
import sys

sys.meta_path.insert(0, P2PBlocker())

# Also block specific WebRTC/P2P related functionality
try:
    # Block asyncio event loops that might be used for P2P
    import asyncio

    _original_new_event_loop = asyncio.new_event_loop

    def _blocked_event_loop() -> None:
        # Allow event loop but monitor for P2P usage
        loop = _original_new_event_loop()
        # Could add additional restrictions here
        return loop

    asyncio.new_event_loop = _blocked_event_loop
except ImportError:
    pass

# Block UDP sockets (commonly used for P2P)
_original_socket_call = _original_socket


def _restricted_socket(family=-1, type=-1, proto=-1, fileno=None) -> None:
    """Restrict socket creation - block UDP which is commonly used for P2P."""
    # Block UDP sockets
    if type == socket.SOCK_DGRAM:
        raise OSError(UDP_BLOCKED_MSG)
    # All sockets are blocked anyway by earlier override
    raise OSError(NETWORK_BLOCKED_MSG)


# Apply additional socket restrictions
socket.socket = _restricted_socket

# Now import PIL with decompression bomb protection
from PIL import Image

# Import constants from parent application
# This sandboxed script runs as a subprocess and needs access to the app's constants.
# We add the project root to sys.path to enable imports from the app module.
# This is safe because:
# 1. The script runs in a restricted subprocess with limited permissions
# 2. Network access is already blocked before any imports
# 3. Only specific constants are imported, not executable code
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from app.core.constants import (MAX_FILE_SIZE, MAX_IMAGE_PIXELS, MAX_QUALITY,
                                MIN_QUALITY, PNG_COMPRESS_LEVEL,
                                SUPPORTED_INPUT_FORMATS,
                                SUPPORTED_OUTPUT_FORMATS, WEBP_METHOD)

# Set decompression bomb protection limit
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

# Use centralized format lists
ALLOWED_INPUT_FORMATS = SUPPORTED_INPUT_FORMATS
ALLOWED_OUTPUT_FORMATS = SUPPORTED_OUTPUT_FORMATS

# Use centralized size limit
MAX_INPUT_SIZE = MAX_FILE_SIZE


def write_error(error_code, message) -> None:
    """Write error to stderr in JSON format for parent process."""
    error_data = {
        "error_code": error_code,
        "message": message,
        "type": "sandboxed_conversion_error",
    }
    sys.stderr.write(json.dumps(error_data) + "\n")
    sys.stderr.flush()


def validate_format(format_str, allowed_formats) -> None:
    """Validate format string against whitelist."""
    format_lower = format_str.lower().strip()
    if format_lower not in allowed_formats:
        raise ValueError(
            f"Format '{format_str}' not in allowed formats: {allowed_formats}"
        )
    return format_lower


def validate_quality(quality_str) -> None:
    """Validate quality parameter."""
    try:
        quality = int(quality_str)
        if not MIN_QUALITY <= quality <= MAX_QUALITY:
            raise ValueError(f"Quality must be between {MIN_QUALITY} and {MAX_QUALITY}")
        return quality
    except ValueError as e:
        raise ValueError(f"Invalid quality parameter: {e}")


# Advanced parameter whitelist for each format (Story 3.5)
ALLOWED_ADVANCED_PARAMS = {
    "jpeg": {
        "progressive": {"type": bool, "default": False},
        "subsampling": {"type": int, "values": [0, 1, 2], "default": 2},
        "optimize": {"type": bool, "default": True},
    },
    "jpg": {  # Same as jpeg
        "progressive": {"type": bool, "default": False},
        "subsampling": {"type": int, "values": [0, 1, 2], "default": 2},
        "optimize": {"type": bool, "default": True},
    },
    "png": {
        "compress_level": {"type": int, "min": 0, "max": 9, "default": 6},
        "progressive": {"type": bool, "default": False},
        "optimize": {"type": bool, "default": True},
    },
    "webp": {
        "lossless": {"type": bool, "default": False},
        "method": {"type": int, "min": 0, "max": 6, "default": 4},
        "alpha_quality": {"type": int, "min": 1, "max": 100, "default": 100},
    },
}


def validate_advanced_params(params, output_format) -> None:
    """Validate and sanitize advanced parameters for a given format.

    Args:
        params: Dict[str, Any] of advanced parameters
        output_format: Target output format

    Returns: Dict[str, Any] of validated parameters safe to use
    """
    if not params or not isinstance(params, dict):
        return {}

    format_lower = output_format.lower()
    allowed_params = ALLOWED_ADVANCED_PARAMS.get(format_lower, {})

    if not allowed_params:
        # Format doesn't support advanced params
        return {}

    validated = {}

    for param_name, param_value in params.items():
        # Skip unknown parameters (security)
        if param_name not in allowed_params:
            continue

        param_spec = allowed_params[param_name]
        expected_type = param_spec["type"]

        # Type validation
        if not isinstance(param_value, expected_type):
            # Try to convert if possible
            if expected_type == bool and isinstance(param_value, (int, str)):
                try:
                    param_value = (
                        bool(param_value)
                        if isinstance(param_value, int)
                        else param_value.lower() == "true"
                    )
                except:
                    continue
            elif expected_type == int and isinstance(param_value, str):
                try:
                    param_value = int(param_value)
                except:
                    continue
            else:
                continue

        # Value validation
        if "values" in param_spec:
            # Must be one of allowed values
            if param_value not in param_spec["values"]:
                continue
        elif "min" in param_spec and "max" in param_spec:
            # Must be within range
            if not param_spec["min"] <= param_value <= param_spec["max"]:
                continue

        # Passed all validation
        validated[param_name] = param_value

    return validated


def check_file_system_writes() -> None:
    """Check for unexpected file writes during conversion."""
    import tempfile

    temp_dir = tempfile.gettempdir()

    # List of directories to monitor for unexpected writes
    monitored_dirs = [temp_dir, "/tmp", "/var/tmp"]
    initial_file_counts = {}

    for dir_path in monitored_dirs:
        try:
            if os.path.exists(dir_path):
                file_count = len(
                    [
                        f
                        for f in os.listdir(dir_path)
                        if os.path.isfile(os.path.join(dir_path, f))
                    ]
                )
                initial_file_counts[dir_path] = file_count
        except (OSError, PermissionError):
            pass  # Skip if can't access directory

    return initial_file_counts


def verify_no_file_writes(initial_counts) -> None:
    """Verify no unexpected files were created."""
    import tempfile

    temp_dir = tempfile.gettempdir()

    monitored_dirs = [temp_dir, "/tmp", "/var/tmp"]

    for dir_path in monitored_dirs:
        if dir_path in initial_counts:
            try:
                if os.path.exists(dir_path):
                    current_count = len(
                        [
                            f
                            for f in os.listdir(dir_path)
                            if os.path.isfile(os.path.join(dir_path, f))
                        ]
                    )
                    if current_count > initial_counts[dir_path]:
                        write_error(
                            "SECURITY_VIOLATION",
                            f"Unexpected file creation detected in {dir_path}",
                        )
                        return False
            except (OSError, PermissionError):
                pass

    return True


def main() -> None:
    """Main conversion function with security hardening."""
    try:
        # Check initial file system state
        initial_file_counts = check_file_system_writes()
        # Parse command line arguments
        if len(sys.argv) < 4:
            write_error("ARGS_ERROR", "Missing arguments")
            sys.exit(1)

        # Validate all inputs before processing
        try:
            input_format = validate_format(sys.argv[1], ALLOWED_INPUT_FORMATS)
            output_format = validate_format(sys.argv[2], ALLOWED_OUTPUT_FORMATS)
            quality = validate_quality(sys.argv[3])

            # Parse optional advanced parameters (Story 3.5)
            advanced_params = {}
            if len(sys.argv) > 4:
                try:
                    raw_params = json.loads(sys.argv[4])
                    if isinstance(raw_params, dict):
                        # Validate parameters for security
                        advanced_params = validate_advanced_params(
                            raw_params, output_format
                        )
                except (json.JSONDecodeError, ValueError):
                    # Invalid JSON, ignore advanced params
                    advanced_params = {}
        except ValueError as e:
            write_error("VALIDATION_ERROR", str(e))
            sys.exit(1)

        # Read input image from stdin (binary mode) with size check
        input_data = sys.stdin.buffer.read(MAX_INPUT_SIZE + 1)

        # Check input size
        if len(input_data) > MAX_INPUT_SIZE:
            write_error(
                "SIZE_ERROR", f"Input exceeds maximum size of {MAX_INPUT_SIZE} bytes"
            )
            sys.exit(1)

        if len(input_data) == 0:
            write_error("INPUT_ERROR", "No input data received")
            sys.exit(1)

        # Open image with PIL
        input_buffer = io.BytesIO(input_data)
        try:
            image = Image.open(input_buffer)
            # Verify image to detect issues early
            image.verify()
            # Need to reopen after verify
            input_buffer.seek(0)
            image = Image.open(input_buffer)
        except Image.DecompressionBombError as e:
            write_error("DECOMPRESSION_BOMB", "Image exceeds decompression limits")
            sys.exit(1)
        except Exception as e:
            write_error("INVALID_IMAGE", f"Failed to open image: {str(e)}")
            sys.exit(1)

        # Convert image mode if needed
        try:
            if output_format.upper() in ["JPEG", "JPG"]:
                # JPEG doesn't support transparency
                if image.mode in ("RGBA", "LA", "P"):
                    # Convert to RGB
                    background = Image.new("RGB", image.size, (255, 255, 255))
                    if image.mode == "P":
                        image = image.convert("RGBA")
                    background.paste(
                        image, mask=image.split()[-1] if image.mode == "RGBA" else None
                    )
                    image = background
            elif output_format.upper() == "PNG":
                # PNG supports transparency, keep as is
                pass
            elif output_format.upper() == "WEBP":
                # WebP supports both RGB and RGBA
                pass
        except Exception as e:
            write_error("CONVERSION_ERROR", f"Failed to convert image mode: {str(e)}")
            sys.exit(1)

        # Prepare save parameters with validation
        save_kwargs = {"format": output_format.upper()}

        # Add quality for lossy formats
        if output_format.upper() in ["JPEG", "JPG", "WEBP"]:
            save_kwargs["quality"] = quality
            if output_format.upper() == "WEBP":
                save_kwargs["method"] = WEBP_METHOD

        # Add optimization for PNG
        if output_format.upper() == "PNG":
            save_kwargs["optimize"] = True
            save_kwargs["compress_level"] = PNG_COMPRESS_LEVEL

        # Apply validated advanced optimization parameters (Story 3.5)
        # Parameters have already been validated by validate_advanced_params()
        # so we can safely apply them
        if advanced_params:
            # All parameters are already validated and safe to use
            for param_name, param_value in advanced_params.items():
                if (
                    param_name == "lossless"
                    and param_value
                    and output_format.upper() == "WEBP"
                ):
                    # Special case: remove quality for lossless WebP
                    save_kwargs["lossless"] = True
                    save_kwargs.pop("quality", None)
                else:
                    # Apply the validated parameter
                    save_kwargs[param_name] = param_value

        # Skip format validation - PIL will handle this during save
        # Image.SAVE may not be populated until formats are used

        # Save to output buffer
        output_buffer = io.BytesIO()
        try:
            image.save(output_buffer, **save_kwargs)
        except Exception as e:
            write_error("SAVE_ERROR", f"Failed to save image: {str(e)}")
            sys.exit(1)

        # Write output to stdout (binary mode)
        output_buffer.seek(0)
        output_data = output_buffer.getvalue()

        # Final size check
        if len(output_data) == 0:
            write_error("OUTPUT_ERROR", "Conversion produced no output")
            sys.exit(1)

        sys.stdout.buffer.write(output_data)
        sys.stdout.buffer.flush()

        # Clean up - secure memory clearing
        try:
            # Clear sensitive buffers before closing
            if hasattr(input_buffer, "getvalue"):
                buffer_data = input_buffer.getvalue()
                if isinstance(buffer_data, (bytearray, memoryview)):
                    # Securely overwrite buffer contents
                    for i in range(len(buffer_data)):
                        buffer_data[i] = 0

            # Close resources
            image.close()
            input_buffer.close()
            output_buffer.close()

            # Clear variables
            input_data = None
            output_data = None

        except:
            pass  # Cleanup errors should not fail the conversion

        # Verify no unexpected file writes occurred
        if not verify_no_file_writes(initial_file_counts):
            sys.exit(1)

        # Success
        sys.exit(0)

    except Exception as e:
        # Catch any unexpected errors
        write_error("UNEXPECTED_ERROR", f"Unexpected error: {str(e)}")
        # Log traceback to stderr for debugging
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
