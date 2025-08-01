#!/usr/bin/env python3
"""
Sandboxed image conversion script.

This script runs in a restricted subprocess to perform pure format conversion
using PIL/Pillow. It reads image data from stdin and writes to stdout.

Metadata handling is done by SecurityEngine before conversion.

Usage:
    python sandboxed_convert.py <input_format> <output_format> <quality>
"""

# Standard library imports only - no app imports to avoid logging initialization
import sys
import io
import os
import json
import traceback

# Disable all logging before any other imports
import logging
logging.disable(logging.CRITICAL)

# Ensure clean environment
os.environ['PYTHONUNBUFFERED'] = '1'
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

# Now import PIL with decompression bomb protection
from PIL import Image

# Import constants (need to add path to sys.path first)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from app.core.constants import (
    MAX_IMAGE_PIXELS, 
    SUPPORTED_INPUT_FORMATS,
    SUPPORTED_OUTPUT_FORMATS, 
    MAX_FILE_SIZE,
    WEBP_METHOD,
    PNG_COMPRESS_LEVEL,
    MIN_QUALITY,
    MAX_QUALITY
)

# Set decompression bomb protection limit
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

# Use centralized format lists
ALLOWED_INPUT_FORMATS = SUPPORTED_INPUT_FORMATS
ALLOWED_OUTPUT_FORMATS = SUPPORTED_OUTPUT_FORMATS

# Use centralized size limit
MAX_INPUT_SIZE = MAX_FILE_SIZE


def write_error(error_code, message):
    """Write error to stderr in JSON format for parent process."""
    error_data = {
        "error_code": error_code,
        "message": message,
        "type": "sandboxed_conversion_error"
    }
    sys.stderr.write(json.dumps(error_data) + "\n")
    sys.stderr.flush()


def validate_format(format_str, allowed_formats):
    """Validate format string against whitelist."""
    format_lower = format_str.lower().strip()
    if format_lower not in allowed_formats:
        raise ValueError(f"Format '{format_str}' not in allowed formats: {allowed_formats}")
    return format_lower


def validate_quality(quality_str):
    """Validate quality parameter."""
    try:
        quality = int(quality_str)
        if not MIN_QUALITY <= quality <= MAX_QUALITY:
            raise ValueError(f"Quality must be between {MIN_QUALITY} and {MAX_QUALITY}")
        return quality
    except ValueError as e:
        raise ValueError(f"Invalid quality parameter: {e}")


def main():
    """Main conversion function with security hardening."""
    try:
        # Parse command line arguments
        if len(sys.argv) < 4:
            write_error("ARGS_ERROR", "Missing arguments")
            sys.exit(1)
        
        # Validate all inputs before processing
        try:
            input_format = validate_format(sys.argv[1], ALLOWED_INPUT_FORMATS)
            output_format = validate_format(sys.argv[2], ALLOWED_OUTPUT_FORMATS)
            quality = validate_quality(sys.argv[3])
        except ValueError as e:
            write_error("VALIDATION_ERROR", str(e))
            sys.exit(1)
        
        # Read input image from stdin (binary mode) with size check
        input_data = sys.stdin.buffer.read(MAX_INPUT_SIZE + 1)
        
        # Check input size
        if len(input_data) > MAX_INPUT_SIZE:
            write_error("SIZE_ERROR", f"Input exceeds maximum size of {MAX_INPUT_SIZE} bytes")
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
                    background.paste(image, mask=image.split()[-1] if image.mode == "RGBA" else None)
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
        save_kwargs = {
            "format": output_format.upper()
        }
        
        # Add quality for lossy formats
        if output_format.upper() in ["JPEG", "JPG", "WEBP"]:
            save_kwargs["quality"] = quality
            if output_format.upper() == "WEBP":
                save_kwargs["method"] = WEBP_METHOD
        
        # Add optimization for PNG
        if output_format.upper() == "PNG":
            save_kwargs["optimize"] = True
            save_kwargs["compress_level"] = PNG_COMPRESS_LEVEL
        
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
        
        # Clean up
        try:
            image.close()
            input_buffer.close()
            output_buffer.close()
        except:
            pass  # Cleanup errors should not fail the conversion
        
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