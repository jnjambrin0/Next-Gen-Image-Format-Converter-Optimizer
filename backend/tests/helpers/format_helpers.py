"""Minimal helper functions for format conversion tests."""

import io

from PIL import Image


def create_test_image_for_format(
    format: str, width: int = 100, height: int = 100
) -> bytes:
    """Create a simple test image for the given format."""
    # Use RGB for formats that don't support transparency
    if format.lower() in ["jpeg", "jpg", "bmp"]:
        mode = "RGB"
    else:
        mode = "RGBA"

    # Create simple red image
    img = Image.new(
        mode, (width, height), color=(255, 0, 0, 255) if mode == "RGBA" else (255, 0, 0)
    )

    # Save to bytes
    buffer = io.BytesIO()
    img.save(buffer, format=format.upper() if format.upper() != "JPG" else "JPEG")
    return buffer.getvalue()


def prepare_image_for_conversion(image_data: bytes, target_format: str) -> bytes:
    """Prepare image for format conversion (handle RGB requirements)."""
    img = Image.open(io.BytesIO(image_data))

    # Convert to RGB for formats that require it
    if target_format.lower() in ["jpeg", "jpg", "bmp"] and img.mode == "RGBA":
        # White background for transparency
        background = Image.new("RGB", img.size, (255, 255, 255))
        background.paste(img, mask=img.split()[-1])
        img = background
    elif target_format.lower() in ["avif", "heif"] and img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


# Stub functions for imports that don't exist yet
def validate_conversion_result(*args, **kwargs):
    """Stub function - not implemented."""
    return True, None


def get_format_capabilities(format: str):
    """Stub function - not implemented."""
    return {}
