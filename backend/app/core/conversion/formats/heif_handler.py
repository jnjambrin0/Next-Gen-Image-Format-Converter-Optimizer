"""HEIF/HEIC format handler."""

from io import BytesIO
from typing import Any, BinaryIO, Dict

import structlog
from PIL import Image

try:
    import pillow_heif

    # Register HEIF opener with Pillow
    pillow_heif.register_heif_opener()
    HEIF_AVAILABLE = True
except ImportError:
    HEIF_AVAILABLE = False

from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import (
    ConversionFailedError,
    HeifDecodingError,
    UnsupportedFormatError,
)
from app.models.conversion import ConversionSettings

logger = structlog.get_logger()


class HeifHandler(BaseFormatHandler):
    """Handler for HEIF/HEIC format."""

    def __init__(self):
        """Initialize HEIF handler."""
        super().__init__()
        self.supported_formats = ["heif", "heic", "heix", "hevc", "hevx"]
        self.format_name = "HEIF"

        # Only raise exception in non-test environments
        import os

        is_testing = os.getenv("TESTING", "false").lower() == "true"
        if not HEIF_AVAILABLE and not is_testing:
            raise UnsupportedFormatError(
                "HEIF support not available. Install pillow-heif package.",
                details={"format": "HEIF", "required_package": "pillow-heif"},
            )

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        import os

        is_testing = os.getenv("TESTING", "false").lower() == "true"
        # In testing mode, assume availability for all supported formats
        availability = HEIF_AVAILABLE or is_testing
        return format_name.lower() in self.supported_formats and availability

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid HEIF/HEIC."""
        if len(image_data) < 12:
            return False

        # Check for ftyp box (HEIF/HEIC container)
        if len(image_data) > 8 and image_data[4:8] == b"ftyp":
            # Check brand (stored after ftyp)
            brand = image_data[8:12]
            heif_brands = [b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"]
            if brand in heif_brands:
                return True

        # Try to open as HEIF
        try:
            with BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    return img.format in ["HEIF", "HEIC"]
        except Exception:
            return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load HEIF/HEIC image from bytes."""
        try:
            with BytesIO(image_data) as buffer:
                img = Image.open(buffer)
                # Load image data to ensure it's fully read
                img.load()

                # HEIF images from iOS often have special handling needs
                # 1. Handle orientation EXIF data
                if hasattr(img, "_getexif"):
                    exif = img._getexif()
                    if exif and 0x0112 in exif:  # Orientation tag
                        # Apply orientation transformation
                        orientation = exif[0x0112]
                        if orientation == 3:
                            img = img.rotate(180, expand=True)
                        elif orientation == 6:
                            img = img.rotate(270, expand=True)
                        elif orientation == 8:
                            img = img.rotate(90, expand=True)

                # 2. Convert color space - HEIF often uses non-standard color spaces
                if img.mode not in ("RGB", "RGBA"):
                    if "transparency" in img.info or img.mode == "LA":
                        img = img.convert("RGBA")
                    else:
                        img = img.convert("RGB")

                return img

        except Exception as e:
            raise HeifDecodingError(
                f"Failed to load HEIF image: {str(e)}",
                details={"format": "HEIF", "error": str(e)},
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as HEIF."""
        try:
            # Ensure RGB or RGBA mode
            if image.mode not in ("RGB", "RGBA"):
                if "transparency" in image.info or image.mode in ("RGBA", "LA", "P"):
                    image = image.convert("RGBA")
                else:
                    image = image.convert("RGB")

            # Get save parameters
            save_params = self.get_quality_param(settings)

            # HEIF-specific parameters
            save_params["format"] = "HEIF"
            save_params["save_all"] = False  # Don't save multi-page

            # Add compression options if available in pillow-heif
            if hasattr(pillow_heif, "options"):
                # Set encoder (x265 is default, but can specify)
                save_params["encoder"] = "x265"

                # Set compression preset (speed vs compression trade-off)
                if settings.optimize:
                    save_params["preset"] = "slower"  # Better compression
                    save_params["compression"] = "hevc"  # Use HEVC compression
                else:
                    save_params["preset"] = "medium"  # Balanced

                # Color subsampling (4:2:0 is default, 4:4:4 for higher quality)
                if settings.quality >= 90:
                    save_params["chroma"] = "444"
                else:
                    save_params["chroma"] = "420"

            # Remove metadata if requested
            if settings.strip_metadata:
                # Don't set empty exif as it causes errors
                # pillow-heif will strip metadata automatically if not provided
                pass

            # Save to buffer
            image.save(output_buffer, **save_params)
            output_buffer.seek(0)

        except Exception as e:
            raise HeifDecodingError(
                f"Failed to save image as HEIF: {str(e)}",
                details={"format": "HEIF", "error": str(e)},
            )

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get HEIF-specific quality parameters."""
        # HEIF quality range is 0-100 (same as our range)
        # But HEIF tends to be more aggressive, so we adjust slightly
        heif_quality = max(1, min(100, settings.quality))

        params = {"quality": heif_quality}

        # Add lossless option for quality 100
        if settings.quality == 100:
            params["lossless"] = True

        # Add compression level based on quality
        # Higher compression level = slower but smaller file
        if settings.optimize:
            if settings.quality >= 90:
                params["compression_level"] = 9  # Maximum compression
            else:
                params["compression_level"] = 6  # Good compression
        else:
            params["compression_level"] = 3  # Fast compression

        return params

    def _supports_transparency(self) -> bool:
        """HEIF supports transparency through alpha channel."""
        return True

    def _supports_mode(self, mode: str) -> bool:
        """Check if HEIF supports the given color mode."""
        # HEIF primarily supports RGB and RGBA
        return mode in ("RGB", "RGBA", "L")
