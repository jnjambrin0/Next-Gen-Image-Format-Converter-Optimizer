"""JPEG 2000 format handler."""

from io import BytesIO
from typing import Any, BinaryIO, Dict

import structlog
from PIL import Image

from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import ConversionFailedError, UnsupportedFormatError
from app.models.conversion import ConversionSettings

logger = structlog.get_logger()


class Jpeg2000Handler(BaseFormatHandler):
    """Handler for JPEG 2000 format."""

    def __init__(self):
        """Initialize JPEG 2000 handler."""
        super().__init__()
        self.supported_formats = ["jp2", "jpeg2000", "j2k", "jpf", "jpx", "jpm"]
        self.format_name = "JPEG2000"

        # Check if Pillow has JPEG 2000 support (via OpenJPEG)
        self.jp2_available = self._check_jp2_support()

        if not self.jp2_available:
            raise UnsupportedFormatError(
                "JPEG 2000 support not available. Pillow needs to be compiled with OpenJPEG support.",
                details={"format": "JPEG2000", "required": "Pillow with OpenJPEG"},
            )

    def _check_jp2_support(self) -> bool:
        """Check if JPEG 2000 support is available in Pillow."""
        try:
            # Try to create a small JPEG 2000 image
            test_img = Image.new("RGB", (1, 1))
            test_buffer = BytesIO()
            test_img.save(test_buffer, format="JPEG2000")
            return True
        except Exception:
            return False

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid JPEG 2000."""
        if len(image_data) < 12:
            return False

        # Check for JP2 magic bytes
        # JP2 format starts with signature box
        if image_data[0:12] == b"\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a":
            return True

        # Check for codestream format (J2K)
        if image_data[0:4] == b"\xff\x4f\xff\x51":
            return True

        # Try to open as JPEG 2000
        try:
            with BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    return img.format == "JPEG2000"
        except Exception:
            return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load JPEG 2000 image from bytes."""
        try:
            with BytesIO(image_data) as buffer:
                img = Image.open(buffer)
                # Load image data to ensure it's fully read
                img.load()

                # Ensure we have a usable mode
                if img.mode not in ("RGB", "RGBA", "L", "LA"):
                    if "transparency" in img.info or img.mode in ("RGBA", "LA"):
                        img = img.convert("RGBA")
                    else:
                        img = img.convert("RGB")

                return img

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to load JPEG 2000 image: {str(e)}",
                details={"format": "JPEG2000", "error": str(e)},
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as JPEG 2000."""
        try:
            # JPEG 2000 supports RGB, RGBA, L, LA modes
            if image.mode not in ("RGB", "RGBA", "L", "LA"):
                if "transparency" in image.info or image.mode == "P":
                    # Check if palette has transparency
                    if image.mode == "P" and "transparency" in image.info:
                        image = image.convert("RGBA")
                    else:
                        image = image.convert("RGB")
                else:
                    image = image.convert("RGB")

            # Get save parameters
            save_params = self.get_quality_param(settings)

            # JPEG 2000 specific parameters
            save_params["format"] = "JPEG2000"

            # Irreversible (lossy) vs reversible (lossless) compression
            if settings.quality == 100:
                save_params["irreversible"] = False  # Lossless
            else:
                save_params["irreversible"] = True  # Lossy

            # Quality layers
            if settings.optimize:
                save_params["quality_layers"] = [
                    settings.quality,
                    settings.quality - 10,
                    settings.quality - 20,
                ]
                save_params["progression"] = (
                    "LRCP"  # Layer-Resolution-Component-Position
                )

            # Save to buffer
            image.save(output_buffer, **save_params)
            output_buffer.seek(0)

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to save image as JPEG 2000: {str(e)}",
                details={"format": "JPEG2000", "error": str(e)},
            )

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get JPEG 2000-specific quality parameters."""
        # JPEG 2000 quality is more complex than simple 0-100
        # It uses compression ratios and quality layers

        if settings.quality == 100:
            # Lossless compression
            return {
                "quality_mode": "rates",
                "quality": 0,  # 0 means lossless for JPEG2000
                "irreversible": False,
            }
        else:
            # Lossy compression
            # Map quality 1-99 to compression ratio
            # Higher quality = lower compression ratio
            # Quality 90 = ~10:1, Quality 50 = ~40:1
            compression_ratio = 100 - settings.quality

            # Convert to rates (bits per pixel)
            # Typical range is 0.1 to 5.0 bpp
            rate = 5.0 - (compression_ratio / 100 * 4.9)

            return {
                "quality_mode": "rates",
                "quality": rate,
                "num_resolutions": 6 if settings.optimize else 1,
                "irreversible": True,
            }

    def _supports_transparency(self) -> bool:
        """JPEG 2000 supports transparency through alpha channel."""
        return True

    def _supports_mode(self, mode: str) -> bool:
        """Check if JPEG 2000 supports the given color mode."""
        return mode in ("RGB", "RGBA", "L", "LA")
