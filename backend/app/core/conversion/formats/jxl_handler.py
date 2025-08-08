"""JPEG XL format handler."""

from typing import BinaryIO, Dict, Any
from io import BytesIO
from PIL import Image
import structlog

try:
    import jxlpy

    JXL_AVAILABLE = True
except ImportError:
    JXL_AVAILABLE = False

from app.models.conversion import ConversionSettings
from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import ConversionFailedError, UnsupportedFormatError

logger = structlog.get_logger()


class JxlHandler(BaseFormatHandler):
    """Handler for JPEG XL format."""

    def __init__(self):
        """Initialize JPEG XL handler."""
        super().__init__()
        self.supported_formats = ["jxl", "jpegxl", "jpeg_xl"]
        self.format_name = "JPEG_XL"

        if not JXL_AVAILABLE:
            raise UnsupportedFormatError(
                "JPEG XL support not available. Install jxlpy package.",
                details={"format": "JPEG_XL", "required_package": "jxlpy"},
            )

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid JPEG XL."""
        if len(image_data) < 12:
            return False

        # Check for JPEG XL magic bytes
        # Codestream: starts with 0xFF0A
        if image_data[:2] == b"\xff\x0a":
            return True

        # ISO container: "JXL " signature at offset 4-8
        if len(image_data) >= 12 and image_data[4:8] == b"JXL ":
            return True

        # Try to decode with jxlpy
        try:
            if JXL_AVAILABLE:
                jxlpy.decode_jpeg_xl(image_data)
                return True
        except Exception:
            pass

        return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load JPEG XL image from bytes."""
        try:
            # Decode JPEG XL to RGB/RGBA array
            decoded = jxlpy.decode_jpeg_xl(image_data)

            # Convert numpy array to PIL Image
            if decoded.shape[2] == 4:
                mode = "RGBA"
            elif decoded.shape[2] == 3:
                mode = "RGB"
            else:
                raise ConversionFailedError(
                    f"Unsupported JPEG XL color channels: {decoded.shape[2]}",
                    details={"format": "JPEG_XL"},
                )

            img = Image.fromarray(decoded, mode=mode)
            return img

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to load JPEG XL image: {str(e)}",
                details={"format": "JPEG_XL", "error": str(e)},
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as JPEG XL."""
        try:
            # Convert image to numpy array
            import numpy as np

            # Ensure RGB or RGBA mode
            if image.mode not in ("RGB", "RGBA"):
                if "transparency" in image.info or image.mode in ("RGBA", "LA", "P"):
                    image = image.convert("RGBA")
                else:
                    image = image.convert("RGB")

            # Convert to numpy array
            img_array = np.array(image)

            # Get encoding options
            encode_options = self._get_encode_options(settings)

            # Encode to JPEG XL
            jxl_data = jxlpy.encode_jpeg_xl(img_array, **encode_options)

            # Write to buffer
            output_buffer.write(jxl_data)
            output_buffer.seek(0)

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to save image as JPEG XL: {str(e)}",
                details={"format": "JPEG_XL", "error": str(e)},
            )

    def _get_encode_options(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get JPEG XL encoding options."""
        options = {}

        # Quality mapping: our 1-100 to JXL distance parameter
        # Lower distance = higher quality
        # Distance 0 = lossless, 1.0 = visually lossless, 3.0 = acceptable quality
        if settings.quality >= 100:
            options["distance"] = 0.0  # Lossless
            options["lossless"] = True
        else:
            # Map quality 1-99 to distance 15.0-0.1
            distance = 15.0 - (settings.quality / 99.0 * 14.9)
            options["distance"] = distance
            options["lossless"] = False

        # Effort level (1-9, higher = slower but better compression)
        if settings.optimize:
            options["effort"] = 7  # High effort for optimization
        else:
            options["effort"] = 4  # Balanced effort

        # Enable progressive decoding
        options["progressive"] = True

        return options

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get JPEG XL-specific quality parameters."""
        return self._get_encode_options(settings)

    def _supports_transparency(self) -> bool:
        """JPEG XL supports transparency."""
        return True

    def _supports_mode(self, mode: str) -> bool:
        """Check if JPEG XL supports the given color mode."""
        return mode in ("RGB", "RGBA", "L")
