"""WebP format handler."""

from typing import BinaryIO, Dict, Any
from io import BytesIO
from PIL import Image
import structlog

from app.models.conversion import ConversionSettings
from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import ConversionFailedError

logger = structlog.get_logger()


class WebPHandler(BaseFormatHandler):
    """Handler for WebP format."""

    def __init__(self):
        """Initialize WebP handler."""
        super().__init__()
        self.supported_formats = ["webp"]
        self.format_name = "WEBP"

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid WebP."""
        if len(image_data) < 12:
            return False

        # Check WebP magic bytes
        if image_data[0:4] != b"RIFF":
            return False
        if image_data[8:12] != b"WEBP":
            return False

        # Try to open as WebP
        try:
            with BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    return img.format == "WEBP"
        except Exception:
            return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load WebP image from bytes."""
        try:
            with BytesIO(image_data) as buffer:
                img = Image.open(buffer)
                # Load image data to ensure it's fully read
                img.load()
                return img

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to load WebP image: {str(e)}", details={"format": "WEBP"}
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as WebP."""
        try:
            # WebP supports RGB and RGBA
            if image.mode not in ("RGB", "RGBA"):
                if "transparency" in image.info or image.mode in ("RGBA", "LA", "P"):
                    image = image.convert("RGBA")
                else:
                    image = image.convert("RGB")

            # Get save parameters
            save_params = self.get_quality_param(settings)

            # WebP-specific optimizations
            if settings.optimize:
                save_params["method"] = 6  # Slowest but best compression
            else:
                save_params["method"] = 4  # Balanced speed/compression

            # Handle transparency
            if image.mode == "RGBA":
                save_params["lossless"] = False  # Use lossy for better compression
                save_params["exact"] = False  # Allow inexact RGBA->RGBA conversion

            # Save to buffer
            image.save(output_buffer, format="WEBP", **save_params)
            output_buffer.seek(0)

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to save image as WebP: {str(e)}", details={"format": "WEBP"}
            )

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get WebP-specific quality parameters."""
        # WebP quality range is 0-100 (same as our range)
        return {"quality": settings.quality}

    def _supports_transparency(self) -> bool:
        """WebP supports transparency."""
        return True

    def _supports_mode(self, mode: str) -> bool:
        """Check if WebP supports the given color mode."""
        return mode in ("RGB", "RGBA")
