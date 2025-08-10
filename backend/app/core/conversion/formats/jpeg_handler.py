"""JPEG format handler."""

from io import BytesIO
from typing import Any, BinaryIO, Dict

import structlog
from PIL import Image, ImageFile

from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import ConversionFailedError
from app.models.conversion import ConversionSettings

# Enable loading of truncated images
ImageFile.LOAD_TRUNCATED_IMAGES = True

logger = structlog.get_logger()


class JPEGHandler(BaseFormatHandler):
    """Handler for JPEG format."""

    def __init__(self):
        """Initialize JPEG handler."""
        super().__init__()
        self.supported_formats = ["jpeg", "jpg", "jpe", "jfif"]
        self.format_name = "JPEG"

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid JPEG."""
        if len(image_data) < 3:
            return False

        # Check JPEG magic bytes
        if image_data[0:2] != b"\xff\xd8":
            return False

        # Try to open as JPEG
        try:
            with BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    return img.format in ["JPEG", "JPG"]
        except Exception:
            return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load JPEG image from bytes."""
        try:
            with BytesIO(image_data) as buffer:
                img = Image.open(buffer)
                # Load image data to ensure it's fully read
                img.load()

                # Convert to RGB if needed (some JPEGs might be in CMYK)
                if img.mode == "CMYK":
                    img = img.convert("RGB")

                return img

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to load JPEG image: {str(e)}", details={"format": "JPEG"}
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as JPEG."""
        try:
            # JPEG doesn't support transparency, ensure RGB mode
            if image.mode in ("RGBA", "LA", "P"):
                # Create white background
                background = Image.new("RGB", image.size, (255, 255, 255))
                if image.mode == "P":
                    image = image.convert("RGBA")
                background.paste(
                    image, mask=image.split()[-1] if "A" in image.mode else None
                )
                image = background
            elif image.mode not in ("RGB", "L"):
                image = image.convert("RGB")

            # Get save parameters
            save_params = self.get_quality_param(settings)

            # Add optimization if requested
            if settings.optimize:
                save_params["optimize"] = True
                save_params["progressive"] = True

            # Remove metadata if requested
            if settings.strip_metadata:
                # Save without EXIF
                save_params["exif"] = b""
            else:
                # Preserve EXIF if available
                if hasattr(image, "info") and "exif" in image.info:
                    save_params["exif"] = image.info["exif"]

            # Save to buffer
            image.save(output_buffer, format="JPEG", **save_params)
            output_buffer.seek(0)

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to save image as JPEG: {str(e)}", details={"format": "JPEG"}
            )

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get JPEG-specific quality parameters."""
        # JPEG quality range is 1-95 (higher values might increase file size)
        # Map our 1-100 range to JPEG's optimal range
        jpeg_quality = int((settings.quality / 100) * 95)
        jpeg_quality = max(1, min(95, jpeg_quality))

        return {
            "quality": jpeg_quality,
            "subsampling": (
                0 if settings.quality > 90 else 2
            ),  # Use 4:4:4 for high quality
        }

    def _supports_transparency(self) -> bool:
        """JPEG doesn't support transparency."""
        return False

    def _supports_mode(self, mode: str) -> bool:
        """Check if JPEG supports the given color mode."""
        return mode in ("RGB", "L", "CMYK")
