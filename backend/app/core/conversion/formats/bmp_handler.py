"""BMP format handler."""

from io import BytesIO
from typing import Any, BinaryIO, Dict

import structlog
from PIL import Image

from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import BmpDecodingError, ConversionFailedError
from app.models.conversion import ConversionSettings

logger = structlog.get_logger()


class BmpHandler(BaseFormatHandler):
    """Handler for BMP format."""

    def __init__(self):
        """Initialize BMP handler."""
        super().__init__()
        self.supported_formats = ["bmp", "dib"]
        self.format_name = "BMP"

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid BMP."""
        if len(image_data) < 2:
            return False

        # Check BMP magic bytes
        if image_data[0:2] not in (b"BM", b"BA", b"CI", b"CP", b"IC", b"PT"):
            return False

        # Try to open as BMP
        try:
            with BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    return img.format == "BMP"
        except Exception:
            return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load BMP image from bytes."""
        try:
            with BytesIO(image_data) as buffer:
                img = Image.open(buffer)
                # Load image data to ensure it's fully read
                img.load()

                # BMP files can have various bit depths and color modes
                # Normalize to RGB/RGBA for consistent processing
                if img.mode == "P":
                    # Palette mode - check for transparency
                    if "transparency" in img.info:
                        img = img.convert("RGBA")
                    else:
                        img = img.convert("RGB")
                elif img.mode in ("1", "L"):
                    # 1-bit or grayscale
                    img = img.convert("RGB")
                elif img.mode not in ("RGB", "RGBA"):
                    # Other modes
                    img = img.convert("RGB")

                return img

        except Exception as e:
            raise BmpDecodingError(
                f"Failed to load BMP image: {str(e)}",
                details={"format": "BMP", "error": str(e)},
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as BMP."""
        try:
            # BMP doesn't support transparency well, convert RGBA to RGB
            if image.mode == "RGBA":
                # Create white background
                background = Image.new("RGB", image.size, (255, 255, 255))
                background.paste(image, mask=image.split()[3])
                image = background
            elif image.mode not in ("RGB", "L", "1"):
                image = image.convert("RGB")

            # BMP doesn't have quality settings, but we can control bit depth
            save_params = {}

            # Use 24-bit for RGB (default)
            if image.mode == "RGB":
                save_params["bits"] = 24
            elif image.mode == "L":
                save_params["bits"] = 8
            elif image.mode == "1":
                save_params["bits"] = 1

            # Save to buffer
            image.save(output_buffer, format="BMP", **save_params)
            output_buffer.seek(0)

        except Exception as e:
            raise BmpDecodingError(
                f"Failed to save image as BMP: {str(e)}",
                details={"format": "BMP", "error": str(e)},
            )

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get BMP-specific quality parameters."""
        # BMP doesn't support quality settings
        return {}

    def _supports_transparency(self) -> bool:
        """BMP has limited transparency support."""
        return False

    def _supports_mode(self, mode: str) -> bool:
        """Check if BMP supports the given color mode."""
        # BMP supports various modes but we normalize to RGB
        return mode in ("RGB", "L", "1", "P")
