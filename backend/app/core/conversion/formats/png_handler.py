"""PNG format handler."""

from io import BytesIO
from typing import Any, BinaryIO, Dict

import structlog
from PIL import Image, PngImagePlugin

from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import ConversionFailedError
from app.models.conversion import ConversionSettings

logger = structlog.get_logger()


class PNGHandler(BaseFormatHandler):
    """Handler for PNG format."""

    def __init__(self) -> None:
        """Initialize PNG handler."""
        super().__init__()
        self.supported_formats = ["png"]
        self.format_name = "PNG"

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid PNG."""
        if len(image_data) < 8:
            return False

        # Check PNG magic bytes
        png_signature = b"\x89PNG\r\n\x1a\n"
        if image_data[0:8] != png_signature:
            return False

        # Try to open as PNG
        try:
            with BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    return img.format == "PNG"
        except Exception:
            return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load PNG image from bytes."""
        try:
            with BytesIO(image_data) as buffer:
                img = Image.open(buffer)
                # Load image data to ensure it's fully read
                img.load()
                return img

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to load PNG image: {str(e)}", details={"format": "PNG"}
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as PNG."""
        try:
            # PNG supports various modes, but RGB/RGBA are most common
            if image.mode not in ("RGB", "RGBA", "L", "LA", "P"):
                if "transparency" in image.info or image.mode == "RGBA":
                    image = image.convert("RGBA")
                else:
                    image = image.convert("RGB")

            # Get save parameters
            save_params = self.get_quality_param(settings)

            # Add optimization if requested
            if settings.optimize:
                save_params["optimize"] = True

            # Handle metadata
            pnginfo = None
            if not settings.strip_metadata and hasattr(image, "info"):
                # Preserve PNG metadata
                pnginfo = PngImagePlugin.PngInfo()
                for key, value in image.info.items():
                    if isinstance(key, str) and isinstance(value, (str, bytes)):
                        if isinstance(value, bytes):
                            value = value.decode("latin-1", errors="ignore")
                        pnginfo.add_text(key, value)
                save_params["pnginfo"] = pnginfo

            # Save to buffer
            image.save(output_buffer, format="PNG", **save_params)
            output_buffer.seek(0)

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to save image as PNG: {str(e)}", details={"format": "PNG"}
            )

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get PNG-specific quality parameters."""
        # PNG uses compression level (0-9) instead of quality
        # Map quality 1-100 to compression 9-0 (inverse relationship)
        compression_level = int(9 - (settings.quality / 100) * 9)
        compression_level = max(0, min(9, compression_level))

        return {"compress_level": compression_level}

    def _supports_transparency(self) -> bool:
        """PNG supports transparency."""
        return True

    def _supports_mode(self, mode: str) -> bool:
        """Check if PNG supports the given color mode."""
        return mode in ("RGB", "RGBA", "L", "LA", "P", "1")
