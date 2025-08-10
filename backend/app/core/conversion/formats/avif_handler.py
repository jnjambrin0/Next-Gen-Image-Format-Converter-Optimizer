"""AVIF format handler."""

from typing import BinaryIO, Dict, Any
from io import BytesIO
from PIL import Image
import structlog

from app.models.conversion import ConversionSettings
from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import ConversionFailedError, UnsupportedFormatError

logger = structlog.get_logger()

try:
    import pillow_avif  # noqa: F401

    AVIF_AVAILABLE = True
except ImportError:
    AVIF_AVAILABLE = False
    logger.warning("pillow-avif-plugin not available, AVIF support disabled")


class AVIFHandler(BaseFormatHandler):
    """Handler for AVIF format."""

    def __init__(self):
        """Initialize AVIF handler."""
        super().__init__()
        self.supported_formats = ["avif"]
        self.format_name = "AVIF"

        if not AVIF_AVAILABLE:
            raise UnsupportedFormatError(
                "AVIF support not available. Please install pillow-avif-plugin."
            )

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats and AVIF_AVAILABLE

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid AVIF."""
        if len(image_data) < 12:
            return False

        # Check AVIF magic bytes (simplified check)
        # AVIF files start with file type box containing 'ftyp' and brand 'avif'
        if image_data[4:8] != b"ftyp":
            return False

        # Try to open as AVIF
        try:
            with BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    return img.format == "AVIF"
        except Exception:
            return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load AVIF image from bytes."""
        try:
            with BytesIO(image_data) as buffer:
                img = Image.open(buffer)
                # Load image data to ensure it's fully read
                img.load()
                return img

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to load AVIF image: {str(e)}", details={"format": "AVIF"}
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as AVIF."""
        try:
            # AVIF supports RGB and RGBA
            if image.mode not in ("RGB", "RGBA"):
                if "transparency" in image.info or image.mode in ("RGBA", "LA", "P"):
                    image = image.convert("RGBA")
                else:
                    image = image.convert("RGB")

            # Get save parameters
            save_params = self.get_quality_param(settings)

            # AVIF-specific optimizations
            if settings.optimize:
                save_params["speed"] = 0  # Slowest but best compression (0-10)
            else:
                save_params["speed"] = 6  # Balanced speed/compression

            # Set codec
            save_params["codec"] = "auto"  # Let Pillow choose the best codec

            # Save to buffer
            image.save(output_buffer, format="AVIF", **save_params)
            output_buffer.seek(0)

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to save image as AVIF: {str(e)}",
                details={"format": "AVIF", "error": str(e)},
            )

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get AVIF-specific quality parameters."""
        # AVIF quality range is 0-100 (same as our range)
        # But AVIF uses it inversely for some encoders, so we keep it as is
        return {
            "quality": settings.quality,
            "subsampling": "4:2:0" if settings.quality < 90 else "4:4:4",
        }

    def _supports_transparency(self) -> bool:
        """AVIF supports transparency."""
        return True

    def _supports_mode(self, mode: str) -> bool:
        """Check if AVIF supports the given color mode."""
        return mode in ("RGB", "RGBA")
