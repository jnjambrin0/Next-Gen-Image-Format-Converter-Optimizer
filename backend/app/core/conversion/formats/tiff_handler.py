"""TIFF format handler."""

from typing import BinaryIO, Dict, Any
from io import BytesIO
from PIL import Image, ImageSequence
import structlog

from app.models.conversion import ConversionSettings
from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import ConversionFailedError, TiffDecodingError

logger = structlog.get_logger()


class TiffHandler(BaseFormatHandler):
    """Handler for TIFF format."""

    def __init__(self):
        """Initialize TIFF handler."""
        super().__init__()
        self.supported_formats = ["tiff", "tif"]
        self.format_name = "TIFF"

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid TIFF."""
        if len(image_data) < 4:
            return False

        # Check TIFF magic bytes (little-endian or big-endian)
        if image_data[0:4] not in (b"II*\x00", b"MM\x00*"):
            return False

        # Try to open as TIFF
        try:
            with BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    return img.format == "TIFF"
        except Exception:
            return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load TIFF image from bytes."""
        try:
            with BytesIO(image_data) as buffer:
                img = Image.open(buffer)

                # Check if it's a multi-page TIFF
                try:
                    img.seek(1)
                    # It's multi-page, go back to first frame
                    img.seek(0)
                    logger.debug(
                        "Multi-page TIFF detected, extracting first frame",
                        n_frames=getattr(img, "n_frames", 1),
                    )
                except EOFError:
                    # Single page TIFF
                    pass

                # Load the first frame/page
                img.load()

                # Create a copy to ensure we have a standalone image
                # (not linked to the BytesIO buffer)
                first_frame = img.copy()

                # TIFF can have various color modes, normalize as needed
                if first_frame.mode == "CMYK":
                    first_frame = first_frame.convert("RGB")
                elif first_frame.mode not in ("RGB", "RGBA", "L", "LA"):
                    if "transparency" in first_frame.info:
                        first_frame = first_frame.convert("RGBA")
                    else:
                        first_frame = first_frame.convert("RGB")

                return first_frame

        except Exception as e:
            raise TiffDecodingError(
                f"Failed to load TIFF image: {str(e)}",
                details={"format": "TIFF", "error": str(e)},
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as TIFF."""
        try:
            # TIFF supports many color modes
            # Ensure we're in a supported mode
            if image.mode not in ("RGB", "RGBA", "L", "LA", "CMYK", "1"):
                if "transparency" in image.info or image.mode in ("RGBA", "LA", "P"):
                    image = image.convert("RGBA")
                else:
                    image = image.convert("RGB")

            # Get save parameters
            save_params = self.get_quality_param(settings)

            # TIFF compression options
            if settings.optimize:
                # Use LZW compression for lossless compression
                save_params["compression"] = "tiff_lzw"
            else:
                # No compression for faster saving
                save_params["compression"] = "none"

            # Remove metadata if requested
            if settings.strip_metadata:
                # TIFF-specific metadata removal - more efficient approach
                # Save without EXIF/metadata tags
                save_params["exif"] = b""
                save_params["tiffinfo"] = {}  # Remove TIFF-specific tags
                # No need to create a copy, just clear the tags

            # Save to buffer
            image.save(output_buffer, format="TIFF", **save_params)
            output_buffer.seek(0)

        except Exception as e:
            raise TiffDecodingError(
                f"Failed to save image as TIFF: {str(e)}",
                details={"format": "TIFF", "error": str(e)},
            )

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get TIFF-specific quality parameters."""
        # TIFF doesn't have quality settings for lossless compression
        # Quality only applies to JPEG compression within TIFF
        params = {}

        # Only use JPEG compression for very low quality settings
        if settings.quality < 50:
            params["compression"] = "jpeg"
            params["quality"] = settings.quality

        return params

    def _supports_transparency(self) -> bool:
        """TIFF supports transparency through alpha channel."""
        return True

    def _supports_mode(self, mode: str) -> bool:
        """Check if TIFF supports the given color mode."""
        # TIFF supports many color modes
        return mode in ("RGB", "RGBA", "L", "LA", "CMYK", "YCbCr", "1", "P")
