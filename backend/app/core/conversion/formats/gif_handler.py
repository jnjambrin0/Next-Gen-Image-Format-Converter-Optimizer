"""GIF format handler."""

from io import BytesIO
from typing import Any, BinaryIO, Dict

import structlog
from PIL import Image

from app.core.conversion.formats.base import BaseFormatHandler
from app.core.exceptions import GifDecodingError
from app.models.conversion import ConversionSettings

logger = structlog.get_logger()


class GifHandler(BaseFormatHandler):
    """Handler for GIF format."""

    def __init__(self) -> None:
        """Initialize GIF handler."""
        super().__init__()
        self.supported_formats = ["gif"]
        self.format_name = "GIF"

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid GIF."""
        if len(image_data) < 6:
            return False

        # Check GIF magic bytes (GIF87a or GIF89a)
        if image_data[0:6] not in (b"GIF87a", b"GIF89a"):
            return False

        # Try to open as GIF
        try:
            with BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    return img.format == "GIF"
        except Exception:
            return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load GIF image from bytes (first frame only)."""
        try:
            with BytesIO(image_data) as buffer:
                img = Image.open(buffer)

                # Check if it's an animated GIF
                is_animated = False
                try:
                    img.seek(1)
                    is_animated = True
                    # Go back to first frame
                    img.seek(0)
                    logger.debug(
                        "Animated GIF detected, extracting first frame",
                        n_frames=getattr(img, "n_frames", 1),
                    )
                except EOFError:
                    # Static GIF
                    pass

                # Load the first frame
                img.load()

                # Convert to RGBA to preserve transparency if present
                # GIF uses palette mode with potential transparency
                if img.mode == "P":
                    # Check for transparency
                    if "transparency" in img.info:
                        # Convert to RGBA to preserve transparency
                        img = img.convert("RGBA")
                    else:
                        # Convert to RGB
                        img = img.convert("RGB")
                elif img.mode == "L":
                    # Grayscale GIF
                    img = img.convert("RGB")
                elif img.mode not in ("RGB", "RGBA"):
                    img = img.convert("RGB")

                # Create a copy to ensure we have a standalone image
                first_frame = img.copy()

                return first_frame

        except Exception as e:
            raise GifDecodingError(
                f"Failed to load GIF image: {str(e)}",
                details={"format": "GIF", "error": str(e)},
            )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as GIF."""
        try:
            # GIF only supports palette mode
            # Convert to P mode with optional transparency
            if image.mode == "RGBA":
                # Convert RGBA to P mode with transparency
                # This approach preserves transparency better by quantizing with alpha
                img_rgba = image.convert("RGBA")

                # Extract alpha for transparency mask
                alpha = img_rgba.split()[3]

                # Convert to palette mode with 255 colors (leaving one for transparency)
                img_p = img_rgba.convert(
                    "P", palette=Image.Palette.ADAPTIVE, colors=255
                )

                # Use a more sophisticated approach to find transparent pixels
                # Set fully transparent pixels (alpha < 128) to index 255
                mask = Image.eval(alpha, lambda a: 255 if a < 128 else 0)

                # Create a new palette image with transparency
                img_with_transparency = Image.new("P", img_p.size, 255)
                img_with_transparency.paste(
                    img_p, mask=Image.eval(alpha, lambda a: 255 if a >= 128 else 0)
                )
                img_with_transparency.putpalette(img_p.getpalette())
                img_with_transparency.info["transparency"] = 255

                image = img_with_transparency
            elif image.mode != "P":
                # Convert to palette mode
                if image.mode == "L":
                    # Grayscale can be saved directly as GIF
                    pass
                else:
                    # Convert to palette mode with adaptive colors
                    image = image.convert(
                        "P", palette=Image.Palette.ADAPTIVE, colors=256
                    )

            # Get save parameters
            save_params = {}

            # GIF doesn't have quality settings, but we can control dithering
            if settings.optimize:
                save_params["optimize"] = True

            # Preserve transparency if present
            if "transparency" in image.info:
                save_params["transparency"] = image.info["transparency"]

            # Save to buffer (single frame only)
            image.save(output_buffer, format="GIF", **save_params)
            output_buffer.seek(0)

        except Exception as e:
            raise GifDecodingError(
                f"Failed to save image as GIF: {str(e)}",
                details={"format": "GIF", "error": str(e)},
            )

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get GIF-specific quality parameters."""
        # GIF doesn't support quality settings
        # Quality is controlled by color palette size
        return {}

    def _supports_transparency(self) -> bool:
        """GIF supports single-color transparency."""
        return True

    def _supports_mode(self, mode: str) -> bool:
        """Check if GIF supports the given color mode."""
        # GIF primarily uses palette mode
        return mode in ("P", "L", "RGB", "RGBA")
