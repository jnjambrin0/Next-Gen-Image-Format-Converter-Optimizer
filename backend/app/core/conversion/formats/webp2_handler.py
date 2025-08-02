"""WebP2 format handler with fallback to WebP."""

from typing import BinaryIO, Dict, Any
from io import BytesIO
from PIL import Image
import structlog

try:
    import webp2
    WEBP2_AVAILABLE = True
except ImportError:
    WEBP2_AVAILABLE = False

from app.models.conversion import ConversionSettings
from app.core.conversion.formats.webp_handler import WebPHandler
from app.core.exceptions import ConversionFailedError, UnsupportedFormatError

logger = structlog.get_logger()


class WebP2Handler(WebPHandler):
    """Handler for WebP2 format with automatic fallback to WebP."""

    def __init__(self):
        """Initialize WebP2 handler."""
        super().__init__()
        self.supported_formats = ["webp2"]
        self.format_name = "WEBP2"
        self.webp2_available = WEBP2_AVAILABLE
        
        if not self.webp2_available:
            logger.info(
                "WebP2 support not available, will fallback to WebP",
                webp2_available=False
            )

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid WebP2."""
        if not self.webp2_available:
            # Fallback to WebP validation
            return super().validate_image(image_data)
        
        if len(image_data) < 12:
            return False

        # WebP2 uses similar container format to WebP
        # Check for RIFF container with WP2 fourcc
        if image_data[0:4] != b"RIFF":
            return False
        if len(image_data) > 12 and image_data[8:12] == b"WP2 ":
            return True

        # Not WebP2, but might be valid for fallback
        return False

    def load_image(self, image_data: bytes) -> Image.Image:
        """Load WebP2 image from bytes."""
        if not self.webp2_available:
            # Fallback to WebP loading
            return super().load_image(image_data)
        
        try:
            # Decode WebP2 to RGB/RGBA array
            decoded = webp2.decode(image_data)
            
            # Convert to PIL Image
            if decoded.shape[2] == 4:
                mode = "RGBA"
            elif decoded.shape[2] == 3:
                mode = "RGB"
            else:
                raise ConversionFailedError(
                    f"Unsupported WebP2 color channels: {decoded.shape[2]}",
                    details={"format": "WEBP2"}
                )
            
            img = Image.fromarray(decoded, mode=mode)
            return img

        except Exception as e:
            # Try fallback to WebP
            try:
                logger.debug("WebP2 decode failed, trying WebP fallback")
                return super().load_image(image_data)
            except Exception:
                # Re-raise original WebP2 error
                raise ConversionFailedError(
                    f"Failed to load WebP2 image: {str(e)}", 
                    details={"format": "WEBP2", "error": str(e)}
                )

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as WebP2 with automatic fallback to WebP."""
        if not self.webp2_available:
            logger.debug("WebP2 not available, using WebP fallback")
            super().save_image(image, output_buffer, settings)
            return
        
        try:
            # Ensure RGB or RGBA mode
            if image.mode not in ("RGB", "RGBA"):
                if "transparency" in image.info or image.mode in ("RGBA", "LA", "P"):
                    image = image.convert("RGBA")
                else:
                    image = image.convert("RGB")

            # Convert to numpy array for WebP2
            import numpy as np
            img_array = np.array(image)
            
            # Get encoding options
            encode_options = self._get_webp2_encode_options(settings)
            
            # Encode to WebP2
            webp2_data = webp2.encode(img_array, **encode_options)
            
            # Write to buffer
            output_buffer.write(webp2_data)
            output_buffer.seek(0)

        except Exception as e:
            logger.warning(
                "WebP2 encoding failed, falling back to WebP",
                error=str(e)
            )
            # Fallback to regular WebP
            super().save_image(image, output_buffer, settings)

    def _get_webp2_encode_options(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get WebP2-specific encoding options."""
        options = {}
        
        # Quality mapping
        options["quality"] = settings.quality
        
        # WebP2 specific options
        if settings.optimize:
            options["effort"] = 9  # Maximum compression effort
            options["pass"] = 10   # Multi-pass encoding
        else:
            options["effort"] = 4  # Balanced effort
            options["pass"] = 1    # Single pass
        
        # Enable advanced features
        options["use_adv_features"] = True
        options["sns"] = 50  # Spatial noise shaping
        
        # Threading for performance
        options["thread_level"] = 1
        
        return options

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get WebP2-specific quality parameters."""
        if self.webp2_available:
            # WebP2 is available, return WebP2-specific quality parameters
            encode_opts = self._get_webp2_encode_options(settings)
            return {
                "quality": settings.quality,
                "effort": encode_opts["effort"],
                "multi_pass": encode_opts["pass"] > 1,
                "advanced_features": encode_opts.get("use_adv_features", False)
            }
        else:
            # Fallback to WebP quality parameters
            return super().get_quality_param(settings)

    def _supports_transparency(self) -> bool:
        """WebP2 supports transparency."""
        return True

    def _supports_mode(self, mode: str) -> bool:
        """Check if WebP2 supports the given color mode."""
        return mode in ("RGB", "RGBA")