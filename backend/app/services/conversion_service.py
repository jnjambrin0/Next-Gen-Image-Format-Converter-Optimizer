"""Service layer for image conversion operations."""

from typing import Tuple, Optional
import asyncio
import structlog

# Try to import magic, but make it optional
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

from app.core.conversion.manager import ConversionManager
from app.models.conversion import (
    ConversionResult,
    ConversionRequest as CoreConversionRequest,
)
from app.models.requests import ConversionApiRequest
from app.core.exceptions import ConversionError, InvalidImageError
from app.services.format_detection_service import format_detection_service
# Removed circular import - stats_collector will be injected or imported elsewhere

logger = structlog.get_logger()


class ConversionService:
    """Service layer for handling image conversions."""

    def __init__(self):
        """Initialize conversion service."""
        self.conversion_manager = ConversionManager()
        # Initialize stats_collector as None - will be set later to avoid circular import
        self.stats_collector = None
        self._mime_to_format = {
            "image/jpeg": ["jpeg", "jpg"],
            "image/png": ["png"],
            "image/webp": ["webp"],
            "image/gif": ["gif"],
            "image/bmp": ["bmp"],
            "image/tiff": ["tiff", "tif"],
            "image/avif": ["avif"],
            "image/heif": ["heif", "heic"],
            "image/heic": ["heif", "heic"],
        }

    async def convert(
        self,
        image_data: bytes,
        request: ConversionApiRequest,
        timeout: Optional[float] = None,
    ) -> Tuple[ConversionResult, Optional[bytes]]:
        """
        Convert an image using the conversion manager.

        Args:
            image_data: Raw image data as bytes
            request: API conversion request
            timeout: Optional timeout for conversion

        Returns:
            Tuple of (ConversionResult, output_bytes)

        Raises:
            ConversionError: If conversion fails
        """
        # Track start time for stats - moved before try to fix UnboundLocalError
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Detect actual format from image content
            try:
                detected_format, is_confident = await format_detection_service.detect_format(image_data)
                logger.info(
                    "Format detected",
                    detected_format=detected_format,
                    claimed_format=request.input_format,
                    confident=is_confident
                )
                
                # Use detected format instead of claimed format
                actual_input_format = detected_format
                
                # Log if there's a mismatch (but don't fail)
                if detected_format != request.input_format.lower():
                    logger.warning(
                        "Format mismatch detected",
                        detected_format=detected_format,
                        claimed_format=request.input_format,
                        filename=request.filename
                    )
                    
            except Exception as e:
                logger.error(
                    "Format detection failed",
                    error=str(e),
                    claimed_format=request.input_format
                )
                # Fall back to claimed format if detection fails
                actual_input_format = request.input_format

            # Create core conversion request
            core_request = CoreConversionRequest(
                output_format=request.output_format,
                settings=request.settings,
            )
            
            # Perform conversion with timeout
            timeout = timeout or 30.0  # Default 30 seconds
            try:
                result, output_data = await asyncio.wait_for(
                    self.conversion_manager.convert_with_output(
                        input_data=image_data,
                        input_format=actual_input_format,  # Use detected format
                        request=core_request,
                        timeout=None,  # Don't pass timeout to conversion_manager
                    ),
                    timeout=timeout,
                )
                
                # Stats are already recorded in conversion_manager, no need to duplicate
                
                return result, output_data
                
            except asyncio.TimeoutError:
                # Stats are already recorded in conversion_manager
                raise

        except asyncio.TimeoutError:
            logger.error(
                "Conversion timeout",
                filename=request.filename,
                timeout=timeout,
            )
            raise

        except Exception as e:
            # Stats are already recorded in conversion_manager
            logger.error(
                "Conversion service error",
                error=str(e),
                error_type=type(e).__name__,
                input_format=actual_input_format if 'actual_input_format' in locals() else request.input_format,
                output_format=request.output_format,
            )
            raise

    async def validate_image(self, image_data: bytes) -> bool:
        """
        Validate that image data is a valid image.

        Args:
            image_data: Raw image data

        Returns:
            True if valid image, False otherwise
        """
        if not image_data:
            return False

        try:
            # Try to detect format - if successful, it's a valid image
            detected_format, _ = await format_detection_service.detect_format(image_data)
            logger.debug(
                "Image validation successful",
                detected_format=detected_format,
                data_size=len(image_data),
            )
            return True
            
        except Exception as e:
            logger.error(
                "Error validating image",
                error=str(e),
                data_size=len(image_data) if image_data else 0,
            )
            return False

    def get_supported_formats(self) -> dict:
        """
        Get lists of supported input and output formats.

        Returns:
            Dictionary with input_formats and output_formats lists
        """
        return {
            "input_formats": [
                {
                    "format": "jpeg",
                    "mime_type": "image/jpeg",
                    "extensions": [".jpg", ".jpeg"],
                    "description": "JPEG image format",
                    "supports_transparency": False,
                    "supports_animation": False,
                },
                {
                    "format": "png",
                    "mime_type": "image/png",
                    "extensions": [".png"],
                    "description": "PNG image format",
                    "supports_transparency": True,
                    "supports_animation": False,
                },
                {
                    "format": "webp",
                    "mime_type": "image/webp",
                    "extensions": [".webp"],
                    "description": "WebP image format",
                    "supports_transparency": True,
                    "supports_animation": True,
                },
                {
                    "format": "gif",
                    "mime_type": "image/gif",
                    "extensions": [".gif"],
                    "description": "GIF image format",
                    "supports_transparency": True,
                    "supports_animation": True,
                },
                {
                    "format": "bmp",
                    "mime_type": "image/bmp",
                    "extensions": [".bmp"],
                    "description": "BMP image format",
                    "supports_transparency": False,
                    "supports_animation": False,
                },
                {
                    "format": "tiff",
                    "mime_type": "image/tiff",
                    "extensions": [".tiff", ".tif"],
                    "description": "TIFF image format",
                    "supports_transparency": True,
                    "supports_animation": False,
                },
                {
                    "format": "heif",
                    "mime_type": "image/heif",
                    "extensions": [".heif", ".heic"],
                    "description": "HEIF/HEIC image format",
                    "supports_transparency": True,
                    "supports_animation": True,
                },
                {
                    "format": "avif",
                    "mime_type": "image/avif",
                    "extensions": [".avif"],
                    "description": "AVIF image format",
                    "supports_transparency": True,
                    "supports_animation": True,
                },
            ],
            "output_formats": [
                {
                    "format": "webp",
                    "mime_type": "image/webp",
                    "extensions": [".webp"],
                    "description": "WebP - Modern format with excellent compression",
                    "supports_transparency": True,
                    "supports_animation": True,
                },
                {
                    "format": "avif",
                    "mime_type": "image/avif",
                    "extensions": [".avif"],
                    "description": "AVIF - Next-gen format with superior compression",
                    "supports_transparency": True,
                    "supports_animation": True,
                },
                {
                    "format": "jpeg",
                    "mime_type": "image/jpeg",
                    "extensions": [".jpg", ".jpeg"],
                    "description": "JPEG - Optimized for photos",
                    "supports_transparency": False,
                    "supports_animation": False,
                },
                {
                    "format": "png",
                    "mime_type": "image/png",
                    "extensions": [".png"],
                    "description": "PNG - Optimized lossless compression",
                    "supports_transparency": True,
                    "supports_animation": False,
                },
            ],
        }

    def _detect_mime_type_fallback(self, data: bytes) -> str:
        """
        Fallback method to detect MIME type using magic bytes.
        
        Args:
            data: Raw file data
            
        Returns:
            Detected MIME type or 'application/octet-stream' if unknown
        """
        if len(data) < 12:
            return "application/octet-stream"
            
        # Check common image format magic bytes
        if data[:2] == b'\xff\xd8':
            return "image/jpeg"
        elif data[:8] == b'\x89PNG\r\n\x1a\n':
            return "image/png"
        elif data[:4] == b'GIF8':
            return "image/gif"
        elif data[:4] == b'RIFF' and data[8:12] == b'WEBP':
            return "image/webp"
        elif data[:2] == b'BM':
            return "image/bmp"
        elif data[:4] == b'II\x2a\x00' or data[:4] == b'MM\x00\x2a':
            return "image/tiff"
        elif data[:12] == b'\x00\x00\x00\x0cjP  \r\n\x87\n':
            return "image/jp2"
        elif data[:12] == b'\x00\x00\x00\x20ftypavif':
            return "image/avif"
        # Check for HEIF/HEIC formats
        # HEIC files can have variable box sizes, check multiple positions
        elif len(data) >= 12:
            # Standard check at offset 4
            if data[4:8] == b'ftyp':
                brand = data[8:12]
                # Common HEIF/HEIC brands
                if brand in [b'heic', b'heix', b'hevc', b'hevx', b'mif1', b'msf1']:
                    return "image/heif"
            # Some HEIC files have different structure, check for 'ftyp' in first 40 bytes
            elif b'ftyp' in data[:40]:
                ftyp_index = data.find(b'ftyp')
                if ftyp_index >= 0 and len(data) > ftyp_index + 8:
                    # Get the brand after ftyp
                    brand = data[ftyp_index + 4:ftyp_index + 8]
                    if brand in [b'heic', b'heix', b'hevc', b'hevx', b'mif1', b'msf1']:
                        return "image/heif"
                    # Also check compatible brands that follow
                    for i in range(ftyp_index + 8, min(ftyp_index + 40, len(data) - 4), 4):
                        compat_brand = data[i:i + 4]
                        if compat_brand in [b'heic', b'heix', b'hevc', b'hevx', b'mif1', b'msf1']:
                            return "image/heif"
        else:
            return "application/octet-stream"


# Create singleton instance
conversion_service = ConversionService()

