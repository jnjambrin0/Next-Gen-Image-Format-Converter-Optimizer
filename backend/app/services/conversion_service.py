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
from app.api.routes.monitoring import stats_collector

logger = structlog.get_logger()


class ConversionService:
    """Service layer for handling image conversions."""

    def __init__(self):
        """Initialize conversion service."""
        self.conversion_manager = ConversionManager()
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
        try:
            # Validate image data before conversion
            if not await self.validate_image(image_data, request.input_format):
                raise InvalidImageError(
                    f"File content does not match expected format: {request.input_format}"
                )

            # Create core conversion request
            core_request = CoreConversionRequest(
                output_format=request.output_format,
                settings=request.settings,
            )

            # Track start time for stats
            start_time = asyncio.get_event_loop().time()
            
            # Perform conversion with timeout
            timeout = timeout or 30.0  # Default 30 seconds
            try:
                result, output_data = await asyncio.wait_for(
                    self.conversion_manager.convert_with_output(
                        input_data=image_data,
                        input_format=request.input_format,
                        request=core_request,
                        timeout=None,  # Don't pass timeout to conversion_manager
                    ),
                    timeout=timeout,
                )
                
                # Record successful conversion stats
                processing_time = asyncio.get_event_loop().time() - start_time
                await stats_collector.record_conversion(
                    input_format=request.input_format,
                    output_format=request.output_format,
                    input_size=len(image_data),
                    processing_time=processing_time,
                    success=True
                )
                
                return result, output_data
                
            except asyncio.TimeoutError:
                # Record timeout failure
                processing_time = asyncio.get_event_loop().time() - start_time
                await stats_collector.record_conversion(
                    input_format=request.input_format,
                    output_format=request.output_format,
                    input_size=len(image_data),
                    processing_time=processing_time,
                    success=False,
                    error_type="timeout"
                )
                raise

        except asyncio.TimeoutError:
            logger.error(
                "Conversion timeout",
                filename=request.filename,
                timeout=timeout,
            )
            raise

        except Exception as e:
            # Record other failures (if not already recorded)
            if not isinstance(e, asyncio.TimeoutError):
                processing_time = asyncio.get_event_loop().time() - start_time
                error_type = type(e).__name__.lower()
                if "memory" in str(e).lower():
                    error_type = "memory_limit"
                elif "invalid" in str(e).lower():
                    error_type = "invalid_input"
                elif "unsupported" in str(e).lower():
                    error_type = "unsupported_format"
                else:
                    error_type = "conversion_error"
                    
                await stats_collector.record_conversion(
                    input_format=request.input_format,
                    output_format=request.output_format,
                    input_size=len(image_data),
                    processing_time=processing_time,
                    success=False,
                    error_type=error_type
                )
            
            logger.error(
                "Conversion service error",
                error=str(e),
                error_type=type(e).__name__,
                input_format=request.input_format,
                output_format=request.output_format,
            )
            raise

    async def validate_image(self, image_data: bytes, expected_format: str) -> bool:
        """
        Validate that image data matches the expected format using magic bytes.

        Args:
            image_data: Raw image data
            expected_format: Expected image format

        Returns:
            True if valid, False otherwise
        """
        if not image_data:
            return False

        try:
            # Get MIME type from file content
            if HAS_MAGIC:
                mime_type = magic.from_buffer(image_data, mime=True)
            else:
                # Fallback: Check magic bytes manually for common formats
                mime_type = self._detect_mime_type_fallback(image_data)
            
            # Log detected MIME type for debugging
            logger.debug(
                "Image validation",
                expected_format=expected_format,
                detected_mime=mime_type,
                data_size=len(image_data),
            )
            
            # Check if detected MIME type is valid for the expected format
            if mime_type in self._mime_to_format:
                allowed_formats = self._mime_to_format[mime_type]
                return expected_format.lower() in allowed_formats
            
            # Handle edge cases for less common formats
            if mime_type == "application/octet-stream":
                # Some formats might not be detected properly, do additional checks
                # For now, log warning and allow
                logger.warning(
                    "Could not determine MIME type",
                    expected_format=expected_format,
                    detected_mime=mime_type,
                )
                return True
                
            return False
            
        except Exception as e:
            logger.error(
                "Error validating image",
                error=str(e),
                expected_format=expected_format,
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
        else:
            return "application/octet-stream"

