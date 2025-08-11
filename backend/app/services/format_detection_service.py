"""
Format Detection Service - Robust image format detection from file content
Detects actual image format regardless of file extension
"""

from io import BytesIO
from typing import Optional, Tuple

import structlog
from PIL import Image

from app.core.constants import FORMAT_ALIASES, HEIF_AVIF_BRANDS, IMAGE_MAGIC_BYTES

logger = structlog.get_logger()


class FormatDetectionService:
    """Service for detecting image formats from file content."""

    def __init__(self):
        """Initialize format detection service."""
        # Map of MIME types to our internal format names
        self._mime_to_format = {
            "image/jpeg": "jpeg",
            "image/png": "png",
            "image/webp": "webp",
            "image/gif": "gif",
            "image/bmp": "bmp",
            "image/tiff": "tiff",
            "image/avif": "avif",
            "image/heif": "heif",
            "image/heic": "heif",
            "image/jp2": "jp2",
            "image/jpx": "jp2",
            "image/jxl": "jxl",
            "image/x-icon": "ico",
            "image/vnd.microsoft.icon": "ico",
        }

        # PIL format to our format mapping
        self._pil_format_map = {
            "JPEG": "jpeg",
            "PNG": "png",
            "WEBP": "webp",
            "GIF": "gif",
            "BMP": "bmp",
            "TIFF": "tiff",
            "ICO": "ico",
            "HEIF": "heif",
            "HEIC": "heif",
            "AVIF": "avif",
        }

    async def detect_format(self, image_data: bytes) -> Tuple[str, bool]:
        """
        Detect image format from file content.

        Args:
            image_data: Raw image data

        Returns:
            Tuple of (detected_format, is_confident)
            - detected_format: The detected format name (e.g., 'jpeg', 'png')
            - is_confident: Whether the detection is confident (True) or a guess (False)
        """
        if not image_data or len(image_data) < 12:
            raise ValueError(
                "The provided image data is invalid or empty. Please ensure you've selected a valid image file."
            )

        # First try: Magic bytes detection (most reliable)
        format_name, confident = self._detect_by_magic_bytes(image_data)
        if format_name and confident:
            logger.debug(
                "Format detected by magic bytes", format=format_name, confident=True
            )
            return self._normalize_format_name(format_name), True

        # Second try: PIL detection (good fallback)
        pil_format = self._detect_by_pil(image_data)
        if pil_format:
            logger.debug("Format detected by PIL", format=pil_format, confident=True)
            return self._normalize_format_name(pil_format), True

        # Third try: Extended magic bytes check
        if format_name:  # We had a partial match
            logger.debug(
                "Format detected by extended check", format=format_name, confident=False
            )
            return self._normalize_format_name(format_name), False

        # Failed to detect
        logger.warning("Failed to detect image format")
        raise ValueError(
            "Unable to detect the image format. The file may be corrupted, truncated, or in an unsupported format. Supported formats include: JPEG, PNG, WebP, GIF, BMP, TIFF, HEIF/HEIC, and AVIF."
        )

    def _detect_by_magic_bytes(self, data: bytes) -> Tuple[Optional[str], bool]:
        """
        Detect format using magic bytes.

        Returns:
            Tuple of (format_name, is_confident)
        """
        # Check each known signature
        for signature, format_name in IMAGE_MAGIC_BYTES.items():
            if data.startswith(signature):
                # Special handling for container formats
                if format_name == "WebP/RIFF":
                    # Verify it's actually WebP
                    if len(data) > 12 and data[8:12] == b"WEBP":
                        return "webp", True
                    # Could be other RIFF format
                    return "riff", False

                elif format_name == "HEIF/AVIF":
                    # Check ftyp box for specific format
                    if len(data) >= 12:
                        brand = data[8:12]
                        specific_format = HEIF_AVIF_BRANDS.get(brand)
                        if specific_format:
                            return specific_format.lower(), True
                    # Generic HEIF container
                    return "heif", False

                else:
                    # Direct match
                    return format_name.lower(), True

        # Extended checks for formats with non-standard headers

        # JPEG with EXIF
        if (
            len(data) > 4
            and data[0:2] == b"\xff\xd8"
            and data[2:4] in [b"\xff\xe0", b"\xff\xe1", b"\xff\xe2"]
        ):
            return "jpeg", True

        # JPEG 2000 variations
        if len(data) > 12:
            if data[0:12] == b"\x00\x00\x00\x0cjP  \r\n\x87\n":
                return "jp2", True
            elif data[0:4] == b"\xff\x4f\xff\x51":
                return "j2k", True

        # JPEG XL variations
        if len(data) > 2:
            if data[0:2] == b"\xff\x0a":
                return "jxl", True
            elif (
                len(data) > 12 and data[0:12] == b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a"
            ):
                return "jxl", True

        return None, False

    def _detect_by_pil(self, data: bytes) -> Optional[str]:
        """Detect format using PIL."""
        try:
            with BytesIO(data) as buffer:
                with Image.open(buffer) as img:
                    # Force PIL to read the image header
                    img.load()
                    if img.format:
                        pil_format = img.format.upper()
                        return self._pil_format_map.get(pil_format, pil_format.lower())
        except Exception as e:
            logger.debug("PIL detection failed", error=str(e))

        return None

    def _normalize_format_name(self, format_name: str) -> str:
        """
        Normalize format name to our standard naming.

        Args:
            format_name: Raw format name

        Returns:
            Normalized format name
        """
        format_lower = format_name.lower()

        # Apply aliases
        canonical = FORMAT_ALIASES.get(format_lower, format_lower)

        # Additional normalizations
        if canonical == "jpg":
            return "jpeg"
        elif canonical in ["heic", "heif", "heix", "hevc", "hevx"]:
            return "heif"
        elif canonical in ["tif", "tiff"]:
            return "tiff"
        elif canonical in ["jp2", "j2k", "jpx", "j2c"]:
            return "jp2"
        elif canonical in ["jxl", "jpegxl", "jpeg_xl"]:
            return "jxl"

        return canonical

    def is_format_supported(self, format_name: str) -> bool:
        """Check if a format is supported."""
        normalized = self._normalize_format_name(format_name)
        # This should check against actual registered handlers
        # For now, we'll use a basic list
        supported = {
            "jpeg",
            "png",
            "webp",
            "gif",
            "bmp",
            "tiff",
            "avif",
            "heif",
            "jp2",
            "jxl",
            "ico",
        }
        return normalized in supported

    async def analyze_format_security(
        self, image_data: bytes, detected_format: str
    ) -> dict:
        """Analyze format for security issues (stub for tests)."""
        result = {
            "is_polyglot": False,
            "has_suspicious_data": False,
            "has_prepended_data": False,
            "is_suspicious": False,
        }

        # Check for polyglot signatures
        if (
            b"GIF89a/*" in image_data
            or b"%PDF" in image_data
            and b"\xff\xd8" in image_data
        ):
            result["is_polyglot"] = True
            result["is_suspicious"] = True

        # Check for prepended data
        for signature in IMAGE_MAGIC_BYTES.values():
            if signature in image_data and not image_data.startswith(signature):
                result["has_prepended_data"] = True
                result["is_suspicious"] = True
                break

        return result

    async def validate_format_integrity(
        self, image_data: bytes, detected_format: str
    ) -> dict:
        """Validate format integrity (stub for tests)."""
        result = {
            "is_complete": True,
            "is_truncated": False,
            "is_valid": True,
        }

        # Check for truncation (very basic)
        if len(image_data) < 100:  # Arbitrary small size
            result["is_truncated"] = True
            result["is_complete"] = False

        # Try to open with PIL to validate
        try:
            img = Image.open(BytesIO(image_data))
            img.verify()
        except Exception:
            result["is_valid"] = False
            result["is_complete"] = False

        return result

    async def get_format_details(self, image_data: bytes, detected_format: str) -> dict:
        """Get detailed format information (stub for tests)."""
        details = {
            "format": detected_format,
            "variant": "",
            "version": "",
        }

        # Detect TIFF endianness
        if detected_format == "tiff":
            if image_data.startswith(b"II"):
                details["variant"] = "little_endian"
            elif image_data.startswith(b"MM"):
                details["variant"] = "big_endian"

        # Detect JPEG type
        elif detected_format == "jpeg":
            if b"\xff\xe0" in image_data[:20]:
                details["variant"] = "jfif"
            elif b"\xff\xe1" in image_data[:20]:
                details["variant"] = "exif"

        return details


# Singleton instance
format_detection_service = FormatDetectionService()
