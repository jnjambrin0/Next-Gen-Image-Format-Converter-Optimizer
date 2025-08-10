"""Core image processing operations."""

import io
from typing import Any, Optional

import structlog
from PIL import Image

from app.core.exceptions import (
    ConversionFailedError,
    InvalidImageError,
)

logger = structlog.get_logger()


class ImageProcessor:
    """Handles core image processing operations."""

    # Maximum image dimensions to prevent memory issues
    MAX_DIMENSION = 10000
    MAX_PIXELS = 100_000_000  # 100 megapixels

    def validate_image_data(self, image_data: bytes) -> bool:
        """
        Validate that the image data is valid and safe to process.

        Args:
            image_data: Raw image bytes

        Returns:
            True if valid, raises exception otherwise
        """
        if not image_data:
            raise InvalidImageError("Empty image data")

        # Try to open image to validate
        try:
            with io.BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    # Verify image
                    img.verify()

                    # Reopen after verify (verify closes the file)
                    buffer.seek(0)
                    with Image.open(buffer) as img:
                        # Check dimensions
                        if (
                            img.width > self.MAX_DIMENSION
                            or img.height > self.MAX_DIMENSION
                        ):
                            raise InvalidImageError(
                                f"Image dimensions exceed maximum allowed ({self.MAX_DIMENSION}x{self.MAX_DIMENSION})",
                                details={
                                    "width": img.width,
                                    "height": img.height,
                                    "max_dimension": self.MAX_DIMENSION,
                                },
                            )

                        # Check total pixels
                        total_pixels = img.width * img.height
                        if total_pixels > self.MAX_PIXELS:
                            raise InvalidImageError(
                                f"Image size exceeds maximum allowed pixels ({self.MAX_PIXELS})",
                                details={
                                    "total_pixels": total_pixels,
                                    "max_pixels": self.MAX_PIXELS,
                                },
                            )

                        return True

        except InvalidImageError:
            raise
        except Exception as e:
            raise InvalidImageError(
                f"Invalid image data: {str(e)}", details={"error": str(e)}
            )

    def detect_format(self, image_data: bytes) -> str:
        """
        Detect image format from data.

        Args:
            image_data: Raw image bytes

        Returns:
            Format name (lowercase)
        """
        # First try magic byte detection for better accuracy
        detected_format = self._detect_format_by_magic_bytes(image_data)
        if detected_format:
            return detected_format.lower()

        # Fall back to PIL detection
        try:
            with io.BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    format_name = img.format
                    if format_name:
                        return format_name.lower()
                    else:
                        raise InvalidImageError("Could not detect image format")
        except Exception as e:
            raise InvalidImageError(
                f"Failed to detect image format: {str(e)}", details={"error": str(e)}
            )

    def _detect_format_by_magic_bytes(self, data: bytes) -> Optional[str]:
        """Detect format by checking magic bytes."""
        if len(data) < 12:
            return None

        # Check common formats first (most likely)
        if data[0:2] == b"\xff\xd8":
            return "jpeg"
        elif data[0:8] == b"\x89PNG\r\n\x1a\n":
            return "png"
        elif data[0:4] == b"RIFF" and len(data) > 12 and data[8:12] == b"WEBP":
            return "webp"
        elif data[0:6] in (b"GIF87a", b"GIF89a"):
            return "gif"
        elif data[0:2] == b"BM":
            return "bmp"
        elif data[0:4] in (b"II*\x00", b"MM\x00*"):
            return "tiff"

        # Check HEIF/AVIF (both use ftyp box)
        if len(data) > 12 and data[4:8] == b"ftyp":
            brand = data[8:12]
            if brand in (b"avif", b"avis"):
                return "avif"
            elif brand in (b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"):
                return "heif"

        return None

    def get_image_info(self, image_data: bytes) -> dict:
        """
        Get basic image information.

        Args:
            image_data: Raw image bytes

        Returns:
            Dictionary with image info
        """
        try:
            with io.BytesIO(image_data) as buffer:
                with Image.open(buffer) as img:
                    info = {
                        "format": img.format,
                        "mode": img.mode,
                        "width": img.width,
                        "height": img.height,
                        "has_transparency": img.mode in ("RGBA", "LA", "P")
                        and "transparency" in img.info,
                        "has_animation": hasattr(img, "is_animated")
                        and img.is_animated,
                    }

                    # Add EXIF info if present using public API
                    try:
                        exif = None
                        if hasattr(img, "getexif"):
                            exif = img.getexif()
                        elif hasattr(img, "_getexif"):
                            # Fallback to private method if public not available
                            exif = img._getexif()

                        if exif:
                            info["has_exif"] = True
                            info["exif_tags"] = len(exif)
                        else:
                            info["has_exif"] = False
                    except Exception:
                        info["has_exif"] = False

                    return info

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to get image info: {str(e)}", details={"error": str(e)}
            )

    def estimate_memory_usage(self, width: int, height: int, mode: str = "RGB") -> int:
        """
        Estimate memory usage for an image.

        Args:
            width: Image width
            height: Image height
            mode: Color mode (RGB, RGBA, etc.)

        Returns:
            Estimated memory usage in bytes
        """
        # Bytes per pixel based on mode
        bytes_per_pixel = {
            "1": 1,  # 1-bit pixels
            "L": 1,  # 8-bit grayscale
            "P": 1,  # 8-bit palette
            "RGB": 3,  # 24-bit RGB
            "RGBA": 4,  # 32-bit RGBA
            "CMYK": 4,  # 32-bit CMYK
            "YCbCr": 3,  # 24-bit YCbCr
            "LAB": 3,  # 24-bit LAB
            "HSV": 3,  # 24-bit HSV
            "I": 4,  # 32-bit integer
            "F": 4,  # 32-bit float
        }.get(
            mode, 4
        )  # Default to 4 bytes if unknown

        # Calculate base memory
        base_memory = width * height * bytes_per_pixel

        # Add overhead (approximately 20% for PIL structures)
        overhead = int(base_memory * 0.2)

        return base_memory + overhead

    def strip_metadata(self, image: Image.Image) -> Image.Image:
        """
        Strip all metadata from image.

        Args:
            image: PIL Image object

        Returns:
            Image without metadata
        """
        # Create a new image without metadata
        data = list(image.getdata())
        image_without_metadata = Image.new(image.mode, image.size)
        image_without_metadata.putdata(data)

        # Preserve some essential info
        if "transparency" in image.info:
            image_without_metadata.info["transparency"] = image.info["transparency"]

        return image_without_metadata

    def optimize_for_web(
        self, image: Image.Image, max_width: int = 2048, max_height: int = 2048
    ) -> Image.Image:
        """
        Optimize image for web display.

        Args:
            image: PIL Image object
            max_width: Maximum width
            max_height: Maximum height

        Returns:
            Optimized image
        """
        # Resize if needed
        if image.width > max_width or image.height > max_height:
            image.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)

        # Convert CMYK to RGB
        if image.mode == "CMYK":
            image = image.convert("RGB")

        return image
