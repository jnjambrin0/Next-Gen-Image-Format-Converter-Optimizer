"""Unit tests for format detection."""

# Import fixtures
import sys
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.conversion.image_processor import ImageProcessor
from app.core.exceptions import InvalidImageError


class TestFormatDetection:
    """Test suite for image format detection."""

    @pytest.fixture
    def image_processor(self) -> None:
        """Create an ImageProcessor instance."""
        return ImageProcessor()

    def test_detect_jpeg_by_magic_bytes(self, image_processor) -> None:
        """Test JPEG detection by magic bytes."""
        # JPEG magic bytes
        jpeg_data = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        assert image_processor.detect_format(jpeg_data) == "jpeg"

    def test_detect_png_by_magic_bytes(self, image_processor) -> None:
        """Test PNG detection by magic bytes."""
        # PNG magic bytes
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        assert image_processor.detect_format(png_data) == "png"

    def test_detect_webp_by_magic_bytes(self, image_processor) -> None:
        """Test WebP detection by magic bytes."""
        # WebP magic bytes (RIFF + WEBP)
        webp_data = b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"\x00" * 100
        assert image_processor.detect_format(webp_data) == "webp"

    def test_detect_gif_by_magic_bytes(self, image_processor) -> None:
        """Test GIF detection by magic bytes."""
        # GIF87a magic bytes
        gif87_data = b"GIF87a" + b"\x00" * 100
        assert image_processor.detect_format(gif87_data) == "gif"

        # GIF89a magic bytes
        gif89_data = b"GIF89a" + b"\x00" * 100
        assert image_processor.detect_format(gif89_data) == "gif"

    def test_detect_bmp_by_magic_bytes(self, image_processor) -> None:
        """Test BMP detection by magic bytes."""
        # BMP magic bytes
        bmp_data = b"BM" + b"\x00" * 100
        assert image_processor.detect_format(bmp_data) == "bmp"

    def test_detect_tiff_by_magic_bytes(self, image_processor) -> None:
        """Test TIFF detection by magic bytes."""
        # Little-endian TIFF
        tiff_le_data = b"II*\x00" + b"\x00" * 100
        assert image_processor.detect_format(tiff_le_data) == "tiff"

        # Big-endian TIFF
        tiff_be_data = b"MM\x00*" + b"\x00" * 100
        assert image_processor.detect_format(tiff_be_data) == "tiff"

    def test_detect_avif_by_magic_bytes(self, image_processor) -> None:
        """Test AVIF detection by magic bytes."""
        # AVIF with ftyp box
        avif_data = b"\x00\x00\x00\x18" + b"ftyp" + b"avif" + b"\x00" * 100
        assert image_processor.detect_format(avif_data) == "avif"

        # AVIF with avis brand
        avis_data = b"\x00\x00\x00\x18" + b"ftyp" + b"avis" + b"\x00" * 100
        assert image_processor.detect_format(avis_data) == "avif"

    def test_detect_heif_by_magic_bytes(self, image_processor) -> None:
        """Test HEIF/HEIC detection by magic bytes."""
        # HEIC with ftyp box
        heic_data = b"\x00\x00\x00\x18" + b"ftyp" + b"heic" + b"\x00" * 100
        assert image_processor.detect_format(heic_data) == "heif"

        # HEIF with mif1 brand
        mif1_data = b"\x00\x00\x00\x18" + b"ftyp" + b"mif1" + b"\x00" * 100
        assert image_processor.detect_format(mif1_data) == "heif"

    def test_detect_format_fallback_to_pil(self, image_processor) -> None:
        """Test format detection falls back to PIL for real images."""
        # Create a real PNG image
        img = Image.new("RGB", (10, 10), color="red")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        png_data = buffer.getvalue()

        assert image_processor.detect_format(png_data) == "png"

    def test_detect_format_invalid_data(self, image_processor) -> None:
        """Test format detection with invalid data."""
        with pytest.raises(InvalidImageError) as exc_info:
            image_processor.detect_format(b"not an image")
        assert "Failed to detect image format" in str(exc_info.value)

    def test_detect_format_empty_data(self, image_processor) -> None:
        """Test format detection with empty data."""
        with pytest.raises(InvalidImageError):
            image_processor.detect_format(b"")

    def test_detect_format_too_short_data(self, image_processor) -> None:
        """Test format detection with data too short for magic bytes."""
        # Less than 12 bytes - should fall back to PIL and fail
        with pytest.raises(InvalidImageError):
            image_processor.detect_format(b"SHORT")

    def test_detect_format_unknown_magic_bytes(self, image_processor) -> None:
        """Test format detection with unknown magic bytes falls back to PIL."""
        # Unknown magic bytes but might be valid image
        unknown_data = b"XXXX" + b"\x00" * 100

        # This should fall back to PIL and raise an error
        with pytest.raises(InvalidImageError):
            image_processor.detect_format(unknown_data)


class TestMagicByteDetection:
    """Test the private _detect_format_by_magic_bytes method."""

    @pytest.fixture
    def image_processor(self) -> None:
        """Create an ImageProcessor instance."""
        return ImageProcessor()

    def test_magic_byte_detection_priority(self, image_processor) -> None:
        """Test that magic byte detection has priority over PIL."""
        # Create data that looks like JPEG by magic bytes but isn't valid
        fake_jpeg = b"\xff\xd8\xff\xe0" + b"not really a jpeg" * 10

        # Magic byte detection should identify it as JPEG
        # (even though PIL would fail to open it)
        assert image_processor._detect_format_by_magic_bytes(fake_jpeg) == "jpeg"

    def test_magic_byte_detection_returns_none_for_unknown(
        self, image_processor
    ) -> None:
        """Test that magic byte detection returns None for unknown formats."""
        unknown_data = b"UNKNOWN_FORMAT" + b"\x00" * 100
        assert image_processor._detect_format_by_magic_bytes(unknown_data) is None

    def test_magic_byte_detection_short_data(self, image_processor) -> None:
        """Test magic byte detection with data shorter than 12 bytes."""
        short_data = b"ABC"
        assert image_processor._detect_format_by_magic_bytes(short_data) is None
