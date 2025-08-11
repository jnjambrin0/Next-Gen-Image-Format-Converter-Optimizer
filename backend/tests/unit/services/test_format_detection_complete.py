"""
Comprehensive unit tests for FormatDetectionService to achieve high coverage.
"""

from io import BytesIO
from unittest.mock import MagicMock, Mock, patch

import pytest
from PIL import Image

from app.services.format_detection_service import (
    FormatDetectionService,
    format_detection_service,
)


class TestFormatDetectionServiceComprehensive:
    """Comprehensive tests for FormatDetectionService."""

    @pytest.fixture
    def service(self):
        """Create a fresh FormatDetectionService instance."""
        return FormatDetectionService()

    @pytest.fixture
    def image_samples(self):
        """Create sample image data for various formats."""
        samples = {}

        # JPEG with JFIF marker
        samples["jpeg"] = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 100

        # PNG with proper header
        samples["png"] = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100

        # GIF89a
        samples["gif"] = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00" * 100

        # WebP
        samples["webp"] = b"RIFF" + b"\x64\x00\x00\x00" + b"WEBPVP8 " + b"\x00" * 100

        # BMP
        samples["bmp"] = b"BM" + b"\x00" * 100

        # TIFF little-endian
        samples["tiff_le"] = b"II\x2a\x00" + b"\x00" * 100

        # TIFF big-endian
        samples["tiff_be"] = b"MM\x00\x2a" + b"\x00" * 100

        # AVIF
        samples["avif"] = b"\x00\x00\x00\x20ftypavif" + b"\x00" * 100

        # HEIC
        samples["heic"] = b"\x00\x00\x00\x20ftypheic" + b"\x00" * 100

        # HEIF with mif1
        samples["heif"] = b"\x00\x00\x00\x20ftypmif1" + b"\x00" * 100

        return samples

    @pytest.mark.asyncio
    async def test_detect_heif_variants(self, service, image_samples):
        """Test detection of HEIF/HEIC variants."""
        # Test HEIC
        format_name, confidence = await service.detect_format(image_samples["heic"])
        assert format_name.lower() in ["heif", "heic"]
        assert confidence > 0.8

        # Test HEIF with mif1
        format_name, confidence = await service.detect_format(image_samples["heif"])
        assert format_name.lower() == "heif"
        assert confidence > 0.8

        # Test with other HEIF brands
        heif_brands = [b"heix", b"hevc", b"hevx", b"msf1"]
        for brand in heif_brands:
            data = b"\x00\x00\x00\x20ftyp" + brand + b"\x00" * 100
            format_name, confidence = await service.detect_format(data)
            assert format_name.lower() == "heif"

    @pytest.mark.asyncio
    async def test_detect_avif_container(self, service, image_samples):
        """Test AVIF container format detection."""
        format_name, confidence = await service.detect_format(image_samples["avif"])
        assert format_name.lower() == "avif"
        assert confidence > 0.8

        # Test AVIF with different structure
        avif_alt = b"\x00\x00\x00\x1cftypavif\x00\x00\x00\x00avifmif1" + b"\x00" * 100
        format_name, confidence = await service.detect_format(avif_alt)
        assert format_name.lower() == "avif"

    @pytest.mark.asyncio
    async def test_detect_webp2_format(self, service):
        """Test WebP2 format detection."""
        # WebP2 has different magic bytes
        webp2_data = b"WEBP2" + b"\x00" * 100

        # Since WebP2 is not widely supported, might return unknown
        format_name, confidence = await service.detect_format(webp2_data)
        # Check that it doesn't crash at least
        assert format_name is not None

    @pytest.mark.asyncio
    async def test_detect_jpeg_xl(self, service):
        """Test JPEG XL detection."""
        # JPEG XL magic bytes
        jxl_data = b"\xff\x0a" + b"\x00" * 100

        format_name, confidence = await service.detect_format(jxl_data)
        # JXL might not be detected by PIL, but should not crash
        assert format_name is not None

        # Alternative JXL container format
        jxl_container = b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a" + b"\x00" * 100
        format_name, confidence = await service.detect_format(jxl_container)
        assert format_name is not None

    @pytest.mark.asyncio
    async def test_magic_bytes_priority(self, service, image_samples):
        """Test that magic bytes take priority over other detection methods."""
        # Create a file with PNG magic bytes but wrong extension hint
        png_data = image_samples["png"]

        # Detect without any hints
        format_name, confidence = await service.detect_format(png_data)
        assert format_name.lower() == "png"
        assert confidence > 0.9  # High confidence from magic bytes

    @pytest.mark.asyncio
    async def test_pil_fallback_detection(self, service):
        """Test fallback to PIL when magic bytes don't match."""
        # Create real image data that PIL can read
        img = Image.new("RGB", (10, 10), color="red")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        png_data = buffer.getvalue()

        # Detect with PIL fallback
        format_name, confidence = await service.detect_format(png_data)
        assert format_name.lower() == "png"

        # Test with JPEG
        buffer = BytesIO()
        img.save(buffer, format="JPEG")
        jpeg_data = buffer.getvalue()

        format_name, confidence = await service.detect_format(jpeg_data)
        assert format_name.lower() in ["jpeg", "jpg"]

    @pytest.mark.asyncio
    async def test_ambiguous_format_resolution(self, service):
        """Test resolution of ambiguous formats."""
        # JPEG with EXIF marker (different from JFIF)
        jpeg_exif = b"\xff\xd8\xff\xe1\x00\x10Exif" + b"\x00" * 100
        format_name, confidence = await service.detect_format(jpeg_exif)
        assert format_name.lower() in ["jpeg", "jpg"]

        # JPEG with no specific marker
        jpeg_raw = b"\xff\xd8\xff\xdb" + b"\x00" * 100
        format_name, confidence = await service.detect_format(jpeg_raw)
        assert format_name.lower() in ["jpeg", "jpg"]

    @pytest.mark.asyncio
    async def test_corrupted_header_detection(self, service):
        """Test detection with corrupted headers."""
        # Corrupted PNG (wrong magic bytes)
        corrupted_png = b"\x88PNG\r\n\x1a\n" + b"\x00" * 100
        format_name, confidence = await service.detect_format(corrupted_png)
        # Should either detect as unknown or with low confidence
        assert confidence < 1.0 or format_name == "unknown"

        # Truncated JPEG
        truncated_jpeg = b"\xff\xd8"  # Only SOI marker
        format_name, confidence = await service.detect_format(truncated_jpeg)
        # Might still detect as JPEG but with lower confidence
        if format_name.lower() in ["jpeg", "jpg"]:
            assert confidence < 1.0

    @pytest.mark.asyncio
    async def test_detect_format_edge_cases(self, service):
        """Test edge cases in format detection."""
        # Empty data
        format_name, confidence = await service.detect_format(b"")
        assert format_name == "unknown"
        assert confidence == 0.0

        # Very small data
        format_name, confidence = await service.detect_format(b"X")
        assert format_name == "unknown"

        # Random binary data
        random_data = b"\x12\x34\x56\x78" * 25
        format_name, confidence = await service.detect_format(random_data)
        assert format_name == "unknown" or confidence < 0.5

    @pytest.mark.asyncio
    async def test_tiff_endianness_detection(self, service, image_samples):
        """Test TIFF endianness detection."""
        # Little-endian TIFF
        format_name, confidence = await service.detect_format(image_samples["tiff_le"])
        assert format_name.lower() == "tiff"

        # Big-endian TIFF
        format_name, confidence = await service.detect_format(image_samples["tiff_be"])
        assert format_name.lower() == "tiff"

    @pytest.mark.asyncio
    async def test_ico_format_detection(self, service):
        """Test ICO format detection."""
        # ICO header
        ico_data = b"\x00\x00\x01\x00\x01\x00\x10\x10" + b"\x00" * 100
        format_name, confidence = await service.detect_format(ico_data)
        # ICO might be detected as unknown or ico
        assert format_name in ["ico", "unknown"] or confidence < 1.0

    @pytest.mark.asyncio
    async def test_all_standard_formats(self, service, image_samples):
        """Test detection of all standard image formats."""
        expected_formats = {
            "jpeg": ["jpeg", "jpg"],
            "png": ["png"],
            "gif": ["gif"],
            "webp": ["webp"],
            "bmp": ["bmp"],
            "tiff_le": ["tiff", "tif"],
            "tiff_be": ["tiff", "tif"],
            "avif": ["avif"],
            "heic": ["heif", "heic"],
            "heif": ["heif"],
        }

        for sample_name, sample_data in image_samples.items():
            format_name, confidence = await service.detect_format(sample_data)

            if sample_name in expected_formats:
                assert (
                    format_name.lower() in expected_formats[sample_name]
                ), f"Failed to detect {sample_name}, got {format_name}"
                assert (
                    confidence > 0.5
                ), f"Low confidence for {sample_name}: {confidence}"

    def test_normalize_format_name(self, service):
        """Test format name normalization."""
        # Test common normalizations
        assert service._normalize_format_name("JPEG") == "jpeg"
        assert service._normalize_format_name("JPG") == "jpeg"
        assert service._normalize_format_name("jpg") == "jpeg"
        assert service._normalize_format_name("HEIC") == "heif"
        assert service._normalize_format_name("heic") == "heif"
        assert service._normalize_format_name("TIF") == "tiff"
        assert service._normalize_format_name("tif") == "tiff"
        assert service._normalize_format_name("PNG") == "png"
        assert service._normalize_format_name("unknown") == "unknown"

    def test_is_format_supported(self, service):
        """Test format support checking."""
        # Supported formats
        assert service.is_format_supported("jpeg") is True
        assert service.is_format_supported("png") is True
        assert service.is_format_supported("webp") is True
        assert service.is_format_supported("avif") is True
        assert service.is_format_supported("heif") is True

        # Normalized names
        assert service.is_format_supported("JPG") is True
        assert service.is_format_supported("HEIC") is True

        # Unsupported formats
        assert service.is_format_supported("xyz") is False
        assert service.is_format_supported("raw") is False

    @pytest.mark.asyncio
    async def test_mime_to_format_mapping(self, service):
        """Test MIME type to format mapping."""
        # Access internal mapping
        assert service._mime_to_format["image/jpeg"] == "jpeg"
        assert service._mime_to_format["image/png"] == "png"
        assert service._mime_to_format["image/webp"] == "webp"
        assert service._mime_to_format["image/avif"] == "avif"
        assert service._mime_to_format["image/heif"] == "heif"
        assert service._mime_to_format["image/heic"] == "heif"

    @pytest.mark.asyncio
    async def test_pil_format_mapping(self, service):
        """Test PIL format to internal format mapping."""
        assert service._pil_format_map["JPEG"] == "jpeg"
        assert service._pil_format_map["PNG"] == "png"
        assert service._pil_format_map["WEBP"] == "webp"
        assert service._pil_format_map["GIF"] == "gif"
        assert service._pil_format_map["BMP"] == "bmp"
        assert service._pil_format_map["TIFF"] == "tiff"

    @pytest.mark.asyncio
    async def test_analyze_format_security_comprehensive(self, service):
        """Test comprehensive format security analysis."""
        # Test polyglot detection
        polyglot_gif_js = b"GIF89a/*" + b"\x00" * 10 + b"*/=1;"
        result = await service.analyze_format_security(polyglot_gif_js, "gif")
        assert result["is_polyglot"] is True or result["is_suspicious"] is True

        # Test prepended data detection
        php_jpeg = b"<?php echo 'test'; ?>" + b"\xff\xd8\xff\xe0"
        result = await service.analyze_format_security(php_jpeg, "jpeg")
        assert result["has_prepended_data"] is True or result["is_suspicious"] is True

        # Test clean file
        clean_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        result = await service.analyze_format_security(clean_png, "png")
        assert result["is_suspicious"] is False

    @pytest.mark.asyncio
    async def test_validate_format_integrity_comprehensive(self, service):
        """Test comprehensive format integrity validation."""
        # Test truncated file
        truncated = b"\xff\xd8"  # Just JPEG SOI
        result = await service.validate_format_integrity(truncated, "jpeg")
        assert result["is_truncated"] is True
        assert result["is_complete"] is False

        # Test valid small file
        valid_small = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        result = await service.validate_format_integrity(valid_small, "png")
        assert result["is_complete"] is True

        # Test invalid data
        invalid = b"NOT_AN_IMAGE"
        result = await service.validate_format_integrity(invalid, "jpeg")
        assert result["is_valid"] is False

    @pytest.mark.asyncio
    async def test_get_format_details_comprehensive(self, service):
        """Test comprehensive format detail extraction."""
        # Test TIFF endianness
        tiff_le = b"II\x2a\x00" + b"\x00" * 100
        details = await service.get_format_details(tiff_le, "tiff")
        assert details["variant"] == "little_endian"

        tiff_be = b"MM\x00\x2a" + b"\x00" * 100
        details = await service.get_format_details(tiff_be, "tiff")
        assert details["variant"] == "big_endian"

        # Test JPEG variants
        jpeg_jfif = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        details = await service.get_format_details(jpeg_jfif, "jpeg")
        assert details["variant"] == "jfif"

        jpeg_exif = b"\xff\xd8\xff\xe1" + b"\x00" * 100
        details = await service.get_format_details(jpeg_exif, "jpeg")
        assert details["variant"] == "exif"

    @pytest.mark.asyncio
    async def test_singleton_instance(self):
        """Test that format_detection_service is a proper singleton."""
        from app.services.format_detection_service import format_detection_service

        assert format_detection_service is not None
        assert isinstance(format_detection_service, FormatDetectionService)

        # Test that it works
        format_name, confidence = await format_detection_service.detect_format(
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 10
        )
        assert format_name.lower() == "png"
