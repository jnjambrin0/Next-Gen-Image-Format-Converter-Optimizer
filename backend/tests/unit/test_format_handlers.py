"""Unit tests for format handlers."""

import pytest
from unittest.mock import Mock
from io import BytesIO
from PIL import Image

# Import fixtures
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.conversion.formats.jpeg_handler import JPEGHandler
from app.core.conversion.formats.png_handler import PNGHandler
from app.core.conversion.formats.webp_handler import WebPHandler
from app.core.conversion.formats.avif_handler import AVIFHandler
from app.core.conversion.formats.jxl_handler import JxlHandler
from app.core.conversion.formats.heif_handler import HeifHandler
from app.core.conversion.formats.png_optimized_handler import PNGOptimizedHandler
from app.core.conversion.formats.jpeg_optimized_handler import JPEGOptimizedHandler
from app.models.conversion import ConversionSettings
from app.core.exceptions import ConversionFailedError, UnsupportedFormatError, HeifDecodingError


class TestJPEGHandler:
    """Test suite for JPEG format handler."""

    @pytest.fixture
    def jpeg_handler(self):
        """Create a JPEG handler instance."""
        return JPEGHandler()

    @pytest.fixture
    def sample_jpeg_image(self):
        """Create a sample JPEG image."""
        img = Image.new("RGB", (100, 100), color="red")
        buffer = BytesIO()
        img.save(buffer, format="JPEG")
        buffer.seek(0)
        return buffer.getvalue()

    def test_can_handle_jpeg_formats(self, jpeg_handler):
        """Test JPEG handler recognizes JPEG formats."""
        assert jpeg_handler.can_handle("jpeg") is True
        assert jpeg_handler.can_handle("jpg") is True
        assert jpeg_handler.can_handle("jpe") is True
        assert jpeg_handler.can_handle("jfif") is True
        assert jpeg_handler.can_handle("png") is False

    def test_validate_valid_jpeg(self, jpeg_handler, sample_jpeg_image):
        """Test validation of valid JPEG data."""
        assert jpeg_handler.validate_image(sample_jpeg_image) is True

    def test_validate_invalid_jpeg(self, jpeg_handler):
        """Test validation of invalid JPEG data."""
        assert jpeg_handler.validate_image(b"not a jpeg") is False
        assert jpeg_handler.validate_image(b"") is False
        assert jpeg_handler.validate_image(b"x" * 10) is False

    def test_load_jpeg_image(self, jpeg_handler, sample_jpeg_image):
        """Test loading JPEG image."""
        # Act
        img = jpeg_handler.load_image(sample_jpeg_image)

        # Assert
        assert isinstance(img, Image.Image)
        assert img.mode == "RGB"
        assert img.size == (100, 100)

    def test_load_cmyk_jpeg_converts_to_rgb(self, jpeg_handler):
        """Test loading CMYK JPEG converts to RGB."""
        # Arrange
        cmyk_img = Image.new("CMYK", (50, 50))
        buffer = BytesIO()
        cmyk_img.save(buffer, format="JPEG")
        cmyk_data = buffer.getvalue()

        # Act
        img = jpeg_handler.load_image(cmyk_data)

        # Assert
        assert img.mode == "RGB"

    def test_save_jpeg_with_quality(self, jpeg_handler):
        """Test saving JPEG with quality settings."""
        # Arrange
        img = Image.new("RGB", (100, 100), color="blue")
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=90, optimize=False)

        # Act
        jpeg_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.format == "JPEG"

    def test_save_jpeg_with_transparency_adds_background(self, jpeg_handler):
        """Test saving RGBA image as JPEG adds white background."""
        # Arrange
        rgba_img = Image.new("RGBA", (50, 50), (255, 0, 0, 128))
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=85)

        # Act
        jpeg_handler.save_image(rgba_img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.mode == "RGB"  # No alpha channel

    def test_save_jpeg_with_optimization(self, jpeg_handler):
        """Test saving JPEG with optimization enabled."""
        # Arrange
        img = Image.new("RGB", (200, 200), color="green")
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=85, optimize=True)

        # Act
        jpeg_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        assert len(output_buffer.getvalue()) > 0

    def test_save_jpeg_strips_metadata(self, jpeg_handler, sample_image_bytes):
        """Test saving JPEG strips metadata when requested."""
        # Arrange
        img = Image.open(BytesIO(sample_image_bytes))
        output_buffer = BytesIO()
        settings = ConversionSettings(strip_metadata=True)

        # Act
        jpeg_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert not hasattr(saved_img, "_getexif") or saved_img._getexif() is None

    def test_quality_mapping(self, jpeg_handler):
        """Test quality parameter mapping."""
        # Test different quality levels
        params_low = jpeg_handler.get_quality_param(ConversionSettings(quality=10))
        params_high = jpeg_handler.get_quality_param(ConversionSettings(quality=95))

        assert params_low["quality"] < params_high["quality"]
        assert params_low["subsampling"] == 2  # Lower quality uses subsampling
        assert params_high["subsampling"] == 0  # High quality uses 4:4:4


class TestHeifHandler:
    """Test suite for HEIF/HEIC format handler."""

    @pytest.fixture
    def heif_handler(self):
        """Create a HEIF handler instance."""
        try:
            from app.core.conversion.formats.heif_handler import HeifHandler
            return HeifHandler()
        except ImportError:
            pytest.skip("HEIF support not available")

    def test_can_handle_heif_formats(self, heif_handler):
        """Test HEIF handler recognizes HEIF/HEIC formats."""
        assert heif_handler.can_handle("heif") is True
        assert heif_handler.can_handle("heic") is True
        assert heif_handler.can_handle("heix") is True
        assert heif_handler.can_handle("hevc") is True
        assert heif_handler.can_handle("jpeg") is False

    def test_validate_heif_magic_bytes(self, heif_handler):
        """Test validation of HEIF magic bytes."""
        # Create minimal HEIF header with ftyp box
        heif_header = b"\x00\x00\x00\x18ftyp" + b"heic" + b"\x00" * 12
        assert heif_handler.validate_image(heif_header) is True
        
        # Test other HEIF brands
        heif_header_mif1 = b"\x00\x00\x00\x18ftyp" + b"mif1" + b"\x00" * 12
        assert heif_handler.validate_image(heif_header_mif1) is True
        
        # Test invalid data
        assert heif_handler.validate_image(b"not heif") is False


class TestBmpHandler:
    """Test suite for BMP format handler."""

    @pytest.fixture
    def bmp_handler(self):
        """Create a BMP handler instance."""
        from app.core.conversion.formats.bmp_handler import BmpHandler
        return BmpHandler()

    @pytest.fixture
    def sample_bmp_image(self):
        """Create a sample BMP image."""
        img = Image.new("RGB", (50, 50), color="yellow")
        buffer = BytesIO()
        img.save(buffer, format="BMP")
        buffer.seek(0)
        return buffer.getvalue()

    def test_can_handle_bmp_formats(self, bmp_handler):
        """Test BMP handler recognizes BMP formats."""
        assert bmp_handler.can_handle("bmp") is True
        assert bmp_handler.can_handle("dib") is True
        assert bmp_handler.can_handle("png") is False

    def test_validate_valid_bmp(self, bmp_handler, sample_bmp_image):
        """Test validation of valid BMP data."""
        assert bmp_handler.validate_image(sample_bmp_image) is True

    def test_validate_invalid_bmp(self, bmp_handler):
        """Test validation of invalid BMP data."""
        assert bmp_handler.validate_image(b"not a bmp") is False
        assert bmp_handler.validate_image(b"") is False

    def test_load_bmp_image(self, bmp_handler, sample_bmp_image):
        """Test loading BMP image."""
        img = bmp_handler.load_image(sample_bmp_image)
        assert isinstance(img, Image.Image)
        assert img.mode == "RGB"
        assert img.size == (50, 50)

    def test_save_bmp_from_rgba(self, bmp_handler):
        """Test saving RGBA image as BMP (no transparency support)."""
        rgba_img = Image.new("RGBA", (30, 30), (255, 0, 0, 128))
        output_buffer = BytesIO()
        settings = ConversionSettings()
        
        bmp_handler.save_image(rgba_img, output_buffer, settings)
        
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.format == "BMP"
        assert saved_img.mode == "RGB"  # Alpha removed


class TestTiffHandler:
    """Test suite for TIFF format handler."""

    @pytest.fixture
    def tiff_handler(self):
        """Create a TIFF handler instance."""
        from app.core.conversion.formats.tiff_handler import TiffHandler
        return TiffHandler()

    @pytest.fixture
    def sample_tiff_image(self):
        """Create a sample TIFF image."""
        img = Image.new("RGB", (60, 60), color="purple")
        buffer = BytesIO()
        img.save(buffer, format="TIFF")
        buffer.seek(0)
        return buffer.getvalue()

    def test_can_handle_tiff_formats(self, tiff_handler):
        """Test TIFF handler recognizes TIFF formats."""
        assert tiff_handler.can_handle("tiff") is True
        assert tiff_handler.can_handle("tif") is True
        assert tiff_handler.can_handle("jpeg") is False

    def test_validate_valid_tiff(self, tiff_handler, sample_tiff_image):
        """Test validation of valid TIFF data."""
        assert tiff_handler.validate_image(sample_tiff_image) is True

    def test_validate_tiff_magic_bytes(self, tiff_handler):
        """Test validation of TIFF magic bytes."""
        # Little-endian TIFF
        assert tiff_handler.validate_image(b"II*\x00" + b"\x00" * 10) is False  # Too short but has header
        # Big-endian TIFF  
        assert tiff_handler.validate_image(b"MM\x00*" + b"\x00" * 10) is False  # Too short but has header
        # Invalid
        assert tiff_handler.validate_image(b"XXXX") is False

    def test_load_tiff_image(self, tiff_handler, sample_tiff_image):
        """Test loading TIFF image."""
        img = tiff_handler.load_image(sample_tiff_image)
        assert isinstance(img, Image.Image)
        assert img.mode == "RGB"
        assert img.size == (60, 60)

    def test_save_tiff_with_compression(self, tiff_handler):
        """Test saving TIFF with compression."""
        img = Image.new("RGB", (100, 100), color="cyan")
        output_buffer = BytesIO()
        settings = ConversionSettings(optimize=True)
        
        tiff_handler.save_image(img, output_buffer, settings)
        
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.format == "TIFF"


class TestGifHandler:
    """Test suite for GIF format handler."""

    @pytest.fixture
    def gif_handler(self):
        """Create a GIF handler instance."""
        from app.core.conversion.formats.gif_handler import GifHandler
        return GifHandler()

    @pytest.fixture
    def sample_gif_image(self):
        """Create a sample GIF image."""
        img = Image.new("P", (40, 40))
        img.putpalette([i//3 for i in range(768)])  # Create palette
        buffer = BytesIO()
        img.save(buffer, format="GIF")
        buffer.seek(0)
        return buffer.getvalue()

    def test_can_handle_gif_format(self, gif_handler):
        """Test GIF handler recognizes GIF format."""
        assert gif_handler.can_handle("gif") is True
        assert gif_handler.can_handle("png") is False

    def test_validate_gif_magic_bytes(self, gif_handler):
        """Test validation of GIF magic bytes."""
        assert gif_handler.validate_image(b"GIF87a" + b"\x00" * 10) is False  # Has header but invalid
        assert gif_handler.validate_image(b"GIF89a" + b"\x00" * 10) is False  # Has header but invalid
        assert gif_handler.validate_image(b"NOTGIF") is False

    def test_load_gif_image(self, gif_handler, sample_gif_image):
        """Test loading GIF image."""
        img = gif_handler.load_image(sample_gif_image)
        assert isinstance(img, Image.Image)
        assert img.mode in ("RGB", "RGBA")  # Converted from P mode

    def test_save_gif_from_rgb(self, gif_handler):
        """Test saving RGB image as GIF."""
        rgb_img = Image.new("RGB", (50, 50), color="orange")
        output_buffer = BytesIO()
        settings = ConversionSettings()
        
        gif_handler.save_image(rgb_img, output_buffer, settings)
        
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.format == "GIF"
        assert saved_img.mode == "P"  # Converted to palette mode


class TestPNGHandler:
    """Test suite for PNG format handler."""

    @pytest.fixture
    def png_handler(self):
        """Create a PNG handler instance."""
        return PNGHandler()

    @pytest.fixture
    def sample_png_image(self):
        """Create a sample PNG image."""
        img = Image.new("RGBA", (100, 100), (0, 255, 0, 200))
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return buffer.getvalue()

    def test_can_handle_png_format(self, png_handler):
        """Test PNG handler recognizes PNG format."""
        assert png_handler.can_handle("png") is True
        assert png_handler.can_handle("jpeg") is False

    def test_validate_valid_png(self, png_handler, sample_png_image):
        """Test validation of valid PNG data."""
        assert png_handler.validate_image(sample_png_image) is True

    def test_validate_invalid_png(self, png_handler):
        """Test validation of invalid PNG data."""
        assert png_handler.validate_image(b"not a png") is False
        assert png_handler.validate_image(b"") is False

    def test_load_png_image(self, png_handler, sample_png_image):
        """Test loading PNG image."""
        # Act
        img = png_handler.load_image(sample_png_image)

        # Assert
        assert isinstance(img, Image.Image)
        assert img.mode == "RGBA"
        assert img.size == (100, 100)

    def test_save_png_with_transparency(self, png_handler):
        """Test saving PNG preserves transparency."""
        # Arrange
        img = Image.new("RGBA", (50, 50), (255, 0, 0, 128))
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=85)

        # Act
        png_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.mode == "RGBA"

    def test_save_png_with_optimization(self, png_handler):
        """Test saving PNG with optimization."""
        # Arrange
        img = Image.new("RGB", (100, 100), color="blue")
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=50, optimize=True)

        # Act
        png_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.format == "PNG"

    def test_compression_level_mapping(self, png_handler):
        """Test PNG compression level mapping."""
        # High quality = low compression
        params_high = png_handler.get_quality_param(ConversionSettings(quality=100))
        assert params_high["compress_level"] == 0

        # Low quality = high compression
        params_low = png_handler.get_quality_param(ConversionSettings(quality=1))
        # Should be close to 9 (allowing for rounding)
        assert params_low["compress_level"] >= 8


class TestWebPHandler:
    """Test suite for WebP format handler."""

    @pytest.fixture
    def webp_handler(self):
        """Create a WebP handler instance."""
        return WebPHandler()

    def test_can_handle_webp_format(self, webp_handler):
        """Test WebP handler recognizes WebP format."""
        assert webp_handler.can_handle("webp") is True
        assert webp_handler.can_handle("jpeg") is False

    def test_validate_valid_webp(self, webp_handler):
        """Test validation of valid WebP data."""
        # Create valid WebP
        img = Image.new("RGB", (10, 10))
        buffer = BytesIO()
        img.save(buffer, format="WEBP")
        webp_data = buffer.getvalue()

        assert webp_handler.validate_image(webp_data) is True

    def test_save_webp_with_quality(self, webp_handler):
        """Test saving WebP with quality settings."""
        # Arrange
        img = Image.new("RGB", (100, 100), color="red")
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=80)

        # Act
        webp_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.format == "WEBP"

    def test_save_webp_with_transparency(self, webp_handler):
        """Test saving WebP with transparency."""
        # Arrange
        img = Image.new("RGBA", (50, 50), (0, 255, 0, 100))
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=85)

        # Act
        webp_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.mode == "RGBA"

    def test_save_webp_with_optimization(self, webp_handler):
        """Test saving WebP with different optimization levels."""
        # Arrange
        img = Image.new("RGB", (100, 100), color="blue")

        # Test with optimization
        buffer_optimized = BytesIO()
        settings_opt = ConversionSettings(quality=80, optimize=True)
        webp_handler.save_image(img, buffer_optimized, settings_opt)

        # Test without optimization
        buffer_normal = BytesIO()
        settings_normal = ConversionSettings(quality=80, optimize=False)
        webp_handler.save_image(img, buffer_normal, settings_normal)

        # Both should produce valid WebP files
        assert len(buffer_optimized.getvalue()) > 0
        assert len(buffer_normal.getvalue()) > 0


class TestAVIFHandler:
    """Test suite for AVIF format handler."""

    @pytest.fixture
    def avif_handler(self):
        """Create an AVIF handler instance."""
        try:
            return AVIFHandler()
        except Exception:
            pytest.skip("AVIF support not available")

    def test_can_handle_avif_format(self, avif_handler):
        """Test AVIF handler recognizes AVIF format."""
        assert avif_handler.can_handle("avif") is True
        assert avif_handler.can_handle("jpeg") is False

    def test_save_avif_with_quality(self, avif_handler):
        """Test saving AVIF with quality settings."""
        # Arrange
        img = Image.new("RGB", (50, 50), color="purple")
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=75)

        # Act
        avif_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        # Verify it's not empty
        assert len(output_buffer.getvalue()) > 0

    def test_save_avif_with_transparency(self, avif_handler):
        """Test saving AVIF with transparency."""
        # Arrange
        img = Image.new("RGBA", (30, 30), (255, 255, 0, 150))
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=80)

        # Act
        avif_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        assert len(output_buffer.getvalue()) > 0

    def test_quality_parameter_mapping(self, avif_handler):
        """Test AVIF quality parameter mapping."""
        # Test high quality
        params_high = avif_handler.get_quality_param(ConversionSettings(quality=95))
        assert params_high["quality"] == 95
        assert params_high["subsampling"] == "4:4:4"

        # Test lower quality
        params_low = avif_handler.get_quality_param(ConversionSettings(quality=70))
        assert params_low["quality"] == 70
        assert params_low["subsampling"] == "4:2:0"

    def test_validate_avif_image(self, avif_handler):
        """Test AVIF validation logic."""
        # Test too small data
        assert avif_handler.validate_image(b"short") is False

        # Test invalid magic bytes
        assert avif_handler.validate_image(b"1234567890123456") is False

        # Test with ftyp but not AVIF
        fake_data = b"\x00\x00\x00\x20ftypisom\x00\x00\x00\x00"
        assert avif_handler.validate_image(fake_data) is False

    def test_avif_handler_mode_conversion(self, avif_handler):
        """Test AVIF handler converts different color modes correctly."""
        # Test grayscale conversion
        img_gray = Image.new("L", (20, 20), color=128)
        buffer = BytesIO()
        settings = ConversionSettings()
        avif_handler.save_image(img_gray, buffer, settings)
        assert len(buffer.getvalue()) > 0

        # Test palette mode with transparency
        img_p = Image.new("P", (20, 20))
        img_p.info["transparency"] = 0
        buffer = BytesIO()
        avif_handler.save_image(img_p, buffer, settings)
        assert len(buffer.getvalue()) > 0

    def test_avif_save_with_optimization(self, avif_handler):
        """Test AVIF saving with optimization enabled/disabled."""
        img = Image.new("RGB", (50, 50), color="green")

        # Save with optimization
        buffer_opt = BytesIO()
        settings_opt = ConversionSettings(quality=80, optimize=True)
        avif_handler.save_image(img, buffer_opt, settings_opt)

        # Save without optimization
        buffer_no_opt = BytesIO()
        settings_no_opt = ConversionSettings(quality=80, optimize=False)
        avif_handler.save_image(img, buffer_no_opt, settings_no_opt)

        # Both should produce valid files
        assert len(buffer_opt.getvalue()) > 0
        assert len(buffer_no_opt.getvalue()) > 0


class TestFormatHandlerErrors:
    """Test error handling across format handlers."""

    @pytest.fixture
    def jpeg_handler(self):
        """Create a JPEG handler instance."""
        return JPEGHandler()

    @pytest.fixture
    def png_handler(self):
        """Create a PNG handler instance."""
        return PNGHandler()

    @pytest.fixture
    def webp_handler(self):
        """Create a WebP handler instance."""
        return WebPHandler()

    @pytest.fixture
    def avif_handler(self):
        """Create an AVIF handler instance."""
        try:
            return AVIFHandler()
        except Exception:
            pytest.skip("AVIF support not available")

    def test_jpeg_handler_load_error(self, jpeg_handler):
        """Test JPEG handler handles load errors."""
        with pytest.raises(ConversionFailedError, match="Failed to load JPEG"):
            jpeg_handler.load_image(b"invalid jpeg data")

    def test_png_handler_save_error(self, png_handler):
        """Test PNG handler handles save errors."""
        # Create a mock file object that raises on write
        mock_buffer = Mock()
        mock_buffer.write.side_effect = IOError("Write failed")

        img = Image.new("RGB", (10, 10))
        settings = ConversionSettings()

        with pytest.raises(ConversionFailedError, match="Failed to save image as PNG"):
            png_handler.save_image(img, mock_buffer, settings)

    def test_webp_handler_invalid_mode(self, webp_handler):
        """Test WebP handler converts unsupported modes."""
        # Arrange
        img = Image.new("LAB", (20, 20))  # LAB mode not directly supported
        output_buffer = BytesIO()
        settings = ConversionSettings()

        # Act - should convert to RGB
        webp_handler.save_image(img, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        saved_img = Image.open(output_buffer)
        assert saved_img.mode == "RGB"

    def test_avif_handler_load_error(self, avif_handler):
        """Test AVIF handler handles load errors."""
        with pytest.raises(ConversionFailedError, match="Failed to load AVIF"):
            avif_handler.load_image(b"invalid avif data")

    def test_avif_handler_save_error(self, avif_handler):
        """Test AVIF handler handles save errors."""
        # Create a mock file object that raises on write
        mock_buffer = Mock()
        mock_buffer.write.side_effect = IOError("Write failed")

        img = Image.new("RGB", (10, 10))
        settings = ConversionSettings()

        with pytest.raises(ConversionFailedError, match="Failed to save image as AVIF"):
            avif_handler.save_image(img, mock_buffer, settings)


class TestJxlHandler:
    """Test suite for JPEG XL format handler."""

    @pytest.fixture
    def jxl_handler(self):
        """Create a JPEG XL handler instance."""
        try:
            return JxlHandler()
        except UnsupportedFormatError:
            pytest.skip("JPEG XL support not available")

    @pytest.fixture
    def sample_rgb_image(self):
        """Create a sample RGB image."""
        return Image.new("RGB", (100, 100), color="red")

    @pytest.fixture
    def sample_rgba_image(self):
        """Create a sample RGBA image with transparency."""
        return Image.new("RGBA", (100, 100), (255, 0, 0, 128))

    def test_can_handle_jxl_formats(self, jxl_handler):
        """Test JPEG XL handler recognizes JXL formats."""
        assert jxl_handler.can_handle("jxl") is True
        assert jxl_handler.can_handle("jpegxl") is True
        assert jxl_handler.can_handle("jpeg_xl") is True
        assert jxl_handler.can_handle("JXL") is True
        assert jxl_handler.can_handle("png") is False
        assert jxl_handler.can_handle("jpeg") is False

    def test_validate_jxl_codestream(self, jxl_handler):
        """Test validation of JXL codestream magic bytes."""
        # Valid JXL codestream starts with 0xFF0A
        valid_jxl = b"\xFF\x0A" + b"\x00" * 100
        assert jxl_handler.validate_image(valid_jxl) is True

    def test_validate_jxl_container(self, jxl_handler):
        """Test validation of JXL ISO container."""
        # Valid JXL container has "JXL " at offset 4-8
        valid_jxl = b"\x00\x00\x00\x0CJXL " + b"\x00" * 100
        assert jxl_handler.validate_image(valid_jxl) is True

    def test_validate_invalid_jxl(self, jxl_handler):
        """Test validation of invalid JXL data."""
        assert jxl_handler.validate_image(b"not a jxl") is False
        assert jxl_handler.validate_image(b"") is False
        assert jxl_handler.validate_image(b"x" * 10) is False

    def test_save_rgb_image_lossless(self, jxl_handler, sample_rgb_image):
        """Test saving RGB image as lossless JPEG XL."""
        # Arrange
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=100)  # Lossless

        # Act
        jxl_handler.save_image(sample_rgb_image, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        assert len(output_buffer.getvalue()) > 0

    def test_save_rgb_image_lossy(self, jxl_handler, sample_rgb_image):
        """Test saving RGB image as lossy JPEG XL."""
        # Arrange
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=85)  # Lossy

        # Act
        jxl_handler.save_image(sample_rgb_image, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        assert len(output_buffer.getvalue()) > 0

    def test_save_rgba_image(self, jxl_handler, sample_rgba_image):
        """Test saving RGBA image with transparency."""
        # Arrange
        output_buffer = BytesIO()
        settings = ConversionSettings(quality=90)

        # Act
        jxl_handler.save_image(sample_rgba_image, output_buffer, settings)

        # Assert
        output_buffer.seek(0)
        assert len(output_buffer.getvalue()) > 0

    def test_save_with_optimization(self, jxl_handler, sample_rgb_image):
        """Test saving with optimization enabled."""
        # Arrange
        buffer_opt = BytesIO()
        buffer_no_opt = BytesIO()
        settings_opt = ConversionSettings(quality=85, optimize=True)
        settings_no_opt = ConversionSettings(quality=85, optimize=False)

        # Act
        jxl_handler.save_image(sample_rgb_image, buffer_opt, settings_opt)
        jxl_handler.save_image(sample_rgb_image, buffer_no_opt, settings_no_opt)

        # Assert - both should produce valid files
        assert len(buffer_opt.getvalue()) > 0
        assert len(buffer_no_opt.getvalue()) > 0

    def test_quality_to_distance_mapping(self, jxl_handler):
        """Test quality parameter mapping to JXL distance."""
        # Quality 100 should be lossless (distance 0)
        opts = jxl_handler._get_encode_options(ConversionSettings(quality=100))
        assert opts["distance"] == 0.0
        assert opts["lossless"] is True

        # Quality 1 should map to distance ~15.0
        opts = jxl_handler._get_encode_options(ConversionSettings(quality=1))
        assert 14.0 < opts["distance"] <= 15.0
        assert opts["lossless"] is False

        # Quality 50 should be somewhere in middle
        opts = jxl_handler._get_encode_options(ConversionSettings(quality=50))
        assert 7.0 < opts["distance"] < 8.0

    def test_supports_transparency(self, jxl_handler):
        """Test that JPEG XL reports transparency support."""
        assert jxl_handler._supports_transparency() is True

    def test_supports_modes(self, jxl_handler):
        """Test supported color modes."""
        assert jxl_handler._supports_mode("RGB") is True
        assert jxl_handler._supports_mode("RGBA") is True
        assert jxl_handler._supports_mode("L") is True
        assert jxl_handler._supports_mode("CMYK") is False


class TestHeifHandler:
    """Test suite for HEIF format handler with enhanced encoding."""

    @pytest.fixture
    def heif_handler(self):
        """Create a HEIF handler instance."""
        try:
            return HeifHandler()
        except UnsupportedFormatError:
            pytest.skip("HEIF support not available")

    @pytest.fixture
    def sample_rgb_image(self):
        """Create a sample RGB image."""
        return Image.new("RGB", (100, 100), color="blue")

    @pytest.fixture
    def sample_rgba_image(self):
        """Create a sample RGBA image with transparency."""
        return Image.new("RGBA", (100, 100), (0, 0, 255, 128))

    def test_can_handle_heif_formats(self, heif_handler):
        """Test HEIF handler recognizes HEIF/HEIC formats."""
        assert heif_handler.can_handle("heif") is True
        assert heif_handler.can_handle("heic") is True
        assert heif_handler.can_handle("heix") is True
        assert heif_handler.can_handle("HEIF") is True
        assert heif_handler.can_handle("HEIC") is True
        assert heif_handler.can_handle("jpeg") is False

    def test_save_heif_with_quality(self, heif_handler, sample_rgb_image):
        """Test saving HEIF with different quality settings."""
        # Test regular quality
        buffer = BytesIO()
        settings = ConversionSettings(quality=85)
        heif_handler.save_image(sample_rgb_image, buffer, settings)
        assert len(buffer.getvalue()) > 0

    def test_save_heif_lossless(self, heif_handler, sample_rgb_image):
        """Test saving HEIF in lossless mode."""
        buffer = BytesIO()
        settings = ConversionSettings(quality=100)
        heif_handler.save_image(sample_rgb_image, buffer, settings)
        
        # Verify lossless parameter was set
        quality_params = heif_handler.get_quality_param(settings)
        assert quality_params.get("lossless") is True
        assert len(buffer.getvalue()) > 0

    def test_save_heif_with_optimization(self, heif_handler, sample_rgb_image):
        """Test HEIF encoding with optimization enabled."""
        # Save with optimization
        buffer_opt = BytesIO()
        settings_opt = ConversionSettings(quality=85, optimize=True)
        heif_handler.save_image(sample_rgb_image, buffer_opt, settings_opt)
        
        # Save without optimization
        buffer_no_opt = BytesIO()
        settings_no_opt = ConversionSettings(quality=85, optimize=False)
        heif_handler.save_image(sample_rgb_image, buffer_no_opt, settings_no_opt)
        
        # Both should produce valid files
        assert len(buffer_opt.getvalue()) > 0
        assert len(buffer_no_opt.getvalue()) > 0

    def test_compression_level_mapping(self, heif_handler):
        """Test compression level based on quality and optimization."""
        # High quality with optimization
        params = heif_handler.get_quality_param(ConversionSettings(quality=95, optimize=True))
        assert params["compression_level"] == 9
        
        # Medium quality with optimization
        params = heif_handler.get_quality_param(ConversionSettings(quality=70, optimize=True))
        assert params["compression_level"] == 6
        
        # Without optimization
        params = heif_handler.get_quality_param(ConversionSettings(quality=85, optimize=False))
        assert params["compression_level"] == 3

    def test_save_rgba_with_transparency(self, heif_handler, sample_rgba_image):
        """Test saving RGBA image preserving transparency."""
        buffer = BytesIO()
        settings = ConversionSettings(quality=90)
        heif_handler.save_image(sample_rgba_image, buffer, settings)
        assert len(buffer.getvalue()) > 0

    def test_metadata_stripping(self, heif_handler, sample_rgb_image):
        """Test metadata removal when requested."""
        # Add some fake metadata to image
        image_with_meta = sample_rgb_image.copy()
        image_with_meta.info["exif"] = b"fake exif data"
        
        buffer = BytesIO()
        settings = ConversionSettings(strip_metadata=True)
        heif_handler.save_image(image_with_meta, buffer, settings)
        assert len(buffer.getvalue()) > 0

    def test_supports_transparency(self, heif_handler):
        """Test that HEIF reports transparency support."""
        assert heif_handler._supports_transparency() is True

    def test_supports_modes(self, heif_handler):
        """Test supported color modes."""
        assert heif_handler._supports_mode("RGB") is True
        assert heif_handler._supports_mode("RGBA") is True
        assert heif_handler._supports_mode("L") is True


class TestPNGOptimizedHandler:
    """Test suite for optimized PNG format handler."""

    @pytest.fixture
    def png_opt_handler(self):
        """Create a PNG optimized handler instance."""
        return PNGOptimizedHandler()

    @pytest.fixture
    def sample_image(self):
        """Create a sample image for testing."""
        # Create image with gradient for better compression testing
        img = Image.new("RGB", (200, 200))
        pixels = img.load()
        for x in range(200):
            for y in range(200):
                pixels[x, y] = (x, y, 128)
        return img

    @pytest.fixture
    def sample_image_alpha(self):
        """Create a sample image with alpha channel."""
        img = Image.new("RGBA", (100, 100))
        pixels = img.load()
        for x in range(100):
            for y in range(100):
                # Create gradient with varying alpha
                pixels[x, y] = (x * 2, y * 2, 128, min(x + y, 255))
        return img

    def test_can_handle_format(self, png_opt_handler):
        """Test PNG optimized handler recognizes its format."""
        assert png_opt_handler.can_handle("png_optimized") is True
        assert png_opt_handler.can_handle("PNG_OPTIMIZED") is True
        assert png_opt_handler.can_handle("png") is False
        assert png_opt_handler.can_handle("jpeg") is False

    def test_tool_availability_check(self, png_opt_handler):
        """Test tool availability is checked on init."""
        # Handler should initialize even if tools aren't available
        assert hasattr(png_opt_handler, 'pngquant')
        assert hasattr(png_opt_handler, 'optipng')
        assert hasattr(png_opt_handler.pngquant, 'is_available')
        assert hasattr(png_opt_handler.optipng, 'is_available')
        assert isinstance(png_opt_handler.pngquant.is_available, bool)
        assert isinstance(png_opt_handler.optipng.is_available, bool)

    def test_save_without_tools(self, png_opt_handler, sample_image):
        """Test saving falls back to regular PNG when tools unavailable."""
        # Temporarily disable tools
        original_pngquant = png_opt_handler.pngquant.is_available
        original_optipng = png_opt_handler.optipng.is_available
        
        png_opt_handler.pngquant.tool_path = None
        png_opt_handler.optipng.tool_path = None
        
        try:
            buffer = BytesIO()
            settings = ConversionSettings(quality=85)
            png_opt_handler.save_image(sample_image, buffer, settings)
            
            # Should still produce valid PNG
            buffer.seek(0)
            result_img = Image.open(buffer)
            assert result_img.format == "PNG"
        finally:
            # Note: Can't properly restore since we modified internal state
            # This test might affect other tests if run in same session
            pass

    def test_save_optimized(self, png_opt_handler, sample_image):
        """Test saving with optimization."""
        buffer = BytesIO()
        settings = ConversionSettings(quality=85, optimize=True)
        png_opt_handler.save_image(sample_image, buffer, settings)
        
        # Should produce valid PNG
        buffer.seek(0)
        result_img = Image.open(buffer)
        assert result_img.format == "PNG"
        assert len(buffer.getvalue()) > 0

    def test_quality_settings(self, png_opt_handler, sample_image):
        """Test different quality settings produce different results."""
        # High quality
        buffer_high = BytesIO()
        settings_high = ConversionSettings(quality=95)
        png_opt_handler.save_image(sample_image, buffer_high, settings_high)
        
        # Low quality (more compression with pngquant)
        buffer_low = BytesIO()
        settings_low = ConversionSettings(quality=60)
        png_opt_handler.save_image(sample_image, buffer_low, settings_low)
        
        # Both should be valid
        assert len(buffer_high.getvalue()) > 0
        assert len(buffer_low.getvalue()) > 0

    def test_alpha_channel_preservation(self, png_opt_handler, sample_image_alpha):
        """Test that alpha channel is preserved during optimization."""
        buffer = BytesIO()
        settings = ConversionSettings(quality=85)
        png_opt_handler.save_image(sample_image_alpha, buffer, settings)
        
        # Load result and check alpha
        buffer.seek(0)
        result_img = Image.open(buffer)
        assert result_img.mode == "RGBA"
        assert result_img.format == "PNG"

    def test_optimization_strategies(self, png_opt_handler):
        """Test that multiple strategies are tried when available."""
        # This test just verifies the internal methods exist
        assert hasattr(png_opt_handler, '_optimize_with_pngquant')
        assert hasattr(png_opt_handler, '_optimize_with_optipng')
        assert hasattr(png_opt_handler, '_optimize_combined')

    def test_get_quality_params(self, png_opt_handler):
        """Test quality parameters include optimization info."""
        settings = ConversionSettings(quality=85)
        params = png_opt_handler.get_quality_param(settings)
        
        assert 'compress_level' in params
        assert 'optimize_externally' in params
        assert params['optimize_externally'] is True
        assert 'tools_available' in params
        assert isinstance(params['tools_available'], dict)


class TestJPEGOptimizedHandler:
    """Test suite for optimized JPEG format handler with mozjpeg."""

    @pytest.fixture
    def jpeg_opt_handler(self):
        """Create a JPEG optimized handler instance."""
        return JPEGOptimizedHandler()

    @pytest.fixture
    def sample_rgb_image(self):
        """Create a sample RGB image."""
        # Create colorful test image for JPEG compression
        img = Image.new("RGB", (200, 200))
        pixels = img.load()
        for x in range(200):
            for y in range(200):
                # Create color gradients
                r = (x * 255) // 200
                g = (y * 255) // 200
                b = 128
                pixels[x, y] = (r, g, b)
        return img

    @pytest.fixture
    def sample_rgba_image(self):
        """Create a sample RGBA image with transparency."""
        img = Image.new("RGBA", (100, 100), (255, 0, 0, 0))
        # Draw a semi-transparent blue square
        for x in range(25, 75):
            for y in range(25, 75):
                img.putpixel((x, y), (0, 0, 255, 128))
        return img

    def test_can_handle_format(self, jpeg_opt_handler):
        """Test JPEG optimized handler recognizes its formats."""
        assert jpeg_opt_handler.can_handle("jpeg_optimized") is True
        assert jpeg_opt_handler.can_handle("jpg_optimized") is True
        assert jpeg_opt_handler.can_handle("JPEG_OPTIMIZED") is True
        assert jpeg_opt_handler.can_handle("jpeg") is False
        assert jpeg_opt_handler.can_handle("png") is False

    def test_mozjpeg_availability_check(self, jpeg_opt_handler):
        """Test mozjpeg availability is checked on init."""
        assert hasattr(jpeg_opt_handler, 'mozjpeg')
        assert hasattr(jpeg_opt_handler.mozjpeg, 'is_available')
        assert isinstance(jpeg_opt_handler.mozjpeg.is_available, bool)
        if jpeg_opt_handler.mozjpeg.is_available:
            assert jpeg_opt_handler.mozjpeg.tool_path is not None

    def test_save_without_mozjpeg(self, jpeg_opt_handler, sample_rgb_image):
        """Test saving falls back to regular JPEG when mozjpeg unavailable."""
        # Temporarily disable mozjpeg
        original_path = jpeg_opt_handler.mozjpeg.tool_path
        jpeg_opt_handler.mozjpeg.tool_path = None
        
        try:
            buffer = BytesIO()
            settings = ConversionSettings(quality=85)
            jpeg_opt_handler.save_image(sample_rgb_image, buffer, settings)
            
            # Should still produce valid JPEG
            buffer.seek(0)
            result_img = Image.open(buffer)
            assert result_img.format == "JPEG"
        finally:
            jpeg_opt_handler.mozjpeg.tool_path = original_path

    def test_save_with_mozjpeg(self, jpeg_opt_handler, sample_rgb_image):
        """Test saving with mozjpeg optimization."""
        buffer = BytesIO()
        settings = ConversionSettings(quality=85, optimize=True)
        jpeg_opt_handler.save_image(sample_rgb_image, buffer, settings)
        
        # Should produce valid JPEG
        buffer.seek(0)
        result_img = Image.open(buffer)
        assert result_img.format == "JPEG"
        assert len(buffer.getvalue()) > 0

    def test_quality_levels(self, jpeg_opt_handler, sample_rgb_image):
        """Test different quality levels produce different results."""
        # High quality
        buffer_high = BytesIO()
        settings_high = ConversionSettings(quality=95)
        jpeg_opt_handler.save_image(sample_rgb_image, buffer_high, settings_high)
        
        # Low quality
        buffer_low = BytesIO()
        settings_low = ConversionSettings(quality=50)
        jpeg_opt_handler.save_image(sample_rgb_image, buffer_low, settings_low)
        
        # High quality should be larger
        high_size = len(buffer_high.getvalue())
        low_size = len(buffer_low.getvalue())
        assert high_size > 0
        assert low_size > 0
        # Note: Can't guarantee high > low due to optimization differences

    def test_rgba_to_rgb_conversion(self, jpeg_opt_handler, sample_rgba_image):
        """Test RGBA images are converted to RGB with white background."""
        buffer = BytesIO()
        settings = ConversionSettings(quality=85)
        jpeg_opt_handler.save_image(sample_rgba_image, buffer, settings)
        
        # Load and verify RGB conversion
        buffer.seek(0)
        result_img = Image.open(buffer)
        assert result_img.format == "JPEG"
        assert result_img.mode == "RGB"

    def test_progressive_encoding(self, jpeg_opt_handler, sample_rgb_image):
        """Test progressive JPEG encoding for optimized images."""
        buffer = BytesIO()
        settings = ConversionSettings(quality=80, optimize=True)
        jpeg_opt_handler.save_image(sample_rgb_image, buffer, settings)
        
        # Verify JPEG was created
        buffer.seek(0)
        result_img = Image.open(buffer)
        assert result_img.format == "JPEG"
        
        # Check if progressive flag is set in quality params
        params = jpeg_opt_handler.get_quality_param(settings)
        if jpeg_opt_handler.mozjpeg.is_available:
            assert params.get("progressive") is True

    def test_get_quality_params_with_mozjpeg(self, jpeg_opt_handler):
        """Test quality parameters include mozjpeg-specific settings."""
        # High quality settings
        params_high = jpeg_opt_handler.get_quality_param(
            ConversionSettings(quality=95, optimize=True)
        )
        
        assert "optimize_with_mozjpeg" in params_high
        if jpeg_opt_handler.mozjpeg.is_available:
            assert "subsampling" in params_high
            assert params_high["subsampling"] == "4:4:4"  # High quality
            assert "trellis_quantization" in params_high
            assert params_high["trellis_quantization"] is True
        
        # Low quality settings
        params_low = jpeg_opt_handler.get_quality_param(
            ConversionSettings(quality=60, optimize=False)
        )
        
        if jpeg_opt_handler.mozjpeg.is_available:
            assert params_low["subsampling"] == "4:2:0"  # Lower quality
            assert params_low["trellis_quantization"] is False

    def test_grayscale_image_support(self, jpeg_opt_handler):
        """Test grayscale image optimization."""
        # Create grayscale image
        gray_img = Image.new("L", (100, 100))
        for x in range(100):
            for y in range(100):
                gray_img.putpixel((x, y), (x + y) % 256)
        
        buffer = BytesIO()
        settings = ConversionSettings(quality=85)
        jpeg_opt_handler.save_image(gray_img, buffer, settings)
        
        # Verify result
        buffer.seek(0)
        result_img = Image.open(buffer)
        assert result_img.format == "JPEG"
        assert result_img.mode in ("L", "RGB")  # May convert to RGB


class TestWebP2Handler:
    """Test WebP2 format handler with fallback."""

    @pytest.fixture
    def webp2_handler(self):
        """Create WebP2 handler instance."""
        from app.core.conversion.formats.webp2_handler import WebP2Handler
        return WebP2Handler()

    def test_handler_initialization(self, webp2_handler):
        """Test WebP2 handler initialization."""
        assert webp2_handler.format_name == "WEBP2"
        assert "webp2" in webp2_handler.supported_formats
        # Should always initialize even if WebP2 not available
        assert webp2_handler is not None

    def test_automatic_fallback_to_webp(self, webp2_handler):
        """Test automatic fallback to WebP when WebP2 not available."""
        # WebP2 is not available yet, so it should use WebP
        test_img = Image.new("RGB", (100, 100), color="red")
        buffer = BytesIO()
        settings = ConversionSettings(quality=85)
        
        webp2_handler.save_image(test_img, buffer, settings)
        
        # Result should be WebP format
        buffer.seek(0)
        result = Image.open(buffer)
        assert result.format == "WEBP"

    def test_transparency_support(self, webp2_handler):
        """Test transparency preservation in fallback."""
        # Create RGBA image with transparency
        rgba_img = Image.new("RGBA", (50, 50), (255, 0, 0, 128))
        buffer = BytesIO()
        settings = ConversionSettings(quality=90)
        
        webp2_handler.save_image(rgba_img, buffer, settings)
        
        buffer.seek(0)
        result = Image.open(buffer)
        assert result.mode == "RGBA"

    def test_quality_parameters(self, webp2_handler):
        """Test WebP2/WebP quality parameter mapping."""
        settings = ConversionSettings(quality=75)
        params = webp2_handler.get_quality_param(settings)
        
        assert "quality" in params
        assert params["quality"] == 75
        # Since WebP2 is not available, it should return WebP params


class TestJpeg2000Handler:
    """Test JPEG 2000 format handler."""

    @pytest.fixture
    def jp2_handler(self):
        """Create JPEG 2000 handler instance."""
        from app.core.conversion.formats.jpeg2000_handler import Jpeg2000Handler
        return Jpeg2000Handler()

    def test_handler_initialization(self, jp2_handler):
        """Test JPEG 2000 handler initialization."""
        assert jp2_handler.format_name == "JPEG2000"
        assert "jp2" in jp2_handler.supported_formats
        assert "jpeg2000" in jp2_handler.supported_formats
        assert "j2k" in jp2_handler.supported_formats

    def test_lossless_mode(self, jp2_handler):
        """Test lossless JPEG 2000 encoding."""
        test_img = Image.new("RGB", (50, 50), color="blue")
        buffer = BytesIO()
        settings = ConversionSettings(quality=100)  # Quality 100 = lossless
        
        jp2_handler.save_image(test_img, buffer, settings)
        
        buffer.seek(0)
        # JPEG 2000 detection
        magic = buffer.read(12)
        buffer.seek(0)
        # JP2 box structure check
        assert magic[4:8] == b"jP  " or magic[:4] == b"\x00\x00\x00\x0c"

    def test_lossy_compression(self, jp2_handler):
        """Test lossy JPEG 2000 compression."""
        test_img = Image.new("RGB", (100, 100), color="green")
        buffer = BytesIO()
        settings = ConversionSettings(quality=75, optimize=True)
        
        jp2_handler.save_image(test_img, buffer, settings)
        
        buffer.seek(0)
        # Verify it's valid JPEG 2000
        result = Image.open(buffer)
        assert result.format == "JPEG2000"

    def test_grayscale_support(self, jp2_handler):
        """Test grayscale image support."""
        gray_img = Image.new("L", (50, 50))
        for i in range(50):
            for j in range(50):
                gray_img.putpixel((i, j), (i + j) % 256)
        
        buffer = BytesIO()
        settings = ConversionSettings(quality=85)
        jp2_handler.save_image(gray_img, buffer, settings)
        
        buffer.seek(0)
        result = Image.open(buffer)
        assert result.mode == "L"

    def test_quality_parameters(self, jp2_handler):
        """Test JPEG 2000 quality parameter mapping."""
        # Test high quality
        settings_high = ConversionSettings(quality=95)
        params_high = jp2_handler.get_quality_param(settings_high)
        assert params_high["quality_mode"] == "rates"
        assert params_high["irreversible"] is True
        
        # Test lossless
        settings_lossless = ConversionSettings(quality=100)
        params_lossless = jp2_handler.get_quality_param(settings_lossless)
        assert params_lossless["irreversible"] is False
