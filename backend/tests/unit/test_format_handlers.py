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
from app.models.conversion import ConversionSettings
from app.core.exceptions import ConversionFailedError


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
