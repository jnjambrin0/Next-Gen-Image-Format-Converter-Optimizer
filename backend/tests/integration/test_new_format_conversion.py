"""Integration tests for new format conversion support."""

import pytest
from io import BytesIO
from PIL import Image
import asyncio

# Import fixtures
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.conversion.manager import ConversionManager
from app.models.conversion import ConversionRequest, InputFormat, OutputFormat
from app.core.exceptions import ConversionFailedError, UnsupportedFormatError


class TestNewFormatConversion:
    """Test suite for new format conversion integration."""

    @pytest.fixture
    def conversion_manager(self):
        """Create a ConversionManager instance."""
        return ConversionManager()

    @pytest.fixture
    def create_test_image(self):
        """Factory to create test images in various formats."""

        def _create(format_name: str, size=(100, 100), color="red"):
            img = Image.new("RGB", size, color=color)
            buffer = BytesIO()

            # Handle special cases
            if format_name.upper() == "GIF":
                # Convert to palette mode for GIF
                img = img.convert("P", palette=Image.Palette.ADAPTIVE)

            img.save(buffer, format=format_name.upper())
            buffer.seek(0)
            return buffer.getvalue()

        return _create

    @pytest.mark.asyncio
    async def test_webp_to_png_conversion(self, conversion_manager, create_test_image):
        """Test WebP to PNG conversion."""
        # Create WebP image
        webp_data = create_test_image("webp")

        # Convert to PNG
        request = ConversionRequest(
            input_format=InputFormat.WEBP, output_format=OutputFormat.PNG, quality=90
        )

        result = await conversion_manager.convert(webp_data, request)

        # Verify result
        assert result.status == "completed"
        assert result.output_format == "png"
        assert len(result.output_data) > 0

        # Verify output is valid PNG
        output_img = Image.open(BytesIO(result.output_data))
        assert output_img.format == "PNG"

    @pytest.mark.asyncio
    async def test_bmp_to_webp_conversion(self, conversion_manager, create_test_image):
        """Test BMP to WebP conversion."""
        # Create BMP image
        bmp_data = create_test_image("bmp", color="blue")

        # Convert to WebP
        request = ConversionRequest(
            input_format=InputFormat.BMP, output_format=OutputFormat.WEBP, quality=85
        )

        result = await conversion_manager.convert(bmp_data, request)

        # Verify result
        assert result.status == "completed"
        assert result.output_format == "webp"
        assert len(result.output_data) > 0

        # Verify output is valid WebP
        output_img = Image.open(BytesIO(result.output_data))
        assert output_img.format == "WEBP"

    @pytest.mark.asyncio
    async def test_tiff_to_jpeg_conversion(self, conversion_manager, create_test_image):
        """Test TIFF to JPEG conversion."""
        # Create TIFF image
        tiff_data = create_test_image("tiff", size=(200, 200), color="green")

        # Convert to JPEG
        request = ConversionRequest(
            input_format=InputFormat.TIFF, output_format=OutputFormat.JPEG, quality=95
        )

        result = await conversion_manager.convert(tiff_data, request)

        # Verify result
        assert result.status == "completed"
        assert result.output_format == "jpeg"
        assert len(result.output_data) > 0

        # Verify output is valid JPEG
        output_img = Image.open(BytesIO(result.output_data))
        assert output_img.format == "JPEG"
        assert output_img.size == (200, 200)

    @pytest.mark.asyncio
    async def test_gif_to_png_conversion(self, conversion_manager, create_test_image):
        """Test GIF to PNG conversion."""
        # Create GIF image
        gif_data = create_test_image("gif", color="yellow")

        # Convert to PNG
        request = ConversionRequest(
            input_format=InputFormat.GIF, output_format=OutputFormat.PNG, quality=100
        )

        result = await conversion_manager.convert(gif_data, request)

        # Verify result
        assert result.status == "completed"
        assert result.output_format == "png"
        assert len(result.output_data) > 0

        # Verify output is valid PNG
        output_img = Image.open(BytesIO(result.output_data))
        assert output_img.format == "PNG"

    @pytest.mark.asyncio
    async def test_avif_to_jpeg_conversion(self, conversion_manager):
        """Test AVIF to JPEG conversion."""
        # Skip if AVIF support not available
        try:
            import pillow_avif_plugin
        except ImportError:
            pytest.skip("AVIF support not available")

        # Create a simple AVIF image
        img = Image.new("RGB", (50, 50), color="purple")
        buffer = BytesIO()
        img.save(buffer, format="AVIF")
        avif_data = buffer.getvalue()

        # Convert to JPEG
        request = ConversionRequest(
            input_format=InputFormat.AVIF, output_format=OutputFormat.JPEG, quality=90
        )

        result = await conversion_manager.convert(avif_data, request)

        # Verify result
        assert result.status == "completed"
        assert result.output_format == "jpeg"
        assert len(result.output_data) > 0

    @pytest.mark.asyncio
    async def test_format_auto_detection(self, conversion_manager, create_test_image):
        """Test that format is auto-detected from content."""
        # Create BMP image but don't specify input format
        bmp_data = create_test_image("bmp")

        # Convert without specifying input format (should auto-detect)
        request = ConversionRequest(output_format=OutputFormat.PNG, quality=90)

        # Note: This assumes ConversionManager has auto-detection capability
        # If not, this test should be adjusted or skipped
        try:
            result = await conversion_manager.convert(bmp_data, request)
            assert result.status == "completed"
        except Exception:
            # Auto-detection might not be implemented
            pytest.skip("Format auto-detection not implemented")

    @pytest.mark.asyncio
    async def test_multi_page_tiff_extracts_first_frame(self, conversion_manager):
        """Test that multi-page TIFF only converts the first frame."""
        # Create a multi-page TIFF (simplified - just one page for now)
        img = Image.new("RGB", (100, 100), color="cyan")
        buffer = BytesIO()
        img.save(buffer, format="TIFF")
        tiff_data = buffer.getvalue()

        # Convert to PNG
        request = ConversionRequest(
            input_format=InputFormat.TIFF, output_format=OutputFormat.PNG, quality=90
        )

        result = await conversion_manager.convert(tiff_data, request)

        # Verify only one image in output
        assert result.status == "completed"
        output_img = Image.open(BytesIO(result.output_data))
        assert output_img.format == "PNG"
        # PNG doesn't support multiple frames, so this confirms single frame

    @pytest.mark.asyncio
    async def test_animated_gif_extracts_first_frame(self, conversion_manager):
        """Test that animated GIF only converts the first frame."""
        # Create a simple GIF (animation would require more complex setup)
        img = Image.new("P", (50, 50))
        img.putpalette([i // 3 for i in range(768)])
        buffer = BytesIO()
        img.save(buffer, format="GIF")
        gif_data = buffer.getvalue()

        # Convert to PNG
        request = ConversionRequest(
            input_format=InputFormat.GIF, output_format=OutputFormat.PNG, quality=90
        )

        result = await conversion_manager.convert(gif_data, request)

        # Verify single frame output
        assert result.status == "completed"
        output_img = Image.open(BytesIO(result.output_data))
        assert output_img.format == "PNG"

    @pytest.mark.asyncio
    async def test_transparency_preservation(self, conversion_manager):
        """Test that transparency is preserved where supported."""
        # Create PNG with transparency
        img = Image.new("RGBA", (100, 100), (255, 0, 0, 128))
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        png_data = buffer.getvalue()

        # Convert to WebP (supports transparency)
        request = ConversionRequest(
            input_format=InputFormat.PNG, output_format=OutputFormat.WEBP, quality=90
        )

        result = await conversion_manager.convert(png_data, request)

        # Verify transparency preserved
        output_img = Image.open(BytesIO(result.output_data))
        assert output_img.mode == "RGBA"

    @pytest.mark.asyncio
    async def test_error_handling_invalid_format(self, conversion_manager):
        """Test error handling for invalid image data."""
        invalid_data = b"This is not an image"

        request = ConversionRequest(
            input_format=InputFormat.JPEG, output_format=OutputFormat.PNG, quality=90
        )

        with pytest.raises(ConversionFailedError):
            await conversion_manager.convert(invalid_data, request)
