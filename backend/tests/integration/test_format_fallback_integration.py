"""Integration tests for format fallback in conversion pipeline."""

# Import fixtures
from typing import Any
import sys
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.conversion.manager import ConversionManager
from app.core.exceptions import UnsupportedFormatError
from app.models.conversion import ConversionRequest, ConversionSettings


class TestFormatFallbackIntegration:
    """Integration tests for format fallback in actual conversions."""

    @pytest.fixture
    def sample_image_data(self) -> None:
        """Create sample image data."""
        img = Image.new("RGB", (100, 100), color="red")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return buffer.getvalue()

    @pytest.fixture
    def conversion_manager(self) -> None:
        """Create actual conversion manager."""
        return ConversionManager()

    @pytest.mark.asyncio
    async def test_webp2_fallback_to_webp(self, conversion_manager, sample_image_data):
        """Test WebP2 request falls back to WebP when WebP2 not available."""
        # Create request for WebP2
        request = ConversionRequest(
            output_format="webp2", settings=ConversionSettings(quality=85)
        )

        # Convert
        result = await conversion_manager.convert_image(
            sample_image_data, "png", request
        )

        # Check result
        assert result.status.value == "completed"
        assert result.output_size > 0

        # Check fallback was used
        if "format_fallback" in result.quality_settings:
            assert result.quality_settings["format_fallback"]["requested"] == "webp2"
            assert result.quality_settings["format_fallback"]["actual"] in [
                "webp",
                "png",
            ]

    @pytest.mark.asyncio
    async def test_jpeg_optimized_fallback(self, conversion_manager, sample_image_data):
        """Test JPEG optimized falls back to regular JPEG when mozjpeg not available."""
        # Create request for optimized JPEG
        request = ConversionRequest(
            output_format="jpeg_optimized", settings=ConversionSettings(quality=85)
        )

        # Convert
        result = await conversion_manager.convert_image(
            sample_image_data, "png", request
        )

        # Check result
        assert result.status.value == "completed"
        assert result.output_size > 0

    @pytest.mark.asyncio
    async def test_png_optimized_fallback(self, conversion_manager, sample_image_data):
        """Test PNG optimized falls back to regular PNG when tools not available."""
        # Create request for optimized PNG
        request = ConversionRequest(
            output_format="png_optimized", settings=ConversionSettings(quality=85)
        )

        # Convert
        result = await conversion_manager.convert_image(
            sample_image_data, "jpeg", request
        )

        # Check result
        assert result.status.value == "completed"
        assert result.output_size > 0

    @pytest.mark.asyncio
    async def test_unavailable_format_raises_error(
        self, conversion_manager, sample_image_data
    ):
        """Test that completely unavailable format raises error."""
        # Mock a format that has no handler and no fallback
        with pytest.raises(UnsupportedFormatError):
            request = ConversionRequest(
                output_format="completely_unknown_format",
                settings=ConversionSettings(quality=85),
            )

            await conversion_manager.convert_image(sample_image_data, "png", request)

    @pytest.mark.asyncio
    async def test_format_availability_check(self, conversion_manager):
        """Test format availability checking."""
        # These should be available (directly or via fallback)
        assert conversion_manager.is_format_available("png") is True
        assert conversion_manager.is_format_available("jpeg") is True
        assert conversion_manager.is_format_available("webp") is True

        # Optimized formats should be available via fallback
        assert conversion_manager.is_format_available("png_optimized") is True
        assert conversion_manager.is_format_available("jpeg_optimized") is True

        # Completely unknown format
        assert conversion_manager.is_format_available("unknown_format") is False

    def test_available_formats_list(self, conversion_manager) -> None:
        """Test getting list of available formats."""
        formats = conversion_manager.get_available_formats()

        # Should include basic formats
        assert "png" in formats
        assert "jpeg" in formats
        assert "jpg" in formats
        assert "webp" in formats

        # Should include formats with fallbacks
        assert "png_optimized" in formats
        assert "jpeg_optimized" in formats

        # List should be sorted
        assert formats == sorted(formats)

    @pytest.mark.asyncio
    async def test_fallback_preserves_settings(
        self, conversion_manager, sample_image_data
    ):
        """Test that conversion settings are preserved when using fallback."""
        # Create request with specific settings
        request = ConversionRequest(
            output_format="jpeg_optimized",
            settings=ConversionSettings(
                quality=95, strip_metadata=False, preserve_metadata=True, optimize=True
            ),
        )

        # Convert
        result = await conversion_manager.convert_image(
            sample_image_data, "png", request
        )

        # Check settings were preserved
        assert result.quality_settings["quality"] == 95
        assert result.quality_settings["strip_metadata"] is False
        assert result.quality_settings["preserve_metadata"] is True
        assert result.quality_settings["optimize"] is True
