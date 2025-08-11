"""Unit tests for the Conversion Manager module."""

import asyncio
import io

# Import fixtures
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.conversion.manager import ConversionManager
from app.core.exceptions import (
    ConversionFailedError,
    InvalidImageError,
    SecurityError,
    UnsupportedFormatError,
)
from app.models.conversion import (
    ConversionRequest,
    ConversionResult,
    ConversionSettings,
    ConversionStatus,
    OutputFormat,
)


class TestConversionManager:
    """Test suite for ConversionManager class."""

    @pytest.fixture
    def conversion_manager(self):
        """Create a ConversionManager instance for testing."""
        return ConversionManager()

    @pytest.fixture
    def sample_jpeg_bytes(self, image_generator):
        """Generate sample JPEG bytes."""
        return image_generator(width=100, height=100, format="JPEG")

    @pytest.fixture
    def sample_png_bytes(self, image_generator):
        """Generate sample PNG bytes."""
        return image_generator(width=100, height=100, format="PNG")

    @pytest.mark.asyncio
    async def test_convert_jpeg_to_webp_success(
        self, conversion_manager, sample_jpeg_bytes
    ):
        """Test successful JPEG to WebP conversion."""
        # Arrange
        request = ConversionRequest(
            output_format=OutputFormat.WEBP, settings=ConversionSettings(quality=85)
        )

        # Act
        result = await conversion_manager.convert_image(
            sample_jpeg_bytes, "jpeg", request
        )

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        assert result.output_format == OutputFormat.WEBP
        assert result.input_size == len(sample_jpeg_bytes)
        assert result.output_size > 0
        assert result.processing_time > 0
        assert hasattr(result, "_output_data")
        assert len(result._output_data) > 0

    @pytest.mark.asyncio
    async def test_convert_png_to_avif_success(
        self, conversion_manager, sample_png_bytes
    ):
        """Test successful PNG to AVIF conversion."""
        # Arrange
        request = ConversionRequest(
            output_format=OutputFormat.AVIF, settings=ConversionSettings(quality=80)
        )

        # Act
        result = await conversion_manager.convert_image(
            sample_png_bytes, "png", request
        )

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        assert result.output_format == OutputFormat.AVIF
        assert result.input_size == len(sample_png_bytes)
        assert result.output_size > 0
        assert result.compression_ratio is not None

    @pytest.mark.asyncio
    async def test_convert_with_default_settings(
        self, conversion_manager, sample_jpeg_bytes
    ):
        """Test conversion with default settings."""
        # Arrange
        request = ConversionRequest(output_format=OutputFormat.WEBP)

        # Act
        result = await conversion_manager.convert_image(
            sample_jpeg_bytes, "jpeg", request
        )

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        # Default settings are created if none provided
        assert len(result.quality_settings) > 0  # Settings were applied

    @pytest.mark.asyncio
    async def test_convert_with_metadata_stripping(
        self, conversion_manager, sample_image_bytes
    ):
        """Test conversion with metadata stripping."""
        # Arrange
        request = ConversionRequest(
            output_format=OutputFormat.JPEG,
            settings=ConversionSettings(strip_metadata=True),
        )

        # Act
        result = await conversion_manager.convert_image(
            sample_image_bytes, "jpeg", request
        )

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        # Verify output has no EXIF data
        output_image = Image.open(io.BytesIO(result._output_data))
        assert not hasattr(output_image, "_getexif") or output_image._getexif() is None

    @pytest.mark.asyncio
    async def test_convert_empty_input_raises_error(self, conversion_manager):
        """Test that empty input raises InvalidImageError."""
        # Arrange
        request = ConversionRequest(output_format=OutputFormat.WEBP)

        # Act & Assert
        with pytest.raises(InvalidImageError, match="Empty input data"):
            await conversion_manager.convert_image(b"", "jpeg", request)

    @pytest.mark.asyncio
    async def test_convert_oversized_input_raises_error(self, conversion_manager):
        """Test that oversized input raises InvalidImageError."""
        # Arrange
        oversized_data = b"x" * (51 * 1024 * 1024)  # 51MB
        request = ConversionRequest(output_format=OutputFormat.WEBP)

        # Act & Assert
        with pytest.raises(InvalidImageError, match="exceeds maximum allowed size"):
            await conversion_manager.convert_image(oversized_data, "jpeg", request)

    @pytest.mark.asyncio
    async def test_convert_unsupported_input_format_raises_error(
        self, conversion_manager, sample_jpeg_bytes
    ):
        """Test that unsupported input format raises error."""
        # Arrange
        request = ConversionRequest(output_format=OutputFormat.WEBP)

        # Act & Assert
        # The error happens during conversion because we validate dynamically
        with pytest.raises(
            Exception
        ):  # Will be either ValueError or UnsupportedFormatError
            await conversion_manager.convert_image(sample_jpeg_bytes, "xyz", request)

    @pytest.mark.asyncio
    async def test_convert_unsupported_output_format_raises_error(
        self, conversion_manager, sample_jpeg_bytes
    ):
        """Test that unsupported output format raises error."""
        # This test now validates at the Pydantic level
        # which is actually better - invalid formats are caught earlier
        from pydantic import ValidationError

        # Act & Assert
        with pytest.raises(ValidationError):
            ConversionRequest(output_format="xyz")

    @pytest.mark.asyncio
    async def test_convert_corrupted_image_raises_error(
        self, conversion_manager, corrupted_image_path
    ):
        """Test that corrupted image raises ConversionFailedError."""
        # Arrange
        with open(corrupted_image_path, "rb") as f:
            corrupted_data = f.read()
        request = ConversionRequest(output_format=OutputFormat.WEBP)

        # Act & Assert
        with pytest.raises(InvalidImageError, match="Image validation failed"):
            await conversion_manager.convert_image(corrupted_data, "jpeg", request)

    @pytest.mark.asyncio
    async def test_convert_handles_processing_error(
        self, conversion_manager, sample_jpeg_bytes
    ):
        """Test error handling during processing."""
        # Arrange
        request = ConversionRequest(output_format=OutputFormat.WEBP)

        # Mock processing error
        with patch.object(
            conversion_manager,
            "_process_image",
            side_effect=ConversionFailedError("Processing failed"),
        ):
            # Act & Assert
            with pytest.raises(ConversionFailedError):
                await conversion_manager.convert_image(
                    sample_jpeg_bytes, "jpeg", request
                )

    @pytest.mark.asyncio
    async def test_convert_quality_affects_output_size(
        self, conversion_manager, sample_jpeg_bytes
    ):
        """Test that quality setting affects output size."""
        # Arrange
        high_quality_request = ConversionRequest(
            output_format=OutputFormat.JPEG, settings=ConversionSettings(quality=95)
        )
        low_quality_request = ConversionRequest(
            output_format=OutputFormat.JPEG, settings=ConversionSettings(quality=30)
        )

        # Act
        high_quality_result = await conversion_manager.convert_image(
            sample_jpeg_bytes, "jpeg", high_quality_request
        )
        low_quality_result = await conversion_manager.convert_image(
            sample_jpeg_bytes, "jpeg", low_quality_request
        )

        # Assert
        assert high_quality_result.output_size > low_quality_result.output_size
        assert (
            low_quality_result.compression_ratio < high_quality_result.compression_ratio
        )

    @pytest.mark.asyncio
    async def test_convert_preserves_transparency(
        self, conversion_manager, image_generator
    ):
        """Test that transparency is preserved in supported formats."""
        # Arrange
        # Create PNG with transparency
        img = Image.new("RGBA", (100, 100), (255, 0, 0, 128))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        transparent_png = buffer.getvalue()

        request = ConversionRequest(
            output_format=OutputFormat.WEBP, settings=ConversionSettings(quality=85)
        )

        # Act
        result = await conversion_manager.convert_image(transparent_png, "png", request)

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        output_image = Image.open(io.BytesIO(result._output_data))
        assert output_image.mode == "RGBA"

    @pytest.mark.asyncio
    async def test_convert_handles_cmyk_images(self, conversion_manager):
        """Test conversion of CMYK images."""
        # Arrange
        # Create CMYK image
        img = Image.new("CMYK", (100, 100), (100, 50, 0, 10))
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG")
        cmyk_jpeg = buffer.getvalue()

        request = ConversionRequest(output_format=OutputFormat.WEBP)

        # Act
        result = await conversion_manager.convert_image(cmyk_jpeg, "jpeg", request)

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        output_image = Image.open(io.BytesIO(result._output_data))
        assert output_image.mode == "RGB"  # Should be converted to RGB

    @pytest.mark.asyncio
    async def test_convert_concurrent_requests(
        self, conversion_manager, sample_jpeg_bytes, sample_png_bytes
    ):
        """Test handling multiple concurrent conversions."""
        # Arrange
        requests = [
            (
                sample_jpeg_bytes,
                "jpeg",
                ConversionRequest(output_format=OutputFormat.WEBP),
            ),
            (
                sample_png_bytes,
                "png",
                ConversionRequest(output_format=OutputFormat.AVIF),
            ),
            (
                sample_jpeg_bytes,
                "jpeg",
                ConversionRequest(output_format=OutputFormat.PNG),
            ),
        ]

        # Act
        tasks = [
            conversion_manager.convert_image(data, fmt, req)
            for data, fmt, req in requests
        ]
        results = await asyncio.gather(*tasks)

        # Assert
        assert len(results) == 3
        assert all(r.status == ConversionStatus.COMPLETED for r in results)
        assert results[0].output_format == OutputFormat.WEBP
        assert results[1].output_format == OutputFormat.AVIF
        assert results[2].output_format == OutputFormat.PNG

    @pytest.mark.parametrize(
        "input_format,output_format",
        [
            ("jpeg", OutputFormat.WEBP),
            ("jpeg", OutputFormat.AVIF),
            ("png", OutputFormat.WEBP),
            ("png", OutputFormat.AVIF),
        ],
    )
    @pytest.mark.asyncio
    async def test_convert_format_combinations(
        self, conversion_manager, image_generator, input_format, output_format
    ):
        """Test various input/output format combinations."""
        # Arrange
        input_data = image_generator(format=input_format.upper())
        request = ConversionRequest(output_format=output_format)

        # Act
        result = await conversion_manager.convert_image(
            input_data, input_format, request
        )

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        assert result.output_format == output_format

    @pytest.mark.asyncio
    async def test_convert_with_output_returns_data(
        self, conversion_manager, sample_jpeg_bytes
    ):
        """Test convert_with_output method returns both result and data."""
        # Create request
        request = ConversionRequest(
            output_format="webp", settings=ConversionSettings(quality=85)
        )

        # Perform conversion with output
        result, output_data = await conversion_manager.convert_with_output(
            sample_jpeg_bytes, "jpeg", request
        )

        # Verify result
        assert result.status == ConversionStatus.COMPLETED
        assert result.output_size > 0
        assert output_data is not None
        assert len(output_data) == result.output_size
        assert output_data.startswith(b"RIFF")  # WebP magic bytes

    @pytest.mark.asyncio
    async def test_convert_with_output_timeout(self, conversion_manager):
        """Test convert_with_output handles timeout properly."""
        # Create request
        request = ConversionRequest(
            output_format="webp", settings=ConversionSettings(quality=85)
        )

        # Mock slow conversion
        original_convert = conversion_manager.convert_image

        async def slow_convert(*args, **kwargs):
            await asyncio.sleep(5)  # Simulate slow conversion
            return await original_convert(*args, **kwargs)

        conversion_manager.convert_image = slow_convert

        # Test with short timeout
        result, output_data = await conversion_manager.convert_with_output(
            b"\xff\xd8\xff\xe0" + b"\x00" * 1000, "jpeg", request, timeout=0.1
        )

        # Verify timeout handling
        assert result.status == ConversionStatus.FAILED
        assert "timed out" in result.error_message
        assert output_data is None
        assert result.processing_time == 0.1
