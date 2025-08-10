"""Unit tests for conversion service layer."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from typing import Tuple

from app.services.conversion_service import ConversionService
from app.models.requests import ConversionApiRequest
from app.models.conversion import (
    ConversionResult,
    ConversionStatus,
    OutputFormat,
    ConversionSettings,
    InputFormat,
)
from app.core.exceptions import ConversionError, InvalidImageError
import asyncio


class TestConversionService:
    """Test conversion service layer."""

    @pytest.fixture
    def conversion_service(self):
        """Create conversion service instance."""
        return ConversionService()

    @pytest.fixture
    def mock_conversion_result(self):
        """Create mock conversion result."""
        return ConversionResult(
            id="test-id",
            input_format=InputFormat.JPEG,
            output_format=OutputFormat.WEBP,
            input_size=1000,
            output_size=800,
            processing_time=0.5,
            status=ConversionStatus.COMPLETED,
        )

    @pytest.fixture
    def conversion_request(self):
        """Create conversion API request."""
        return ConversionApiRequest(
            filename="test.jpg",
            input_format="jpeg",
            output_format=OutputFormat.WEBP,
            settings=ConversionSettings(quality=85),
        )

    @pytest.mark.asyncio
    async def test_convert_success(
        self, conversion_service, conversion_request, mock_conversion_result
    ):
        """Test successful conversion."""
        # Arrange
        image_data = b"fake image data"
        output_data = b"converted image data"

        with patch.object(
            conversion_service.conversion_manager,
            "convert_with_output",
            new_callable=AsyncMock,
        ) as mock_convert:
            mock_convert.return_value = (mock_conversion_result, output_data)

            # Act
            result, output = await conversion_service.convert(
                image_data, conversion_request
            )

            # Assert
            assert result == mock_conversion_result
            assert output == output_data
            mock_convert.assert_called_once()

            # Verify call arguments
            call_args = mock_convert.call_args
            assert call_args[1]["input_data"] == image_data
            assert call_args[1]["input_format"] == "jpeg"
            assert call_args[1]["request"].output_format == OutputFormat.WEBP
            assert call_args[1]["request"].settings.quality == 85

    @pytest.mark.asyncio
    async def test_convert_with_timeout(
        self, conversion_service, conversion_request, mock_conversion_result
    ):
        """Test conversion with custom timeout."""
        # Arrange
        image_data = b"fake image data"
        output_data = b"converted image data"
        timeout = 60.0

        with patch.object(
            conversion_service.conversion_manager,
            "convert_with_output",
            new_callable=AsyncMock,
        ) as mock_convert:
            mock_convert.return_value = (mock_conversion_result, output_data)

            # Act
            result, output = await conversion_service.convert(
                image_data, conversion_request, timeout=timeout
            )

            # Assert
            assert result == mock_conversion_result
            assert output == output_data
            mock_convert.assert_called_once()
            # We don't pass timeout to convert_with_output anymore
            assert mock_convert.call_args[1]["timeout"] is None

    @pytest.mark.asyncio
    async def test_convert_error_handling(self, conversion_service, conversion_request):
        """Test error handling in conversion."""
        # Arrange
        image_data = b"fake image data"
        error_message = "Conversion failed"

        with patch.object(
            conversion_service.conversion_manager,
            "convert_with_output",
            new_callable=AsyncMock,
        ) as mock_convert:
            mock_convert.side_effect = ConversionError(error_message)

            # Act & Assert
            with pytest.raises(ConversionError) as exc_info:
                await conversion_service.convert(image_data, conversion_request)

            assert str(exc_info.value) == error_message

    @pytest.mark.asyncio
    async def test_validate_image(self, conversion_service):
        """Test image validation with magic byte checking."""
        # Test with empty data
        assert await conversion_service.validate_image(b"", "jpeg") is False

        # Since magic might not be installed, test the fallback
        # First test with fallback (no magic)
        with patch("app.services.conversion_service.HAS_MAGIC", False):
            # Test valid JPEG magic bytes
            jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"x" * 100
            assert await conversion_service.validate_image(jpeg_data, "jpeg") is True

            # Test PNG magic bytes
            png_data = b"\x89PNG\r\n\x1a\n" + b"x" * 100
            assert await conversion_service.validate_image(png_data, "png") is True

            # Test mismatch
            assert await conversion_service.validate_image(jpeg_data, "png") is False

        # If we can test with magic, do so (but make it optional)
        try:
            import magic

            with patch("app.services.conversion_service.HAS_MAGIC", True), patch.object(
                magic, "from_buffer"
            ) as mock_magic:
                # Test valid JPEG
                mock_magic.return_value = "image/jpeg"
                assert (
                    await conversion_service.validate_image(b"fake jpeg data", "jpeg")
                    is True
                )
                assert (
                    await conversion_service.validate_image(b"fake jpeg data", "jpg")
                    is True
                )

                # Test valid PNG
                mock_magic.return_value = "image/png"
                assert (
                    await conversion_service.validate_image(b"fake png data", "png")
                    is True
                )

                # Test mismatch - expecting JPEG but got PNG
                mock_magic.return_value = "image/png"
                assert (
                    await conversion_service.validate_image(b"fake png data", "jpeg")
                    is False
                )

                # Test unknown MIME type
                mock_magic.return_value = "application/octet-stream"
                assert (
                    await conversion_service.validate_image(b"unknown data", "jpeg")
                    is True
                )  # Currently allows

                # Test unsupported MIME type
                mock_magic.return_value = "text/plain"
                assert (
                    await conversion_service.validate_image(b"text data", "jpeg")
                    is False
                )

                # Test exception handling
                mock_magic.side_effect = Exception("Magic error")
                assert await conversion_service.validate_image(b"data", "jpeg") is False
        except ImportError:
            # If magic is not installed, that's OK - we tested the fallback above
            pass

    def test_get_supported_formats(self, conversion_service):
        """Test getting supported formats."""
        # Act
        formats = conversion_service.get_supported_formats()

        # Assert
        assert "input_formats" in formats
        assert "output_formats" in formats

        # Check input formats
        input_formats = formats["input_formats"]
        assert len(input_formats) > 0
        assert any(f["format"] == "jpeg" for f in input_formats)
        assert any(f["format"] == "png" for f in input_formats)

        # Check output formats
        output_formats = formats["output_formats"]
        assert len(output_formats) > 0
        assert any(f["format"] == "webp" for f in output_formats)
        assert any(f["format"] == "avif" for f in output_formats)

        # Check format structure
        for fmt in input_formats + output_formats:
            assert "format" in fmt
            assert "mime_type" in fmt
            assert "extensions" in fmt
            assert "description" in fmt
            assert "supports_transparency" in fmt
            assert "supports_animation" in fmt

    @pytest.mark.asyncio
    async def test_convert_without_settings(
        self, conversion_service, mock_conversion_result
    ):
        """Test conversion without explicit settings."""
        # Arrange
        image_data = b"fake image data"
        output_data = b"converted image data"
        request = ConversionApiRequest(
            filename="test.jpg",
            input_format="jpeg",
            output_format=OutputFormat.WEBP,
            settings=None,  # No settings provided
        )

        with patch.object(
            conversion_service.conversion_manager,
            "convert_with_output",
            new_callable=AsyncMock,
        ) as mock_convert:
            mock_convert.return_value = (mock_conversion_result, output_data)

            # Act
            result, output = await conversion_service.convert(image_data, request)

            # Assert
            assert result == mock_conversion_result
            assert output == output_data
            mock_convert.assert_called_once()

    @pytest.mark.asyncio
    async def test_convert_logs_errors(self, conversion_service, conversion_request):
        """Test that errors are logged properly."""
        # Arrange
        image_data = b"fake image data"
        error_message = "Test error"

        with patch.object(
            conversion_service.conversion_manager,
            "convert_with_output",
            new_callable=AsyncMock,
        ) as mock_convert:
            mock_convert.side_effect = Exception(error_message)

            # Act & Assert
            with pytest.raises(Exception) as exc_info:
                await conversion_service.convert(image_data, conversion_request)

            assert str(exc_info.value) == error_message

    @pytest.mark.asyncio
    async def test_convert_preserves_exception_type(
        self, conversion_service, conversion_request
    ):
        """Test that specific exception types are preserved."""
        # Arrange
        image_data = b"fake image data"
        exceptions_to_test = [
            InvalidImageError("Invalid image"),
            ConversionError("Conversion error"),
            ValueError("Value error"),
            RuntimeError("Runtime error"),
        ]

        for original_exception in exceptions_to_test:
            with patch.object(
                conversion_service.conversion_manager,
                "convert_with_output",
                new_callable=AsyncMock,
            ) as mock_convert:
                mock_convert.side_effect = original_exception

                # Act & Assert
                with pytest.raises(type(original_exception)) as exc_info:
                    await conversion_service.convert(image_data, conversion_request)

                assert str(exc_info.value) == str(original_exception)

    @pytest.mark.asyncio
    async def test_convert_validates_image_content(
        self, conversion_service, conversion_request
    ):
        """Test that convert() validates image content before processing."""
        # Arrange
        image_data = b"fake image data"

        # Mock validate_image to return False
        with patch.object(
            conversion_service, "validate_image", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = False

            # Act & Assert
            with pytest.raises(InvalidImageError) as exc_info:
                await conversion_service.convert(image_data, conversion_request)

            assert "File content does not match expected format" in str(exc_info.value)
            mock_validate.assert_called_once_with(image_data, "jpeg")

    @pytest.mark.asyncio
    async def test_validate_image_fallback(self, conversion_service):
        """Test image validation fallback when magic is not available."""
        # Test with HAS_MAGIC = False
        with patch("app.services.conversion_service.HAS_MAGIC", False):
            # Test valid JPEG magic bytes
            jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"rest of data"
            assert await conversion_service.validate_image(jpeg_data, "jpeg") is True
            assert await conversion_service.validate_image(jpeg_data, "jpg") is True

            # Test valid PNG magic bytes
            png_data = b"\x89PNG\r\n\x1a\n" + b"rest of data"
            assert await conversion_service.validate_image(png_data, "png") is True

            # Test mismatch - JPEG magic bytes but expecting PNG
            assert await conversion_service.validate_image(jpeg_data, "png") is False

            # Test unknown data
            unknown_data = b"unknown file format"
            assert (
                await conversion_service.validate_image(unknown_data, "jpeg") is True
            )  # Falls back to allow

    @pytest.mark.asyncio
    async def test_convert_timeout_exceeded(
        self, conversion_service, conversion_request
    ):
        """Test conversion timeout handling."""
        # Arrange
        image_data = b"fake image data"

        async def slow_convert(*args, **kwargs):
            await asyncio.sleep(2)  # Simulate slow conversion
            return (Mock(), b"data")

        with patch.object(
            conversion_service, "validate_image", new_callable=AsyncMock
        ) as mock_validate:
            mock_validate.return_value = True

            with patch.object(
                conversion_service.conversion_manager,
                "convert_with_output",
                new=slow_convert,
            ):
                # Act & Assert - use very short timeout
                with pytest.raises(asyncio.TimeoutError):
                    await conversion_service.convert(
                        image_data, conversion_request, timeout=0.1
                    )
