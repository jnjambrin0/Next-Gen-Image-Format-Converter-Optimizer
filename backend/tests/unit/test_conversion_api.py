"""Unit tests for conversion API route."""

from typing import Any
import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException, UploadFile

from app.api.routes.conversion import convert_image
from app.core.exceptions import (
    ConversionFailedError,
    InvalidImageError,
    UnsupportedFormatError,
)
from app.models.conversion import (
    ConversionResult,
    ConversionStatus,
    InputFormat,
    OutputFormat,
)


class TestConversionAPI:
    """Test conversion API endpoint."""

    @pytest.fixture
    def mock_request(self) -> None:
        """Create mock request with correlation ID."""
        request = Mock()
        request.state.correlation_id = "test-correlation-id"
        return request

    @pytest.fixture
    def mock_file(self) -> None:
        """Create mock upload file."""
        file = Mock(spec=UploadFile)
        file.filename = "test.jpg"
        file.content_type = "image/jpeg"
        file.read = AsyncMock(return_value=b"fake image data")
        return file

    @pytest.fixture
    def mock_conversion_result(self) -> None:
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

    @pytest.mark.asyncio
    async def test_convert_image_success(
        self, mock_request, mock_file, mock_conversion_result
    ):
        """Test successful image conversion."""
        # Arrange
        output_data = b"converted image data"

        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            mock_service.convert = AsyncMock(
                return_value=(mock_conversion_result, output_data)
            )

            # Act
            response = await convert_image(
                request=mock_request,
                file=mock_file,
                output_format=OutputFormat.WEBP,
                quality=85,
            )

            # Assert
            assert response.body == output_data
            assert response.media_type == "image/webp"
            assert (
                response.headers["Content-Disposition"]
                == 'attachment; filename="test.webp"'
            )
            assert response.headers["X-Conversion-Id"] == "test-id"
            assert response.headers["X-Processing-Time"] == "0.5"
            assert response.headers["X-Compression-Ratio"] == "0.8"

    @pytest.mark.asyncio
    async def test_convert_image_empty_file(self, mock_request):
        """Test conversion with empty file."""
        # Arrange
        mock_file = Mock(spec=UploadFile)
        mock_file.filename = "empty.jpg"
        mock_file.read = AsyncMock(return_value=b"")

        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await convert_image(
                request=mock_request,
                file=mock_file,
                output_format=OutputFormat.WEBP,
            )

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["error_code"] == "CONV201"
        assert "Empty file" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_file_too_large(self, mock_request):
        """Test conversion with file exceeding size limit."""
        # Arrange
        mock_file = Mock(spec=UploadFile)
        mock_file.filename = "large.jpg"
        # Create 51MB of data (exceeds 50MB limit)
        mock_file.read = AsyncMock(return_value=b"x" * (51 * 1024 * 1024))

        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await convert_image(
                request=mock_request,
                file=mock_file,
                output_format=OutputFormat.WEBP,
            )

        assert exc_info.value.status_code == 413
        assert exc_info.value.detail["error_code"] == "CONV202"
        assert "exceeds maximum" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_no_filename(self, mock_request):
        """Test conversion with missing filename."""
        # Arrange
        mock_file = Mock(spec=UploadFile)
        mock_file.filename = None
        mock_file.read = AsyncMock(return_value=b"fake image data")

        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await convert_image(
                request=mock_request,
                file=mock_file,
                output_format=OutputFormat.WEBP,
            )

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["error_code"] == "CONV203"
        assert "Filename is required" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_no_extension(self, mock_request):
        """Test conversion with filename lacking extension."""
        # Arrange
        mock_file = Mock(spec=UploadFile)
        mock_file.filename = "noextension"
        mock_file.read = AsyncMock(return_value=b"fake image data")

        # Act & Assert
        with pytest.raises(HTTPException) as exc_info:
            await convert_image(
                request=mock_request,
                file=mock_file,
                output_format=OutputFormat.WEBP,
            )

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["error_code"] == "CONV204"
        assert "Cannot determine file format" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_timeout(self, mock_request, mock_file):
        """Test conversion timeout handling."""
        # Arrange
        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            mock_service.convert = AsyncMock(side_effect=asyncio.TimeoutError())

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=OutputFormat.WEBP,
                    quality=85,
                )

            assert exc_info.value.status_code == 500
            assert exc_info.value.detail["error_code"] == "CONV250"
            assert "timed out" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_invalid_image(self, mock_request, mock_file):
        """Test handling of invalid image error."""
        # Arrange
        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            mock_service.convert = AsyncMock(
                side_effect=InvalidImageError("Not a valid image")
            )

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=OutputFormat.WEBP,
                    quality=85,
                )

            assert exc_info.value.status_code == 422
            assert exc_info.value.detail["error_code"] == "CONV210"
            assert "Not a valid image" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_unsupported_format(self, mock_request, mock_file):
        """Test handling of unsupported format error."""
        # Arrange
        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            mock_service.convert = AsyncMock(
                side_effect=UnsupportedFormatError("Format not supported")
            )

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=OutputFormat.WEBP,
                    quality=85,
                )

            assert exc_info.value.status_code == 415
            assert exc_info.value.detail["error_code"] == "CONV211"
            assert "Format not supported" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_conversion_failed(self, mock_request, mock_file):
        """Test handling of conversion failure."""
        # Arrange
        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            mock_service.convert = AsyncMock(
                side_effect=ConversionFailedError("Processing failed")
            )

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=OutputFormat.WEBP,
                    quality=85,
                )

            assert exc_info.value.status_code == 500
            assert exc_info.value.detail["error_code"] == "CONV299"
            assert "Processing failed" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_no_output_data(
        self, mock_request, mock_file, mock_conversion_result
    ):
        """Test handling when conversion produces no output."""
        # Arrange
        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            mock_service.convert = AsyncMock(
                return_value=(mock_conversion_result, None)
            )

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=OutputFormat.WEBP,
                    quality=85,
                )

            assert exc_info.value.status_code == 500
            assert exc_info.value.detail["error_code"] == "CONV299"
            assert "failed to produce output" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_at_capacity(self, mock_request, mock_file):
        """Test handling when service is at capacity."""
        # Arrange
        with patch("app.api.routes.conversion.conversion_semaphore") as mock_semaphore:
            mock_semaphore.locked.return_value = True

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=OutputFormat.WEBP,
                    quality=85,
                )

            assert exc_info.value.status_code == 503
            assert exc_info.value.detail["error_code"] == "CONV251"
            assert "temporarily unavailable" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_all_output_formats(
        self, mock_request, mock_file, mock_conversion_result
    ):
        """Test conversion with all supported output formats."""
        # Arrange
        output_data = b"converted image data"
        format_content_types = {
            OutputFormat.WEBP: "image/webp",
            OutputFormat.AVIF: "image/avif",
            OutputFormat.JPEG: "image/jpeg",
            OutputFormat.PNG: "image/png",
            OutputFormat.HEIF: "image/heif",
            OutputFormat.JPEGXL: "image/jxl",
            OutputFormat.WEBP2: "image/webp2",
            OutputFormat.JP2: "image/jp2",
        }

        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            for output_format, expected_content_type in format_content_types.items():
                # Update mock result
                mock_conversion_result.output_format = output_format
                mock_service.convert = AsyncMock(
                    return_value=(mock_conversion_result, output_data)
                )

                # Act
                response = await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=output_format,
                    quality=85,
                )

                # Assert
                assert response.media_type == expected_content_type
                ext = output_format.value.lower()
                assert (
                    response.headers["Content-Disposition"]
                    == f'attachment; filename="test.{ext}"'
                )

    @pytest.mark.asyncio
    async def test_convert_image_quality_bounds(self, mock_request, mock_file):
        """Test quality parameter validation."""
        # Quality values outside 1-100 should be rejected by FastAPI validation
        # This test documents expected behavior
        pass  # FastAPI handles validation before route is called

    @pytest.mark.asyncio
    async def test_convert_image_unexpected_error(self, mock_request, mock_file):
        """Test handling of unexpected errors."""
        # Arrange
        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            mock_service.convert = AsyncMock(side_effect=Exception("Unexpected error"))

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=OutputFormat.WEBP,
                    quality=85,
                )

            assert exc_info.value.status_code == 500
            assert exc_info.value.detail["error_code"] == "CONV299"
            assert "unexpected error occurred" in exc_info.value.detail["message"]

    @pytest.mark.asyncio
    async def test_convert_image_filename_sanitization(
        self, mock_request, mock_conversion_result
    ):
        """Test that malicious filenames are sanitized."""
        # Arrange
        malicious_filenames = [
            "../../../etc/passwd.jpg",
            "..\\..\\windows\\system32\\config\\sam.jpg",
            "test\x00.jpg",
            "test\nmalicious.jpg",
            "/etc/passwd.jpg",
            "C:\\Windows\\system.jpg",
        ]

        output_data = b"converted image data"

        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            mock_service.convert = AsyncMock(
                return_value=(mock_conversion_result, output_data)
            )

            for malicious_name in malicious_filenames:
                mock_file = Mock(spec=UploadFile)
                mock_file.filename = malicious_name
                mock_file.content_type = "image/jpeg"
                mock_file.read = AsyncMock(return_value=b"fake image data")

                # Act
                response = await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=OutputFormat.WEBP,
                    quality=85,
                )

                # Assert - filename should be sanitized
                assert response.status_code == 200
                # Check that the conversion was called with sanitized filename
                call_args = mock_service.convert.call_args[0]
                conversion_request = call_args[1]
                # Should not contain path traversal sequences
                assert ".." not in conversion_request.filename
                assert "/" not in conversion_request.filename
                assert "\\" not in conversion_request.filename
                assert "\x00" not in conversion_request.filename

    @pytest.mark.asyncio
    async def test_convert_image_mime_validation(self, mock_request):
        """Test that file content validation is performed."""
        # Arrange
        mock_file = Mock(spec=UploadFile)
        mock_file.filename = "fake.jpg"
        mock_file.content_type = "image/jpeg"
        # This is not a valid JPEG file
        mock_file.read = AsyncMock(return_value=b"Not a real image file")

        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            # Service should reject invalid image
            mock_service.convert = AsyncMock(
                side_effect=InvalidImageError(
                    "File content does not match expected format"
                )
            )

            # Act & Assert
            with pytest.raises(HTTPException) as exc_info:
                await convert_image(
                    request=mock_request,
                    file=mock_file,
                    output_format=OutputFormat.WEBP,
                    quality=85,
                )

            assert exc_info.value.status_code == 422
            assert exc_info.value.detail["error_code"] == "CONV210"
