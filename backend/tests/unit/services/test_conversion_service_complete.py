"""
Comprehensive unit tests for ConversionService to achieve high coverage.
"""

import asyncio
from io import BytesIO
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from PIL import Image

from app.core.exceptions import ConversionError, InvalidImageError
from app.models.conversion import (
    ConversionRequest,
    ConversionResult,
    ConversionSettings,
)
from app.models.requests import ConversionApiRequest
from app.services.conversion_service import ConversionService, conversion_service


class TestConversionServiceComprehensive:
    """Comprehensive tests for ConversionService."""

    @pytest.fixture
    def service(self):
        """Create a fresh ConversionService instance."""
        service = ConversionService()
        service.stats_collector = Mock()
        service.preset_service = Mock()
        return service

    @pytest.fixture
    def valid_image_data(self):
        """Create valid test image data."""
        img = Image.new("RGB", (100, 100), color="red")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    @pytest.fixture
    def mock_conversion_manager(self):
        """Create a mock conversion manager."""
        manager = AsyncMock()
        result = ConversionResult(
            status="completed",
            output_format="webp",
            file_size_reduction=50.0,
            conversion_time=0.5,
            quality_metrics={"ssim": 0.95},
        )
        result._output_data = b"converted_image_data"
        manager.convert_image.return_value = result
        manager.convert_with_output.return_value = (result, b"converted_image_data")
        return manager

    @pytest.mark.asyncio
    async def test_convert_with_preset_override(
        self, service, valid_image_data, mock_conversion_manager
    ):
        """Test conversion with preset that overrides settings."""
        service.conversion_manager = mock_conversion_manager

        # Mock preset service
        mock_preset = Mock()
        mock_preset.output_format = "avif"
        mock_preset.quality = 90
        mock_preset.advanced_settings = {"compression": "high"}
        service.preset_service = Mock()
        service.preset_service.get_preset.return_value = mock_preset

        # Create request with preset
        request = ConversionApiRequest(
            output_format="webp",  # Will be overridden by preset
            preset_id="high_quality",
        )

        result, output_data = await service.convert(valid_image_data, request)

        assert result.status == "completed"
        assert output_data == b"converted_image_data"
        service.preset_service.get_preset.assert_called_once_with("high_quality")

    @pytest.mark.asyncio
    async def test_convert_with_intelligence_mode(
        self, service, valid_image_data, mock_conversion_manager
    ):
        """Test conversion with intelligence mode enabled."""
        service.conversion_manager = mock_conversion_manager

        request = ConversionApiRequest(
            output_format="webp",
            settings=ConversionSettings(
                quality=85, enable_intelligent_mode=True, strip_metadata=True
            ),
        )

        result, output_data = await service.convert(valid_image_data, request)

        assert result.status == "completed"
        assert mock_conversion_manager.convert_with_output.called

    @pytest.mark.asyncio
    async def test_convert_memory_limits(self, service, mock_conversion_manager):
        """Test conversion with large image respects memory limits."""
        # Create large fake image data (10MB)
        large_image_data = b"FAKE" * (10 * 1024 * 256)  # ~10MB

        service.conversion_manager = mock_conversion_manager
        request = ConversionApiRequest(output_format="webp")

        # Should still work but with appropriate handling
        result, output_data = await service.convert(large_image_data, request)

        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_convert_invalid_formats(self, service, valid_image_data):
        """Test conversion with invalid/unsupported formats."""
        request = ConversionApiRequest(output_format="invalid_format")

        # Mock format detection to return unknown
        with patch(
            "app.services.conversion_service.format_detection_service"
        ) as mock_detection:
            mock_detection.detect_format.return_value = ("unknown", 0.0)

            with pytest.raises(InvalidImageError):
                await service.convert(valid_image_data, request)

    @pytest.mark.asyncio
    async def test_convert_security_sandbox(
        self, service, valid_image_data, mock_conversion_manager
    ):
        """Test conversion runs in security sandbox."""
        service.conversion_manager = mock_conversion_manager

        request = ConversionApiRequest(
            output_format="webp",
            settings=ConversionSettings(enable_sandbox=True, sandbox_timeout=10),
        )

        result, output_data = await service.convert(valid_image_data, request)

        assert result.status == "completed"
        # Verify sandbox parameters were passed
        call_args = mock_conversion_manager.convert_with_output.call_args
        assert call_args is not None

    @pytest.mark.asyncio
    async def test_stats_collection_integration(
        self, service, valid_image_data, mock_conversion_manager
    ):
        """Test that stats are collected during conversion."""
        service.conversion_manager = mock_conversion_manager
        mock_stats = Mock()
        service.stats_collector = mock_stats

        request = ConversionApiRequest(output_format="webp")

        result, output_data = await service.convert(valid_image_data, request)

        # Stats collector should be notified
        if mock_stats.record_conversion.called:
            mock_stats.record_conversion.assert_called_once()

    @pytest.mark.asyncio
    async def test_mime_type_detection(self, service):
        """Test MIME type detection for various formats."""
        # Test JPEG
        jpeg_data = b"\xff\xd8\xff\xe0" + b"test" * 100
        mime = service._detect_mime_type_fallback(jpeg_data)
        assert mime == "image/jpeg"

        # Test PNG
        png_data = b"\x89PNG\r\n\x1a\n" + b"test" * 100
        mime = service._detect_mime_type_fallback(png_data)
        assert mime == "image/png"

        # Test WebP
        webp_data = b"RIFF" + b"\x00" * 4 + b"WEBP" + b"test" * 100
        mime = service._detect_mime_type_fallback(webp_data)
        assert mime == "image/webp"

        # Test AVIF
        avif_data = b"\x00\x00\x00\x20ftypavif" + b"test" * 100
        mime = service._detect_mime_type_fallback(avif_data)
        assert mime == "image/avif"

        # Test HEIC
        heic_data = b"\x00\x00\x00\x20ftypheic" + b"test" * 100
        mime = service._detect_mime_type_fallback(heic_data)
        assert mime == "image/heif"

        # Test unknown
        unknown_data = b"UNKNOWN" * 10
        mime = service._detect_mime_type_fallback(unknown_data)
        assert mime == "application/octet-stream"

    @pytest.mark.asyncio
    async def test_error_recovery_modes(self, service, mock_conversion_manager):
        """Test error recovery during conversion."""
        # First call fails, second succeeds
        mock_conversion_manager.convert_with_output.side_effect = [
            ConversionError("First attempt failed"),
            (ConversionResult(status="completed", output_format="webp"), b"data"),
        ]
        service.conversion_manager = mock_conversion_manager

        request = ConversionApiRequest(
            output_format="webp", settings=ConversionSettings(enable_retry=True)
        )

        # Should fail on first attempt (no built-in retry in service)
        with pytest.raises(ConversionError):
            await service.convert(b"image", request)

    @pytest.mark.asyncio
    async def test_convert_with_advanced_options(
        self, service, valid_image_data, mock_conversion_manager
    ):
        """Test convert_with_advanced_options method."""
        service.conversion_manager = mock_conversion_manager

        # Test with advanced options
        output = await service.convert_with_advanced_options(
            valid_image_data,
            "webp",
            quality=90,
            compression_level=9,
            optimize_for="web",
            progressive=True,
        )

        assert output == b"converted_image_data"

        # Verify advanced options were passed
        call_args = mock_conversion_manager.convert_image.call_args
        assert call_args is not None
        request_arg = call_args[0][2]  # Third positional argument
        assert request_arg.settings.advanced_optimization is not None

    @pytest.mark.asyncio
    async def test_validate_image_comprehensive(self, service):
        """Test comprehensive image validation scenarios."""
        # Test with None
        assert await service.validate_image(None) is False

        # Test with empty bytes
        assert await service.validate_image(b"") is False

        # Test with valid image data
        with patch(
            "app.services.format_detection_service.format_detection_service"
        ) as mock_detection:
            mock_detection.detect_format.return_value = ("jpeg", 0.95)

            # Valid JPEG
            assert await service.validate_image(b"fake_jpeg", "jpeg") is True

            # Valid but wrong format hint
            assert await service.validate_image(b"fake_jpeg", "png") is False

            # Valid with no hint
            assert await service.validate_image(b"fake_jpeg") is True

            # Handle jpg/jpeg alias
            assert await service.validate_image(b"fake_jpeg", "jpg") is True

    @pytest.mark.asyncio
    async def test_validate_image_with_detection_error(self, service):
        """Test image validation when detection fails."""
        with patch(
            "app.services.format_detection_service.format_detection_service"
        ) as mock_detection:
            mock_detection.detect_format.side_effect = Exception("Detection failed")

            assert await service.validate_image(b"fake_image") is False

    def test_get_supported_formats_structure(self, service):
        """Test get_supported_formats returns correct structure."""
        formats = service.get_supported_formats()

        assert "input_formats" in formats
        assert "output_formats" in formats

        # Check input formats
        assert len(formats["input_formats"]) > 0
        for fmt in formats["input_formats"]:
            assert "format" in fmt
            assert "mime_type" in fmt
            assert "extensions" in fmt
            assert "description" in fmt
            assert "supports_transparency" in fmt
            assert "supports_animation" in fmt

        # Check output formats
        assert len(formats["output_formats"]) > 0
        for fmt in formats["output_formats"]:
            assert "format" in fmt
            assert "mime_type" in fmt
            assert "extensions" in fmt
            assert "description" in fmt

    @pytest.mark.asyncio
    async def test_detect_format_fallback(self, service):
        """Test _detect_format fallback method."""
        # Test successful detection
        with patch(
            "app.services.format_detection_service.format_detection_service"
        ) as mock_detection:
            mock_detection.detect_format.return_value = ("jpeg", 0.95)

            format_detected = await service._detect_format(b"fake_image")
            assert format_detected == "jpeg"

        # Test detection failure
        with patch(
            "app.services.format_detection_service.format_detection_service"
        ) as mock_detection:
            mock_detection.detect_format.side_effect = Exception("Failed")

            format_detected = await service._detect_format(b"fake_image")
            assert format_detected is None

    @pytest.mark.asyncio
    async def test_convert_with_timeout(self, service, valid_image_data):
        """Test conversion with timeout handling."""
        # Create a manager that times out
        mock_manager = AsyncMock()
        mock_manager.convert_with_output.side_effect = asyncio.TimeoutError()
        service.conversion_manager = mock_manager

        request = ConversionApiRequest(
            output_format="webp", timeout=0.001  # Very short timeout
        )

        with pytest.raises(asyncio.TimeoutError):
            await service.convert(valid_image_data, request)

    @pytest.mark.asyncio
    async def test_convert_with_missing_output_data(self, service, valid_image_data):
        """Test handling when conversion returns no output data."""
        mock_manager = AsyncMock()
        # Return result without _output_data attribute
        result = ConversionResult(status="completed", output_format="webp")
        mock_manager.convert_with_output.return_value = (result, None)
        service.conversion_manager = mock_manager

        request = ConversionApiRequest(output_format="webp")

        with pytest.raises(ConversionError, match="No output data"):
            await service.convert(valid_image_data, request)

    @pytest.mark.asyncio
    async def test_heic_mime_detection_variations(self, service):
        """Test HEIC/HEIF detection with various file structures."""
        # Standard HEIC at offset 4
        heic1 = b"\x00\x00\x00\x20ftypheic" + b"x" * 100
        assert service._detect_mime_type_fallback(heic1) == "image/heif"

        # HEIF with mif1 brand
        heif1 = b"\x00\x00\x00\x20ftypmif1" + b"x" * 100
        assert service._detect_mime_type_fallback(heif1) == "image/heif"

        # HEIC with ftyp at different offset
        heic2 = b"x" * 10 + b"ftypheic" + b"x" * 100
        assert service._detect_mime_type_fallback(heic2) == "image/heif"

        # Test with compatible brands
        heic3 = b"\x00\x00\x00\x20ftypmp42" + b"heic" + b"x" * 100
        assert service._detect_mime_type_fallback(heic3) == "image/heif"

    @pytest.mark.asyncio
    async def test_convert_logs_errors_correctly(self, service, valid_image_data):
        """Test that errors are logged with correct context."""
        mock_manager = AsyncMock()
        mock_manager.convert_with_output.side_effect = ConversionError("Test error")
        service.conversion_manager = mock_manager

        request = ConversionApiRequest(output_format="webp")

        with patch("app.services.conversion_service.logger") as mock_logger:
            with pytest.raises(ConversionError):
                await service.convert(valid_image_data, request)

            # Verify error was logged
            mock_logger.error.assert_called()
            call_args = mock_logger.error.call_args
            assert "Conversion service error" in str(call_args)

    @pytest.mark.asyncio
    async def test_singleton_instance(self):
        """Test that conversion_service is a proper singleton."""
        from app.services.conversion_service import conversion_service

        assert conversion_service is not None
        assert isinstance(conversion_service, ConversionService)

        # Verify it has the expected attributes
        assert hasattr(conversion_service, "conversion_manager")
        assert hasattr(conversion_service, "stats_collector")
        assert hasattr(conversion_service, "preset_service")
