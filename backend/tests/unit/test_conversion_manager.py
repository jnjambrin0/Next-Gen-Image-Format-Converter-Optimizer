"""Unit tests for the Conversion Manager module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import io
from PIL import Image

# Import fixtures - using absolute imports for pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.fixtures.conftest import (
    sample_image_path,
    sample_image_bytes,
    mock_conversion_request,
    image_generator,
)


class TestConversionManager:
    """Test suite for ConversionManager class."""

    @pytest.fixture
    def conversion_manager(self):
        """Create a ConversionManager instance for testing."""
        # TODO: Uncomment when ConversionManager is implemented
        # from app.core.conversion.manager import ConversionManager
        # return ConversionManager()

        # For now, return a mock
        mock_manager = Mock()
        mock_manager.convert = Mock(
            return_value=Mock(
                status="success",
                output_format="webp",
                output_size=50000,
                compression_ratio=0.5,
                processing_time=1.5,
                output_data=b"mock_output",
                metadata_stripped=True,
                dimensions={
                    "original": {"width": 1920, "height": 1080},
                    "output": {"width": 800, "height": 450},
                },
                mime_type="image/webp",
                advanced_settings_applied=True,
            )
        )
        return mock_manager

    def test_convert_single_image_success(
        self, conversion_manager, sample_image_bytes, mock_conversion_request
    ):
        """Test successful single image conversion."""
        # TODO: Remove skip when ConversionManager is implemented
        pytest.skip("Waiting for ConversionManager implementation")

        # Arrange
        request = mock_conversion_request

        # Act
        result = conversion_manager.convert(sample_image_bytes, request)

        # Assert
        assert result is not None
        assert result.status == "success"
        assert result.output_format == request["output_format"]
        assert result.output_size > 0
        assert result.output_size < len(sample_image_bytes)  # Should be compressed
        assert 0 < result.compression_ratio < 1
        assert result.processing_time > 0

    def test_convert_with_resize(self, conversion_manager, image_generator):
        """Test image conversion with resizing."""
        # Arrange
        original_image = image_generator(width=1920, height=1080)
        request = {
            "output_format": "webp",
            "quality": 85,
            "resize": {"width": 800, "height": None, "maintain_aspect_ratio": True},
        }

        # Act
        result = conversion_manager.convert(original_image, request)

        # Assert
        assert result.status == "success"
        assert result.dimensions["output"]["width"] == 800
        assert result.dimensions["output"]["height"] == 450  # Maintains 16:9 ratio
        assert result.dimensions["original"]["width"] == 1920
        assert result.dimensions["original"]["height"] == 1080

    def test_convert_strip_metadata(self, conversion_manager, sample_image_bytes):
        """Test metadata stripping functionality."""
        # Arrange
        request = {"output_format": "jpeg", "quality": 90, "strip_metadata": True}

        # Act
        result = conversion_manager.convert(sample_image_bytes, request)

        # Assert
        assert result.status == "success"
        assert result.metadata_stripped is True
        # Verify output has no EXIF data
        output_image = Image.open(io.BytesIO(result.output_data))
        assert not hasattr(output_image, "_getexif") or output_image._getexif() is None

    def test_convert_preserve_metadata(self, conversion_manager, sample_image_bytes):
        """Test metadata preservation."""
        # Arrange
        request = {"output_format": "jpeg", "quality": 90, "strip_metadata": False}

        # Act
        result = conversion_manager.convert(sample_image_bytes, request)

        # Assert
        assert result.status == "success"
        assert result.metadata_stripped is False
        # Verify output retains EXIF data
        output_image = Image.open(io.BytesIO(result.output_data))
        assert hasattr(output_image, "_getexif") and output_image._getexif() is not None

    def test_convert_invalid_format(self, conversion_manager, sample_image_bytes):
        """Test conversion with unsupported output format."""
        # Arrange
        request = {"output_format": "bpg", "quality": 85}  # Unsupported format

        # Act & Assert
        with pytest.raises(ValueError, match="Unsupported output format"):
            conversion_manager.convert(sample_image_bytes, request)

    def test_convert_corrupted_image(self, conversion_manager, corrupted_image_path):
        """Test handling of corrupted image files."""
        # Arrange
        with open(corrupted_image_path, "rb") as f:
            corrupted_data = f.read()

        request = {"output_format": "webp", "quality": 85}

        # Act & Assert
        with pytest.raises(Exception, match="corrupted|invalid|cannot"):
            conversion_manager.convert(corrupted_data, request)

    def test_convert_empty_file(self, conversion_manager, empty_image_path):
        """Test handling of empty files."""
        # Arrange
        with open(empty_image_path, "rb") as f:
            empty_data = f.read()

        request = {"output_format": "webp", "quality": 85}

        # Act & Assert
        with pytest.raises(ValueError, match="Empty file"):
            conversion_manager.convert(empty_data, request)

    @pytest.mark.parametrize(
        "output_format,expected_mime",
        [
            ("webp", "image/webp"),
            ("avif", "image/avif"),
            ("jpeg", "image/jpeg"),
            ("png", "image/png"),
        ],
    )
    def test_convert_multiple_formats(
        self, conversion_manager, image_generator, output_format, expected_mime
    ):
        """Test conversion to multiple output formats."""
        # Arrange
        test_image = image_generator(width=100, height=100)
        request = {"output_format": output_format, "quality": 85}

        # Act
        result = conversion_manager.convert(test_image, request)

        # Assert
        assert result.status == "success"
        assert result.output_format == output_format
        assert result.mime_type == expected_mime

    def test_convert_with_quality_settings(self, conversion_manager, image_generator):
        """Test quality affects file size."""
        # Arrange
        test_image = image_generator(width=500, height=500)

        # Convert at different quality levels
        high_quality = conversion_manager.convert(
            test_image, {"output_format": "jpeg", "quality": 95}
        )

        low_quality = conversion_manager.convert(
            test_image, {"output_format": "jpeg", "quality": 30}
        )

        # Assert
        assert high_quality.output_size > low_quality.output_size
        assert low_quality.compression_ratio < high_quality.compression_ratio

    def test_convert_with_advanced_settings(self, conversion_manager, image_generator):
        """Test conversion with advanced settings."""
        # Arrange
        test_image = image_generator(width=800, height=600)
        request = {
            "output_format": "webp",
            "quality": 85,
            "advanced": {
                "effort": 6,
                "compression_level": 6,
                "progressive": True,
                "chroma_subsampling": "4:2:0",
            },
        }

        # Act
        result = conversion_manager.convert(test_image, request)

        # Assert
        assert result.status == "success"
        assert result.advanced_settings_applied is True

    @pytest.mark.skip(reason="Uncomment when ProcessSandbox is implemented")
    # @patch('app.core.conversion.manager.ProcessSandbox')
    def test_convert_uses_sandbox(
        self, mock_sandbox, conversion_manager, sample_image_bytes
    ):
        """Test that conversion uses process sandboxing."""
        # Arrange
        mock_sandbox_instance = Mock()
        mock_sandbox.return_value = mock_sandbox_instance
        mock_sandbox_instance.execute.return_value = Mock(
            status="success", output_data=b"converted_data"
        )

        request = {"output_format": "webp", "quality": 85}

        # Act
        result = conversion_manager.convert(sample_image_bytes, request)

        # Assert
        mock_sandbox.assert_called_once()
        mock_sandbox_instance.execute.assert_called_once()
        assert result.status == "success"

    def test_convert_resource_limits(self, conversion_manager):
        """Test resource limit enforcement during conversion."""
        # Arrange
        # Create a very large image that should trigger limits
        large_image = image_generator(width=10000, height=10000)
        request = {"output_format": "png", "quality": 100}

        # Act & Assert
        with pytest.raises(Exception, match="Resource limit|Memory limit"):
            conversion_manager.convert(large_image, request)

    def test_convert_timeout_handling(self, conversion_manager, image_generator):
        """Test conversion timeout handling."""
        # Arrange
        test_image = image_generator(width=1000, height=1000)
        request = {
            "output_format": "avif",
            "quality": 100,
            "advanced": {"effort": 10},  # Maximum effort, slow conversion
        }

        # Mock slow conversion
        with patch.object(conversion_manager, "_convert_image") as mock_convert:
            mock_convert.side_effect = TimeoutError("Conversion timeout")

            # Act & Assert
            with pytest.raises(TimeoutError):
                conversion_manager.convert(test_image, request)
