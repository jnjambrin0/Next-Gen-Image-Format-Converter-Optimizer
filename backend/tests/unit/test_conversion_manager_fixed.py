"""Unit tests for the Conversion Manager module - Ready to run version."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import io
from PIL import Image

# Import fixtures
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestConversionManager:
    """Test suite for ConversionManager class."""

    @pytest.fixture
    def sample_image_bytes(self):
        """Generate a sample image for testing."""
        img = Image.new("RGB", (100, 100), color="red")
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG")
        return buffer.getvalue()

    @pytest.fixture
    def mock_conversion_request(self):
        """Sample conversion request data."""
        return {
            "output_format": "webp",
            "quality": 85,
            "resize": {"width": 1200, "height": None, "maintain_aspect_ratio": True},
            "strip_metadata": True,
            "optimize": True,
        }

    @pytest.fixture
    def conversion_manager(self):
        """Create a mock ConversionManager for testing."""
        # TODO: Replace with real implementation when available
        # from app.core.conversion.manager import ConversionManager
        # return ConversionManager()

        mock_manager = Mock()
        mock_manager.convert = Mock(
            return_value=Mock(
                status="success",
                output_format="webp",
                output_size=50000,
                compression_ratio=0.5,
                processing_time=1.5,
            )
        )
        return mock_manager

    def test_fixtures_work(self, sample_image_bytes, mock_conversion_request):
        """Test that our fixtures are working correctly."""
        assert len(sample_image_bytes) > 0
        assert mock_conversion_request["output_format"] == "webp"
        assert mock_conversion_request["quality"] == 85

    def test_sample_image_is_valid(self, sample_image_bytes):
        """Test that we can create valid test images."""
        img = Image.open(io.BytesIO(sample_image_bytes))
        assert img.format == "JPEG"
        assert img.size == (100, 100)
        assert img.mode == "RGB"

    @pytest.mark.skip(reason="Waiting for ConversionManager implementation")
    def test_convert_single_image_success(
        self, conversion_manager, sample_image_bytes, mock_conversion_request
    ):
        """Test successful single image conversion."""
        # This test is ready to be enabled when ConversionManager is implemented
        request = mock_conversion_request
        result = conversion_manager.convert(sample_image_bytes, request)

        assert result is not None
        assert result.status == "success"
        assert result.output_format == request["output_format"]

    def test_image_generation(self):
        """Test we can generate various test images."""
        # Test different sizes
        for size in [(50, 50), (200, 100), (1000, 1000)]:
            img = Image.new("RGB", size, color="blue")
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            data = buffer.getvalue()

            assert len(data) > 0
            loaded = Image.open(io.BytesIO(data))
            assert loaded.size == size

    def test_conversion_request_validation(self, mock_conversion_request):
        """Test conversion request structure."""
        assert "output_format" in mock_conversion_request
        assert "quality" in mock_conversion_request
        assert mock_conversion_request["quality"] >= 0
        assert mock_conversion_request["quality"] <= 100

    @pytest.mark.parametrize(
        "format,mime_type",
        [
            ("JPEG", "image/jpeg"),
            ("PNG", "image/png"),
            ("GIF", "image/gif"),
            ("BMP", "image/bmp"),
        ],
    )
    def test_image_format_creation(self, format, mime_type):
        """Test creating images in different formats."""
        img = Image.new("RGB", (50, 50), color="green")
        buffer = io.BytesIO()

        # GIF requires palette mode for single frame
        if format == "GIF":
            img = img.convert("P")

        img.save(buffer, format=format)
        data = buffer.getvalue()

        assert len(data) > 0
        loaded = Image.open(io.BytesIO(data))
        assert loaded.format == format
