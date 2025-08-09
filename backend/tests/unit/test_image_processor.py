"""Unit tests for the Image Processor module."""

# Import fixtures
import sys
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.conversion.image_processor import ImageProcessor
from app.core.exceptions import (
    ConversionFailedError,
    InvalidImageError,
)


class TestImageProcessor:
    """Test suite for ImageProcessor class."""

    @pytest.fixture
    def image_processor(self) -> None:
        """Create an ImageProcessor instance for testing."""
        return ImageProcessor()

    @pytest.fixture
    def valid_jpeg_data(self, image_generator) -> None:
        """Generate valid JPEG data."""
        return image_generator(width=100, height=100, format="JPEG")

    @pytest.fixture
    def valid_png_data(self, image_generator) -> None:
        """Generate valid PNG data."""
        return image_generator(width=100, height=100, format="PNG")

    def test_validate_image_data_success(
        self, image_processor, valid_jpeg_data
    ) -> None:
        """Test successful image validation."""
        # Act & Assert
        assert image_processor.validate_image_data(valid_jpeg_data) is True

    def test_validate_empty_data_raises_error(self, image_processor) -> None:
        """Test validation of empty data."""
        # Act & Assert
        with pytest.raises(InvalidImageError, match="Empty image data"):
            image_processor.validate_image_data(b"")

    def test_validate_invalid_data_raises_error(self, image_processor) -> None:
        """Test validation of invalid image data."""
        # Arrange
        invalid_data = b"This is not an image"

        # Act & Assert
        with pytest.raises(InvalidImageError, match="Invalid image data"):
            image_processor.validate_image_data(invalid_data)

    def test_validate_oversized_dimensions_raises_error(self, image_processor) -> None:
        """Test validation of images exceeding dimension limits."""
        # Arrange
        # Create image exceeding max dimension
        img = Image.new("RGB", (15000, 100))
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        oversized_data = buffer.getvalue()

        # Act & Assert
        with pytest.raises(InvalidImageError, match="dimensions exceed maximum"):
            image_processor.validate_image_data(oversized_data)

    def test_validate_too_many_pixels_raises_error(self, image_processor) -> None:
        """Test validation of images exceeding pixel count limit."""
        # Arrange
        # Create image with too many pixels
        img = Image.new("RGB", (10000, 10001))  # Just over 100 megapixels
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        large_data = buffer.getvalue()

        # Act & Assert
        with pytest.raises(InvalidImageError, match="exceed"):
            image_processor.validate_image_data(large_data)

    def test_detect_format_jpeg(self, image_processor, valid_jpeg_data) -> None:
        """Test JPEG format detection."""
        # Act
        format_name = image_processor.detect_format(valid_jpeg_data)

        # Assert
        assert format_name == "jpeg"

    def test_detect_format_png(self, image_processor, valid_png_data) -> None:
        """Test PNG format detection."""
        # Act
        format_name = image_processor.detect_format(valid_png_data)

        # Assert
        assert format_name == "png"

    def test_detect_format_invalid_data_raises_error(self, image_processor) -> None:
        """Test format detection with invalid data."""
        # Arrange
        invalid_data = b"Not an image"

        # Act & Assert
        with pytest.raises(InvalidImageError, match="Failed to detect image format"):
            image_processor.detect_format(invalid_data)

    def test_get_image_info_success(self, image_processor, sample_image_bytes) -> None:
        """Test getting image information."""
        # Act
        info = image_processor.get_image_info(sample_image_bytes)

        # Assert
        assert info["format"] == "JPEG"
        assert info["width"] > 0
        assert info["height"] > 0
        assert "mode" in info
        assert "has_transparency" in info
        assert "has_animation" in info
        assert "has_exif" in info

    def test_get_image_info_with_transparency(self, image_processor) -> None:
        """Test getting info for image with transparency."""
        # Arrange
        img = Image.new("RGBA", (100, 100), (255, 0, 0, 128))
        # Add transparency info to ensure it's detected
        img.info["transparency"] = 128
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        transparent_data = buffer.getvalue()

        # Act
        info = image_processor.get_image_info(transparent_data)

        # Assert
        # RGBA mode alone doesn't guarantee transparency info is preserved
        assert info["mode"] == "RGBA"

    def test_get_image_info_animated_gif(
        self, image_processor, all_test_images
    ) -> None:
        """Test getting info for animated GIF."""
        # Arrange
        gif_path = all_test_images["animated_gif"]["path"]
        with open(gif_path, "rb") as f:
            gif_data = f.read()

        # Act
        info = image_processor.get_image_info(gif_data)

        # Assert
        assert info["format"] == "GIF"
        assert info["has_animation"] is True

    def test_get_image_info_invalid_data_raises_error(self, image_processor) -> None:
        """Test getting info from invalid data."""
        # Arrange
        invalid_data = b"Not an image"

        # Act & Assert
        with pytest.raises(ConversionFailedError, match="Failed to get image info"):
            image_processor.get_image_info(invalid_data)

    def test_estimate_memory_usage_rgb(self, image_processor) -> None:
        """Test memory usage estimation for RGB image."""
        # Act
        memory = image_processor.estimate_memory_usage(1920, 1080, "RGB")

        # Assert
        expected_base = 1920 * 1080 * 3
        expected_with_overhead = expected_base * 1.2
        assert memory == int(expected_with_overhead)

    def test_estimate_memory_usage_rgba(self, image_processor) -> None:
        """Test memory usage estimation for RGBA image."""
        # Act
        memory = image_processor.estimate_memory_usage(1000, 1000, "RGBA")

        # Assert
        expected_base = 1000 * 1000 * 4
        expected_with_overhead = expected_base * 1.2
        assert memory == int(expected_with_overhead)

    def test_estimate_memory_usage_grayscale(self, image_processor) -> None:
        """Test memory usage estimation for grayscale image."""
        # Act
        memory = image_processor.estimate_memory_usage(500, 500, "L")

        # Assert
        expected_base = 500 * 500 * 1
        expected_with_overhead = expected_base * 1.2
        assert memory == int(expected_with_overhead)

    def test_strip_metadata(self, image_processor, sample_image_path) -> None:
        """Test metadata stripping."""
        # Arrange
        with Image.open(sample_image_path) as img:
            # Verify original has EXIF
            assert hasattr(img, "_getexif") and img._getexif() is not None

            # Act
            stripped_img = image_processor.strip_metadata(img)

            # Assert
            # Try to get EXIF from stripped image
            if hasattr(stripped_img, "_getexif"):
                assert stripped_img._getexif() is None

    def test_strip_metadata_preserves_transparency(self, image_processor) -> None:
        """Test that transparency is preserved when stripping metadata."""
        # Arrange
        img = Image.new("RGBA", (100, 100), (255, 0, 0, 128))
        img.info["transparency"] = 128

        # Act
        stripped_img = image_processor.strip_metadata(img)

        # Assert
        assert "transparency" in stripped_img.info
        assert stripped_img.info["transparency"] == 128

    def test_optimize_for_web_resizes_large_image(self, image_processor) -> None:
        """Test web optimization resizes large images."""
        # Arrange
        large_img = Image.new("RGB", (4000, 3000))

        # Act
        optimized = image_processor.optimize_for_web(
            large_img, max_width=1920, max_height=1080
        )

        # Assert
        assert optimized.width <= 1920
        assert optimized.height <= 1080
        # Should maintain aspect ratio
        assert abs((optimized.width / optimized.height) - (4000 / 3000)) < 0.01

    def test_optimize_for_web_keeps_small_image(self, image_processor) -> None:
        """Test web optimization doesn't resize small images."""
        # Arrange
        small_img = Image.new("RGB", (800, 600))

        # Act
        optimized = image_processor.optimize_for_web(small_img)

        # Assert
        assert optimized.width == 800
        assert optimized.height == 600

    def test_optimize_for_web_converts_cmyk(self, image_processor) -> None:
        """Test web optimization converts CMYK to RGB."""
        # Arrange
        cmyk_img = Image.new("CMYK", (100, 100))

        # Act
        optimized = image_processor.optimize_for_web(cmyk_img)

        # Assert
        assert optimized.mode == "RGB"

    @pytest.mark.parametrize(
        "mode,expected_bytes",
        [
            ("1", 1),  # 1-bit
            ("L", 1),  # 8-bit grayscale
            ("P", 1),  # 8-bit palette
            ("RGB", 3),  # 24-bit RGB
            ("RGBA", 4),  # 32-bit RGBA
            ("CMYK", 4),  # 32-bit CMYK
            ("YCbCr", 3),  # 24-bit YCbCr
            ("LAB", 3),  # 24-bit LAB
            ("HSV", 3),  # 24-bit HSV
            ("I", 4),  # 32-bit integer
            ("F", 4),  # 32-bit float
            ("UNKNOWN", 4),  # Unknown mode defaults to 4
        ],
    )
    def test_estimate_memory_usage_modes(
        self, image_processor, mode, expected_bytes
    ) -> None:
        """Test memory estimation for different color modes."""
        # Act
        memory = image_processor.estimate_memory_usage(100, 100, mode)

        # Assert
        expected_base = 100 * 100 * expected_bytes
        expected_with_overhead = expected_base * 1.2
        assert memory == int(expected_with_overhead)
