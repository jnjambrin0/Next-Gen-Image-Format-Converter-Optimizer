"""Unit tests for encoding options."""

from typing import Any

import pytest

from app.core.optimization.encoding_options import (
    ChromaSubsampling,
    EncodingOptions,
    QuantizationTable,
)
from app.core.security.errors_simplified import SecurityError


class TestEncodingOptions:
    """Test cases for EncodingOptions."""

    @pytest.fixture
    def encoding_options(self) -> None:
        """Create an EncodingOptions instance."""
        return EncodingOptions()

    def test_validate_options_jpeg(self, encoding_options) -> None:
        """Test JPEG encoding options validation."""
        options = encoding_options.validate_options(
            "jpeg",
            chroma_subsampling=ChromaSubsampling.YUV420,
            progressive=True,
            lossless=False,  # JPEG doesn't support lossless
            alpha_quality=50,  # JPEG doesn't support alpha
        )

        # Should include supported options
        assert options["chroma_subsampling"] == ChromaSubsampling.YUV420
        assert options["progressive"] is True
        # Should not include unsupported options
        assert "lossless" not in options
        assert "alpha_quality" not in options

    def test_validate_options_webp(self, encoding_options) -> None:
        """Test WebP encoding options validation."""
        options = encoding_options.validate_options(
            "webp",
            chroma_subsampling=ChromaSubsampling.YUV444,
            lossless=True,
            alpha_quality=90,
        )

        assert options["chroma_subsampling"] == ChromaSubsampling.YUV444
        assert options["lossless"] is True
        assert options["alpha_quality"] == 90

    def test_validate_options_png(self, encoding_options) -> None:
        """Test PNG encoding options validation."""
        options = encoding_options.validate_options(
            "png",
            progressive=True,
            lossless=True,
            chroma_subsampling=ChromaSubsampling.YUV420,  # PNG doesn't support this
        )

        assert options["progressive"] is True
        assert options["lossless"] is True
        # Should not include unsupported options
        assert "chroma_subsampling" not in options

    def test_validate_options_unsupported_format(self, encoding_options) -> None:
        """Test validation with unsupported format."""
        with pytest.raises(SecurityError) as exc_info:
            encoding_options.validate_options("bmp")
        assert exc_info.value  # Just verify SecurityError was raised

    def test_validate_custom_quantization(self, encoding_options) -> None:
        """Test custom quantization table validation."""
        # Valid quantization table
        valid_table = QuantizationTable(
            luminance=[[16] * 8 for _ in range(8)],
            chrominance=[[17] * 8 for _ in range(8)],
        )

        options = encoding_options.validate_options(
            "jpeg", custom_quantization=valid_table
        )

        assert options["custom_quantization"] == valid_table

        # Invalid quantization table (wrong dimensions)
        invalid_table = QuantizationTable(
            luminance=[[16] * 7 for _ in range(8)],  # Wrong width
            chrominance=[[17] * 8 for _ in range(8)],
        )

        with pytest.raises(SecurityError) as exc_info:
            encoding_options.validate_options("jpeg", custom_quantization=invalid_table)
        assert exc_info.value  # Just verify SecurityError was raised

    def test_validate_alpha_quality_range(self, encoding_options) -> None:
        """Test alpha quality validation."""
        # Valid range
        options = encoding_options.validate_options("webp", alpha_quality=50)
        assert options["alpha_quality"] == 50

        # Invalid range
        with pytest.raises(SecurityError) as exc_info:
            encoding_options.validate_options("webp", alpha_quality=150)  # Out of range
        assert exc_info.value  # Just verify SecurityError was raised

    def test_get_pillow_save_params_jpeg(self, encoding_options) -> None:
        """Test Pillow save parameters for JPEG."""
        options = {"progressive": True, "chroma_subsampling": ChromaSubsampling.YUV420}

        params = encoding_options.get_pillow_save_params("jpeg", options, quality=85)

        assert params["quality"] == 85
        assert params["progressive"] is True
        assert params["subsampling"] == 2  # 4:2:0

    def test_get_pillow_save_params_png(self, encoding_options) -> None:
        """Test Pillow save parameters for PNG."""
        options = {"progressive": True, "lossless": True}

        params = encoding_options.get_pillow_save_params("png", options)

        assert params["progressive"] is True
        assert params["compress_level"] == 9  # Max compression for lossless

    def test_get_pillow_save_params_webp(self, encoding_options) -> None:
        """Test Pillow save parameters for WebP."""
        options = {"lossless": True, "alpha_quality": 80}

        params = encoding_options.get_pillow_save_params("webp", options, quality=90)

        assert params["lossless"] is True
        assert params["alpha_quality"] == 80
        assert "quality" not in params  # Quality not used in lossless mode

    def test_scale_quantization_table(self, encoding_options) -> None:
        """Test quantization table scaling."""
        base_table = [
            [16, 11, 10, 16, 24, 40, 51, 61],
            [12, 12, 14, 19, 26, 58, 60, 55],
            [14, 13, 16, 24, 40, 57, 69, 56],
            [14, 17, 22, 29, 51, 87, 80, 62],
            [18, 22, 37, 56, 68, 109, 103, 77],
            [24, 35, 55, 64, 81, 104, 113, 92],
            [49, 64, 78, 87, 103, 121, 120, 101],
            [72, 92, 95, 98, 112, 100, 103, 99],
        ]

        # Test with high quality (should reduce values)
        scaled_high = encoding_options.scale_quantization_table(base_table, 90)
        assert scaled_high[0][0] < base_table[0][0]

        # Test with low quality (should increase values)
        scaled_low = encoding_options.scale_quantization_table(base_table, 10)
        assert scaled_low[0][0] > base_table[0][0]

        # Test bounds
        with pytest.raises(SecurityError) as exc_info:
            encoding_options.scale_quantization_table(base_table, 150)
        assert exc_info.value  # Just verify SecurityError was raised

    def test_get_format_capabilities(self, encoding_options) -> None:
        """Test getting format capabilities."""
        jpeg_caps = encoding_options.get_format_capabilities("jpeg")
        assert jpeg_caps["chroma_subsampling"] is True
        assert jpeg_caps["progressive"] is True
        assert jpeg_caps["lossless"] is False

        webp_caps = encoding_options.get_format_capabilities("webp")
        assert webp_caps["lossless"] is True
        assert webp_caps["alpha"] is True

        # Unknown format
        unknown_caps = encoding_options.get_format_capabilities("unknown")
        assert unknown_caps == {}

    def test_chroma_subsampling_enum(self) -> None:
        """Test ChromaSubsampling enum values."""
        assert ChromaSubsampling.YUV444.value == "444"
        assert ChromaSubsampling.YUV422.value == "422"
        assert ChromaSubsampling.YUV420.value == "420"
        assert ChromaSubsampling.AUTO.value == "auto"

    def test_quantization_table_validation(self) -> None:
        """Test QuantizationTable validation method."""
        # Valid table
        valid_table = QuantizationTable(
            luminance=[[1] * 8 for _ in range(8)],
            chrominance=[[2] * 8 for _ in range(8)],
        )
        assert valid_table.validate() is True

        # Invalid width
        invalid_width = QuantizationTable(
            luminance=[[1] * 7 for _ in range(8)],
            chrominance=[[2] * 8 for _ in range(8)],
        )
        assert invalid_width.validate() is False

        # Invalid height
        invalid_height = QuantizationTable(
            luminance=[[1] * 8 for _ in range(7)],
            chrominance=[[2] * 8 for _ in range(8)],
        )
        assert invalid_height.validate() is False
