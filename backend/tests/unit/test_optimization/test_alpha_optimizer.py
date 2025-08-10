"""Unit tests for the AlphaOptimizer."""

from typing import Any
import io

import pytest
from PIL import Image

from app.core.optimization.alpha_optimizer import AlphaOptimizer
from app.core.security.errors_simplified import SecurityError


class TestAlphaOptimizer:
    """Test cases for AlphaOptimizer."""

    @pytest.fixture
    def optimizer(self) -> None:
        """Create an AlphaOptimizer instance."""
        return AlphaOptimizer()

    @pytest.fixture
    def test_image_rgba(self) -> None:
        """Create a test RGBA image with alpha channel."""
        img = Image.new("RGBA", (100, 100))
        pixels = img.load()

        # Create gradient alpha channel
        for y in range(100):
            for x in range(100):
                # Red channel full, green/blue based on position
                # Alpha gradient from top-left (transparent) to bottom-right (opaque)
                alpha = int((x + y) * 255 / 200)
                pixels[x, y] = (255, x * 255 // 100, y * 255 // 100, alpha)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    @pytest.fixture
    def test_image_rgb(self) -> None:
        """Create a test RGB image without alpha."""
        img = Image.new("RGB", (100, 100), color="red")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    @pytest.fixture
    def test_image_binary_alpha(self) -> None:
        """Create image with binary alpha (fully transparent or opaque)."""
        img = Image.new("RGBA", (100, 100))
        pixels = img.load()

        # Make a checkerboard pattern
        for y in range(100):
            for x in range(100):
                if (x // 10 + y // 10) % 2 == 0:
                    pixels[x, y] = (255, 0, 0, 255)  # Opaque red
                else:
                    pixels[x, y] = (0, 255, 0, 0)  # Transparent green

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    @pytest.mark.asyncio
    async def test_optimize_alpha_basic(self, optimizer, test_image_rgba):
        """Test basic alpha channel optimization."""
        result, info = await optimizer.optimize_alpha(
            test_image_rgba, "webp", alpha_quality=80
        )

        assert isinstance(result, bytes)
        assert len(result) > 0
        assert info["has_alpha"] is True
        assert info["alpha_usage"] in ["simple", "complex", "mostly_binary", "binary"]
        assert "transparent_pixel_count" in info
        assert "alpha_complexity" in info

    @pytest.mark.asyncio
    async def test_optimize_no_alpha(self, optimizer, test_image_rgb):
        """Test optimization of image without alpha channel."""
        result, info = await optimizer.optimize_alpha(
            test_image_rgb, "jpeg", alpha_quality=80
        )

        assert result == test_image_rgb  # Should return unchanged
        assert info["has_alpha"] is False
        assert info["alpha_usage"] == "none"
        assert info["removed_alpha"] is False

    @pytest.mark.asyncio
    async def test_remove_unnecessary_alpha(self, optimizer):
        """Test removal of unnecessary alpha channel."""
        # Create fully opaque image
        img = Image.new("RGBA", (100, 100), color=(255, 0, 0, 255))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        opaque_data = buffer.getvalue()

        result, info = await optimizer.optimize_alpha(
            opaque_data, "jpeg", remove_unnecessary=True
        )

        # Load result and check it's RGB
        result_img = Image.open(io.BytesIO(result))
        assert result_img.mode == "RGB"
        assert info["removed_alpha"] is True
        assert info["alpha_usage"] == "unnecessary"

    @pytest.mark.asyncio
    async def test_binary_alpha_optimization(self, optimizer, test_image_binary_alpha):
        """Test optimization of binary alpha channel."""
        result, info = await optimizer.optimize_alpha(
            test_image_binary_alpha, "png", alpha_quality=100
        )

        assert info["has_alpha"] is True
        assert info["alpha_usage"] == "binary"
        assert info["alpha_complexity"] == 0.0  # No semi-transparent pixels

    @pytest.mark.asyncio
    async def test_separate_alpha_quality_webp(self, optimizer, test_image_rgba):
        """Test separate alpha quality for WebP format."""
        result, info = await optimizer.optimize_alpha(
            test_image_rgba, "webp", alpha_quality=50, separate_quality=True
        )

        assert info["alpha_compressed"] is True
        # Result should be smaller due to lower alpha quality
        assert len(result) < len(test_image_rgba)

    @pytest.mark.asyncio
    async def test_alpha_quantization(self, optimizer):
        """Test alpha channel quantization."""
        # Create image with low alpha complexity (mostly opaque with some transparency)
        img = Image.new("RGBA", (50, 50))
        pixels = img.load()

        for y in range(50):
            for x in range(50):
                # Mostly opaque with very few semi-transparent pixels
                if x == 0 or y == 0:  # Only the very edge
                    alpha = 128  # Semi-transparent edges
                else:
                    alpha = 255  # Fully opaque
                pixels[x, y] = (255, 0, 0, alpha)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        low_complexity_data = buffer.getvalue()

        result, info = await optimizer.optimize_alpha(
            low_complexity_data, "png", remove_unnecessary=False
        )

        # Should be compressed due to low complexity (<0.1)
        assert info["alpha_compressed"] is True
        assert info["alpha_complexity"] < 0.1  # Low complexity triggers quantization

    @pytest.mark.asyncio
    async def test_input_validation(self, optimizer):
        """Test input validation."""
        # Test invalid input type
        with pytest.raises(SecurityError):
            await optimizer.optimize_alpha("not bytes", "webp")

        # Test empty input
        with pytest.raises(SecurityError):
            await optimizer.optimize_alpha(b"", "webp")

        # Test too large input
        # IMAGE_MAX_PIXELS * 4 is the limit, which is about 715MB
        # Create data slightly larger than that
        large_data = b"x" * (179_000_000 * 4)  # Just over the limit
        with pytest.raises(SecurityError):
            await optimizer.optimize_alpha(large_data, "webp")

    @pytest.mark.asyncio
    async def test_analyze_alpha_channel(self, optimizer, test_image_rgba):
        """Test alpha channel analysis."""
        analysis = await optimizer.analyze_alpha_channel(test_image_rgba)

        assert analysis["has_alpha"] is True
        assert "alpha_usage" in analysis
        assert "fully_transparent_pixels" in analysis
        assert "fully_opaque_pixels" in analysis
        assert "semi_transparent_pixels" in analysis
        assert "transparency_ratio" in analysis
        assert "alpha_complexity" in analysis
        assert "recommended_action" in analysis

    @pytest.mark.asyncio
    async def test_grayscale_alpha(self, optimizer):
        """Test grayscale image with alpha."""
        img = Image.new("LA", (100, 100))
        pixels = img.load()

        for y in range(100):
            for x in range(100):
                gray = x * 255 // 100
                alpha = y * 255 // 100
                pixels[x, y] = (gray, alpha)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        la_data = buffer.getvalue()

        result, info = await optimizer.optimize_alpha(la_data, "png", alpha_quality=90)

        assert info["has_alpha"] is True
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_palette_mode_transparency(self, optimizer):
        """Test palette mode image with transparency."""
        # Create palette image
        img = Image.new("P", (100, 100))
        img.putpalette([i // 3 for i in range(768)])  # Simple palette

        # Set transparency for palette index 0
        img.info["transparency"] = 0

        # Fill with different palette indices
        pixels = img.load()
        for y in range(100):
            for x in range(100):
                pixels[x, y] = (x + y) % 256

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        p_data = buffer.getvalue()

        result, info = await optimizer.optimize_alpha(p_data, "png")

        assert info["has_alpha"] is True
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_different_output_formats(self, optimizer, test_image_rgba):
        """Test optimization for different output formats."""
        formats = ["webp", "png", "avif"]

        for fmt in formats:
            result, info = await optimizer.optimize_alpha(
                test_image_rgba, fmt, alpha_quality=85
            )

            assert len(result) > 0
            assert info["has_alpha"] is True

    @pytest.mark.asyncio
    async def test_recommendation_logic(self, optimizer):
        """Test alpha optimization recommendations."""
        # Test unnecessary alpha
        img = Image.new("RGBA", (50, 50), (255, 0, 0, 255))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")

        analysis = await optimizer.analyze_alpha_channel(buffer.getvalue())
        assert analysis["recommended_action"] == "remove_alpha"

        # Test binary alpha
        img = Image.new("RGBA", (50, 50))
        pixels = img.load()
        for y in range(50):
            for x in range(50):
                pixels[x, y] = (255, 0, 0, 255 if x < 25 else 0)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")

        analysis = await optimizer.analyze_alpha_channel(buffer.getvalue())
        assert analysis["recommended_action"] == "use_palette_transparency"
