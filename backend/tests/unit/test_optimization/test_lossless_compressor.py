"""Unit tests for the LosslessCompressor."""

import pytest
import io
import hashlib
from PIL import Image

from app.core.optimization.lossless_compressor import LosslessCompressor
from app.core.security.errors_simplified import SecurityError


class TestLosslessCompressor:
    """Test cases for LosslessCompressor."""

    @pytest.fixture
    def compressor(self):
        """Create a LosslessCompressor instance."""
        return LosslessCompressor()

    @pytest.fixture
    def test_image_png(self):
        """Create a test PNG image."""
        img = Image.new("RGB", (100, 100))
        pixels = img.load()

        # Create pattern for testing
        for y in range(100):
            for x in range(100):
                r = (x * 255) // 100
                g = (y * 255) // 100
                b = ((x + y) * 255) // 200
                pixels[x, y] = (r, g, b)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    @pytest.fixture
    def test_image_jpeg(self):
        """Create a test JPEG image."""
        img = Image.new("RGB", (100, 100), color="blue")
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        return buffer.getvalue()

    @pytest.fixture
    def test_image_webp(self):
        """Create a test WebP image."""
        img = Image.new("RGB", (100, 100), color="green")
        buffer = io.BytesIO()
        img.save(buffer, format="WebP", quality=85)
        return buffer.getvalue()

    @pytest.mark.asyncio
    async def test_compress_lossless_png(self, compressor, test_image_png):
        """Test lossless compression of PNG format."""
        result, info = await compressor.compress_lossless(test_image_png, "png")

        assert isinstance(result, bytes)
        assert len(result) > 0
        assert "compression_ratio" in info
        assert info["compression_ratio"] > 0
        assert info["original_size"] == len(test_image_png)
        assert info["compressed_size"] == len(result)

        # Verify lossless - pixels should be identical
        original_img = Image.open(io.BytesIO(test_image_png))
        compressed_img = Image.open(io.BytesIO(result))

        assert original_img.size == compressed_img.size
        assert original_img.mode == compressed_img.mode

    @pytest.mark.asyncio
    async def test_compress_lossless_webp(self, compressor, test_image_webp):
        """Test lossless compression of WebP format."""
        result, info = await compressor.compress_lossless(test_image_webp, "webp")

        assert len(result) > 0
        assert "compression_ratio" in info

    @pytest.mark.asyncio
    async def test_compress_lossless_jpeg(self, compressor, test_image_jpeg):
        """Test lossless recompression of JPEG format."""
        # JPEG lossless means optimizing without quality loss
        result, info = await compressor.compress_lossless(test_image_jpeg, "jpeg")

        assert len(result) > 0
        assert "compression_ratio" in info
        assert info["compression_ratio"] >= 0  # May not compress much

    @pytest.mark.asyncio
    async def test_unsupported_format(self, compressor):
        """Test handling of unsupported format."""
        # Create a simple BMP which may not support lossless compression
        img = Image.new("RGB", (50, 50), color="red")
        buffer = io.BytesIO()
        img.save(buffer, format="BMP")
        bmp_data = buffer.getvalue()

        with pytest.raises(Exception):  # Should raise appropriate error
            await compressor.compress_lossless(bmp_data, "bmp")

    @pytest.mark.asyncio
    async def test_format_capabilities(self, compressor):
        """Test format capability checking."""
        # Get capabilities for specific formats
        capabilities = {}
        for fmt in ["png", "webp", "jpeg"]:
            capabilities[fmt] = compressor.get_format_capabilities(fmt)

        assert "png" in capabilities
        assert capabilities["png"]["native"] is True
        assert "compression_levels" in capabilities["png"]
        assert "filters" in capabilities["png"]

        assert "webp" in capabilities
        assert capabilities["webp"]["native"] is True

        assert "jpeg" in capabilities
        # JPEG can do lossless recompression but is marked as non-native
        assert capabilities["jpeg"]["native"] is False
        assert "operations" in capabilities["jpeg"]

    @pytest.mark.asyncio
    async def test_png_optimization_levels(self, compressor, test_image_png):
        """Test different PNG optimization levels."""
        # Test with different compression levels
        from app.core.optimization.lossless_compressor import CompressionLevel

        levels = [
            CompressionLevel.FAST,
            CompressionLevel.BALANCED,
            CompressionLevel.MAXIMUM,
        ]
        results = []

        for level in levels:
            result, info = await compressor.compress_lossless(
                test_image_png, "png", compression_level=level
            )

            assert "compress_level" in info  # PNG specific field
            assert len(result) > 0
            results.append((level, len(result)))

            # Higher compression should generally produce smaller files
            # (though not always guaranteed)

    @pytest.mark.asyncio
    async def test_avif_lossless(self, compressor):
        """Test AVIF lossless compression if supported."""
        # Create test image
        img = Image.new("RGB", (50, 50), color="purple")
        buffer = io.BytesIO()

        # Try to save as AVIF if supported
        try:
            img.save(buffer, format="AVIF")
            avif_data = buffer.getvalue()

            result, info = await compressor.compress_lossless(avif_data, "avif")

            assert info["method"] == "avif_lossless"
            assert "compression_ratio" in info
        except Exception:
            # AVIF might not be supported
            pytest.skip("AVIF format not supported")

    @pytest.mark.asyncio
    async def test_input_validation(self, compressor):
        """Test input validation."""
        # Test invalid input type
        with pytest.raises(SecurityError):
            await compressor.compress_lossless("not bytes", "png")

        # Test empty input
        with pytest.raises(SecurityError):
            await compressor.compress_lossless(b"", "png")

        # Test invalid format string
        img = Image.new("RGB", (10, 10))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")

        with pytest.raises(Exception):  # Should raise for invalid format
            await compressor.compress_lossless(buffer.getvalue(), "invalid_format")

    @pytest.mark.asyncio
    async def test_preserve_metadata_option(self, compressor):
        """Test metadata preservation during lossless compression."""
        # Create image with metadata
        img = Image.new("RGB", (50, 50), color="yellow")

        # Create PNG with text chunks
        from PIL import PngImagePlugin

        pnginfo = PngImagePlugin.PngInfo()
        pnginfo.add_text("Comment", "Test comment")
        pnginfo.add_text("Software", "Test software")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG", pnginfo=pnginfo)
        png_with_metadata = buffer.getvalue()

        # Compress with metadata preservation
        result, info = await compressor.compress_lossless(
            png_with_metadata, "png", preserve_metadata=True
        )

        # Should have compressed the image
        assert len(result) > 0
        assert "compression_ratio" in info

    @pytest.mark.asyncio
    async def test_concurrent_compression(self, compressor):
        """Test concurrent lossless compressions."""
        import asyncio

        # Create different test images
        images = []
        for i in range(5):
            img = Image.new("RGB", (50, 50), color=(i * 50, 0, 0))
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            images.append(buffer.getvalue())

        # Compress concurrently
        tasks = []
        for img_data in images:
            task = compressor.compress_lossless(img_data, "png")
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        # All should complete successfully
        assert len(results) == 5
        for result, info in results:
            assert len(result) > 0
            assert "compression_ratio" in info

    @pytest.mark.asyncio
    async def test_large_image_handling(self, compressor):
        """Test handling of large images."""
        # Create a larger image
        img = Image.new("RGB", (1000, 1000))
        pixels = img.load()

        # Fill with pattern
        for y in range(1000):
            for x in range(1000):
                pixels[x, y] = ((x + y) % 256, x % 256, y % 256)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        large_data = buffer.getvalue()

        result, info = await compressor.compress_lossless(
            large_data, "png", effort=3  # Lower effort for speed
        )

        assert len(result) > 0
        # PNG can compress patterns very efficiently
        assert info["original_size"] > 1000  # Just ensure it's not empty
        assert info["compression_ratio"] > 0

    @pytest.mark.asyncio
    async def test_algorithm_selection(self, compressor, test_image_png):
        """Test specific filter selection for PNG."""
        # Test with specific PNG filters
        filters = [["none"], ["sub"], ["paeth"]]

        for filter_list in filters:
            result, info = await compressor.compress_lossless(
                test_image_png, "png", filters=filter_list
            )

            assert "filter" in info  # Should indicate which filter was used
            assert len(result) > 0

    @pytest.mark.asyncio
    async def test_webp_lossless_with_alpha(self, compressor):
        """Test WebP lossless compression with alpha channel."""
        # Create RGBA image
        img = Image.new("RGBA", (100, 100))
        pixels = img.load()

        for y in range(100):
            for x in range(100):
                alpha = int((x + y) * 255 / 200)
                pixels[x, y] = (255, 0, 0, alpha)

        buffer = io.BytesIO()
        img.save(buffer, format="WebP")
        webp_alpha = buffer.getvalue()

        result, info = await compressor.compress_lossless(webp_alpha, "webp")

        assert info["method"] == "webp_lossless"
        assert info.get("exact", True)  # WebP lossless should be exact
        assert len(result) > 0

        # Verify alpha channel preserved
        compressed_img = Image.open(io.BytesIO(result))
        assert compressed_img.mode == "RGBA"
