"""
Core integration tests for ConversionManager.
Tests the main conversion pipeline with real images.
"""

import pytest
import asyncio
from pathlib import Path
from PIL import Image
import io
from typing import Tuple

from app.core.conversion.manager import ConversionManager
from app.core.constants import (
    SUPPORTED_INPUT_FORMATS,
    SUPPORTED_OUTPUT_FORMATS,
    MAX_FILE_SIZE,
)
from app.models.conversion import ConversionRequest, ConversionResult


@pytest.fixture
async def conversion_manager():
    """Create ConversionManager instance."""
    manager = ConversionManager()
    yield manager
    # Cleanup if needed
    await manager.cleanup() if hasattr(manager, 'cleanup') else None


@pytest.fixture
def sample_jpeg() -> bytes:
    """Create a sample JPEG image."""
    img = Image.new('RGB', (100, 100), color='red')
    buffer = io.BytesIO()
    img.save(buffer, format='JPEG')
    return buffer.getvalue()


@pytest.fixture
def sample_png() -> bytes:
    """Create a sample PNG image."""
    img = Image.new('RGBA', (100, 100), color=(255, 0, 0, 128))
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()


class TestConversionManagerCore:
    """Test core conversion functionality."""

    @pytest.mark.asyncio
    async def test_basic_jpeg_to_png_conversion(self, conversion_manager, sample_jpeg):
        """Test basic JPEG to PNG conversion."""
        request = ConversionRequest(
            output_format="png",
            quality=90
        )
        
        result = await conversion_manager.convert(
            image_data=sample_jpeg,
            request=request
        )
        
        assert isinstance(result, ConversionResult)
        assert result.success is True
        assert result.output_format == "png"
        assert result.output_size > 0
        assert result.error is None

    @pytest.mark.asyncio
    async def test_png_to_webp_conversion(self, conversion_manager, sample_png):
        """Test PNG to WebP conversion with alpha channel."""
        request = ConversionRequest(
            output_format="webp",
            quality=85,
            lossless=False
        )
        
        result = await conversion_manager.convert(
            image_data=sample_png,
            request=request
        )
        
        assert result.success is True
        assert result.output_format == "webp"
        assert result.output_size > 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize("output_format", ["jpeg", "png", "webp", "avif"])
    async def test_conversion_to_multiple_formats(
        self, conversion_manager, sample_jpeg, output_format
    ):
        """Test conversion to multiple output formats."""
        request = ConversionRequest(
            output_format=output_format,
            quality=85
        )
        
        result = await conversion_manager.convert(
            image_data=sample_jpeg,
            request=request
        )
        
        assert result.success is True
        assert result.output_format == output_format

    @pytest.mark.asyncio
    async def test_conversion_with_resize(self, conversion_manager, sample_jpeg):
        """Test conversion with resize options."""
        request = ConversionRequest(
            output_format="jpeg",
            quality=85,
            resize_width=50,
            resize_height=50,
            maintain_aspect_ratio=True
        )
        
        result = await conversion_manager.convert(
            image_data=sample_jpeg,
            request=request
        )
        
        assert result.success is True
        # Check output dimensions
        output_img = Image.open(io.BytesIO(result.output_data))
        assert output_img.width == 50
        assert output_img.height == 50

    @pytest.mark.asyncio
    async def test_conversion_with_optimization(self, conversion_manager, sample_jpeg):
        """Test conversion with optimization enabled."""
        request = ConversionRequest(
            output_format="jpeg",
            quality=85,
            optimize=True
        )
        
        result = await conversion_manager.convert(
            image_data=sample_jpeg,
            request=request
        )
        
        assert result.success is True
        # Optimized file should be smaller or equal
        assert result.output_size <= len(sample_jpeg)

    @pytest.mark.asyncio
    async def test_conversion_with_metadata_stripping(
        self, conversion_manager, sample_jpeg
    ):
        """Test conversion with metadata stripping."""
        request = ConversionRequest(
            output_format="jpeg",
            quality=85,
            strip_metadata=True
        )
        
        result = await conversion_manager.convert(
            image_data=sample_jpeg,
            request=request
        )
        
        assert result.success is True
        assert result.metadata_removed is True

    @pytest.mark.asyncio
    async def test_conversion_error_handling_invalid_data(self, conversion_manager):
        """Test error handling for invalid image data."""
        request = ConversionRequest(
            output_format="png",
            quality=85
        )
        
        with pytest.raises(Exception):
            await conversion_manager.convert(
                image_data=b"invalid image data",
                request=request
            )

    @pytest.mark.asyncio
    async def test_conversion_error_handling_empty_data(self, conversion_manager):
        """Test error handling for empty image data."""
        request = ConversionRequest(
            output_format="png",
            quality=85
        )
        
        with pytest.raises(Exception):
            await conversion_manager.convert(
                image_data=b"",
                request=request
            )

    @pytest.mark.asyncio
    async def test_conversion_with_preset(self, conversion_manager, sample_jpeg):
        """Test conversion using a preset."""
        request = ConversionRequest(
            output_format="webp",  # Will be overridden by preset
            preset_id="web_optimized"
        )
        
        result = await conversion_manager.convert(
            image_data=sample_jpeg,
            request=request
        )
        
        assert result.success is True
        # Preset should override format
        assert result.preset_used == "web_optimized"

    @pytest.mark.asyncio
    async def test_concurrent_conversions(self, conversion_manager, sample_jpeg):
        """Test multiple concurrent conversions."""
        requests = [
            ConversionRequest(output_format="png", quality=90),
            ConversionRequest(output_format="webp", quality=85),
            ConversionRequest(output_format="avif", quality=80),
        ]
        
        tasks = [
            conversion_manager.convert(sample_jpeg, req)
            for req in requests
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 3
        assert all(r.success for r in results)
        assert [r.output_format for r in results] == ["png", "webp", "avif"]

    @pytest.mark.asyncio
    async def test_large_image_handling(self, conversion_manager):
        """Test handling of large images."""
        # Create a large image (2000x2000)
        large_img = Image.new('RGB', (2000, 2000), color='blue')
        buffer = io.BytesIO()
        large_img.save(buffer, format='JPEG')
        large_data = buffer.getvalue()
        
        request = ConversionRequest(
            output_format="webp",
            quality=75,
            optimize=True
        )
        
        result = await conversion_manager.convert(
            image_data=large_data,
            request=request
        )
        
        assert result.success is True
        # WebP should be smaller than original JPEG
        assert result.output_size < len(large_data)

    @pytest.mark.asyncio
    async def test_conversion_with_security_sandbox(
        self, conversion_manager, sample_jpeg
    ):
        """Test conversion runs in security sandbox."""
        request = ConversionRequest(
            output_format="png",
            quality=90,
            enable_sandbox=True  # Explicitly enable sandbox
        )
        
        result = await conversion_manager.convert(
            image_data=sample_jpeg,
            request=request
        )
        
        assert result.success is True
        assert result.sandboxed is True

    @pytest.mark.asyncio
    async def test_format_validation(self, conversion_manager, sample_jpeg):
        """Test validation of unsupported formats."""
        request = ConversionRequest(
            output_format="invalid_format",
            quality=85
        )
        
        with pytest.raises(ValueError, match="Unsupported output format"):
            await conversion_manager.convert(
                image_data=sample_jpeg,
                request=request
            )

    @pytest.mark.asyncio
    async def test_quality_range_validation(self, conversion_manager, sample_jpeg):
        """Test quality parameter validation."""
        # Test quality too low
        request = ConversionRequest(
            output_format="jpeg",
            quality=0
        )
        
        with pytest.raises(ValueError, match="Quality must be between"):
            await conversion_manager.convert(
                image_data=sample_jpeg,
                request=request
            )
        
        # Test quality too high
        request = ConversionRequest(
            output_format="jpeg",
            quality=101
        )
        
        with pytest.raises(ValueError, match="Quality must be between"):
            await conversion_manager.convert(
                image_data=sample_jpeg,
                request=request
            )

    @pytest.mark.asyncio
    async def test_memory_cleanup_after_conversion(
        self, conversion_manager, sample_jpeg
    ):
        """Test that memory is properly cleaned up after conversion."""
        import gc
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform multiple conversions
        for _ in range(10):
            request = ConversionRequest(
                output_format="png",
                quality=90
            )
            result = await conversion_manager.convert(
                image_data=sample_jpeg,
                request=request
            )
            assert result.success is True
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be minimal (< 50MB)
        assert memory_increase < 50, f"Memory leak detected: {memory_increase}MB increase"