"""Performance tests for optimization features."""

import pytest
import asyncio
import time
import io
from PIL import Image

from app.core.optimization import (
    QualityAnalyzer,
    OptimizationEngine,
    OptimizationMode,
    LosslessCompressor,
    CompressionLevel
)


class TestOptimizationPerformance:
    """Performance tests for optimization components."""
    
    @pytest.fixture
    def large_image(self):
        """Create a large test image (10MP)."""
        # 10 megapixel image (3650x2740)
        img = Image.new('RGB', (3650, 2740), color='blue')
        # Add some complexity
        pixels = img.load()
        for x in range(0, 3650, 100):
            for y in range(0, 2740, 100):
                pixels[x, y] = (x % 255, y % 255, (x + y) % 255)
        
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=90)
        return buffer.getvalue()
    
    @pytest.fixture
    def typical_image(self):
        """Create a typical size test image (2MP)."""
        # 2 megapixel image (1600x1200)
        img = Image.new('RGB', (1600, 1200), color='green')
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=85)
        return buffer.getvalue()
    
    @pytest.mark.asyncio
    async def test_quality_analyzer_performance(self, typical_image):
        """Test quality analyzer performance for typical images."""
        analyzer = QualityAnalyzer(enable_caching=False)
        
        # Compress the image
        img = Image.open(io.BytesIO(typical_image))
        compressed_buffer = io.BytesIO()
        img.save(compressed_buffer, format='JPEG', quality=70)
        compressed_data = compressed_buffer.getvalue()
        
        # Measure calculation time
        start_time = time.time()
        
        metrics = await analyzer.calculate_metrics(
            typical_image,
            compressed_data,
            calculate_ssim=True,
            calculate_psnr=True
        )
        
        elapsed_time = time.time() - start_time
        
        # Pure Python SSIM is slower than C implementations
        # Allow more time for 1600x1200 images
        assert elapsed_time < 60.0  # 60 seconds max
        assert metrics['ssim_score'] is not None
        assert metrics['psnr_value'] is not None
    
    @pytest.mark.asyncio
    async def test_multi_pass_optimization_performance(self, typical_image):
        """Test multi-pass optimization performance."""
        quality_analyzer = QualityAnalyzer(enable_caching=True)
        engine = OptimizationEngine(
            quality_analyzer=quality_analyzer,
            max_passes=10
        )
        
        # Mock conversion function
        async def mock_conversion(image_data, output_format, quality=85, **kwargs):
            img = Image.open(io.BytesIO(image_data))
            buffer = io.BytesIO()
            img.save(buffer, format=output_format.upper(), quality=quality)
            return buffer.getvalue()
        
        # Measure optimization time
        start_time = time.time()
        
        optimized_data, result = await engine.optimize(
            typical_image,
            'jpeg',
            target_size_kb=500,  # 500KB target
            mode=OptimizationMode.SIZE,
            conversion_func=mock_conversion
        )
        
        elapsed_time = time.time() - start_time
        
        # Should complete in under 5 seconds for typical images
        assert elapsed_time < 5.0
        assert result.total_passes <= 10
        assert len(optimized_data) > 0
    
    @pytest.mark.asyncio
    async def test_concurrent_optimization_performance(self, typical_image):
        """Test performance with concurrent optimizations."""
        analyzer = QualityAnalyzer(enable_caching=True)
        
        # Create slightly different versions
        images = []
        for i in range(10):
            img = Image.open(io.BytesIO(typical_image))
            # Adjust brightness slightly
            pixels = img.load()
            for x in range(0, img.width, 100):
                for y in range(0, img.height, 100):
                    if x < img.width and y < img.height:
                        r, g, b = pixels[x, y]
                        pixels[x, y] = (min(255, r + i), g, b)
            
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=85 - i)
            images.append(buffer.getvalue())
        
        # Measure concurrent processing time
        start_time = time.time()
        
        tasks = []
        for i in range(9):
            task = analyzer.calculate_metrics(images[i], images[i+1])
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        elapsed_time = time.time() - start_time
        
        # Should handle concurrent requests efficiently
        # Total time should be less than sequential time
        assert elapsed_time < 2.0  # Should complete in under 2 seconds
        assert len(results) == 9
    
    @pytest.mark.asyncio
    async def test_lossless_compression_performance(self, typical_image):
        """Test lossless compression performance."""
        compressor = LosslessCompressor()
        
        # Convert to PNG first (lossless format)
        img = Image.open(io.BytesIO(typical_image))
        png_buffer = io.BytesIO()
        img.save(png_buffer, format='PNG')
        png_data = png_buffer.getvalue()
        
        # Test different compression levels
        for level in [CompressionLevel.FAST, CompressionLevel.BALANCED, CompressionLevel.MAXIMUM]:
            start_time = time.time()
            
            compressed_data, info = await compressor.compress_lossless(
                png_data,
                'png',
                compression_level=level
            )
            
            elapsed_time = time.time() - start_time
            
            # Performance expectations by level
            if level == CompressionLevel.FAST:
                assert elapsed_time < 0.5
            elif level == CompressionLevel.BALANCED:
                assert elapsed_time < 1.0
            else:  # MAXIMUM
                assert elapsed_time < 2.0
            
            assert len(compressed_data) > 0
            assert info['compression_ratio'] < 1.0
    
    @pytest.mark.asyncio
    async def test_large_image_handling(self, large_image):
        """Test performance with large images."""
        analyzer = QualityAnalyzer(enable_caching=False)
        
        # Create compressed version
        img = Image.open(io.BytesIO(large_image))
        compressed_buffer = io.BytesIO()
        img.save(compressed_buffer, format='JPEG', quality=60)
        compressed_data = compressed_buffer.getvalue()
        
        start_time = time.time()
        
        # Should automatically downsample for performance
        metrics = await analyzer.calculate_metrics(
            large_image,
            compressed_data
        )
        
        elapsed_time = time.time() - start_time
        
        # Should still complete reasonably fast with downsampling
        assert elapsed_time < 2.0
        assert metrics['ssim_score'] is not None
    
    @pytest.mark.asyncio
    async def test_memory_efficiency(self, typical_image):
        """Test memory usage remains reasonable."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        analyzer = QualityAnalyzer(enable_caching=True)
        
        # Process multiple images
        for i in range(20):
            compressed = typical_image[:-100] + b'modified' * 10
            await analyzer.calculate_metrics(typical_image, compressed)
        
        # Clear cache to test memory cleanup
        await analyzer.clear_cache()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB)
        assert memory_increase < 100