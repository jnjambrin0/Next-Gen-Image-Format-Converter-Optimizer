"""Unit tests for the QualityAnalyzer."""

import pytest
import asyncio
import io
from PIL import Image
import numpy as np

from app.core.optimization import QualityAnalyzer
from app.core.security.errors_simplified import SecurityError


class TestQualityAnalyzer:
    """Test cases for QualityAnalyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create a QualityAnalyzer instance."""
        return QualityAnalyzer(enable_caching=True)
    
    @pytest.fixture
    def test_image_rgb(self):
        """Create a test RGB image."""
        img = Image.new('RGB', (100, 100), color='red')
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        return buffer.getvalue()
    
    @pytest.fixture
    def test_image_rgba(self):
        """Create a test RGBA image with transparency."""
        img = Image.new('RGBA', (100, 100), color=(255, 0, 0, 128))
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        return buffer.getvalue()
    
    @pytest.fixture
    def compressed_image(self):
        """Create a compressed version of the test image."""
        img = Image.new('RGB', (100, 100), color='red')
        # Add some noise to make it different
        pixels = img.load()
        for i in range(0, 100, 10):
            for j in range(0, 100, 10):
                pixels[i, j] = (250, 5, 5)
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=50)
        return buffer.getvalue()
    
    @pytest.mark.asyncio
    async def test_calculate_metrics_basic(self, analyzer, test_image_rgb, compressed_image):
        """Test basic metric calculation."""
        metrics = await analyzer.calculate_metrics(
            test_image_rgb,
            compressed_image,
            calculate_ssim=True,
            calculate_psnr=True
        )
        
        assert 'ssim_score' in metrics
        assert 'psnr_value' in metrics
        assert 0 <= metrics['ssim_score'] <= 1
        assert metrics['psnr_value'] > 0
    
    @pytest.mark.asyncio
    async def test_calculate_metrics_identical_images(self, analyzer, test_image_rgb):
        """Test metrics for identical images."""
        metrics = await analyzer.calculate_metrics(
            test_image_rgb,
            test_image_rgb,
            calculate_ssim=True,
            calculate_psnr=True
        )
        
        # Identical images should have perfect SSIM
        assert metrics['ssim_score'] > 0.99
        # PSNR should be very high for identical images
        assert metrics['psnr_value'] > 40
    
    @pytest.mark.asyncio
    async def test_calculate_metrics_different_sizes(self, analyzer):
        """Test metrics for images with different sizes."""
        # Create images of different sizes
        img1 = Image.new('RGB', (100, 100), color='red')
        img2 = Image.new('RGB', (200, 200), color='red')
        
        buffer1 = io.BytesIO()
        buffer2 = io.BytesIO()
        img1.save(buffer1, format='PNG')
        img2.save(buffer2, format='PNG')
        
        # Should handle size differences by resizing
        metrics = await analyzer.calculate_metrics(
            buffer1.getvalue(),
            buffer2.getvalue()
        )
        
        assert 'ssim_score' in metrics
        assert metrics['ssim_score'] > 0.9  # Should be similar after resize
    
    @pytest.mark.asyncio
    async def test_input_validation(self, analyzer):
        """Test input validation."""
        # Test invalid input types
        with pytest.raises(SecurityError) as exc_info:
            await analyzer.calculate_metrics("not bytes", b"valid")
        assert exc_info.value  # Just verify SecurityError was raised
        
        # Test empty input
        with pytest.raises(SecurityError) as exc_info:
            await analyzer.calculate_metrics(b"", b"valid")
        assert exc_info.value  # Verify SecurityError was raised
        
        # Test too large input
        large_data = b"x" * (101 * 1024 * 1024 * 4)  # Over limit
        with pytest.raises(SecurityError) as exc_info:
            await analyzer.calculate_metrics(large_data, b"valid")
        assert exc_info.value  # Verify SecurityError was raised
    
    @pytest.mark.asyncio
    async def test_caching(self, analyzer, test_image_rgb, compressed_image):
        """Test metrics caching."""
        # First call
        metrics1 = await analyzer.calculate_metrics(
            test_image_rgb,
            compressed_image
        )
        
        # Second call should hit cache
        metrics2 = await analyzer.calculate_metrics(
            test_image_rgb,
            compressed_image
        )
        
        assert metrics1 == metrics2
        
        # Clear cache
        await analyzer.clear_cache()
        
        # Third call should recalculate
        metrics3 = await analyzer.calculate_metrics(
            test_image_rgb,
            compressed_image
        )
        
        assert metrics1 == metrics3
    
    @pytest.mark.asyncio
    async def test_file_size_reduction(self, analyzer):
        """Test file size reduction calculation."""
        reduction = await analyzer.calculate_file_size_reduction(1000, 750)
        assert reduction == 25.0
        
        reduction = await analyzer.calculate_file_size_reduction(1000, 1200)
        assert reduction == 0.0  # No negative reduction
        
        reduction = await analyzer.calculate_file_size_reduction(0, 100)
        assert reduction == 0.0  # Handle zero original size
    
    def test_visual_quality_rating(self, analyzer):
        """Test visual quality rating."""
        assert analyzer.get_visual_quality_rating(0.98) == "high"
        assert analyzer.get_visual_quality_rating(0.90) == "medium"
        assert analyzer.get_visual_quality_rating(0.80) == "low"
    
    @pytest.mark.asyncio
    async def test_concurrent_calculations(self, analyzer):
        """Test concurrent metric calculations."""
        # Create different image pairs
        images = []
        for i in range(5):
            img = Image.new('RGB', (50, 50), color=(i*50, 0, 0))
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            images.append(buffer.getvalue())
        
        # Calculate metrics concurrently
        tasks = []
        for i in range(4):
            task = analyzer.calculate_metrics(images[i], images[i+1])
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # All should complete successfully
        assert len(results) == 4
        for result in results:
            assert 'ssim_score' in result
            assert 'psnr_value' in result
    
    @pytest.mark.asyncio
    async def test_grayscale_images(self, analyzer):
        """Test metrics for grayscale images."""
        # Create grayscale images
        img1 = Image.new('L', (100, 100), color=128)
        img2 = Image.new('L', (100, 100), color=120)
        
        buffer1 = io.BytesIO()
        buffer2 = io.BytesIO()
        img1.save(buffer1, format='PNG')
        img2.save(buffer2, format='PNG')
        
        metrics = await analyzer.calculate_metrics(
            buffer1.getvalue(),
            buffer2.getvalue()
        )
        
        assert 'ssim_score' in metrics
        assert 'psnr_value' in metrics
        assert metrics['ssim_score'] > 0.9  # Similar grayscale images
    
    @pytest.mark.asyncio
    async def test_large_image_downsampling(self, analyzer):
        """Test automatic downsampling of large images."""
        # Create a large image
        large_img = Image.new('RGB', (5000, 5000), color='blue')
        buffer = io.BytesIO()
        large_img.save(buffer, format='PNG')
        large_data = buffer.getvalue()
        
        # Calculate metrics - should downsample automatically
        metrics = await analyzer.calculate_metrics(
            large_data,
            large_data
        )
        
        assert metrics['ssim_score'] > 0.99  # Should still be identical after downsampling