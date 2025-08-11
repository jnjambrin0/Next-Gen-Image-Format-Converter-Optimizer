"""
Ultra-realistic quality metrics tests with SSIM/PSNR calculations.
Tests real-world quality assessment and optimization scenarios.
"""

import asyncio
import io
import math
import time
from typing import Any, Dict, Tuple

import numpy as np
import pytest
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter

from app.core.optimization.quality_analyzer import QualityAnalyzer
from app.models.conversion import ConversionRequest
from app.services.conversion_service import conversion_service
from app.services.optimization_service import optimization_service


class TestQualityMetricsRealistic:
    """Test quality metrics calculation and optimization with realistic scenarios."""

    @pytest.fixture
    def quality_analyzer(self):
        """Create QualityAnalyzer instance."""
        return QualityAnalyzer()

    def create_test_image_with_detail(self, detail_level: str = "high") -> bytes:
        """Create test image with varying levels of detail."""
        img = Image.new("RGB", (1920, 1080))

        if detail_level == "high":
            # High frequency details (textures, edges)
            for x in range(0, 1920, 2):
                for y in range(0, 1080, 2):
                    # Checkerboard pattern with gradients
                    if (x + y) % 4 == 0:
                        color = (
                            min(255, x * 255 // 1920),
                            min(255, y * 255 // 1080),
                            128,
                        )
                    else:
                        color = (
                            128,
                            min(255, 255 - x * 255 // 1920),
                            min(255, 255 - y * 255 // 1080),
                        )
                    img.putpixel((x, y), color)

            # Add some edges
            img = img.filter(ImageFilter.FIND_EDGES)
            img = Image.blend(img, Image.new("RGB", (1920, 1080), (100, 100, 100)), 0.5)

        elif detail_level == "medium":
            # Medium frequency (natural photo-like)
            draw = ImageDraw.Draw(img)

            # Gradient background
            for y in range(1080):
                color = (100 + y * 100 // 1080, 150, 200 - y * 50 // 1080)
                draw.rectangle([(0, y), (1920, y + 1)], fill=color)

            # Add some shapes
            for i in range(20):
                x = np.random.randint(100, 1820)
                y = np.random.randint(100, 980)
                r = np.random.randint(20, 100)
                color = tuple(np.random.randint(0, 255, 3))
                draw.ellipse([x - r, y - r, x + r, y + r], fill=color)

        else:  # low detail
            # Low frequency (smooth gradients)
            for y in range(1080):
                color = (
                    50 + y * 50 // 1080,
                    100 + y * 50 // 1080,
                    150 + y * 50 // 1080,
                )
                for x in range(1920):
                    img.putpixel((x, y), color)

        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=95)
        return buffer.getvalue()

    @pytest.mark.critical
    async def test_ssim_calculation_accuracy(self, quality_analyzer):
        """
        Test SSIM (Structural Similarity Index) calculation accuracy.

        Validates the custom SSIM implementation against known values.
        """
        # Create original image
        original = Image.new("RGB", (256, 256))
        pixels = original.load()
        for i in range(256):
            for j in range(256):
                pixels[i, j] = (i, j, (i + j) // 2)

        # Test cases with expected SSIM ranges
        test_cases = [
            ("identical", original.copy(), 0.99, 1.0),  # Should be ~1.0
            ("slight_compression", None, 0.90, 0.98),  # JPEG compression
            ("moderate_blur", original.filter(ImageFilter.GaussianBlur(2)), 0.70, 0.85),
            ("heavy_blur", original.filter(ImageFilter.GaussianBlur(5)), 0.40, 0.60),
            (
                "brightness_change",
                ImageEnhance.Brightness(original).enhance(1.2),
                0.85,
                0.95,
            ),
            (
                "contrast_change",
                ImageEnhance.Contrast(original).enhance(0.8),
                0.80,
                0.90,
            ),
        ]

        for name, modified_img, min_ssim, max_ssim in test_cases:
            if name == "slight_compression":
                # Create compressed version
                buffer = io.BytesIO()
                original.save(buffer, format="JPEG", quality=85)
                modified_img = Image.open(buffer)

            # Calculate SSIM
            ssim_value = quality_analyzer.calculate_ssim(original, modified_img)

            assert (
                min_ssim <= ssim_value <= max_ssim
            ), f"SSIM for {name} out of range: {ssim_value:.3f} (expected {min_ssim}-{max_ssim})"

    @pytest.mark.critical
    async def test_psnr_calculation_accuracy(self, quality_analyzer):
        """
        Test PSNR (Peak Signal-to-Noise Ratio) calculation accuracy.

        Validates PSNR calculation for various distortion levels.
        """
        # Create original image
        original = Image.new("RGB", (512, 512), color=(128, 128, 128))

        # Test cases with expected PSNR ranges
        test_cases = [
            ("identical", original.copy(), 50, float("inf")),  # Should be infinite
            ("slight_noise", self._add_noise(original, 5), 35, 45),
            ("moderate_noise", self._add_noise(original, 20), 25, 35),
            ("heavy_noise", self._add_noise(original, 50), 15, 25),
        ]

        for name, modified_img, min_psnr, max_psnr in test_cases:
            psnr_value = quality_analyzer.calculate_psnr(original, modified_img)

            if max_psnr == float("inf"):
                assert (
                    psnr_value > min_psnr
                ), f"PSNR for {name} too low: {psnr_value:.2f}"
            else:
                assert (
                    min_psnr <= psnr_value <= max_psnr
                ), f"PSNR for {name} out of range: {psnr_value:.2f} (expected {min_psnr}-{max_psnr})"

    def _add_noise(self, image: Image.Image, noise_level: int) -> Image.Image:
        """Add random noise to an image."""
        img_array = np.array(image)
        noise = np.random.randint(-noise_level, noise_level, img_array.shape)
        noisy_array = np.clip(img_array + noise, 0, 255).astype(np.uint8)
        return Image.fromarray(noisy_array)

    @pytest.mark.performance
    async def test_quality_based_optimization(self):
        """
        Test quality-based optimization for different content types.

        Validates that optimization preserves quality appropriately.
        """
        # Test different content types
        content_types = [
            ("high_detail", self.create_test_image_with_detail("high"), 0.85),
            ("medium_detail", self.create_test_image_with_detail("medium"), 0.90),
            ("low_detail", self.create_test_image_with_detail("low"), 0.95),
        ]

        for content_name, image_data, min_acceptable_ssim in content_types:
            # Find optimal quality setting
            result = await optimization_service.find_optimal_quality(
                image_data=image_data,
                output_format="webp",
                target_ssim=min_acceptable_ssim,
                min_quality=50,
                max_quality=95,
            )

            assert result is not None, f"Optimization failed for {content_name}"
            assert result.optimal_quality is not None
            assert (
                result.achieved_ssim >= min_acceptable_ssim - 0.02
            ), f"Failed to achieve target SSIM for {content_name}"

            # Verify file size reduction
            assert result.output_size < len(image_data), "No size reduction achieved"

            # High detail should require higher quality
            if content_name == "high_detail":
                assert (
                    result.optimal_quality >= 75
                ), "Quality too low for high detail image"
            elif content_name == "low_detail":
                assert (
                    result.optimal_quality <= 85
                ), "Quality unnecessarily high for low detail"

    @pytest.mark.critical
    async def test_perceptual_quality_preservation(self):
        """
        Test that perceptually important features are preserved.

        Validates face and text region quality preservation.
        """
        # Create image with face-like region and text-like region
        img = Image.new("RGB", (1024, 768), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)

        # Add face-like region (center)
        face_bbox = (400, 300, 600, 500)
        draw.ellipse(face_bbox, fill=(255, 220, 177))
        # Eyes
        draw.ellipse([440, 350, 460, 370], fill=(50, 50, 50))
        draw.ellipse([540, 350, 560, 370], fill=(50, 50, 50))

        # Add text-like region (bottom)
        text_region = (100, 600, 900, 700)
        for x in range(100, 900, 20):
            draw.rectangle([x, 620, x + 15, 635], fill=(0, 0, 0))

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        original_data = buffer.getvalue()

        # Convert with perceptual optimization
        request = ConversionRequest(
            output_format="jpeg",
            quality=70,  # Lower quality
            optimization_mode="perceptual",  # Should preserve important regions
            preserve_regions=[
                {"x": 400, "y": 300, "width": 200, "height": 200, "type": "face"},
                {"x": 100, "y": 600, "width": 800, "height": 100, "type": "text"},
            ],
        )

        result, output_data = await conversion_service.convert(
            image_data=original_data, request=request
        )

        assert result.success

        # Analyze quality in different regions
        original_img = Image.open(io.BytesIO(original_data))
        output_img = Image.open(io.BytesIO(output_data))

        # Check face region quality
        face_original = original_img.crop(face_bbox)
        face_output = output_img.crop(face_bbox)
        face_ssim = QualityAnalyzer().calculate_ssim(face_original, face_output)
        assert face_ssim > 0.85, f"Face region quality too low: {face_ssim:.3f}"

        # Check text region quality
        text_original = original_img.crop(text_region)
        text_output = output_img.crop(text_region)
        text_ssim = QualityAnalyzer().calculate_ssim(text_original, text_output)
        assert text_ssim > 0.80, f"Text region quality too low: {text_ssim:.3f}"

    @pytest.mark.performance
    async def test_adaptive_quality_for_different_formats(self):
        """
        Test adaptive quality selection for different output formats.

        Each format has different quality characteristics.
        """
        # Create test image
        test_image = self.create_test_image_with_detail("medium")

        # Test different formats
        format_tests = [
            ("jpeg", 85, 0.90),
            ("webp", 85, 0.92),  # WebP typically better at same quality
            ("avif", 85, 0.93),  # AVIF even better
            ("png", None, 0.99),  # Lossless
        ]

        results = {}
        for output_format, quality, expected_min_ssim in format_tests:
            request = ConversionRequest(
                output_format=output_format,
                quality=quality,
                optimization_mode="balanced",
            )

            result, output_data = await conversion_service.convert(
                image_data=test_image, request=request
            )

            assert result.success

            # Calculate actual SSIM
            original_img = Image.open(io.BytesIO(test_image))
            output_img = Image.open(io.BytesIO(output_data))
            actual_ssim = QualityAnalyzer().calculate_ssim(original_img, output_img)

            results[output_format] = {
                "ssim": actual_ssim,
                "size": len(output_data),
                "compression_ratio": len(output_data) / len(test_image),
            }

            assert (
                actual_ssim >= expected_min_ssim - 0.02
            ), f"{output_format} SSIM too low: {actual_ssim:.3f}"

        # Verify format efficiency ordering
        # AVIF should be most efficient, then WebP, then JPEG
        if "avif" in results and "webp" in results:
            assert results["avif"]["size"] <= results["webp"]["size"] * 1.1
        if "webp" in results and "jpeg" in results:
            assert results["webp"]["size"] <= results["jpeg"]["size"] * 1.05

    @pytest.mark.slow
    async def test_quality_metrics_performance(self, quality_analyzer):
        """
        Test performance of quality metrics calculation.

        Ensures metrics calculation is fast enough for real-time use.
        """
        # Test with different image sizes
        sizes = [
            (640, 480),  # VGA
            (1280, 720),  # HD
            (1920, 1080),  # Full HD
            (3840, 2160),  # 4K
        ]

        for width, height in sizes:
            # Create test images
            img1 = Image.new("RGB", (width, height), color=(100, 100, 100))
            img2 = Image.new("RGB", (width, height), color=(110, 110, 110))

            # Measure SSIM calculation time
            start_time = time.perf_counter()
            ssim_value = quality_analyzer.calculate_ssim(img1, img2)
            ssim_time = time.perf_counter() - start_time

            # Measure PSNR calculation time
            start_time = time.perf_counter()
            psnr_value = quality_analyzer.calculate_psnr(img1, img2)
            psnr_time = time.perf_counter() - start_time

            # Performance assertions based on size
            if width * height <= 1920 * 1080:  # Up to Full HD
                assert (
                    ssim_time < 0.5
                ), f"SSIM too slow for {width}x{height}: {ssim_time:.3f}s"
                assert (
                    psnr_time < 0.1
                ), f"PSNR too slow for {width}x{height}: {psnr_time:.3f}s"
            else:  # 4K
                assert ssim_time < 2.0, f"SSIM too slow for 4K: {ssim_time:.3f}s"
                assert psnr_time < 0.5, f"PSNR too slow for 4K: {psnr_time:.3f}s"

    @pytest.mark.critical
    async def test_quality_degradation_cascade(self):
        """
        Test quality degradation through multiple conversions.

        Simulates real-world scenario of repeated editing/sharing.
        """
        # Start with high quality image
        original = self.create_test_image_with_detail("high")

        # Track quality through conversions
        quality_cascade = [
            ("original", original, 1.0),
        ]

        current_data = original

        # Simulate multiple conversions (like social media sharing)
        conversions = [
            ("jpeg", 85),  # First save
            ("jpeg", 80),  # Re-save after edit
            ("webp", 75),  # Convert for web
            ("jpeg", 70),  # Download and re-upload
            ("jpeg", 65),  # Final share
        ]

        for i, (format, quality) in enumerate(conversions, 1):
            request = ConversionRequest(output_format=format, quality=quality)

            result, output_data = await conversion_service.convert(
                image_data=current_data, request=request
            )

            assert result.success

            # Calculate degradation
            original_img = Image.open(io.BytesIO(original))
            current_img = Image.open(io.BytesIO(output_data))
            ssim = QualityAnalyzer().calculate_ssim(original_img, current_img)

            quality_cascade.append((f"gen_{i}_{format}_{quality}", output_data, ssim))
            current_data = output_data

        # Verify progressive degradation
        for i in range(1, len(quality_cascade)):
            current_ssim = quality_cascade[i][2]
            prev_ssim = quality_cascade[i - 1][2]

            # Quality should decrease or stay same
            assert (
                current_ssim <= prev_ssim + 0.01
            ), f"Quality increased unexpectedly at step {i}"

        # Final quality should still be acceptable
        final_ssim = quality_cascade[-1][2]
        assert final_ssim > 0.60, f"Excessive quality loss: {final_ssim:.3f}"

    @pytest.mark.performance
    async def test_quality_memory_efficiency(self, memory_monitor):
        """
        Test memory efficiency of quality calculations.

        Ensures no memory leaks during repeated quality assessments.
        """
        memory_monitor.start()

        # Create test images
        img1 = Image.new("RGB", (2048, 1536))
        img2 = Image.new("RGB", (2048, 1536))

        # Perform many quality calculations
        analyzer = QualityAnalyzer()

        for i in range(50):
            # Calculate metrics
            ssim = analyzer.calculate_ssim(img1, img2)
            psnr = analyzer.calculate_psnr(img1, img2)

            # Modify image slightly
            img2.putpixel((i, i), (i * 5, i * 5, i * 5))

            # Sample memory every 10 iterations
            if i % 10 == 0:
                memory_monitor.sample()

        # Check memory stability
        memory_monitor.assert_stable(max_growth_mb=50)
