"""Unit tests for the OptimizationEngine."""

import asyncio
import io
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from PIL import Image

from app.core.optimization.optimization_engine import (OptimizationEngine,
                                                       OptimizationMode,
                                                       OptimizationResult)
from app.core.security.errors_simplified import SecurityError


class TestOptimizationEngine:
    """Test cases for OptimizationEngine."""

    @pytest.fixture
    def mock_quality_analyzer(self) -> None:
        """Create a mock quality analyzer."""
        analyzer = MagicMock()
        analyzer.calculate_metrics = AsyncMock(
            return_value={"ssim_score": 0.95, "psnr_value": 35.0}
        )
        return analyzer

    @pytest.fixture
    def engine(self, mock_quality_analyzer) -> None:
        """Create an OptimizationEngine instance."""
        return OptimizationEngine(
            quality_analyzer=mock_quality_analyzer,
            max_passes=5,
            size_tolerance_percent=5,
        )

    @pytest.fixture
    def test_image(self) -> None:
        """Create a test image."""
        img = Image.new("RGB", (100, 100), color="red")
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        return buffer.getvalue()

    @pytest.fixture
    def mock_conversion_func(self) -> None:
        """Create a mock conversion function."""

        async def conversion_func(image_data, output_format, quality=85, **kwargs):
            # Simulate realistic size reduction based on quality
            # Higher quality = larger file size
            # Use exponential curve for more realistic compression
            base_size = 20000  # Base size for quality 100

            # Exponential reduction: size decreases faster at lower qualities
            quality_factor = (quality / 100) ** 1.5
            new_size = int(base_size * quality_factor)

            # Ensure minimum size
            new_size = max(new_size, 500)

            # Create dummy data of the target size
            data = b"JPEG" + b"\x00" * (new_size - 4)

            return data

        return conversion_func

    @pytest.mark.asyncio
    async def test_optimize_balanced_mode(
        self, engine, test_image, mock_conversion_func
    ):
        """Test optimization in balanced mode."""
        optimized_data, result = await engine.optimize(
            test_image,
            "jpeg",
            target_size_kb=None,
            mode=OptimizationMode.BALANCED,
            conversion_func=mock_conversion_func,
        )

        assert isinstance(result, OptimizationResult)
        assert result.total_passes >= 1
        assert result.final_quality >= 40
        assert result.final_quality <= 95
        assert len(optimized_data) > 0

    @pytest.mark.asyncio
    async def test_optimize_size_mode_with_target(
        self, engine, test_image, mock_conversion_func
    ):
        """Test optimization in size mode with target."""
        target_size_kb = 10  # 10KB target

        optimized_data, result = await engine.optimize(
            test_image,
            "jpeg",
            target_size_kb=target_size_kb,
            mode=OptimizationMode.SIZE,
            conversion_func=mock_conversion_func,
        )

        assert result.final_size > 0
        # Check if within tolerance
        size_diff_percent = (
            abs(result.final_size - target_size_kb * 1024)
            / (target_size_kb * 1024)
            * 100
        )
        assert size_diff_percent <= 10  # Allow some tolerance

    @pytest.mark.asyncio
    async def test_optimize_quality_mode(
        self, engine, test_image, mock_conversion_func
    ):
        """Test optimization in quality mode."""
        optimized_data, result = await engine.optimize(
            test_image,
            "jpeg",
            target_size_kb=None,
            mode=OptimizationMode.QUALITY,
            conversion_func=mock_conversion_func,
        )

        # Quality mode should start high
        assert result.passes[0].quality >= 90

    @pytest.mark.asyncio
    async def test_optimize_perceptual_mode(
        self, engine, test_image, mock_conversion_func
    ):
        """Test optimization in perceptual mode."""
        optimized_data, result = await engine.optimize(
            test_image,
            "jpeg",
            target_size_kb=None,
            mode=OptimizationMode.PERCEPTUAL,
            conversion_func=mock_conversion_func,
            original_data=test_image,
        )

        # Should calculate SSIM/PSNR
        assert engine.quality_analyzer.calculate_metrics.called

    @pytest.mark.asyncio
    async def test_convergence(self, engine, test_image):
        """Test convergence detection."""

        # Mock conversion that reaches target quickly
        async def quick_convergence_func(
            image_data, output_format, quality=85, **kwargs
        ):
            target_size = 10240  # 10KB
            return b"x" * target_size

        optimized_data, result = await engine.optimize(
            test_image,
            "jpeg",
            target_size_kb=10,
            mode=OptimizationMode.SIZE,
            conversion_func=quick_convergence_func,
        )

        assert result.converged
        assert result.total_passes < 5  # Should converge before max passes

    @pytest.mark.asyncio
    async def test_max_passes_limit(self, engine, test_image, mock_conversion_func):
        """Test that optimization respects max passes limit."""
        engine.max_passes = 3

        optimized_data, result = await engine.optimize(
            test_image,
            "jpeg",
            target_size_kb=1,  # Very small target to prevent convergence
            mode=OptimizationMode.SIZE,
            conversion_func=mock_conversion_func,
        )

        assert result.total_passes == 3

    @pytest.mark.asyncio
    async def test_input_validation(self, engine, mock_conversion_func):
        """Test input validation."""
        # Invalid input type
        with pytest.raises(SecurityError) as exc_info:
            await engine.optimize(
                "not bytes",
                "jpeg",
                None,
                OptimizationMode.BALANCED,
                mock_conversion_func,
            )
        assert exc_info.value  # Just verify SecurityError was raised

        # Empty input
        with pytest.raises(SecurityError) as exc_info:
            await engine.optimize(
                b"", "jpeg", None, OptimizationMode.BALANCED, mock_conversion_func
            )
        assert exc_info.value  # Just verify SecurityError was raised

    @pytest.mark.asyncio
    async def test_quality_bounds(self, engine, test_image, mock_conversion_func):
        """Test custom quality bounds."""
        optimized_data, result = await engine.optimize(
            test_image,
            "jpeg",
            target_size_kb=None,
            mode=OptimizationMode.BALANCED,
            conversion_func=mock_conversion_func,
            min_quality=60,
            max_quality=80,
        )

        # All passes should respect bounds
        for pass_data in result.passes:
            assert pass_data.quality >= 60
            assert pass_data.quality <= 80

    @pytest.mark.asyncio
    async def test_timeout_handling(self, engine, test_image):
        """Test timeout handling."""

        # Mock conversion that takes too long
        async def slow_conversion_func(image_data, output_format, quality=85, **kwargs):
            await asyncio.sleep(40)  # Longer than timeout
            return b"data"

        with pytest.raises(SecurityError) as exc_info:
            await engine.optimize(
                test_image,
                "jpeg",
                None,
                OptimizationMode.BALANCED,
                slow_conversion_func,
            )
        assert exc_info.value  # Just verify SecurityError was raised

    @pytest.mark.asyncio
    async def test_pass_recording(self, engine, test_image, mock_conversion_func):
        """Test that optimization passes are recorded correctly."""
        optimized_data, result = await engine.optimize(
            test_image,
            "jpeg",
            target_size_kb=20,
            mode=OptimizationMode.SIZE,
            conversion_func=mock_conversion_func,
        )

        # Check pass details
        assert len(result.passes) == result.total_passes
        for i, pass_data in enumerate(result.passes):
            assert pass_data.pass_number == i + 1
            assert pass_data.quality > 0
            assert pass_data.file_size > 0
            assert pass_data.processing_time > 0

    @pytest.mark.asyncio
    async def test_concurrent_optimizations(
        self, engine, test_image, mock_conversion_func
    ):
        """Test concurrent optimization limit."""
        # Start multiple optimizations
        tasks = []
        for i in range(10):
            task = engine.optimize(
                test_image,
                "jpeg",
                None,
                OptimizationMode.BALANCED,
                mock_conversion_func,
            )
            tasks.append(task)

        # All should complete but semaphore limits concurrency
        results = await asyncio.gather(*tasks)
        assert len(results) == 10

        # Check all completed successfully
        for data, result in results:
            assert len(data) > 0
            assert result.total_passes > 0
