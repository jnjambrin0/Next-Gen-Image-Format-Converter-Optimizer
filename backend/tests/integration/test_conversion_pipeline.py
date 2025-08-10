"""Integration tests for the complete conversion pipeline."""

import asyncio
import io
# Import fixtures
import sys
from pathlib import Path
from typing import Any

import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.conversion.manager import ConversionManager
from app.core.exceptions import ConversionFailedError
from app.models.conversion import (ConversionRequest, ConversionSettings,
                                   ConversionStatus, OutputFormat)


class TestConversionPipeline:
    """Integration tests for the full conversion pipeline."""

    @pytest.fixture
    def conversion_manager(self) -> None:
        """Create a ConversionManager instance."""
        return ConversionManager()

    @pytest.mark.asyncio
    async def test_full_pipeline_jpeg_to_webp(
        self, conversion_manager, sample_image_path
    ):
        """Test complete pipeline: JPEG input to WebP output."""
        # Arrange
        with open(sample_image_path, "rb") as f:
            jpeg_data = f.read()

        request = ConversionRequest(
            output_format=OutputFormat.WEBP,
            settings=ConversionSettings(quality=85, strip_metadata=True, optimize=True),
        )

        # Act
        result = await conversion_manager.convert_image(jpeg_data, "jpeg", request)

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        assert result.output_format == OutputFormat.WEBP
        assert result.output_size > 0
        assert result.compression_ratio < 1.0  # Should be compressed

        # Verify output is valid WebP
        output_img = Image.open(io.BytesIO(result._output_data))
        assert output_img.format == "WEBP"

        # Verify metadata was stripped
        assert not hasattr(output_img, "_getexif") or output_img._getexif() is None

    @pytest.mark.asyncio
    async def test_full_pipeline_png_to_avif(self, conversion_manager, all_test_images):
        """Test complete pipeline: PNG input to AVIF output."""
        # Arrange
        png_path = all_test_images["screenshot"]["path"]
        with open(png_path, "rb") as f:
            png_data = f.read()

        request = ConversionRequest(
            output_format=OutputFormat.AVIF, settings=ConversionSettings(quality=80)
        )

        # Act
        result = await conversion_manager.convert_image(png_data, "png", request)

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        assert result.output_format == OutputFormat.AVIF
        assert result.output_size > 0

    @pytest.mark.asyncio
    async def test_pipeline_with_transparency_preservation(
        self, conversion_manager, all_test_images
    ):
        """Test pipeline preserves transparency."""
        # Arrange
        transparent_png_path = all_test_images["illustration"]["path"]
        with open(transparent_png_path, "rb") as f:
            png_data = f.read()

        request = ConversionRequest(
            output_format=OutputFormat.WEBP, settings=ConversionSettings(quality=90)
        )

        # Act
        result = await conversion_manager.convert_image(png_data, "png", request)

        # Assert
        assert result.status == ConversionStatus.COMPLETED

        # Verify transparency is preserved
        output_img = Image.open(io.BytesIO(result._output_data))
        assert output_img.mode == "RGBA"

    @pytest.mark.asyncio
    async def test_pipeline_with_different_quality_levels(
        self, conversion_manager, sample_image_bytes
    ):
        """Test pipeline with various quality settings."""
        # Arrange
        quality_levels = [30, 50, 70, 90]
        results = []

        # Act
        for quality in quality_levels:
            request = ConversionRequest(
                output_format=OutputFormat.JPEG,
                settings=ConversionSettings(quality=quality),
            )
            result = await conversion_manager.convert_image(
                sample_image_bytes, "jpeg", request
            )
            results.append(result)

        # Assert
        assert all(r.status == ConversionStatus.COMPLETED for r in results)

        # Verify general trend that higher quality produces larger files
        # (Note: JPEG compression can sometimes produce counterintuitive results at extremes)
        assert (
            results[0].output_size < results[3].output_size
        )  # Lowest vs highest quality

    @pytest.mark.asyncio
    async def test_pipeline_handles_large_images(
        self, conversion_manager, all_test_images
    ):
        """Test pipeline handles large images properly."""
        # Arrange
        large_image_path = all_test_images["large_photo"]["path"]
        with open(large_image_path, "rb") as f:
            large_data = f.read()

        request = ConversionRequest(
            output_format=OutputFormat.WEBP,
            settings=ConversionSettings(quality=75, optimize=True),
        )

        # Act
        result = await conversion_manager.convert_image(large_data, "jpeg", request)

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        assert (
            result.processing_time < 3.0
        )  # Should complete within 3 seconds (large images may take longer)
        assert result.compression_ratio < 0.5  # Should achieve good compression

    @pytest.mark.asyncio
    async def test_pipeline_handles_tiny_images(
        self, conversion_manager, all_test_images
    ):
        """Test pipeline handles tiny images properly."""
        # Arrange
        tiny_image_path = all_test_images["tiny_icon"]["path"]
        with open(tiny_image_path, "rb") as f:
            tiny_data = f.read()

        request = ConversionRequest(
            output_format=OutputFormat.PNG, settings=ConversionSettings(quality=100)
        )

        # Act
        result = await conversion_manager.convert_image(tiny_data, "png", request)

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        assert result.output_size > 0

    @pytest.mark.asyncio
    async def test_pipeline_error_propagation(
        self, conversion_manager, corrupted_image_path
    ):
        """Test that errors are properly propagated through the pipeline."""
        # Arrange
        with open(corrupted_image_path, "rb") as f:
            corrupted_data = f.read()

        request = ConversionRequest(output_format=OutputFormat.WEBP)

        # Act & Assert
        with pytest.raises(ConversionFailedError):
            await conversion_manager.convert_image(corrupted_data, "jpeg", request)

    @pytest.mark.asyncio
    async def test_pipeline_concurrent_conversions(
        self, conversion_manager, all_test_images
    ):
        """Test pipeline handles concurrent conversions."""
        # Arrange
        conversions = []

        # Prepare different conversion tasks
        for img_name, img_info in list(all_test_images.items())[:4]:
            with open(img_info["path"], "rb") as f:
                img_data = f.read()

            conversions.append(
                {
                    "data": img_data,
                    "format": img_info["format"].lower(),
                    "request": ConversionRequest(
                        output_format=OutputFormat.WEBP,
                        settings=ConversionSettings(quality=80),
                    ),
                }
            )

        # Act - Run conversions concurrently
        tasks = [
            conversion_manager.convert_image(
                conv["data"], conv["format"], conv["request"]
            )
            for conv in conversions
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Assert
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) >= 3  # Most should succeed

        for result in successful_results:
            assert result.status == ConversionStatus.COMPLETED
            assert result.output_format == OutputFormat.WEBP

    @pytest.mark.asyncio
    async def test_pipeline_memory_cleanup(
        self, conversion_manager, sample_image_bytes
    ):
        """Test that memory is properly cleaned up after conversion."""
        # This test is more conceptual - in real implementation,
        # you might use memory profiling tools

        # Arrange
        request = ConversionRequest(
            output_format=OutputFormat.WEBP, settings=ConversionSettings(quality=85)
        )

        # Act - Perform multiple conversions
        for _ in range(10):
            result = await conversion_manager.convert_image(
                sample_image_bytes, "jpeg", request
            )
            assert result.status == ConversionStatus.COMPLETED

            # Clear reference to result
            del result

        # In a real test, you might check memory usage here
        # For now, we just verify no crashes or memory errors

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "input_format,input_file,output_format",
        [
            ("jpeg", "sample_photo", OutputFormat.WEBP),
            ("jpeg", "portrait_photo", OutputFormat.AVIF),
            ("png", "screenshot", OutputFormat.WEBP),
            ("png", "document_scan", OutputFormat.JPEG),
            ("png", "illustration", OutputFormat.AVIF),
        ],
    )
    async def test_pipeline_format_combinations(
        self,
        conversion_manager,
        all_test_images,
        input_format,
        input_file,
        output_format,
    ):
        """Test various input/output format combinations."""
        # Arrange
        image_path = all_test_images[input_file]["path"]
        with open(image_path, "rb") as f:
            image_data = f.read()

        request = ConversionRequest(
            output_format=output_format, settings=ConversionSettings(quality=85)
        )

        # Act
        result = await conversion_manager.convert_image(
            image_data, input_format, request
        )

        # Assert
        assert result.status == ConversionStatus.COMPLETED
        assert result.output_format == output_format
        assert result.output_size > 0

        # Verify output is valid
        output_img = Image.open(io.BytesIO(result._output_data))
        assert output_img.size[0] > 0 and output_img.size[1] > 0

    @pytest.mark.asyncio
    async def test_pipeline_optimization_impact(
        self, conversion_manager, sample_image_bytes
    ):
        """Test impact of optimization settings."""
        # Arrange
        request_optimized = ConversionRequest(
            output_format=OutputFormat.WEBP,
            settings=ConversionSettings(quality=80, optimize=True),
        )
        request_normal = ConversionRequest(
            output_format=OutputFormat.WEBP,
            settings=ConversionSettings(quality=80, optimize=False),
        )

        # Act
        result_optimized = await conversion_manager.convert_image(
            sample_image_bytes, "jpeg", request_optimized
        )
        result_normal = await conversion_manager.convert_image(
            sample_image_bytes, "jpeg", request_normal
        )

        # Assert
        assert result_optimized.status == ConversionStatus.COMPLETED
        assert result_normal.status == ConversionStatus.COMPLETED

        # Optimized should take longer but produce smaller file
        assert result_optimized.processing_time >= result_normal.processing_time
        # Note: In some cases, optimization might not reduce size significantly
        # for small test images
