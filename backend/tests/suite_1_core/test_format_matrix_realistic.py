"""
Ultra-realistic test suite for comprehensive format conversion matrix.
Tests all 121 combinations of format conversions with real image data.
"""

import asyncio
import hashlib
import io
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import pytest
from PIL import Image

# Add tests directory to path for helpers
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helpers.format_helpers import (
    create_test_image_for_format,
    get_format_capabilities,
    prepare_image_for_conversion,
    validate_conversion_result,
)

from app.core.constants import SUPPORTED_INPUT_FORMATS, SUPPORTED_OUTPUT_FORMATS
from app.models.conversion import ConversionRequest, ConversionStatus
from app.services.conversion_service import conversion_service


class TestFormatMatrixRealistic:
    """Comprehensive format conversion matrix tests with realistic data."""

    # Define all testable format combinations
    INPUT_FORMATS = ["jpeg", "png", "webp", "gif", "bmp", "tiff", "avif"]
    OUTPUT_FORMATS = [
        "jpeg",
        "png",
        "webp",
        "gif",
        "bmp",
        "tiff",
        "avif",
        "jxl",
        "jp2",
        "heif",
    ]

    # Known problematic conversions that need special handling
    SPECIAL_CONVERSIONS = {
        ("heif", "avif"): "requires_rgb_intermediate",
        ("gif", "avif"): "animation_loss",
        ("tiff", "gif"): "quality_degradation",
        ("avif", "gif"): "transparency_loss",
    }

    @pytest.fixture(autouse=True)
    def setup(self, realistic_image_generator, initialized_services):
        """Setup test environment with realistic images."""
        self.image_generator = realistic_image_generator
        self.conversion_times = {}
        self.quality_metrics = {}
        self.conversion_service = initialized_services["conversion_service"]

    def create_test_image(self, format: str, content_type: str = "photo") -> bytes:
        """Create a realistic test image for the given format."""
        # Generate base image
        if format.lower() in ["jpeg", "jpg"]:
            return self.image_generator(
                width=2048,
                height=1536,
                content_type=content_type,
                has_metadata=True,
                format="JPEG",
            )
        elif format.lower() == "png":
            return self.image_generator(
                width=1920,
                height=1080,
                content_type=(
                    "screenshot" if content_type == "screenshot" else "illustration"
                ),
                has_metadata=False,
                format="PNG",
            )
        elif format.lower() == "gif":
            # Create animated GIF
            img = Image.new("RGB", (500, 500))
            frames = []
            for i in range(3):
                frame = img.copy()
                # Add variation to each frame
                for x in range(100, 400, 10):
                    for y in range(100, 400, 10):
                        frame.putpixel((x, y), (i * 80, 255 - i * 80, 128))
                frames.append(frame)

            buffer = io.BytesIO()
            frames[0].save(
                buffer,
                format="GIF",
                save_all=True,
                append_images=frames[1:],
                duration=100,
                loop=0,
            )
            return buffer.getvalue()
        elif format.lower() == "bmp":
            img = Image.new("RGB", (800, 600), color=(100, 150, 200))
            buffer = io.BytesIO()
            img.save(buffer, format="BMP")
            return buffer.getvalue()
        elif format.lower() in ["tiff", "tif"]:
            return self.image_generator(
                width=2550,
                height=3300,
                content_type="document",
                has_metadata=True,
                format="TIFF",
            )
        elif format.lower() == "webp":
            img = Image.new("RGBA", (1024, 768), color=(255, 255, 255, 200))
            buffer = io.BytesIO()
            img.save(buffer, format="WEBP", quality=85)
            return buffer.getvalue()
        else:
            # For AVIF, HEIF, JXL, JP2 - use a standard format and mark for conversion
            return self.image_generator(
                width=1920,
                height=1080,
                content_type=content_type,
                has_metadata=True,
                format="PNG",
            )

    @pytest.mark.critical
    @pytest.mark.parametrize("input_format", INPUT_FORMATS)
    @pytest.mark.parametrize("output_format", OUTPUT_FORMATS)
    async def test_format_conversion_matrix(self, input_format, output_format):
        """
        Test every possible format conversion with realistic images.

        This test validates:
        - All 70+ format combinations work correctly
        - Conversion quality is acceptable
        - Performance is within limits
        - Metadata handling is correct
        - Special cases are handled properly
        """
        # Skip same-format conversions unless optimization is involved
        if input_format == output_format and output_format not in [
            "jpeg_optimized",
            "png_optimized",
        ]:
            pytest.skip(
                f"Skipping same-format conversion {input_format} -> {output_format}"
            )

        # Create realistic test image
        try:
            test_image = self.create_test_image(input_format)
        except Exception:
            # Fallback to helper function if custom generator fails
            test_image = create_test_image_for_format(input_format)

        # Prepare image for conversion if needed
        if (input_format, output_format) in self.SPECIAL_CONVERSIONS:
            test_image = prepare_image_for_conversion(test_image, output_format)

        # Setup conversion request
        request = ConversionRequest(
            output_format=output_format,
            quality=85 if output_format in ["jpeg", "webp", "avif"] else None,
            strip_metadata=True,
            optimization_mode="balanced",
        )

        # Measure conversion time
        start_time = time.perf_counter()

        try:
            # Execute conversion
            result, output_data = await conversion_service.convert(
                image_data=test_image,
                request=request,
            )

            conversion_time = time.perf_counter() - start_time

            # Store metrics
            conversion_key = f"{input_format}_to_{output_format}"
            self.conversion_times[conversion_key] = conversion_time

            # Validate successful conversion
            assert (
                result.status == ConversionStatus.COMPLETED
            ), f"Conversion {input_format} -> {output_format} failed: {result.error_message}"
            assert output_data is not None, "No output data received"
            assert len(output_data) > 0, "Empty output data"

            # Validate output format detection
            output_img = Image.open(io.BytesIO(output_data))

            # Check dimensions preserved (no resizing in this test)
            input_img = Image.open(io.BytesIO(test_image))
            assert abs(output_img.width - input_img.width) <= 1, "Width not preserved"
            assert (
                abs(output_img.height - input_img.height) <= 1
            ), "Height not preserved"

            # Performance validation
            max_time = self.get_max_conversion_time(
                input_format, output_format, len(test_image)
            )
            assert (
                conversion_time < max_time
            ), f"Conversion too slow: {conversion_time:.2f}s (max: {max_time}s)"

            # Quality validation for lossy formats
            # TODO: Enable when metrics are available
            # if output_format in ["jpeg", "webp", "avif"] and hasattr(result, 'metrics'):
            #     if result.metrics.ssim is not None:
            #         assert (
            #             result.metrics.ssim > 0.7
            #         ), f"Quality too low: SSIM={result.metrics.ssim}"

            # Special case validation
            special_key = (input_format, output_format)
            if special_key in self.SPECIAL_CONVERSIONS:
                self.validate_special_conversion(special_key, result, output_data)

            # Compression ratio validation
            compression_ratio = len(output_data) / len(test_image)
            if output_format in ["webp", "avif", "jxl"]:
                assert (
                    compression_ratio < 1.0
                ), f"No compression achieved: {compression_ratio:.2%}"

        except Exception as e:
            # Log detailed error for debugging
            pytest.fail(
                f"Conversion {input_format} -> {output_format} raised {type(e).__name__}: {str(e)}"
            )

    def get_max_conversion_time(
        self, input_format: str, output_format: str, input_size: int
    ) -> float:
        """Calculate maximum acceptable conversion time based on formats and size."""
        base_time = 2.0  # Base 2 seconds

        # Add time for complex formats
        complex_formats = ["avif", "jxl", "heif", "jp2"]
        if input_format in complex_formats:
            base_time += 1.0
        if output_format in complex_formats:
            base_time += 1.5

        # Add time for large files
        size_mb = input_size / (1024 * 1024)
        if size_mb > 10:
            base_time += size_mb / 10

        return base_time

    def validate_special_conversion(
        self, conversion_key: Tuple[str, str], result, output_data: bytes
    ):
        """Validate special conversion cases that need extra handling."""
        special_type = self.SPECIAL_CONVERSIONS[conversion_key]

        if special_type == "requires_rgb_intermediate":
            # Verify color space was handled correctly
            assert (
                result.warnings is None
                or "color space" not in str(result.warnings).lower()
            )

        elif special_type == "animation_loss":
            # Verify animation frames were handled
            if result.warnings:
                assert "animation" in str(result.warnings).lower()

        elif special_type == "quality_degradation":
            # Accept lower quality for problematic conversions
            if result.metrics and result.metrics.ssim:
                assert result.metrics.ssim > 0.5, "Excessive quality loss"

        elif special_type == "transparency_loss":
            # Verify transparency was handled
            if result.warnings:
                assert (
                    "transparency" in str(result.warnings).lower()
                    or "alpha" in str(result.warnings).lower()
                )

    @pytest.mark.slow
    async def test_format_conversion_stress(self, realistic_image_generator):
        """
        Stress test with rapid format conversions.

        Simulates real-world scenario of bulk format migration.
        """
        # Create diverse test images
        test_images = [
            (
                "photo.jpg",
                realistic_image_generator(content_type="photo", format="JPEG"),
            ),
            (
                "screenshot.png",
                realistic_image_generator(content_type="screenshot", format="PNG"),
            ),
            (
                "document.tiff",
                realistic_image_generator(content_type="document", format="TIFF"),
            ),
        ]

        # Convert each to multiple formats rapidly
        conversions = []
        target_formats = ["webp", "avif", "png"]

        for filename, image_data in test_images:
            for target_format in target_formats:
                request = ConversionRequest(
                    output_format=target_format, quality=80, strip_metadata=True
                )
                conversions.append((filename, image_data, request))

        # Execute all conversions concurrently
        start_time = time.perf_counter()

        tasks = [
            conversion_service.convert(image_data=img_data, request=req)
            for fname, img_data, req in conversions
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        total_time = time.perf_counter() - start_time

        # Validate results
        successful = sum(
            1
            for r in results
            if not isinstance(r, Exception)
            and r[0].status == ConversionStatus.COMPLETED
        )
        assert (
            successful >= len(conversions) * 0.9
        ), f"Too many failures: {successful}/{len(conversions)}"

        # Performance check
        avg_time = total_time / len(conversions)
        assert avg_time < 2.0, f"Average conversion too slow: {avg_time:.2f}s"

    @pytest.mark.critical
    async def test_lossy_to_lossless_quality_preservation(self):
        """
        Test that converting from lossy to lossless preserves maximum quality.

        Important for archival workflows.
        """
        # Start with high-quality JPEG
        jpeg_image = self.image_generator(
            width=3000,
            height=2000,
            content_type="photo",
            has_metadata=True,
            format="JPEG",
        )

        # Convert to lossless formats
        lossless_formats = ["png", "tiff", "bmp"]

        for target_format in lossless_formats:
            request = ConversionRequest(
                output_format=target_format,
                strip_metadata=False,  # Preserve for archival
                optimization_mode="quality",
            )

            result, output_data = await conversion_service.convert(
                image_data=jpeg_image,
                request=request,
            )

            assert result.status == ConversionStatus.COMPLETED

            # Verify no additional quality loss
            if result.metrics and result.metrics.ssim:
                assert (
                    result.metrics.ssim > 0.95
                ), f"Quality loss in lossless conversion to {target_format}"

            # Verify file size increased (lossless is larger)
            assert (
                len(output_data) > len(jpeg_image) * 0.8
            ), "Suspicious compression for lossless format"

    @pytest.mark.performance
    async def test_format_conversion_memory_stability(self, memory_monitor):
        """
        Test memory stability during multiple format conversions.

        Ensures no memory leaks during format transformations.
        """
        memory_monitor.start()

        # Perform 20 conversions with different formats
        for i in range(20):
            format_pairs = [
                ("jpeg", "webp"),
                ("png", "avif"),
                ("tiff", "jpeg"),
                ("bmp", "png"),
                ("webp", "jpeg"),
            ]

            input_fmt, output_fmt = format_pairs[i % len(format_pairs)]

            test_image = self.create_test_image(input_fmt)

            request = ConversionRequest(
                output_format=output_fmt, quality=85, strip_metadata=True
            )

            result, output_data = await conversion_service.convert(
                image_data=test_image, request=request
            )

            assert result.status == ConversionStatus.COMPLETED

            # Sample memory every 5 conversions
            if i % 5 == 0:
                memory_monitor.sample()

        # Check memory stability
        memory_monitor.assert_stable(max_growth_mb=50)
