"""
Ultra-realistic tests for extreme image dimensions.
Tests edge cases from 1x1 pixels to gigapixel images.
"""

import pytest
import asyncio
import struct
import io
from PIL import Image
import numpy as np
from typing import Tuple
import psutil

from app.services.conversion_service import conversion_service
from app.models.conversion import ConversionRequest
from app.core.exceptions import ValidationError, ConversionFailedError


class TestExtremeDimensions:
    """Test handling of images with extreme dimensions."""

    def create_extreme_image(
        self, width: int, height: int, format: str = "PNG"
    ) -> bytes:
        """Create an image with extreme dimensions."""
        # For very large images, create sparse data to avoid memory issues
        if width * height > 10000000:  # >10MP
            # Create a small pattern and claim it's larger
            if format.upper() == "PNG":
                # Create minimal PNG with fake dimensions
                png_header = b"\x89PNG\r\n\x1a\n"
                # IHDR chunk with specified dimensions
                ihdr_data = struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"
                ihdr_crc = struct.pack(">I", 0)  # Simplified CRC
                ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc

                # Minimal IDAT
                idat_data = b"\x78\x9c\x62\x00\x00\x00\x02\x00\x01"
                idat_chunk = (
                    struct.pack(">I", len(idat_data))
                    + b"IDAT"
                    + idat_data
                    + struct.pack(">I", 0)
                )

                # IEND
                iend_chunk = (
                    struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)
                )

                return png_header + ihdr_chunk + idat_chunk + iend_chunk
            else:
                # For other formats, create a small real image
                # System will handle the size validation
                img = Image.new("RGB", (min(width, 1000), min(height, 1000)))
                buffer = io.BytesIO()
                img.save(buffer, format=format)
                return buffer.getvalue()
        else:
            # Create actual image for reasonable sizes
            img = Image.new("RGB", (width, height))

            # Add some pattern to make it realistic
            pixels = img.load()
            for i in range(0, width, max(1, width // 10)):
                for j in range(0, height, max(1, height // 10)):
                    pixels[i, j] = (i % 256, j % 256, (i + j) % 256)

            buffer = io.BytesIO()
            img.save(buffer, format=format)
            return buffer.getvalue()

    @pytest.mark.critical
    async def test_tiny_1x1_pixel_image(self):
        """
        Test processing of 1x1 pixel images.

        Edge case: Smallest possible valid image.
        """
        # Create 1x1 pixel image
        tiny_image = self.create_extreme_image(1, 1, "PNG")

        request = ConversionRequest(output_format="jpeg", quality=90)

        # Should handle gracefully
        result, output_data = await conversion_service.convert(
            image_data=tiny_image, request=request, source_filename="tiny_1x1.png"
        )

        assert result.success, f"Failed to convert 1x1 image: {result.error}"
        assert output_data is not None

        # Verify output is still 1x1
        output_img = Image.open(io.BytesIO(output_data))
        assert output_img.size == (1, 1), f"Dimension changed: {output_img.size}"

    @pytest.mark.critical
    async def test_extreme_aspect_ratio_1x10000(self):
        """
        Test processing of extreme aspect ratio (1 pixel wide, 10000 tall).

        Edge case: Line-like images (e.g., timeline visualizations).
        """
        # Create 1x10000 image (vertical line)
        line_image = self.create_extreme_image(1, 10000, "PNG")

        request = ConversionRequest(output_format="webp", quality=85)

        result, output_data = await conversion_service.convert(
            image_data=line_image, request=request, source_filename="vertical_line.png"
        )

        assert result.success, f"Failed to convert line image: {result.error}"

        # Check dimensions preserved
        output_img = Image.open(io.BytesIO(output_data))
        assert output_img.width == 1
        assert output_img.height == 10000

    async def test_extreme_aspect_ratio_10000x1(self):
        """
        Test processing of extreme horizontal aspect ratio.

        Edge case: Panoramic or timeline images.
        """
        # Create 10000x1 image (horizontal line)
        line_image = self.create_extreme_image(10000, 1, "PNG")

        request = ConversionRequest(output_format="jpeg", quality=85)

        result, output_data = await conversion_service.convert(
            image_data=line_image,
            request=request,
            source_filename="horizontal_line.png",
        )

        assert result.success

        output_img = Image.open(io.BytesIO(output_data))
        assert output_img.width == 10000
        assert output_img.height == 1

    @pytest.mark.slow
    async def test_large_but_valid_20000x20000(self):
        """
        Test processing of large but valid images (400MP).

        Edge case: Satellite imagery, gigapixel photography.
        """
        # Create large image (but within PIL limits)
        # Note: This is memory-intensive, using sparse data
        large_image = self.create_extreme_image(20000, 20000, "PNG")

        request = ConversionRequest(
            output_format="jpeg",
            quality=75,  # Lower quality for large image
            optimization_mode="size",  # Optimize for file size
        )

        # Should handle with appropriate resource management
        try:
            result, output_data = await conversion_service.convert(
                image_data=large_image,
                request=request,
                source_filename="large_image.png",
            )

            if result.success:
                assert output_data is not None
                # Should achieve good compression
                compression_ratio = len(output_data) / len(large_image)
                assert compression_ratio < 1.0, "No compression achieved"
            else:
                # Acceptable to fail with clear error
                assert (
                    "size" in result.error.lower() or "memory" in result.error.lower()
                )
        except (MemoryError, ValidationError) as e:
            # Expected for very large images
            assert "memory" in str(e).lower() or "size" in str(e).lower()

    @pytest.mark.critical
    async def test_maximum_png_dimensions_65535x65535(self):
        """
        Test handling of maximum PNG dimensions (65535x65535).

        Edge case: PNG format maximum, should be rejected.
        """
        # Create PNG claiming maximum dimensions
        max_png = self.create_extreme_image(65535, 65535, "PNG")

        request = ConversionRequest(output_format="jpeg", quality=75)

        # Should reject as too large
        with pytest.raises((ValidationError, ConversionFailedError, MemoryError)):
            await conversion_service.convert(
                image_data=max_png, request=request, source_filename="max_png.png"
            )

    async def test_prime_number_dimensions(self):
        """
        Test images with prime number dimensions.

        Edge case: Dimensions that don't divide evenly for optimization algorithms.
        """
        prime_dimensions = [
            (97, 101),  # Small primes
            (1009, 1013),  # Medium primes
            (2017, 2027),  # Larger primes
        ]

        for width, height in prime_dimensions:
            img_data = self.create_extreme_image(width, height, "JPEG")

            request = ConversionRequest(output_format="webp", quality=85)

            result, output_data = await conversion_service.convert(
                image_data=img_data, request=request
            )

            assert result.success, f"Failed for {width}x{height}"

            # Verify dimensions preserved exactly
            output_img = Image.open(io.BytesIO(output_data))
            assert output_img.size == (
                width,
                height,
            ), f"Dimensions changed for prime numbers"

    async def test_zero_dimension_rejection(self):
        """
        Test that 0x0 or 0xN images are properly rejected.

        Edge case: Invalid dimension validation.
        """
        # Try to create 0x0 image
        with pytest.raises((ValueError, ValidationError)):
            # This should fail at creation
            img = Image.new("RGB", (0, 0))
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            zero_image = buffer.getvalue()

            request = ConversionRequest(output_format="jpeg")

            await conversion_service.convert(image_data=zero_image, request=request)

    @pytest.mark.performance
    async def test_dimension_resize_extreme_downscale(self):
        """
        Test extreme downscaling (e.g., 10000x10000 to 100x100).

        Use case: Thumbnail generation from large images.
        """
        # Create large source image
        large_image = self.create_extreme_image(5000, 5000, "JPEG")

        request = ConversionRequest(
            output_format="jpeg",
            quality=85,
            resize={"width": 100, "height": 100, "maintain_aspect_ratio": True},
        )

        result, output_data = await conversion_service.convert(
            image_data=large_image,
            request=request,
            source_filename="large_to_thumb.jpg",
        )

        assert result.success

        # Verify thumbnail size
        output_img = Image.open(io.BytesIO(output_data))
        assert (
            max(output_img.size) == 100
        ), f"Incorrect thumbnail size: {output_img.size}"

        # Should be much smaller file
        assert len(output_data) < len(large_image) * 0.01, "Thumbnail too large"

    async def test_dimension_resize_extreme_upscale(self):
        """
        Test extreme upscaling (e.g., 10x10 to 1000x1000).

        Edge case: Quality preservation during upscaling.
        """
        # Create tiny source image
        tiny_image = self.create_extreme_image(10, 10, "PNG")

        request = ConversionRequest(
            output_format="png",
            resize={
                "width": 1000,
                "height": 1000,
                "maintain_aspect_ratio": False,
                "resample": "lanczos",  # Best quality for upscaling
            },
        )

        result, output_data = await conversion_service.convert(
            image_data=tiny_image, request=request, source_filename="tiny_to_large.png"
        )

        assert result.success

        # Verify upscaled size
        output_img = Image.open(io.BytesIO(output_data))
        assert output_img.size == (
            1000,
            1000,
        ), f"Incorrect upscaled size: {output_img.size}"

        # File should be larger
        assert len(output_data) > len(tiny_image), "Upscaled image not larger"

    @pytest.mark.slow
    async def test_common_device_dimensions(self):
        """
        Test common device screen dimensions.

        Validates handling of real-world dimension requirements.
        """
        device_dimensions = [
            (2048, 2732),  # iPad Pro 12.9"
            (1668, 2388),  # iPad Pro 11"
            (1170, 2532),  # iPhone 13 Pro
            (1284, 2778),  # iPhone 13 Pro Max
            (3840, 2160),  # 4K TV
            (7680, 4320),  # 8K TV
            (1080, 1920),  # Vertical Full HD
            (1080, 2400),  # Common Android flagship
        ]

        for width, height in device_dimensions:
            # Create image matching device dimensions
            img_data = self.create_extreme_image(width, height, "PNG")

            request = ConversionRequest(
                output_format="webp", quality=90, optimization_mode="balanced"
            )

            result, output_data = await conversion_service.convert(
                image_data=img_data, request=request
            )

            assert result.success, f"Failed for device dimension {width}x{height}"

            # Verify exact dimensions preserved
            output_img = Image.open(io.BytesIO(output_data))
            assert output_img.size == (width, height)

    @pytest.mark.performance
    async def test_memory_efficiency_large_dimensions(self, memory_monitor):
        """
        Test memory efficiency when processing large dimension images.

        Ensures streaming/chunked processing for large files.
        """
        memory_monitor.start()

        # Process increasingly large images
        dimensions = [
            (1000, 1000),  # 1MP
            (2000, 2000),  # 4MP
            (3000, 3000),  # 9MP
            (4000, 4000),  # 16MP
        ]

        for width, height in dimensions:
            img_data = self.create_extreme_image(width, height, "JPEG")

            request = ConversionRequest(output_format="webp", quality=80)

            # Process image
            result, output_data = await conversion_service.convert(
                image_data=img_data, request=request
            )

            assert result.success

            # Sample memory
            current_memory = memory_monitor.sample()

            # Memory should not grow linearly with image size
            # Due to streaming/efficient processing

        # Check memory didn't grow excessively
        memory_monitor.assert_stable(max_growth_mb=200)

    async def test_non_standard_aspect_ratios(self):
        """
        Test non-standard aspect ratios used in special applications.

        Edge cases from real applications.
        """
        special_ratios = [
            (1920, 128),  # Banner/ticker
            (128, 1920),  # Vertical banner
            (3000, 1000),  # Ultrawide 3:1
            (1000, 3000),  # Tall infographic
            (2048, 2048),  # Square (Instagram)
            (1080, 1350),  # Instagram portrait
            (1200, 628),  # Facebook link preview
            (1500, 500),  # Twitter header
        ]

        for width, height in special_ratios:
            img_data = self.create_extreme_image(width, height, "PNG")

            request = ConversionRequest(
                output_format="jpeg", quality=85, optimization_mode="balanced"
            )

            result, output_data = await conversion_service.convert(
                image_data=img_data, request=request
            )

            assert result.success, f"Failed for aspect ratio {width}:{height}"

            # Verify aspect ratio preserved
            output_img = Image.open(io.BytesIO(output_data))
            output_ratio = output_img.width / output_img.height
            input_ratio = width / height
            assert abs(output_ratio - input_ratio) < 0.01, "Aspect ratio not preserved"
