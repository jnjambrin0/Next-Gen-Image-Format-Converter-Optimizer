"""Real-world integration tests for Intelligence Engine.

from typing import Any
These tests validate the engine's behavior under realistic conditions including:
- Various image formats and edge cases
- Concurrent processing scenarios
- Resource constraints and failures
- Security attack vectors
- Performance under load
"""

import asyncio
import gc
import io
import os
import tempfile
import time
from unittest.mock import Mock, patch

import numpy as np
import psutil
import pytest
from PIL import Image

from app.core.intelligence.engine import IntelligenceEngine
from app.core.security.errors_simplified import SecurityError
from app.models.conversion import ContentClassification
from app.services.intelligence_service import intelligence_service


class TestIntelligenceEngineRealWorld:
    """Comprehensive real-world tests for the Intelligence Engine."""

    @pytest.fixture
    def engine(self) -> None:
        """Create a fresh engine instance for each test."""
        engine = IntelligenceEngine(
            models_dir="./test_models", fallback_mode=True, enable_caching=True
        )
        yield engine
        # Cleanup
        engine.clear_cache()

    @pytest.fixture
    def sample_images(self) -> None:
        """Generate various test images representing real-world scenarios."""
        images = {}

        # Photo-like image with noise
        photo = Image.new("RGB", (1920, 1080))
        pixels = photo.load()
        for i in range(1920):
            for j in range(1080):
                # Natural photo-like variation
                r = int(128 + np.random.normal(0, 30))
                g = int(128 + np.random.normal(0, 30))
                b = int(128 + np.random.normal(0, 30))
                pixels[i, j] = (
                    max(0, min(255, r)),
                    max(0, min(255, g)),
                    max(0, min(255, b)),
                )
        images["photo"] = photo

        # Screenshot with UI elements
        screenshot = Image.new("RGB", (1920, 1080), color="white")
        # Add UI-like rectangles
        for i in range(5):
            x = i * 300
            screenshot.paste(
                Image.new("RGB", (250, 100), color=(240, 240, 240)), (x + 50, 100)
            )
        images["screenshot"] = screenshot

        # Document (mostly white with text-like patterns)
        document = Image.new("L", (2100, 2970), color=255)  # A4 at 300 DPI
        pixels = document.load()
        # Add text-like horizontal lines
        for y in range(100, 2900, 40):
            for x in range(200, 1900):
                if np.random.random() > 0.3:
                    pixels[x, y] = 0
        images["document"] = document

        # Illustration with solid colors
        illustration = Image.new("RGB", (800, 800))
        # Create geometric patterns
        for i in range(4):
            for j in range(4):
                color = ((i * 60) % 255, (j * 80) % 255, 150)
                illustration.paste(
                    Image.new("RGB", (200, 200), color=color), (i * 200, j * 200)
                )
        images["illustration"] = illustration

        return images

    # Test 1: Robustness with corrupted images
    @pytest.mark.asyncio
    async def test_corrupted_image_handling(self, engine):
        """Test handling of various corrupted image scenarios."""
        # Completely invalid data
        invalid_data = b"This is not an image at all!"
        with pytest.raises(SecurityError) as exc:
            await engine.classify_content(invalid_data)
        assert exc.value.category == "file"

        # Truncated JPEG
        valid_jpeg = Image.new("RGB", (100, 100), color="red")
        buffer = io.BytesIO()
        valid_jpeg.save(buffer, format="JPEG")
        truncated_jpeg = buffer.getvalue()[: len(buffer.getvalue()) // 2]

        with pytest.raises(SecurityError) as exc:
            await engine.classify_content(truncated_jpeg)
        assert exc.value.category == "file"

        # Invalid image header
        fake_png = b"\x89PNG\r\n\x1a\n" + b"corrupted_data" * 100
        with pytest.raises(SecurityError) as exc:
            await engine.classify_content(fake_png)
        assert exc.value.category == "file"

    # Test 2: Concurrent processing stress test
    @pytest.mark.asyncio
    async def test_concurrent_processing(self, engine, sample_images):
        """Test engine under heavy concurrent load."""
        # Create multiple different images
        images_data = []
        for name, img in sample_images.items():
            for i in range(5):  # 5 variations of each type
                buffer = io.BytesIO()
                # Add slight variation to avoid cache hits
                varied_img = img.copy()
                varied_img.paste(
                    Image.new("RGB", (10, 10), color=(i * 50, 0, 0)), (0, 0)
                )
                varied_img.save(buffer, format="PNG")
                images_data.append((f"{name}_{i}", buffer.getvalue()))

        # Process concurrently
        start_time = time.time()
        tasks = []
        for name, data in images_data:
            task = asyncio.create_task(engine.classify_content(data))
            tasks.append((name, task))

        results = []
        for name, task in tasks:
            try:
                result = await task
                results.append((name, result))
            except Exception as e:
                pytest.fail(f"Concurrent processing failed for {name}: {e}")

        # Verify results
        assert len(results) == len(images_data)

        # Check timing - should benefit from concurrency
        total_time = time.time() - start_time
        avg_time = total_time / len(images_data)
        assert avg_time < 0.5  # Should average less than 500ms per image

        # Verify all results are valid
        for name, result in results:
            assert isinstance(result, ContentClassification)
            assert result.confidence > 0
            assert result.processing_time_ms < 500

    # Test 3: Memory exhaustion scenarios
    @pytest.mark.asyncio
    async def test_memory_constraints(self, engine):
        """Test behavior under memory pressure."""
        # Create a very large image that approaches memory limits
        large_image = Image.new("RGB", (8000, 8000), color="white")

        # Add some content to prevent simple optimization
        for i in range(0, 8000, 100):
            large_image.paste(Image.new("RGB", (50, 50), color=(i % 255, 0, 0)), (i, i))

        buffer = io.BytesIO()
        large_image.save(buffer, format="PNG")
        large_data = buffer.getvalue()

        # Should handle large image with downsampling
        result = await engine.classify_content(large_data)
        assert isinstance(result, ContentClassification)

        # Test cache eviction under memory pressure
        # Fill cache with many unique images
        for i in range(150):  # More than cache size
            small_img = Image.new("RGB", (100, 100), color=(i, i, i))
            buf = io.BytesIO()
            small_img.save(buf, format="PNG")
            await engine.classify_content(buf.getvalue())

        # Cache should not exceed limit
        assert len(engine._cache) <= 100

    # Test 4: Race condition detection
    @pytest.mark.asyncio
    async def test_cache_race_conditions(self, engine):
        """Test for race conditions in cache access."""
        # Create test image
        test_image = Image.new("RGB", (100, 100), color="blue")
        buffer = io.BytesIO()
        test_image.save(buffer, format="PNG")
        image_data = buffer.getvalue()

        # Track any race condition errors
        errors = []
        results = []

        async def classify_with_cache_manipulation():
            try:
                # Simulate concurrent cache access
                result = await engine.classify_content(image_data)
                results.append(result)

                # Try to manipulate cache during operation
                if hasattr(engine, "_cache"):
                    engine._cache.move_to_end(list(engine._cache.keys())[0])

            except Exception as e:
                errors.append(e)

        # Run multiple concurrent operations
        tasks = [classify_with_cache_manipulation() for _ in range(20)]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Should have no errors from race conditions
        assert len(errors) == 0

        # All results should be consistent
        if results:
            first_type = results[0].primary_type
            for result in results:
                assert result.primary_type == first_type

    # Test 5: Model loading failures and recovery
    @pytest.mark.asyncio
    async def test_model_loading_failures(self):
        """Test graceful handling of model loading failures."""
        # Test with non-existent model directory
        engine = IntelligenceEngine(models_dir="/non/existent/path", fallback_mode=True)

        # Should work with fallback
        test_img = Image.new("RGB", (200, 200), color="green")
        buffer = io.BytesIO()
        test_img.save(buffer, format="PNG")

        result = await engine.classify_content(buffer.getvalue())
        assert isinstance(result, ContentClassification)
        assert engine.fallback_mode is True

        # Test with corrupted model file
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake model structure
            content_dir = os.path.join(tmpdir, "content")
            os.makedirs(content_dir)

            # Write corrupted model file
            model_path = os.path.join(content_dir, "mobilenet_v3_content.onnx")
            with open(model_path, "wb") as f:
                f.write(b"corrupted model data")

            # Write metadata with wrong checksum
            metadata_path = os.path.join(content_dir, "model_metadata.json")
            with open(metadata_path, "w") as f:
                f.write('{"checksum": "incorrect_checksum"}')

            # Should fail checksum validation
            with pytest.raises(SecurityError) as exc:
                engine = IntelligenceEngine(models_dir=tmpdir, fallback_mode=False)
            assert exc.value.category == "verification"

    # Test 6: Input validation security
    @pytest.mark.asyncio
    async def test_input_validation_security(self, engine):
        """Test security of input validation against various attacks."""
        # Test extremely large dimensions
        with patch("PIL.Image.open") as mock_open:
            mock_img = Mock()
            mock_img.width = 999999
            mock_img.height = 999999
            mock_img.mode = "RGB"
            mock_open.return_value = mock_img

            with pytest.raises(SecurityError) as exc:
                await engine.classify_content(b"fake_data")
            assert exc.value.category == "file"

        # Test zip bomb protection
        # Create a highly compressed image that expands significantly
        tiny_img = Image.new("RGB", (1, 1), color="white")
        compressed_buffer = io.BytesIO()
        tiny_img.save(compressed_buffer, format="PNG", compress_level=9)

        # Repeat the data to simulate expansion
        bomb_data = compressed_buffer.getvalue() * 1000

        # Should handle without memory explosion
        try:
            result = await engine.classify_content(bomb_data[:1000])  # Use portion
        except SecurityError:
            # Expected for invalid format
            pass

    # Test 7: Performance benchmarks
    @pytest.mark.asyncio
    async def test_performance_benchmarks(self, engine, sample_images):
        """Benchmark performance across different image types and sizes."""
        benchmarks = {}

        for img_type, base_img in sample_images.items():
            type_benchmarks = []

            # Test different sizes
            for scale in [0.5, 1.0, 2.0]:
                new_size = (int(base_img.width * scale), int(base_img.height * scale))
                if new_size[0] > 0 and new_size[1] > 0:
                    scaled_img = base_img.resize(new_size, Image.Resampling.LANCZOS)

                    buffer = io.BytesIO()
                    scaled_img.save(buffer, format="PNG")
                    data = buffer.getvalue()

                    # Measure classification time
                    start = time.time()
                    result = await engine.classify_content(data)
                    elapsed = (time.time() - start) * 1000

                    type_benchmarks.append(
                        {
                            "size": new_size,
                            "time_ms": elapsed,
                            "confidence": result.confidence,
                            "detected_type": result.primary_type.value,
                        }
                    )

            benchmarks[img_type] = type_benchmarks

        # Verify performance requirements
        for img_type, results in benchmarks.items():
            for result in results:
                # Should meet <500ms requirement
                assert (
                    result["time_ms"] < 500
                ), f"{img_type} at {result['size']} took {result['time_ms']}ms"

    # Test 8: Memory leak detection
    @pytest.mark.asyncio
    async def test_memory_leaks(self, engine):
        """Test for memory leaks during extended operation."""
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Process many images
        for i in range(100):
            img = Image.new("RGB", (500, 500), color=(i % 255, 0, 0))
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")

            result = await engine.classify_content(buffer.getvalue())

            # Periodically clear to trigger cleanup
            if i % 20 == 0:
                engine.clear_cache()
                gc.collect()

        # Final cleanup
        engine.clear_cache()
        gc.collect()
        time.sleep(0.1)  # Allow cleanup to complete

        # Check final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_growth = final_memory - initial_memory

        # Allow some growth but not excessive
        assert memory_growth < 100, f"Memory grew by {memory_growth}MB"

    # Test 9: Cross-format consistency
    @pytest.mark.asyncio
    async def test_format_consistency(self, engine):
        """Test consistent classification across different image formats."""
        # Create base image
        base_img = Image.new("RGB", (800, 600), color="white")
        # Add some features
        for x in range(0, 800, 100):
            base_img.paste(
                Image.new("RGB", (80, 80), color=(x % 255, 100, 150)), (x, 250)
            )

        formats = ["PNG", "JPEG", "BMP", "WEBP"]
        results = {}

        for fmt in formats:
            buffer = io.BytesIO()
            # Handle format-specific options
            if fmt == "JPEG":
                base_img.save(buffer, format=fmt, quality=95)
            else:
                base_img.save(buffer, format=fmt)

            result = await engine.classify_content(buffer.getvalue())
            results[fmt] = result

        # All formats should classify similarly
        primary_types = [r.primary_type for r in results.values()]
        assert len(set(primary_types)) == 1, f"Inconsistent classification: {results}"

        # Confidence should be similar (within 20%)
        confidences = [r.confidence for r in results.values()]
        min_conf, max_conf = min(confidences), max(confidences)
        assert (max_conf - min_conf) < 0.2, f"Confidence varies too much: {confidences}"

    # Test 10: API integration scenarios
    @pytest.mark.asyncio
    async def test_api_integration_errors(self):
        """Test intelligence service API integration error handling."""
        # Test service initialization failure
        service = intelligence_service

        # Test with invalid image through service
        with pytest.raises(Exception):
            await service.analyze_image(b"invalid", debug=True)

        # Test service recovery after error
        valid_img = Image.new("RGB", (100, 100), color="red")
        buffer = io.BytesIO()
        valid_img.save(buffer, format="PNG")

        # Should work after previous error
        result = await service.analyze_image(buffer.getvalue(), debug=False)
        assert isinstance(result, ContentClassification)

    # Test 11: Extreme edge cases
    @pytest.mark.asyncio
    async def test_extreme_edge_cases(self, engine):
        """Test extreme edge cases that might occur in production."""
        # 1x1 pixel image
        tiny = Image.new("RGB", (1, 1), color="red")
        buffer = io.BytesIO()
        tiny.save(buffer, format="PNG")
        result = await engine.classify_content(buffer.getvalue())
        assert isinstance(result, ContentClassification)

        # Extremely wide image
        wide = Image.new("RGB", (10000, 10), color="blue")
        buffer = io.BytesIO()
        wide.save(buffer, format="PNG")
        result = await engine.classify_content(buffer.getvalue())
        assert isinstance(result, ContentClassification)

        # Monochrome image
        mono = Image.new("L", (500, 500), color=128)
        buffer = io.BytesIO()
        mono.save(buffer, format="PNG")
        result = await engine.classify_content(buffer.getvalue())
        assert isinstance(result, ContentClassification)

        # Transparent image
        transparent = Image.new("RGBA", (400, 400), color=(255, 255, 255, 0))
        buffer = io.BytesIO()
        transparent.save(buffer, format="PNG")
        result = await engine.classify_content(buffer.getvalue())
        assert isinstance(result, ContentClassification)
