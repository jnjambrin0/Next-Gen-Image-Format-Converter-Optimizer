"""Integration tests for batch image processing functionality."""

import pytest
from unittest.mock import Mock, patch
import asyncio
import time
from pathlib import Path
import concurrent.futures

# Fixtures are automatically discovered by pytest from conftest.py
# TODO: Uncomment when generators module is properly set up
# from tests.fixtures.generators import ImageGenerator


class TestBatchProcessing:
    """Integration tests for batch image processing."""

    @pytest.fixture
    def batch_processor(self):
        """Create a BatchProcessor instance."""
        # TODO: Uncomment when BatchProcessor is implemented
        # from app.core.processing.batch import BatchProcessor
        # return BatchProcessor()

        # Mock for now
        mock_processor = Mock()
        mock_processor.process_batch = Mock(
            return_value={"completed": [], "failed": [], "total_processed": 0}
        )
        mock_processor.cancel = Mock()
        return mock_processor

    @pytest.fixture
    def test_batch_images(self, temp_dir, image_generator):
        """Generate a batch of test images."""
        images = []
        for i in range(10):
            img_path = temp_dir / f"test_image_{i}.jpg"
            img_data = image_generator(
                width=800 + i * 100, height=600 + i * 100, format="JPEG"
            )
            with open(img_path, "wb") as f:
                f.write(img_data)
            images.append({"path": img_path, "size": len(img_data), "index": i})
        return images

    def test_batch_conversion_success(
        self, batch_processor, test_batch_images, temp_dir
    ):
        """Test successful batch conversion of multiple images."""
        # TODO: Enable when BatchProcessor is implemented
        pytest.skip("Waiting for BatchProcessor implementation")

        # Arrange
        input_files = [img["path"] for img in test_batch_images]
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        request = {
            "files": input_files,
            "output_format": "webp",
            "quality": 85,
            "output_directory": str(output_dir),
        }

        # Act
        results = batch_processor.process_batch(request)

        # Assert
        assert len(results["completed"]) == 10
        assert len(results["failed"]) == 0
        assert results["total_processed"] == 10
        assert all((output_dir / f"test_image_{i}.webp").exists() for i in range(10))

    def test_parallel_batch_processing(
        self, batch_processor, test_batch_images, temp_dir
    ):
        """Test parallel processing improves performance."""
        # Arrange
        input_files = [img["path"] for img in test_batch_images]
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Sequential processing
        start_sequential = time.time()
        results_seq = batch_processor.process_batch(
            {
                "files": input_files,
                "output_format": "webp",
                "parallel": False,
                "output_directory": str(output_dir),
            }
        )
        time_sequential = time.time() - start_sequential

        # Clear output
        for f in output_dir.glob("*.webp"):
            f.unlink()

        # Parallel processing
        start_parallel = time.time()
        results_par = batch_processor.process_batch(
            {
                "files": input_files,
                "output_format": "webp",
                "parallel": True,
                "max_workers": 4,
                "output_directory": str(output_dir),
            }
        )
        time_parallel = time.time() - start_parallel

        # Assert
        assert results_seq["total_processed"] == results_par["total_processed"]
        assert time_parallel < time_sequential * 0.7  # At least 30% faster

    def test_batch_with_mixed_formats(self, batch_processor, temp_dir):
        """Test batch processing with different input formats."""
        # Arrange
        formats = ["JPEG", "PNG", "GIF", "BMP"]
        input_files = []

        for i, fmt in enumerate(formats):
            img = ImageGenerator.create_test_image(width=500, height=500, format=fmt)
            path = temp_dir / f"mixed_{i}.{fmt.lower()}"
            with open(path, "wb") as f:
                f.write(img)
            input_files.append(path)

        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Act
        results = batch_processor.process_batch(
            {
                "files": input_files,
                "output_format": "webp",
                "output_directory": str(output_dir),
            }
        )

        # Assert
        assert results["total_processed"] == 4
        assert len(results["completed"]) == 4
        assert all((output_dir / f"mixed_{i}.webp").exists() for i in range(4))

    def test_batch_error_handling(self, batch_processor, test_batch_images, temp_dir):
        """Test batch processing continues on individual failures."""
        # Arrange
        input_files = [img["path"] for img in test_batch_images]

        # Add a corrupted file
        corrupted_path = temp_dir / "corrupted.jpg"
        with open(corrupted_path, "wb") as f:
            f.write(b"Not a real image")
        input_files.insert(5, corrupted_path)

        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Act
        results = batch_processor.process_batch(
            {
                "files": input_files,
                "output_format": "webp",
                "continue_on_error": True,
                "output_directory": str(output_dir),
            }
        )

        # Assert
        assert results["total_processed"] == 11
        assert len(results["completed"]) == 10
        assert len(results["failed"]) == 1
        assert results["failed"][0]["file"] == str(corrupted_path)
        assert "error" in results["failed"][0]

    def test_batch_progress_callback(
        self, batch_processor, test_batch_images, temp_dir
    ):
        """Test progress callback during batch processing."""
        # Arrange
        input_files = [img["path"] for img in test_batch_images[:5]]
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        progress_updates = []

        def progress_callback(update):
            progress_updates.append(update)

        # Act
        results = batch_processor.process_batch(
            {
                "files": input_files,
                "output_format": "webp",
                "output_directory": str(output_dir),
                "progress_callback": progress_callback,
            }
        )

        # Assert
        assert len(progress_updates) > 0
        assert any(update["type"] == "started" for update in progress_updates)
        assert any(update["type"] == "progress" for update in progress_updates)
        assert any(update["type"] == "completed" for update in progress_updates)

        # Check progress percentages
        progress_percentages = [
            update["percentage"]
            for update in progress_updates
            if update["type"] == "progress"
        ]
        assert progress_percentages == sorted(progress_percentages)  # Increasing

    def test_batch_memory_management(self, batch_processor, temp_dir):
        """Test memory is properly managed during large batch processing."""
        # Arrange
        # Create 50 medium-sized images
        input_files = []
        for i in range(50):
            img = ImageGenerator.create_test_image(
                width=2000, height=2000, format="JPEG"
            )
            path = temp_dir / f"large_{i}.jpg"
            with open(path, "wb") as f:
                f.write(img)
            input_files.append(path)

        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Monitor memory usage
        import psutil

        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Act
        results = batch_processor.process_batch(
            {
                "files": input_files,
                "output_format": "webp",
                "quality": 70,
                "parallel": True,
                "max_workers": 2,  # Limit workers to control memory
                "output_directory": str(output_dir),
            }
        )

        peak_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Assert
        assert results["total_processed"] == 50
        assert (peak_memory - initial_memory) < 1000  # Less than 1GB increase

    def test_batch_with_presets(self, batch_processor, test_batch_images, temp_dir):
        """Test batch processing using predefined presets."""
        # Arrange
        input_files = [img["path"] for img in test_batch_images[:3]]
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Act
        results = batch_processor.process_batch(
            {
                "files": input_files,
                "preset": "web_optimized",
                "output_directory": str(output_dir),
            }
        )

        # Assert
        assert results["total_processed"] == 3
        assert all((output_dir / f"test_image_{i}.webp").exists() for i in range(3))

        # Verify preset settings were applied
        for result in results["completed"]:
            assert result["output_format"] == "webp"
            assert result["quality"] == 85
            assert result["metadata_stripped"] is True

    def test_batch_cancellation(self, batch_processor, test_batch_images, temp_dir):
        """Test cancellation of batch processing."""
        # Arrange
        input_files = [img["path"] for img in test_batch_images]
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Start batch processing in thread
        import threading

        results_container = {"results": None}

        def run_batch():
            results_container["results"] = batch_processor.process_batch(
                {
                    "files": input_files,
                    "output_format": "avif",  # Slow format
                    "quality": 95,
                    "output_directory": str(output_dir),
                }
            )

        thread = threading.Thread(target=run_batch)
        thread.start()

        # Cancel after short delay
        time.sleep(0.5)
        batch_processor.cancel()
        thread.join(timeout=5)

        # Assert
        results = results_container["results"]
        assert results["cancelled"] is True
        assert results["total_processed"] < 10  # Not all processed

    def test_batch_with_different_sizes(self, batch_processor, temp_dir):
        """Test batch processing handles images of vastly different sizes."""
        # Arrange
        sizes = [(100, 100), (1000, 1000), (4000, 3000), (50, 50), (2000, 1000)]
        input_files = []

        for i, (w, h) in enumerate(sizes):
            img = ImageGenerator.create_test_image(width=w, height=h)
            path = temp_dir / f"size_{i}.jpg"
            with open(path, "wb") as f:
                f.write(img)
            input_files.append(path)

        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Act
        results = batch_processor.process_batch(
            {
                "files": input_files,
                "output_format": "webp",
                "resize": {
                    "max_width": 1920,
                    "max_height": 1080,
                    "maintain_aspect_ratio": True,
                },
                "output_directory": str(output_dir),
            }
        )

        # Assert
        assert results["total_processed"] == 5
        assert len(results["completed"]) == 5

        # Verify resize was applied correctly
        from PIL import Image

        for i in range(5):
            output_path = output_dir / f"size_{i}.webp"
            img = Image.open(output_path)
            assert img.width <= 1920
            assert img.height <= 1080

    async def test_async_batch_processing(
        self, batch_processor, test_batch_images, temp_dir
    ):
        """Test asynchronous batch processing."""
        # Arrange
        input_files = [img["path"] for img in test_batch_images[:5]]
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        # Act
        results = await batch_processor.process_batch_async(
            {
                "files": input_files,
                "output_format": "webp",
                "output_directory": str(output_dir),
            }
        )

        # Assert
        assert results["total_processed"] == 5
        assert all((output_dir / f"test_image_{i}.webp").exists() for i in range(5))
