"""
Ultra-realistic batch processing tests with 100+ files.
Tests real-world batch conversion scenarios with progress tracking.
"""

import asyncio
import concurrent.futures
import json
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import numpy as np
import psutil
import pytest

from app.core.batch.models import BatchItemStatus, BatchJob, BatchStatus
from app.services.batch_service import batch_service


class TestBatch100FilesRealistic:
    """Test batch processing with realistic file sets and conditions."""

    @pytest.fixture
    async def setup_batch_files(self, realistic_image_generator, temp_dir):
        """Generate 100 diverse test files simulating real user batch."""
        files = []

        # Simulate real-world file distribution
        # 40% photos, 30% screenshots, 20% documents, 10% illustrations
        distribution = {
            "photo": 40,
            "screenshot": 30,
            "document": 20,
            "illustration": 10,
        }

        file_index = 0
        for content_type, count in distribution.items():
            for i in range(count):
                # Vary dimensions realistically
                if content_type == "photo":
                    # Simulate various camera resolutions
                    resolutions = [
                        (3024, 4032),  # iPhone 13 Pro
                        (4000, 3000),  # DSLR
                        (1920, 1080),  # HD
                        (2048, 1536),  # iPad
                    ]
                    width, height = resolutions[i % len(resolutions)]
                elif content_type == "screenshot":
                    # Common screen resolutions
                    resolutions = [
                        (1920, 1080),  # Full HD
                        (2560, 1440),  # 2K
                        (1366, 768),  # Common laptop
                        (3840, 2160),  # 4K
                    ]
                    width, height = resolutions[i % len(resolutions)]
                elif content_type == "document":
                    # A4 and Letter sizes
                    width, height = (2480, 3508) if i % 2 == 0 else (2550, 3300)
                else:  # illustration
                    # Various artistic dimensions
                    width = 500 + (i * 100)
                    height = 500 + (i * 100)

                # Generate realistic image data
                image_data = realistic_image_generator(
                    width=width,
                    height=height,
                    content_type=content_type,
                    has_metadata=(file_index % 3 == 0),  # 33% have metadata
                    format="JPEG" if content_type == "photo" else "PNG",
                )

                # Create realistic filename
                if content_type == "photo":
                    filename = f"IMG_{file_index:04d}.jpg"
                elif content_type == "screenshot":
                    filename = f"Screenshot_{file_index:04d}.png"
                elif content_type == "document":
                    filename = f"Scan_{file_index:04d}.png"
                else:
                    filename = f"Design_{file_index:04d}.png"

                # Save to temp directory
                file_path = temp_dir / filename
                with open(file_path, "wb") as f:
                    f.write(image_data)

                files.append(
                    {
                        "path": file_path,
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(image_data),
                        "index": file_index,
                    }
                )

                file_index += 1

        return files

    @pytest.mark.performance
    @pytest.mark.slow
    async def test_batch_100_files_complete_workflow(self, setup_batch_files):
        """
        Test complete batch processing workflow with 100 files.

        Simulates: User uploading folder of vacation photos for web optimization.
        """
        test_files = await setup_batch_files

        # Prepare file uploads
        file_uploads = []
        for file_info in test_files:
            with open(file_info["path"], "rb") as f:
                file_uploads.append(
                    {
                        "filename": file_info["filename"],
                        "content": f.read(),
                        "content_type": (
                            "image/jpeg"
                            if file_info["filename"].endswith(".jpg")
                            else "image/png"
                        ),
                    }
                )

        # Track performance metrics
        memory_before = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        start_time = time.perf_counter()

        # Create batch job
        job = await batch_service.create_batch_job(
            files=file_uploads,
            output_format="webp",
            quality=85,
            optimization_mode="balanced",
            strip_metadata=True,
        )

        assert job is not None
        assert job.id is not None
        assert job.total_files == 100
        assert job.status == BatchStatus.PENDING

        # Track progress updates
        progress_updates = []

        async def progress_callback(progress):
            progress_updates.append(
                {
                    "completed": progress.completed_count,
                    "failed": progress.failed_count,
                    "timestamp": time.perf_counter() - start_time,
                }
            )

        # Process batch with progress tracking
        result = await batch_service.process_batch(
            job_id=job.id, progress_callback=progress_callback
        )

        processing_time = time.perf_counter() - start_time
        memory_after = psutil.Process().memory_info().rss / 1024 / 1024
        memory_growth = memory_after - memory_before

        # Validate results
        assert result is not None
        assert (
            len(result.completed) >= 95
        ), f"Too many failures: {len(result.failed)}/{job.total_files}"
        assert len(result.completed) + len(result.failed) == 100

        # Performance assertions
        assert (
            processing_time < 120
        ), f"Batch took too long: {processing_time:.2f}s for 100 files"
        avg_time_per_file = processing_time / 100
        assert (
            avg_time_per_file < 1.2
        ), f"Average time per file too high: {avg_time_per_file:.2f}s"

        # Memory assertions
        assert memory_growth < 500, f"Excessive memory growth: {memory_growth:.2f}MB"

        # Progress update assertions
        assert len(progress_updates) > 10, "Too few progress updates"
        assert progress_updates[-1]["completed"] >= 95, "Final progress incomplete"

        # Validate output files
        for completed_item in result.completed[:10]:  # Check first 10
            assert completed_item.output_data is not None
            assert len(completed_item.output_data) > 0
            assert completed_item.output_format == "webp"

            # Check compression achieved
            original_size = test_files[completed_item.index]["size"]
            compression_ratio = len(completed_item.output_data) / original_size
            assert (
                compression_ratio < 1.0
            ), f"No compression for file {completed_item.index}"

    @pytest.mark.performance
    async def test_batch_concurrent_processing_efficiency(self, setup_batch_files):
        """
        Test that batch processing uses concurrent workers efficiently.

        Validates parallel processing and resource utilization.
        """
        test_files = await setup_batch_files

        # Prepare smaller batch for concurrency test
        file_uploads = []
        for file_info in test_files[:20]:  # Use 20 files
            with open(file_info["path"], "rb") as f:
                file_uploads.append(
                    {
                        "filename": file_info["filename"],
                        "content": f.read(),
                        "content_type": (
                            "image/jpeg"
                            if file_info["filename"].endswith(".jpg")
                            else "image/png"
                        ),
                    }
                )

        # Test sequential processing (mock single worker)
        with patch.object(batch_service, "MAX_WORKERS", 1):
            job_seq = await batch_service.create_batch_job(
                files=file_uploads, output_format="webp"
            )

            start_seq = time.perf_counter()
            result_seq = await batch_service.process_batch(job_seq.id)
            time_seq = time.perf_counter() - start_seq

        # Test parallel processing (default workers)
        job_par = await batch_service.create_batch_job(
            files=file_uploads, output_format="webp"
        )

        start_par = time.perf_counter()
        result_par = await batch_service.process_batch(job_par.id)
        time_par = time.perf_counter() - start_par

        # Parallel should be significantly faster
        speedup = time_seq / time_par
        assert speedup > 1.5, f"Insufficient parallel speedup: {speedup:.2f}x"

        # Both should complete successfully
        assert len(result_seq.completed) == len(result_par.completed)

    @pytest.mark.performance
    async def test_batch_with_mixed_formats_and_sizes(
        self, realistic_image_generator, temp_dir
    ):
        """
        Test batch with diverse formats and extreme size variations.

        Simulates: Real-world folder with mixed file types.
        """
        # Create diverse test set
        test_files = []

        # Tiny icons (16x16)
        for i in range(10):
            data = realistic_image_generator(16, 16, "illustration", format="PNG")
            path = temp_dir / f"icon_{i}.png"
            path.write_bytes(data)
            test_files.append(("icon", path, len(data)))

        # Regular photos (2MP)
        for i in range(10):
            data = realistic_image_generator(1920, 1080, "photo", format="JPEG")
            path = temp_dir / f"photo_{i}.jpg"
            path.write_bytes(data)
            test_files.append(("photo", path, len(data)))

        # Large photos (12MP)
        for i in range(5):
            data = realistic_image_generator(4000, 3000, "photo", format="JPEG")
            path = temp_dir / f"large_{i}.jpg"
            path.write_bytes(data)
            test_files.append(("large", path, len(data)))

        # Documents (A4)
        for i in range(5):
            data = realistic_image_generator(2480, 3508, "document", format="PNG")
            path = temp_dir / f"doc_{i}.png"
            path.write_bytes(data)
            test_files.append(("document", path, len(data)))

        # Prepare uploads
        file_uploads = []
        for file_type, path, size in test_files:
            with open(path, "rb") as f:
                file_uploads.append(
                    {
                        "filename": path.name,
                        "content": f.read(),
                        "content_type": (
                            "image/jpeg" if path.suffix == ".jpg" else "image/png"
                        ),
                    }
                )

        # Process batch
        job = await batch_service.create_batch_job(
            files=file_uploads,
            output_format="webp",
            optimization_mode="auto",  # Should adapt to each file type
        )

        result = await batch_service.process_batch(job.id)

        # Validate all processed
        assert (
            len(result.completed) >= 28
        ), f"Too many failures: {len(result.failed)}/30"

        # Check optimization was appropriate for each type
        for i, completed in enumerate(result.completed):
            original_type, _, original_size = test_files[i]
            output_size = len(completed.output_data)

            if original_type == "icon":
                # Icons should stay small
                assert (
                    output_size < 5000
                ), f"Icon too large after conversion: {output_size}"
            elif original_type == "large":
                # Large photos should compress well
                compression = output_size / original_size
                assert (
                    compression < 0.5
                ), f"Poor compression for large photo: {compression:.2%}"

    @pytest.mark.performance
    async def test_batch_cancellation_during_processing(self, setup_batch_files):
        """
        Test batch cancellation while processing is in progress.

        Validates graceful cancellation and resource cleanup.
        """
        test_files = await setup_batch_files

        # Prepare file uploads
        file_uploads = []
        for file_info in test_files[:50]:  # Use 50 files
            with open(file_info["path"], "rb") as f:
                file_uploads.append(
                    {
                        "filename": file_info["filename"],
                        "content": f.read(),
                        "content_type": (
                            "image/jpeg"
                            if file_info["filename"].endswith(".jpg")
                            else "image/png"
                        ),
                    }
                )

        # Create and start processing
        job = await batch_service.create_batch_job(
            files=file_uploads,
            output_format="avif",  # Slower format for more time
            quality=90,
        )

        # Start processing in background
        process_task = asyncio.create_task(batch_service.process_batch(job.id))

        # Wait a bit then cancel
        await asyncio.sleep(2)

        # Cancel the batch
        cancelled = await batch_service.cancel_batch(job.id)
        assert cancelled is True

        # Cancel the task
        process_task.cancel()

        try:
            await process_task
        except asyncio.CancelledError:
            pass

        # Check job status
        job_status = await batch_service.get_batch_status(job.id)
        assert job_status.status in [BatchStatus.CANCELLED, BatchStatus.CANCELLING]

        # Verify partial results are available
        assert job_status.completed_count >= 0
        assert job_status.completed_count < 50  # Should not have completed all

        # Verify resources are cleaned up
        # Check no orphaned processes
        current_process = psutil.Process()
        children = current_process.children(recursive=True)
        assert len(children) == 0, f"Found {len(children)} orphaned processes"

    @pytest.mark.performance
    @pytest.mark.slow
    async def test_batch_memory_stability_100_files(
        self, setup_batch_files, memory_monitor
    ):
        """
        Test memory stability during 100-file batch processing.

        Ensures no memory leaks during large batch operations.
        """
        test_files = await setup_batch_files
        memory_monitor.start()

        # Process in batches to test memory cleanup
        for batch_num in range(2):  # Process 2 batches of 50
            batch_files = test_files[batch_num * 50 : (batch_num + 1) * 50]

            file_uploads = []
            for file_info in batch_files:
                with open(file_info["path"], "rb") as f:
                    file_uploads.append(
                        {
                            "filename": file_info["filename"],
                            "content": f.read(),
                            "content_type": (
                                "image/jpeg"
                                if file_info["filename"].endswith(".jpg")
                                else "image/png"
                            ),
                        }
                    )

            # Create and process batch
            job = await batch_service.create_batch_job(
                files=file_uploads, output_format="webp", quality=80
            )

            result = await batch_service.process_batch(job.id)

            # Cleanup batch results
            await batch_service.cleanup_job_results(job.id)

            # Sample memory after each batch
            memory_monitor.sample()

            # Small delay between batches
            await asyncio.sleep(1)

        # Check memory stability
        memory_monitor.assert_stable(max_growth_mb=100)

    @pytest.mark.performance
    async def test_batch_error_recovery_and_retry(self, create_malicious_image):
        """
        Test batch processing with some corrupted files.

        Validates error handling and partial success scenarios.
        """
        # Create mix of valid and corrupted files
        file_uploads = []

        # Add valid files
        for i in range(20):
            img = Image.new("RGB", (800, 600), color=(i * 10, 100, 200 - i * 5))
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG")
            file_uploads.append(
                {
                    "filename": f"valid_{i}.jpg",
                    "content": buffer.getvalue(),
                    "content_type": "image/jpeg",
                }
            )

        # Add corrupted files
        for i in range(5):
            corrupted_data = create_malicious_image("corrupted")
            file_uploads.append(
                {
                    "filename": f"corrupted_{i}.jpg",
                    "content": corrupted_data,
                    "content_type": "image/jpeg",
                }
            )

        # Process batch
        job = await batch_service.create_batch_job(
            files=file_uploads,
            output_format="webp",
            error_handling="continue",  # Continue on errors
        )

        result = await batch_service.process_batch(job.id)

        # Should process valid files successfully
        assert (
            len(result.completed) >= 18
        ), f"Too many valid files failed: {len(result.completed)}/20"
        assert (
            len(result.failed) >= 3
        ), f"Corrupted files not detected: {len(result.failed)}/5"

        # Check error information
        for failed_item in result.failed:
            assert failed_item.error is not None
            assert (
                "corrupt" in failed_item.error.lower()
                or "invalid" in failed_item.error.lower()
            )

        # Verify batch completed despite errors
        job_status = await batch_service.get_batch_status(job.id)
        assert job_status.status == BatchStatus.COMPLETED_WITH_ERRORS
