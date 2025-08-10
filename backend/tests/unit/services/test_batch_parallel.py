"""
from typing import Any
Unit tests for parallel batch processing functionality.
Tests worker pool scaling, efficiency, and resource management.
"""

import asyncio
import time
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from app.core.batch.manager import BatchManager
from app.core.batch.models import (BatchItem, BatchItemStatus, BatchJob,
                                   BatchStatus)
from app.models import ConversionResult


@pytest.fixture
def batch_manager() -> None:
    """Create a BatchManager instance for testing."""
    manager = BatchManager()
    # Mock conversion service
    manager.conversion_service = AsyncMock()
    manager.conversion_service.convert = AsyncMock(
        return_value=(
            ConversionResult(
                success=True,
                input_format="jpeg",
                input_size=100000,
                output_format="webp",
                output_size=50000,
                processing_time=0.5,
            ),
            b"fake_output_data",
        )
    )
    return manager


@pytest.fixture
def sample_batch_job() -> None:
    """Create a sample batch job for testing."""
    items = [
        BatchItem(
            file_index=i, filename=f"test_{i}.jpg", status=BatchItemStatus.PENDING
        )
        for i in range(10)
    ]

    job = BatchJob(
        job_id=str(uuid.uuid4()),
        total_files=10,
        settings={"output_format": "webp", "quality": 85},
        items=items,
        created_at=datetime.utcnow(),
    )
    return job


class TestBatchManagerParallel:
    """Test parallel processing functionality in BatchManager."""

    def test_worker_count_calculation(self, batch_manager) -> None:
        """Test that worker count is calculated correctly based on CPU cores."""
        with patch("multiprocessing.cpu_count", return_value=8):
            worker_count = batch_manager._calculate_worker_count()
            # Should be 80% of 8 cores = 6.4, rounded to 6
            assert worker_count == 6

        with patch("multiprocessing.cpu_count", return_value=2):
            worker_count = batch_manager._calculate_worker_count()
            # Minimum is 2
            assert worker_count == 2

        with patch("multiprocessing.cpu_count", return_value=20):
            worker_count = batch_manager._calculate_worker_count()
            # Maximum is 10 (MAX_BATCH_WORKERS)
            assert worker_count == 10

    @pytest.mark.asyncio
    async def test_parallel_job_creation(self, batch_manager, sample_batch_job):
        """Test creating a batch job with parallel workers."""
        job_id = sample_batch_job.job_id
        file_data_list = [b"fake_image_data" for _ in range(10)]

        await batch_manager.create_job(
            job_id=job_id,
            batch_job=sample_batch_job,
            file_data_list=file_data_list,
            progress_callback=None,
        )

        # Check job is stored
        assert job_id in batch_manager._jobs
        assert batch_manager._jobs[job_id] == sample_batch_job

        # Check queue is created
        assert job_id in batch_manager._job_queues
        queue = batch_manager._job_queues[job_id]
        assert queue.qsize() == 10  # All tasks queued

        # Check workers are created
        assert job_id in batch_manager._job_workers
        workers = batch_manager._job_workers[job_id]
        assert len(workers) <= batch_manager._num_workers
        assert len(workers) <= 10  # No more workers than files

        # Check semaphore is created
        assert job_id in batch_manager._job_semaphores

        # Check metrics are initialized
        assert job_id in batch_manager._job_metrics
        metrics = batch_manager._job_metrics[job_id]
        assert "start_time" in metrics
        assert "worker_activity" in metrics

        # Clean up
        await batch_manager.cancel_job(job_id)

    @pytest.mark.asyncio
    async def test_worker_efficiency_tracking(self, batch_manager, sample_batch_job):
        """Test that worker efficiency is tracked correctly."""
        job_id = sample_batch_job.job_id

        # Initialize metrics
        batch_manager._init_job_metrics(job_id)

        # Simulate worker activity
        task1 = asyncio.create_task(asyncio.sleep(0))
        task2 = asyncio.create_task(asyncio.sleep(0))

        # Update metrics as if workers processed files
        with patch("asyncio.current_task", return_value=task1):
            batch_manager._update_memory_metrics(job_id)
            batch_manager._update_memory_metrics(job_id)

        with patch("asyncio.current_task", return_value=task2):
            batch_manager._update_memory_metrics(job_id)

        metrics = batch_manager._job_metrics[job_id]
        worker_activity = metrics["worker_activity"]

        # Check worker activity tracking
        assert len(worker_activity) == 2  # Two workers

        worker1_id = id(task1)
        worker2_id = id(task2)

        assert worker_activity[worker1_id]["files_processed"] == 2
        assert worker_activity[worker2_id]["files_processed"] == 1

    @pytest.mark.asyncio
    async def test_parallel_processing_performance(
        self, batch_manager, sample_batch_job
    ):
        """Test that parallel processing improves performance."""
        job_id = sample_batch_job.job_id
        file_data_list = [b"fake_image_data" for _ in range(20)]

        # Adjust items for 20 files
        sample_batch_job.items = [
            BatchItem(
                file_index=i, filename=f"test_{i}.jpg", status=BatchItemStatus.PENDING
            )
            for i in range(20)
        ]
        sample_batch_job.total_files = 20

        # Mock conversion with delay to simulate processing time
        async def mock_convert(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simulate 100ms processing
            return (
                ConversionResult(
                    success=True,
                    input_format="jpeg",
                    input_size=100000,
                    output_format="webp",
                    output_size=50000,
                    processing_time=0.1,
                ),
                b"fake_output",
            )

        batch_manager.conversion_service.convert = mock_convert

        start_time = time.time()

        # Create job with multiple workers
        await batch_manager.create_job(
            job_id=job_id,
            batch_job=sample_batch_job,
            file_data_list=file_data_list,
            progress_callback=None,
        )

        # Wait for completion (with timeout)
        max_wait = 5  # 5 seconds max
        while (
            sample_batch_job.status != BatchStatus.COMPLETED
            and time.time() - start_time < max_wait
        ):
            await asyncio.sleep(0.1)

        elapsed_time = time.time() - start_time

        # With parallel processing, 20 files at 0.1s each should take less than 2 seconds
        # (Sequential would take 2 seconds)
        assert elapsed_time < 2.0, f"Parallel processing took too long: {elapsed_time}s"

        # Get metrics
        metrics = batch_manager.get_job_metrics(job_id)
        assert metrics is not None

        # Check throughput
        throughput = metrics["throughput"]["files_per_second"]
        assert throughput > 10  # Should process >10 files/second with parallelism

        # Clean up
        await batch_manager.cancel_job(job_id)

    @pytest.mark.asyncio
    async def test_memory_metrics_tracking(self, batch_manager, sample_batch_job):
        """Test memory usage tracking during batch processing."""
        job_id = sample_batch_job.job_id

        # Initialize metrics
        batch_manager._init_job_metrics(job_id)

        # Update memory metrics multiple times
        for _ in range(5):
            batch_manager._update_memory_metrics(job_id)
            await asyncio.sleep(0.01)

        metrics = batch_manager._job_metrics[job_id]

        # Check memory tracking
        assert "start_memory_mb" in metrics
        assert "peak_memory_mb" in metrics
        assert "memory_samples" in metrics
        assert len(metrics["memory_samples"]) == 5

        # Peak should be at least as high as start
        assert metrics["peak_memory_mb"] >= metrics["start_memory_mb"]

    @pytest.mark.asyncio
    async def test_worker_cleanup_on_cancel(self, batch_manager, sample_batch_job):
        """Test that workers are properly cleaned up when job is cancelled."""
        job_id = sample_batch_job.job_id
        file_data_list = [b"fake_image_data" for _ in range(10)]

        # Create job
        await batch_manager.create_job(
            job_id=job_id,
            batch_job=sample_batch_job,
            file_data_list=file_data_list,
            progress_callback=None,
        )

        # Get worker tasks
        workers = batch_manager._job_workers[job_id]
        worker_count = len(workers)

        # Cancel job
        await batch_manager.cancel_job(job_id)

        # Wait a bit for cancellation to propagate
        await asyncio.sleep(0.1)

        # Check all workers are cancelled or done
        for worker in workers:
            assert worker.cancelled() or worker.done()

        # Check job status
        assert sample_batch_job.status == BatchStatus.CANCELLED

        # Check queue is empty
        queue = batch_manager._job_queues.get(job_id)
        if queue:
            assert queue.empty()

    @pytest.mark.asyncio
    async def test_concurrent_job_handling(self, batch_manager):
        """Test handling multiple concurrent batch jobs."""
        # Create multiple jobs
        jobs = []
        for i in range(3):
            job = BatchJob(
                job_id=f"job_{i}",
                total_files=5,
                settings={"output_format": "webp"},
                items=[
                    BatchItem(
                        file_index=j,
                        filename=f"file_{j}.jpg",
                        status=BatchItemStatus.PENDING,
                    )
                    for j in range(5)
                ],
                created_at=datetime.utcnow(),
            )
            jobs.append(job)

        # Start all jobs concurrently
        tasks = []
        for job in jobs:
            task = batch_manager.create_job(
                job_id=job.job_id,
                batch_job=job,
                file_data_list=[b"data" for _ in range(5)],
                progress_callback=None,
            )
            tasks.append(task)

        await asyncio.gather(*tasks)

        # Check all jobs are created
        for job in jobs:
            assert job.job_id in batch_manager._jobs
            assert job.job_id in batch_manager._job_workers

        # Clean up
        for job in jobs:
            await batch_manager.cancel_job(job.job_id)

    def test_get_job_metrics_calculation(self, batch_manager, sample_batch_job) -> None:
        """Test job metrics calculation and reporting."""
        job_id = sample_batch_job.job_id

        # Setup job and metrics
        batch_manager._jobs[job_id] = sample_batch_job
        batch_manager._init_job_metrics(job_id)

        # Simulate some processing
        metrics = batch_manager._job_metrics[job_id]
        metrics["file_times"] = [0.5, 0.6, 0.4, 0.7, 0.5]  # Processing times
        metrics["start_time"] = time.time() - 10  # Started 10 seconds ago

        # Update job stats
        sample_batch_job.completed_files = 5
        sample_batch_job.failed_files = 0

        # Get metrics report
        report = batch_manager.get_job_metrics(job_id)

        assert report is not None
        assert report["job_id"] == job_id
        assert report["elapsed_time_seconds"] >= 10

        # Check file processing stats
        file_stats = report["file_processing"]
        assert file_stats["completed"] == 5
        assert file_stats["failed"] == 0
        assert file_stats["average_time_seconds"] == pytest.approx(0.54, 0.01)
        assert file_stats["min_time_seconds"] == 0.4
        assert file_stats["max_time_seconds"] == 0.7

        # Check throughput
        throughput_stats = report["throughput"]
        assert throughput_stats["files_per_second"] > 0

        # Check memory stats
        memory_stats = report["memory_usage"]
        assert "start_mb" in memory_stats
        assert "current_mb" in memory_stats
        assert "peak_mb" in memory_stats

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self, batch_manager, sample_batch_job):
        """Test that semaphore properly limits concurrent conversions per job."""
        job_id = sample_batch_job.job_id

        # Set a low concurrency limit
        batch_manager._max_concurrent_per_job = 2

        # Track concurrent executions
        concurrent_count = 0
        max_concurrent = 0

        async def mock_convert(*args, **kwargs):
            nonlocal concurrent_count, max_concurrent
            concurrent_count += 1
            max_concurrent = max(max_concurrent, concurrent_count)
            await asyncio.sleep(0.1)  # Simulate processing
            concurrent_count -= 1
            return (
                ConversionResult(
                    success=True,
                    input_format="jpeg",
                    input_size=100000,
                    output_format="webp",
                    output_size=50000,
                    processing_time=0.1,
                ),
                b"output",
            )

        batch_manager.conversion_service.convert = mock_convert

        # Create job with 10 files
        await batch_manager.create_job(
            job_id=job_id,
            batch_job=sample_batch_job,
            file_data_list=[b"data" for _ in range(10)],
            progress_callback=None,
        )

        # Wait for processing to start
        await asyncio.sleep(0.2)

        # Check that concurrency was limited
        assert (
            max_concurrent <= 2
        ), f"Max concurrent was {max_concurrent}, expected <= 2"

        # Clean up
        await batch_manager.cancel_job(job_id)
