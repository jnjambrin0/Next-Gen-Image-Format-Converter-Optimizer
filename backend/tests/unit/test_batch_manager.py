"""Unit tests for the BatchManager class."""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
import uuid

from app.core.batch.manager import BatchManager, BatchWorkerTask
from app.core.batch.models import (
    BatchJob,
    BatchItem,
    BatchStatus,
    BatchItemStatus,
    BatchProgress,
)
from app.models.schemas import ConversionRequest, ConversionResult


class TestBatchManager:
    """Test BatchManager functionality."""

    @pytest.fixture
    def mock_conversion_service(self):
        """Create a mock conversion service."""
        service = AsyncMock()
        service.convert.return_value = (
            ConversionResult(
                status="completed",
                output_format="webp",
                output_size=1000,
                processing_time=0.5,
                optimization_applied=False,
            ),
            b"fake output data",
        )
        return service

    @pytest.fixture
    async def batch_manager(self, mock_conversion_service):
        """Create a BatchManager instance with mocked dependencies."""
        manager = BatchManager()
        manager.set_conversion_service(mock_conversion_service)
        yield manager
        await manager.shutdown()

    @pytest.fixture
    def sample_batch_job(self):
        """Create a sample batch job."""
        job_id = str(uuid.uuid4())
        items = [
            BatchItem(file_index=0, filename="test1.jpg"),
            BatchItem(file_index=1, filename="test2.png"),
            BatchItem(file_index=2, filename="test3.webp"),
        ]
        
        job = BatchJob(
            job_id=job_id,
            total_files=3,
            items=items,
            settings={
                "output_format": "webp",
                "quality": 85,
                "preserve_metadata": False,
            },
        )
        return job

    @pytest.mark.asyncio
    async def test_calculate_worker_count(self, batch_manager):
        """Test worker count calculation based on CPU cores."""
        with patch("multiprocessing.cpu_count", return_value=8):
            count = batch_manager._calculate_worker_count()
            # 80% of 8 cores = 6.4, rounded to 6
            assert count == 6
        
        with patch("multiprocessing.cpu_count", return_value=2):
            count = batch_manager._calculate_worker_count()
            # 80% of 2 cores = 1.6, but minimum is 2
            assert count == 2

    @pytest.mark.asyncio
    async def test_create_job_success(self, batch_manager, sample_batch_job):
        """Test successful job creation and initialization."""
        job_id = sample_batch_job.job_id
        file_data = [b"data1", b"data2", b"data3"]
        progress_callback = AsyncMock()
        
        await batch_manager.create_job(
            job_id,
            sample_batch_job,
            file_data,
            progress_callback,
        )
        
        # Verify job was stored
        assert job_id in batch_manager._jobs
        assert batch_manager._jobs[job_id] == sample_batch_job
        
        # Verify queue was created
        assert job_id in batch_manager._job_queues
        queue = batch_manager._job_queues[job_id]
        assert queue.qsize() == 3
        
        # Verify workers were started
        assert job_id in batch_manager._job_workers
        workers = batch_manager._job_workers[job_id]
        assert len(workers) > 0
        assert all(isinstance(w, asyncio.Task) for w in workers)
        
        # Verify job status was updated
        assert sample_batch_job.status == BatchStatus.PROCESSING

    @pytest.mark.asyncio
    async def test_create_job_no_conversion_service(self, batch_manager, sample_batch_job):
        """Test job creation fails without conversion service."""
        batch_manager.conversion_service = None
        
        with pytest.raises(RuntimeError, match="Conversion service not initialized"):
            await batch_manager.create_job(
                sample_batch_job.job_id,
                sample_batch_job,
                [b"data"],
            )

    @pytest.mark.asyncio
    async def test_process_task_success(self, batch_manager, sample_batch_job, mock_conversion_service):
        """Test successful task processing."""
        job_id = sample_batch_job.job_id
        batch_manager._jobs[job_id] = sample_batch_job
        
        task = BatchWorkerTask(
            job_id=job_id,
            file_index=0,
            file_data=b"test data",
            filename="test.jpg",
            conversion_request=ConversionRequest(output_format="webp"),
        )
        
        # Mock progress callback
        progress_updates = []
        async def progress_callback(progress: BatchProgress):
            progress_updates.append(progress)
        
        batch_manager._progress_callbacks[job_id] = progress_callback
        
        # Process task
        await batch_manager._process_task(task, sample_batch_job)
        
        # Verify item was updated
        item = sample_batch_job.items[0]
        assert item.status == BatchItemStatus.COMPLETED
        assert item.progress == 100
        assert item.processing_time > 0
        assert item.output_size == 16  # len(b"fake output data")
        assert item.completed_at is not None
        
        # Verify job counters
        assert sample_batch_job.completed_files == 1
        assert sample_batch_job.failed_files == 0
        
        # Verify progress updates were sent
        assert len(progress_updates) >= 2  # At least start and end
        assert progress_updates[-1].status == BatchItemStatus.COMPLETED
        assert progress_updates[-1].progress == 100

    @pytest.mark.asyncio
    async def test_process_task_failure(self, batch_manager, sample_batch_job, mock_conversion_service):
        """Test task processing with conversion failure."""
        job_id = sample_batch_job.job_id
        batch_manager._jobs[job_id] = sample_batch_job
        
        # Make conversion fail
        mock_conversion_service.convert.side_effect = Exception("Conversion failed")
        
        task = BatchWorkerTask(
            job_id=job_id,
            file_index=0,
            file_data=b"test data",
            filename="test.jpg",
            conversion_request=ConversionRequest(output_format="webp"),
        )
        
        # Process task
        await batch_manager._process_task(task, sample_batch_job)
        
        # Verify item was marked as failed
        item = sample_batch_job.items[0]
        assert item.status == BatchItemStatus.FAILED
        assert item.error_message == "Conversion failed"
        assert item.completed_at is not None
        
        # Verify job counters
        assert sample_batch_job.completed_files == 0
        assert sample_batch_job.failed_files == 1

    @pytest.mark.asyncio
    async def test_process_task_cancelled_item(self, batch_manager, sample_batch_job):
        """Test processing skips cancelled items."""
        job_id = sample_batch_job.job_id
        batch_manager._jobs[job_id] = sample_batch_job
        
        # Mark item as cancelled
        sample_batch_job.items[0].status = BatchItemStatus.CANCELLED
        
        task = BatchWorkerTask(
            job_id=job_id,
            file_index=0,
            file_data=b"test data",
            filename="test.jpg",
            conversion_request=ConversionRequest(output_format="webp"),
        )
        
        # Process task - should return immediately
        await batch_manager._process_task(task, sample_batch_job)
        
        # Verify item status didn't change
        assert sample_batch_job.items[0].status == BatchItemStatus.CANCELLED
        
        # Verify conversion was not called
        batch_manager.conversion_service.convert.assert_not_called()

    @pytest.mark.asyncio
    async def test_cancel_job(self, batch_manager, sample_batch_job):
        """Test cancelling an entire job."""
        job_id = sample_batch_job.job_id
        file_data = [b"data1", b"data2", b"data3"]
        
        # Create job
        await batch_manager.create_job(job_id, sample_batch_job, file_data)
        
        # Let workers start
        await asyncio.sleep(0.1)
        
        # Cancel job
        result = await batch_manager.cancel_job(job_id)
        assert result is True
        
        # Verify job status
        assert sample_batch_job.status == BatchStatus.CANCELLED
        assert sample_batch_job.completed_at is not None
        
        # Verify all items were cancelled
        for item in sample_batch_job.items:
            assert item.status == BatchItemStatus.CANCELLED
        
        # Verify workers were cancelled
        workers = batch_manager._job_workers.get(job_id, [])
        for worker in workers:
            assert worker.cancelled() or worker.done()

    @pytest.mark.asyncio
    async def test_cancel_job_not_found(self, batch_manager):
        """Test cancelling non-existent job."""
        result = await batch_manager.cancel_job("non-existent")
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_item_success(self, batch_manager, sample_batch_job):
        """Test cancelling a specific item."""
        job_id = sample_batch_job.job_id
        batch_manager._jobs[job_id] = sample_batch_job
        
        # Cancel item 1
        result = await batch_manager.cancel_item(job_id, 1)
        assert result is True
        
        # Verify item was cancelled
        assert sample_batch_job.items[1].status == BatchItemStatus.CANCELLED
        assert sample_batch_job.items[1].completed_at is not None
        
        # Verify other items were not affected
        assert sample_batch_job.items[0].status == BatchItemStatus.PENDING
        assert sample_batch_job.items[2].status == BatchItemStatus.PENDING

    @pytest.mark.asyncio
    async def test_cancel_item_invalid_index(self, batch_manager, sample_batch_job):
        """Test cancelling item with invalid index."""
        job_id = sample_batch_job.job_id
        batch_manager._jobs[job_id] = sample_batch_job
        
        result = await batch_manager.cancel_item(job_id, 10)
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_item_already_completed(self, batch_manager, sample_batch_job):
        """Test cannot cancel completed item."""
        job_id = sample_batch_job.job_id
        batch_manager._jobs[job_id] = sample_batch_job
        
        # Mark item as completed
        sample_batch_job.items[0].status = BatchItemStatus.COMPLETED
        
        result = await batch_manager.cancel_item(job_id, 0)
        assert result is False

    @pytest.mark.asyncio
    async def test_check_job_completion(self, batch_manager, sample_batch_job):
        """Test job completion detection."""
        # Mark all items as completed
        for item in sample_batch_job.items:
            item.status = BatchItemStatus.COMPLETED
        
        sample_batch_job.completed_files = 3
        
        # Check completion
        batch_manager._check_job_completion(sample_batch_job)
        
        # Verify job status
        assert sample_batch_job.status == BatchStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_check_job_completion_with_failures(self, batch_manager, sample_batch_job):
        """Test job completion with some failures."""
        # Mark items with mixed statuses
        sample_batch_job.items[0].status = BatchItemStatus.COMPLETED
        sample_batch_job.items[1].status = BatchItemStatus.FAILED
        sample_batch_job.items[2].status = BatchItemStatus.COMPLETED
        
        sample_batch_job.completed_files = 2
        sample_batch_job.failed_files = 1
        
        # Check completion
        batch_manager._check_job_completion(sample_batch_job)
        
        # Verify job status (should be completed, not failed)
        assert sample_batch_job.status == BatchStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_check_job_completion_all_failed(self, batch_manager, sample_batch_job):
        """Test job completion when all items fail."""
        # Mark all items as failed
        for item in sample_batch_job.items:
            item.status = BatchItemStatus.FAILED
        
        sample_batch_job.failed_files = 3
        
        # Check completion
        batch_manager._check_job_completion(sample_batch_job)
        
        # Verify job status
        assert sample_batch_job.status == BatchStatus.FAILED

    @pytest.mark.asyncio
    async def test_cleanup_job(self, batch_manager, sample_batch_job):
        """Test job cleanup removes resources."""
        job_id = sample_batch_job.job_id
        file_data = [b"data1", b"data2", b"data3"]
        
        # Create job
        await batch_manager.create_job(job_id, sample_batch_job, file_data)
        
        # Cleanup job
        await batch_manager.cleanup_job(job_id)
        
        # Verify resources were removed
        assert job_id not in batch_manager._job_workers
        assert job_id not in batch_manager._job_queues
        assert job_id not in batch_manager._job_semaphores
        assert job_id not in batch_manager._progress_callbacks
        
        # Job itself should still exist for status queries
        assert job_id in batch_manager._jobs

    @pytest.mark.asyncio
    async def test_worker_processes_queue(self, batch_manager, sample_batch_job, mock_conversion_service):
        """Test worker processes items from queue."""
        job_id = sample_batch_job.job_id
        batch_manager._jobs[job_id] = sample_batch_job
        
        # Create queue with one task
        queue = asyncio.Queue()
        batch_manager._job_queues[job_id] = queue
        batch_manager._job_semaphores[job_id] = asyncio.Semaphore(1)
        
        task = BatchWorkerTask(
            job_id=job_id,
            file_index=0,
            file_data=b"test data",
            filename="test.jpg",
            conversion_request=ConversionRequest(output_format="webp"),
        )
        await queue.put(task)
        
        # Start worker
        worker_task = asyncio.create_task(batch_manager._worker(job_id))
        
        # Wait for processing
        await queue.join()
        
        # Cancel worker
        sample_batch_job.status = BatchStatus.CANCELLED
        worker_task.cancel()
        
        try:
            await worker_task
        except asyncio.CancelledError:
            pass
        
        # Verify task was processed
        assert mock_conversion_service.convert.called
        assert sample_batch_job.items[0].status == BatchItemStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_shutdown(self, batch_manager, sample_batch_job):
        """Test batch manager shutdown."""
        job_id = sample_batch_job.job_id
        file_data = [b"data1", b"data2", b"data3"]
        
        # Create multiple jobs
        await batch_manager.create_job(job_id, sample_batch_job, file_data)
        
        job2 = BatchJob(
            job_id=str(uuid.uuid4()),
            total_files=1,
            items=[BatchItem(file_index=0, filename="test.jpg")],
            settings={"output_format": "png"},
        )
        await batch_manager.create_job(job2.job_id, job2, [b"data"])
        
        # Shutdown
        await batch_manager.shutdown()
        
        # Verify all jobs were cancelled
        assert sample_batch_job.status == BatchStatus.CANCELLED
        assert job2.status == BatchStatus.CANCELLED
        
        # Verify no workers remain
        assert len(batch_manager._job_workers) == 0
        assert len(batch_manager._job_queues) == 0