"""Integration tests for batch job persistence and history service."""

import asyncio
import os
import tempfile
from datetime import datetime, timedelta
from typing import Dict, Any
import pytest

from app.services.batch_history_service import BatchHistoryService
from app.core.batch.models import BatchJobStatus, BatchResult


@pytest.fixture
async def temp_db():
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    yield db_path

    # Cleanup
    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
async def history_service(temp_db):
    """Create history service with temporary database."""
    service = BatchHistoryService(db_path=temp_db)
    return service


class TestBatchHistoryService:
    """Test batch history persistence functionality."""

    async def test_create_and_retrieve_job(self, history_service):
        """Test creating and retrieving a batch job."""
        # Create job
        job_id = "test-job-123"
        await history_service.create_job(
            job_id=job_id,
            total_files=5,
            settings={"output_format": "webp", "quality": 85},
            user_ip="127.0.0.1",
        )

        # Add file records
        for i in range(5):
            await history_service.add_file_record(
                job_id=job_id, file_index=i, filename=f"test_{i}.jpg", status="pending"
            )

        # Retrieve job status
        status = await history_service.get_job_status(job_id)

        assert status is not None
        assert status.job_id == job_id
        assert status.total_files == 5
        assert status.status == "pending"
        assert len(status.files) == 5
        assert all(f["status"] == "pending" for f in status.files)

    async def test_update_file_status(self, history_service):
        """Test updating individual file status."""
        # Create job
        job_id = "test-job-456"
        await history_service.create_job(
            job_id=job_id, total_files=3, settings={"output_format": "avif"}
        )

        # Add files
        for i in range(3):
            await history_service.add_file_record(
                job_id=job_id, file_index=i, filename=f"image_{i}.png"
            )

        # Update file statuses
        await history_service.update_file_status(
            job_id=job_id,
            file_index=0,
            status="completed",
            processing_time=1.5,
            output_size=50000,
        )

        await history_service.update_file_status(
            job_id=job_id,
            file_index=1,
            status="failed",
            error_message="Unsupported format",
        )

        # Check status
        status = await history_service.get_job_status(job_id)
        assert status.files[0]["status"] == "completed"
        assert status.files[0]["processing_time"] == 1.5
        assert status.files[0]["output_size"] == 50000
        assert status.files[1]["status"] == "failed"
        assert status.files[1]["error"] == "Unsupported format"
        assert status.files[2]["status"] == "pending"

    async def test_update_job_status(self, history_service):
        """Test updating overall job status."""
        # Create job
        job_id = "test-job-789"
        await history_service.create_job(job_id=job_id, total_files=2, settings={})

        # Update to processing
        await history_service.update_job_status(job_id=job_id, status="processing")

        status = await history_service.get_job_status(job_id)
        assert status.status == "processing"

        # Complete job
        await history_service.update_job_status(
            job_id=job_id,
            status="completed",
            completed_files=2,
            failed_files=0,
            processing_time=5.5,
        )

        status = await history_service.get_job_status(job_id)
        assert status.status == "completed"
        assert status.completed_files == 2
        assert status.failed_files == 0
        assert status.processing_time_seconds == 5.5
        assert status.completed_at is not None

    async def test_get_job_results(self, history_service):
        """Test retrieving job results."""
        # Create completed job
        job_id = "test-job-results"
        await history_service.create_job(
            job_id=job_id, total_files=3, settings={"output_format": "jpeg"}
        )

        # Add files with mixed results
        for i in range(3):
            await history_service.add_file_record(
                job_id=job_id, file_index=i, filename=f"photo_{i}.tiff"
            )

        # Update statuses
        await history_service.update_file_status(
            job_id=job_id, file_index=0, status="completed", output_size=100000
        )

        await history_service.update_file_status(
            job_id=job_id, file_index=1, status="completed", output_size=120000
        )

        await history_service.update_file_status(
            job_id=job_id, file_index=2, status="failed", error_message="Corrupted file"
        )

        # Complete job
        await history_service.update_job_status(
            job_id=job_id,
            status="completed",
            completed_files=2,
            failed_files=1,
            processing_time=3.0,
        )

        # Get results
        result = await history_service.get_job_results(job_id)

        assert result is not None
        assert result.job_id == job_id
        assert result.total_files == 3
        assert len(result.successful_files) == 2
        assert len(result.failed_files) == 1
        assert result.processing_time_seconds == 3.0
        assert result.failed_files[0]["error"] == "Corrupted file"

    async def test_cleanup_old_jobs(self, history_service):
        """Test cleaning up old batch jobs."""
        # Create old job (mock old timestamp)
        old_job_id = "old-job-123"
        await history_service.create_job(job_id=old_job_id, total_files=1, settings={})

        # Create recent job
        recent_job_id = "recent-job-456"
        await history_service.create_job(
            job_id=recent_job_id, total_files=1, settings={}
        )

        # Complete both jobs
        await history_service.update_job_status(old_job_id, "completed")
        await history_service.update_job_status(recent_job_id, "completed")

        # Manually update old job's created_at to be old
        async with history_service._lock:
            with history_service._get_db() as conn:
                old_date = (datetime.now() - timedelta(days=8)).isoformat()
                conn.execute(
                    "UPDATE batch_jobs SET created_at = ? WHERE job_id = ?",
                    (old_date, old_job_id),
                )

        # Run cleanup
        deleted_count = await history_service.cleanup_old_jobs()

        assert deleted_count == 1

        # Verify old job is gone
        old_status = await history_service.get_job_status(old_job_id)
        assert old_status is None

        # Verify recent job still exists
        recent_status = await history_service.get_job_status(recent_job_id)
        assert recent_status is not None

    async def test_rate_limiting_check(self, history_service):
        """Test checking recent jobs by IP for rate limiting."""
        user_ip = "192.168.1.100"

        # Create multiple jobs from same IP
        for i in range(3):
            await history_service.create_job(
                job_id=f"rate-test-{i}", total_files=10, settings={}, user_ip=user_ip
            )

        # Check recent jobs
        recent_jobs = await history_service.get_recent_jobs_by_ip(
            user_ip=user_ip, minutes=60
        )

        assert len(recent_jobs) == 3
        assert all(job["total_files"] == 10 for job in recent_jobs)

        # Check different IP has no jobs
        other_jobs = await history_service.get_recent_jobs_by_ip(
            user_ip="10.0.0.1", minutes=60
        )

        assert len(other_jobs) == 0

    async def test_concurrent_updates(self, history_service):
        """Test concurrent updates to same job."""
        job_id = "concurrent-test"
        await history_service.create_job(job_id=job_id, total_files=10, settings={})

        # Add all files
        for i in range(10):
            await history_service.add_file_record(
                job_id=job_id, file_index=i, filename=f"concurrent_{i}.jpg"
            )

        # Simulate concurrent updates
        async def update_file(index: int):
            await history_service.update_file_status(
                job_id=job_id,
                file_index=index,
                status="completed" if index % 2 == 0 else "failed",
                processing_time=1.0 + index * 0.1,
            )

        # Run updates concurrently
        await asyncio.gather(*[update_file(i) for i in range(10)])

        # Check results
        status = await history_service.get_job_status(job_id)
        completed_count = sum(1 for f in status.files if f["status"] == "completed")
        failed_count = sum(1 for f in status.files if f["status"] == "failed")

        assert completed_count == 5
        assert failed_count == 5

    async def test_nonexistent_job(self, history_service):
        """Test retrieving nonexistent job."""
        status = await history_service.get_job_status("nonexistent-job")
        assert status is None

        result = await history_service.get_job_results("nonexistent-job")
        assert result is None
