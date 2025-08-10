"""
Comprehensive test coverage for batch processing.
Target: 90%+ coverage for all batch functionality.
"""

import pytest
import asyncio
import uuid
import time
from pathlib import Path
from typing import List, Dict, Any
from unittest.mock import Mock, AsyncMock, MagicMock, patch
import io
from PIL import Image

from app.core.batch.models import BatchJob, BatchStatus, BatchItem, BatchItemStatus
from app.models.conversion import ConversionRequest


@pytest.mark.asyncio
class TestBatchManagerComplete:
    """Complete test coverage for batch processing manager."""
    
    @pytest.fixture
    def batch_manager(self, initialized_services):
        """Create batch manager with dependencies."""
        from app.core.batch.manager import BatchManager
        manager = BatchManager()
        manager.conversion_service = initialized_services['conversion_service']
        return manager
    
    @pytest.fixture
    def sample_batch_files(self):
        """Create sample files for batch processing."""
        from PIL import Image
        import io
        
        files = []
        for i in range(5):
            # Create a simple test image
            img = Image.new('RGB', (100, 100), color=(255, 0, 0))
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_data = buffer.getvalue()
            
            files.append({
                'filename': f'test_{i}.png',
                'content': img_data,
                'size': len(img_data)
            })
        return files
    
    async def test_batch_job_lifecycle(self, batch_manager, sample_batch_files):
        """Test complete batch job lifecycle."""
        # Create job
        job = await batch_manager.create_job(
            files=sample_batch_files,
            output_format='webp',
            quality=85
        )
        
        assert job is not None
        assert job.status == BatchStatus.PENDING
        assert job.total_files == 5
        
        # Start processing
        await batch_manager.start_job(job.id)
        assert job.status == BatchStatus.PROCESSING
        
        # Wait for completion (with timeout)
        start_time = time.time()
        while job.status == BatchStatus.PROCESSING and time.time() - start_time < 10:
            await asyncio.sleep(0.1)
        
        # Check completion
        assert job.status in [BatchStatus.COMPLETED, BatchStatus.PARTIAL]
        assert job.completed_files > 0
    
    async def test_batch_item_processing(self, batch_manager):
        """Test individual item processing in batch."""
        # Create single item
        from PIL import Image
        import io
        img = Image.new('RGB', (200, 200), color=(0, 255, 0))
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG')
        img_data = buffer.getvalue()
        item = BatchItem(
            index=0,
            filename='test.jpg',
            input_data=img_data,
            status=BatchItemStatus.PENDING
        )
        
        # Process item
        request = ConversionRequest(
            output_format='png',
            quality=90
        )
        
        result = await batch_manager._process_item(item, request)
        
        assert result is not None
        assert item.status in [BatchItemStatus.COMPLETED, BatchItemStatus.FAILED]
        if item.status == BatchItemStatus.COMPLETED:
            assert item.output_data is not None
            assert len(item.output_data) > 0
    
    async def test_concurrent_batch_processing(self, batch_manager, sample_batch_files):
        """Test concurrent processing with worker pool."""
        # Set worker count
        batch_manager.MAX_WORKERS = 3
        
        # Create larger batch
        large_batch = sample_batch_files * 4  # 20 files
        
        job = await batch_manager.create_job(
            files=large_batch,
            output_format='webp'
        )
        
        # Track processing times
        start_time = time.time()
        await batch_manager.start_job(job.id)
        
        # Wait for completion
        while job.status == BatchStatus.PROCESSING and time.time() - start_time < 30:
            await asyncio.sleep(0.1)
        
        # Should process multiple files concurrently
        assert job.completed_files > 0
        processing_time = time.time() - start_time
        
        # With 3 workers, should be faster than sequential
        expected_sequential_time = len(large_batch) * 0.5  # Assume 0.5s per file
        assert processing_time < expected_sequential_time
    
    async def test_batch_cancellation(self, batch_manager, sample_batch_files):
        """Test job cancellation."""
        # Create and start job
        job = await batch_manager.create_job(
            files=sample_batch_files,
            output_format='avif'
        )
        
        # Start processing
        process_task = asyncio.create_task(batch_manager.start_job(job.id))
        
        # Cancel after short delay
        await asyncio.sleep(0.1)
        await batch_manager.cancel_job(job.id)
        
        # Wait for task to finish
        try:
            await process_task
        except asyncio.CancelledError:
            pass
        
        # Check job status
        assert job.status == BatchStatus.CANCELLED
    
    async def test_item_level_cancellation(self, batch_manager, sample_batch_files):
        """Test cancelling specific items in batch."""
        job = await batch_manager.create_job(
            files=sample_batch_files,
            output_format='webp'
        )
        
        # Cancel specific items
        await batch_manager.cancel_item(job.id, 1)
        await batch_manager.cancel_item(job.id, 3)
        
        # Start processing
        await batch_manager.start_job(job.id)
        
        # Wait for completion
        start_time = time.time()
        while job.status == BatchStatus.PROCESSING and time.time() - start_time < 10:
            await asyncio.sleep(0.1)
        
        # Check cancelled items
        assert job.items[1].status == BatchItemStatus.CANCELLED
        assert job.items[3].status == BatchItemStatus.CANCELLED
        
        # Others should process
        assert job.items[0].status != BatchItemStatus.CANCELLED
        assert job.items[2].status != BatchItemStatus.CANCELLED
    
    async def test_batch_progress_tracking(self, batch_manager, sample_batch_files):
        """Test progress tracking and callbacks."""
        progress_updates = []
        
        async def progress_callback(progress):
            progress_updates.append(progress)
        
        # Create job with callback
        job = await batch_manager.create_job(
            files=sample_batch_files,
            output_format='webp',
            progress_callback=progress_callback
        )
        
        # Process
        await batch_manager.start_job(job.id)
        
        # Wait for completion
        start_time = time.time()
        while job.status == BatchStatus.PROCESSING and time.time() - start_time < 10:
            await asyncio.sleep(0.1)
        
        # Should have progress updates
        assert len(progress_updates) > 0
        
        # Check progress structure
        for update in progress_updates:
            assert 'completed' in update
            assert 'total' in update
            assert 'percentage' in update
    
    async def test_batch_error_handling(self, batch_manager):
        """Test error handling in batch processing."""
        # Create batch with invalid data
        invalid_files = [
            {'filename': 'bad1.jpg', 'content': b'NOT_AN_IMAGE', 'size': 12},
            {'filename': 'bad2.png', 'content': b'INVALID', 'size': 7},
        ]
        
        job = await batch_manager.create_job(
            files=invalid_files,
            output_format='webp'
        )
        
        # Process
        await batch_manager.start_job(job.id)
        
        # Wait for completion
        start_time = time.time()
        while job.status == BatchStatus.PROCESSING and time.time() - start_time < 5:
            await asyncio.sleep(0.1)
        
        # Should mark as partial or failed
        assert job.status in [BatchStatus.PARTIAL, BatchStatus.FAILED]
        assert job.failed_files > 0
        
        # Check error details
        for item in job.items:
            if item.status == BatchItemStatus.FAILED:
                assert item.error is not None
    
    async def test_batch_memory_management(self, batch_manager):
        """Test memory management with large batches."""
        # Create large files
        from PIL import Image
        import io
        
        large_files = []
        for i in range(10):
            # Create large image
            img = Image.new('RGB', (2000, 2000), color=(255, 255, 0))
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_data = buffer.getvalue()
            large_files.append({
                'filename': f'large_{i}.png',
                'content': img_data,
                'size': len(img_data)
            })
        
        # Monitor memory
        import psutil
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Process batch
        job = await batch_manager.create_job(
            files=large_files,
            output_format='jpeg',
            quality=70
        )
        
        await batch_manager.start_job(job.id)
        
        # Wait for completion
        start_time = time.time()
        while job.status == BatchStatus.PROCESSING and time.time() - start_time < 30:
            await asyncio.sleep(0.1)
        
        # Check memory growth
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory
        
        # Should not grow excessively (< 500MB for 10 files)
        assert memory_growth < 500
        
        # Cleanup
        await batch_manager.cleanup_job(job.id)
        
        # Memory should be released
        await asyncio.sleep(0.5)  # Give GC time
        import gc
        gc.collect()
        
        post_cleanup_memory = process.memory_info().rss / 1024 / 1024
        assert post_cleanup_memory < final_memory
    
    async def test_batch_result_retrieval(self, batch_manager, sample_batch_files):
        """Test retrieving batch results."""
        # Process batch
        job = await batch_manager.create_job(
            files=sample_batch_files,
            output_format='webp'
        )
        
        await batch_manager.start_job(job.id)
        
        # Wait for completion
        start_time = time.time()
        while job.status == BatchStatus.PROCESSING and time.time() - start_time < 10:
            await asyncio.sleep(0.1)
        
        # Get results
        results = await batch_manager.get_results(job.id)
        
        assert results is not None
        assert 'successful' in results
        assert 'failed' in results
        assert len(results['successful']) > 0
        
        # Check result structure
        for result in results['successful']:
            assert 'filename' in result
            assert 'data' in result
            assert 'size' in result
    
    async def test_batch_queue_management(self, batch_manager):
        """Test job queue management."""
        # Create multiple jobs
        jobs = []
        for i in range(5):
            job = await batch_manager.create_job(
                files=[{'filename': f'file_{i}.png', 'content': b'test', 'size': 4}],
                output_format='webp'
            )
            jobs.append(job)
        
        # Check queue
        assert len(batch_manager._job_queue) == 5
        
        # Process queue
        await batch_manager.process_queue()
        
        # All should be processed or processing
        for job in jobs:
            assert job.status != BatchStatus.PENDING
    
    async def test_batch_priority_processing(self, batch_manager):
        """Test priority-based batch processing."""
        # Create jobs with different priorities
        high_priority = await batch_manager.create_job(
            files=[{'filename': 'high.png', 'content': b'test', 'size': 4}],
            output_format='webp',
            priority=10
        )
        
        low_priority = await batch_manager.create_job(
            files=[{'filename': 'low.png', 'content': b'test', 'size': 4}],
            output_format='webp',
            priority=1
        )
        
        # Process queue
        await batch_manager.process_queue()
        
        # High priority should process first
        # This depends on implementation, but we can check processing order
        assert high_priority.started_at is not None
        if low_priority.started_at:
            assert high_priority.started_at <= low_priority.started_at


@pytest.mark.asyncio  
class TestBatchService:
    """Test batch service layer."""
    
    @pytest.fixture
    def batch_service(self, initialized_services):
        """Create batch service with dependencies."""
        from app.services.batch_service import batch_service
        batch_service.set_conversion_service(initialized_services['conversion_service'])
        return batch_service
    
    async def test_batch_service_create_job(self, batch_service, sample_batch_files):
        """Test creating batch job through service."""
        job_id = await batch_service.create_batch_job(
            files=sample_batch_files,
            output_format='avif',
            quality=80,
            resize={'width': 800, 'height': 600}
        )
        
        assert job_id is not None
        assert isinstance(job_id, str)
        
        # Get status
        status = await batch_service.get_job_status(job_id)
        assert status is not None
        assert status['status'] == 'pending'
        assert status['total_files'] == len(sample_batch_files)
    
    async def test_batch_service_download_results(self, batch_service, sample_batch_files):
        """Test downloading batch results as ZIP."""
        # Create and process job
        job_id = await batch_service.create_batch_job(
            files=sample_batch_files,
            output_format='jpeg'
        )
        
        # Wait for processing
        await asyncio.sleep(1)
        
        # Get download
        zip_data = await batch_service.get_download_zip(job_id)
        
        if zip_data:  # May be None if still processing
            assert isinstance(zip_data, bytes)
            assert len(zip_data) > 0
            
            # Verify it's a valid ZIP
            import zipfile
            import io
            
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                assert len(zf.namelist()) > 0