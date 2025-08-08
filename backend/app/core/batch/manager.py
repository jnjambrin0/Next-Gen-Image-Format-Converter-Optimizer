"""Batch processing manager for handling multiple image conversions."""

import asyncio
import multiprocessing
import psutil
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any, Tuple, Set
from uuid import UUID
import logging

from app.core.batch.models import (
    BatchJob,
    BatchItem,
    BatchStatus,
    BatchItemStatus,
    BatchProgress,
)
from app.core.constants import MAX_BATCH_WORKERS, BATCH_CHUNK_SIZE
from app.config import settings
from app.utils.logging import get_logger
from app.models import ConversionApiRequest, ConversionResult, ConversionSettings
from app.core.exceptions import ValidationError
from app.api.websockets import send_job_status_update

logger = get_logger(__name__)


class BatchWorkerTask:
    """Represents a single work item in the batch queue."""
    
    def __init__(
        self,
        job_id: str,
        file_index: int,
        file_data: bytes,
        filename: str,
        conversion_request: ConversionApiRequest,
    ):
        self.job_id = job_id
        self.file_index = file_index
        self.file_data = file_data
        self.filename = filename
        self.conversion_request = conversion_request
        self.cancelled = False


class BatchManager:
    """Manages batch processing operations with worker pool and queue management."""
    
    def __init__(self):
        """Initialize the batch manager."""
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Job storage
        self._jobs: Dict[str, BatchJob] = {}
        self._job_queues: Dict[str, asyncio.Queue] = {}
        self._job_workers: Dict[str, List[asyncio.Task]] = {}
        self._job_semaphores: Dict[str, asyncio.Semaphore] = {}
        
        # Progress callbacks
        self._progress_callbacks: Dict[str, Callable[[BatchProgress], None]] = {}
        
        # Result storage for converted images
        self._job_results: Dict[str, Dict[int, Dict[str, Any]]] = {}
        
        # Cancellation tracking
        self._cancelled_jobs: Set[str] = set()
        self._cancelled_items: Dict[str, Set[int]] = {}
        
        # Worker configuration
        self._num_workers = self._calculate_worker_count()
        self._max_concurrent_per_job = min(self._num_workers, settings.max_concurrent_conversions)
        
        # Conversion service (will be injected)
        self.conversion_service = None
        
        # Performance metrics
        self._job_metrics: Dict[str, Dict[str, Any]] = {}
        self._memory_process = psutil.Process()
        
        # Pending file DATA storage for deferred processing
        # Changed from _pending_files to _pending_file_data to store bytes, not file handles
        self._pending_file_data: Dict[str, List[bytes]] = {}
        
        self.logger.info(
            f"BatchManager initialized with {self._num_workers} workers, "
            f"max {self._max_concurrent_per_job} concurrent per job"
        )
    
    def _calculate_worker_count(self) -> int:
        """Calculate optimal number of workers based on CPU cores."""
        cpu_count = multiprocessing.cpu_count()
        # Use 80% of CPU cores, minimum 2, maximum MAX_BATCH_WORKERS
        worker_count = max(2, int(cpu_count * 0.8))
        return min(worker_count, MAX_BATCH_WORKERS)
    
    def set_conversion_service(self, service):
        """Inject the conversion service dependency."""
        self.conversion_service = service
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        return self._memory_process.memory_info().rss / 1024 / 1024
    
    def _init_job_metrics(self, job_id: str):
        """Initialize performance metrics for a job."""
        self._job_metrics[job_id] = {
            "start_time": time.time(),
            "start_memory_mb": self._get_memory_usage(),
            "peak_memory_mb": self._get_memory_usage(),
            "file_times": [],
            "worker_activity": {},
            "memory_samples": []
        }
    
    def _update_memory_metrics(self, job_id: str):
        """Update memory metrics for a job."""
        if job_id not in self._job_metrics:
            return
        
        current_memory = self._get_memory_usage()
        metrics = self._job_metrics[job_id]
        metrics["peak_memory_mb"] = max(metrics["peak_memory_mb"], current_memory)
        metrics["memory_samples"].append((time.time(), current_memory))
        
        # Track worker efficiency
        worker_id = id(asyncio.current_task())
        if "worker_activity" not in metrics:
            metrics["worker_activity"] = {}
        if worker_id not in metrics["worker_activity"]:
            metrics["worker_activity"][worker_id] = {"files_processed": 0, "total_time": 0}
        metrics["worker_activity"][worker_id]["files_processed"] += 1
    
    async def create_job(
        self,
        job_id: str,
        batch_job: BatchJob,
        file_data_list: List[bytes],
        progress_callback: Optional[Callable[[BatchProgress], None]] = None,
    ) -> None:
        """Create and start processing a batch job.
        
        Args:
            job_id: Unique job identifier
            batch_job: Batch job model
            file_data_list: List of file data bytes
            progress_callback: Optional callback for progress updates
        """
        if not self.conversion_service:
            raise RuntimeError("Conversion service not initialized")
        
        # Store job
        self._jobs[job_id] = batch_job
        
        # Initialize performance metrics
        self._init_job_metrics(job_id)
        
        # Create job queue
        queue = asyncio.Queue(maxsize=len(file_data_list))
        self._job_queues[job_id] = queue
        
        # Create semaphore for this job
        self._job_semaphores[job_id] = asyncio.Semaphore(self._max_concurrent_per_job)
        
        # Store progress callback if provided
        if progress_callback:
            self._progress_callbacks[job_id] = progress_callback
        
        # Queue all tasks
        for i, (item, file_data) in enumerate(zip(batch_job.items, file_data_list)):
            # Create conversion settings
            conv_settings = None
            if any(k in batch_job.settings for k in ["quality", "preserve_metadata", "optimization_mode"]):
                conv_settings = ConversionSettings(
                    quality=batch_job.settings.get("quality"),
                    preserve_metadata=batch_job.settings.get("preserve_metadata", False),
                    optimization_mode=batch_job.settings.get("optimization_mode"),
                )
            
            # We need to detect format - for now use a simple extension-based approach
            # In production, you'd use the format detection service
            import os
            file_ext = os.path.splitext(item.filename)[1].lower().strip('.')
            if file_ext in ['jpg', 'jpeg']:
                input_format = 'jpeg'
            elif file_ext == 'png':
                input_format = 'png'
            elif file_ext == 'webp':
                input_format = 'webp'
            elif file_ext == 'gif':
                input_format = 'gif'
            elif file_ext == 'bmp':
                input_format = 'bmp'
            elif file_ext in ['tiff', 'tif']:
                input_format = 'tiff'
            elif file_ext == 'avif':
                input_format = 'avif'
            elif file_ext in ['heic', 'heif']:
                input_format = 'heif'
            else:
                input_format = 'unknown'
            
            conversion_request = ConversionApiRequest(
                filename=item.filename,
                input_format=input_format,
                output_format=batch_job.settings["output_format"],
                settings=conv_settings,
                preset_id=batch_job.settings.get("preset_id"),
            )
            
            task = BatchWorkerTask(
                job_id=job_id,
                file_index=i,
                file_data=file_data,
                filename=item.filename,
                conversion_request=conversion_request,
            )
            
            await queue.put(task)
        
        # Start workers for this job
        workers = []
        num_workers_for_job = min(self._num_workers, len(file_data_list))
        
        for _ in range(num_workers_for_job):
            worker = asyncio.create_task(self._worker(job_id))
            workers.append(worker)
        
        self._job_workers[job_id] = workers
        
        # Update job status
        batch_job.status = BatchStatus.PROCESSING
        
        self.logger.info(
            f"Started batch job {job_id} with {len(file_data_list)} files "
            f"and {num_workers_for_job} workers"
        )
    
    async def _worker(self, job_id: str) -> None:
        """Worker coroutine that processes tasks from the job queue.
        
        Args:
            job_id: Job ID this worker is processing
        """
        queue = self._job_queues.get(job_id)
        if not queue:
            return
        
        job = self._jobs.get(job_id)
        if not job:
            return
        
        semaphore = self._job_semaphores.get(job_id)
        
        while True:
            try:
                # Get task from queue (with timeout to check for cancellation)
                try:
                    task = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    # Check if job is cancelled
                    if job.status == BatchStatus.CANCELLED:
                        break
                    continue
                
                # Check if task or job is cancelled
                if task.cancelled or job.status == BatchStatus.CANCELLED:
                    queue.task_done()
                    continue
                
                # Process the task with semaphore
                async with semaphore:
                    await self._process_task(task, job)
                
                queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Worker error for job {job_id}: {e}")
                queue.task_done()
        
        self.logger.debug(f"Worker for job {job_id} shutting down")
    
    async def _process_task(self, task: BatchWorkerTask, job: BatchJob) -> None:
        """Process a single batch task.
        
        Args:
            task: Worker task to process
            job: Parent batch job
        """
        item = job.items[task.file_index]
        
        # Check if item is cancelled
        if item.status == BatchItemStatus.CANCELLED:
            return
        
        # Update status to processing
        item.status = BatchItemStatus.PROCESSING
        item.progress = 0
        await self._send_progress(task.job_id, task.file_index, item)
        
        start_time = datetime.utcnow()
        file_start_time = time.time()
        
        # Update memory metrics before processing
        self._update_memory_metrics(task.job_id)
        
        try:
            # Estimate conversion time based on file size
            # Observed: 7MB takes ~2.8s, 15MB takes ~3.4s
            # Using more accurate estimation based on actual data
            file_size_mb = len(task.file_data) / (1024 * 1024)
            if file_size_mb < 5:
                estimated_time = 2.5  # Small files: 2.5 seconds
            elif file_size_mb < 10:
                estimated_time = 3.0  # Medium files: 3 seconds
            else:
                estimated_time = min(3.0 + (file_size_mb - 10) * 0.1, 5.0)  # Large files: 3-5 seconds
            
            # Start progress simulation task
            progress_task = asyncio.create_task(
                self._simulate_progress(task.job_id, task.file_index, item, estimated_time)
            )
            
            # Perform conversion using the conversion service
            try:
                result, output_data = await self.conversion_service.convert(
                    image_data=task.file_data,
                    request=task.conversion_request,
                )
            finally:
                # Cancel progress simulation when conversion completes
                progress_task.cancel()
                try:
                    await progress_task
                except asyncio.CancelledError:
                    pass
            
            # Update item with results
            item.status = BatchItemStatus.COMPLETED
            item.progress = 100
            item.processing_time = (datetime.utcnow() - start_time).total_seconds()
            item.output_size = len(output_data) if output_data else 0
            item.completed_at = datetime.utcnow()
            
            # Update job counters
            job.completed_files += 1
            
            # Store output data for results collector
            if task.job_id not in self._job_results:
                self._job_results[task.job_id] = {}
            
            self._job_results[task.job_id][task.file_index] = {
                "filename": task.filename,
                "output_data": output_data,
                "output_size": len(output_data) if output_data else 0,
                "processing_time": item.processing_time
            }
            
            # Track file processing time and worker efficiency
            file_processing_time = time.time() - file_start_time
            if task.job_id in self._job_metrics:
                self._job_metrics[task.job_id]["file_times"].append(file_processing_time)
                
                # Update worker activity
                worker_id = id(asyncio.current_task())
                if worker_id in self._job_metrics[task.job_id]["worker_activity"]:
                    self._job_metrics[task.job_id]["worker_activity"][worker_id]["total_time"] += file_processing_time
            
            self.logger.debug(
                f"Completed file {task.file_index} in job {task.job_id} "
                f"in {item.processing_time:.2f}s"
            )
            
        except Exception as e:
            # Handle conversion failure
            item.status = BatchItemStatus.FAILED
            item.error_message = str(e)[:200]  # Limit error message length
            item.completed_at = datetime.utcnow()
            item.processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Update job counters
            job.failed_files += 1
            
            # Track file processing time even for failures
            file_processing_time = time.time() - file_start_time
            if task.job_id in self._job_metrics:
                self._job_metrics[task.job_id]["file_times"].append(file_processing_time)
                
                # Update worker activity even for failures
                worker_id = id(asyncio.current_task())
                if worker_id in self._job_metrics[task.job_id]["worker_activity"]:
                    self._job_metrics[task.job_id]["worker_activity"][worker_id]["total_time"] += file_processing_time
            
            self.logger.error(
                f"Failed to process file {task.file_index} in job {task.job_id}: {e}"
            )
        
        # Send final progress update
        await self._send_progress(task.job_id, task.file_index, item)
        
        # Check if job is complete
        self._check_job_completion(job)
    
    async def _send_progress(self, job_id: str, file_index: int, item: BatchItem) -> None:
        """Send progress update via callback if registered.
        
        Args:
            job_id: Job ID
            file_index: Index of file being processed
            item: Batch item with current status
        """
        callback = self._progress_callbacks.get(job_id)
        if callback:
            progress = BatchProgress(
                job_id=job_id,
                file_index=file_index,
                filename=item.filename,
                status=item.status,
                progress=item.progress,
                message=item.error_message if item.status == BatchItemStatus.FAILED else None,
            )
            try:
                await callback(progress)
            except Exception as e:
                self.logger.error(f"Error in progress callback: {e}")
    
    async def _simulate_progress(self, job_id: str, file_index: int, item: BatchItem, estimated_time: float = 3.0) -> None:
        """Simulate progressive updates during conversion.
        
        This provides visual feedback during the conversion process which
        runs atomically in a subprocess without progress callbacks.
        
        Args:
            job_id: Job ID
            file_index: Index of file being processed
            item: Batch item to update
            estimated_time: Estimated conversion time in seconds
        """
        try:
            start_time = asyncio.get_event_loop().time()
            update_interval = 0.2  # Update every 200ms for smooth progress
            
            # Start at 5% immediately to show activity
            item.progress = 5
            await self._send_progress(job_id, file_index, item)
            
            # Continue updating until cancelled or completed
            while item.status == BatchItemStatus.PROCESSING:
                await asyncio.sleep(update_interval)
                
                # Calculate elapsed time and progress
                elapsed = asyncio.get_event_loop().time() - start_time
                
                # Use exponential curve for realistic feel (starts fast, slows down)
                # Progress = (elapsed/estimated)^1.5 * 90 + 5 (5-95% range)
                time_ratio = min(elapsed / estimated_time, 1.0)
                progress = int(5 + (time_ratio ** 1.5) * 90)
                
                # Cap at 95% to leave room for completion
                progress = min(progress, 95)
                
                # Only update if progress changed
                if progress != item.progress:
                    item.progress = progress
                    await self._send_progress(job_id, file_index, item)
                
                # Stop if we've reached the estimated time
                if elapsed >= estimated_time:
                    # Stay at 95% until actual completion
                    if item.progress < 95:
                        item.progress = 95
                        await self._send_progress(job_id, file_index, item)
                    break
                    
        except asyncio.CancelledError:
            # Task was cancelled (conversion completed)
            pass
        except Exception as e:
            self.logger.debug(f"Progress simulation error (non-critical): {e}")
    
    def _check_job_completion(self, job: BatchJob) -> None:
        """Check if a job is complete and update its status.
        
        Args:
            job: Batch job to check
        """
        job.update_status()
        
        if job.status in [BatchStatus.COMPLETED, BatchStatus.FAILED]:
            self.logger.info(
                f"Batch job {job.job_id} completed with status {job.status}. "
                f"Completed: {job.completed_files}, Failed: {job.failed_files}"
            )
            
            # Update database with final status
            if job.created_at and job.completed_at:
                processing_time = (job.completed_at - job.created_at).total_seconds()
            else:
                processing_time = None
                
            # Import here to avoid circular dependency
            from app.services.batch_history_service import batch_history_service
            import asyncio
            
            # Schedule database update (fire and forget)
            asyncio.create_task(batch_history_service.update_job_status(
                job_id=job.job_id,
                status=job.status.value,
                completed_files=job.completed_files,
                failed_files=job.failed_files,
                processing_time=processing_time
            ))
            
            # Add a small delay before sending job completion notification
            # This ensures all individual file progress updates are sent first
            async def delayed_status_update():
                await asyncio.sleep(0.5)  # 500ms delay
                await send_job_status_update(job.job_id, job.status)
            
            asyncio.create_task(delayed_status_update())
    
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel an entire batch job.
        
        Args:
            job_id: Job ID to cancel
            
        Returns:
            True if cancelled successfully
        """
        job = self._jobs.get(job_id)
        if not job:
            return False
        
        # Update job status
        job.status = BatchStatus.CANCELLED
        job.completed_at = datetime.utcnow()
        
        # Cancel all pending/processing items
        for item in job.items:
            if item.status in [BatchItemStatus.PENDING, BatchItemStatus.PROCESSING]:
                item.status = BatchItemStatus.CANCELLED
                item.completed_at = datetime.utcnow()
        
        # Cancel workers
        workers = self._job_workers.get(job_id, [])
        for worker in workers:
            worker.cancel()
        
        # Clear queue
        queue = self._job_queues.get(job_id)
        if queue:
            while not queue.empty():
                try:
                    task = queue.get_nowait()
                    task.cancelled = True
                    queue.task_done()
                except asyncio.QueueEmpty:
                    break
        
        self.logger.info(f"Cancelled batch job {job_id}")
        return True
    
    async def cancel_item(self, job_id: str, file_index: int) -> bool:
        """Cancel a specific item in a batch job.
        
        Args:
            job_id: Job ID
            file_index: Index of file to cancel
            
        Returns:
            True if cancelled successfully
        """
        job = self._jobs.get(job_id)
        if not job or file_index >= len(job.items):
            return False
        
        item = job.items[file_index]
        
        # Can only cancel pending or processing items
        if item.status not in [BatchItemStatus.PENDING, BatchItemStatus.PROCESSING]:
            return False
        
        # Mark as cancelled
        item.status = BatchItemStatus.CANCELLED
        item.completed_at = datetime.utcnow()
        
        # Mark the task in queue as cancelled if still pending
        queue = self._job_queues.get(job_id)
        if queue:
            # We can't easily remove from queue, so we mark tasks as cancelled
            # Workers will skip cancelled tasks
            pass
        
        # Update job status
        self._check_job_completion(job)
        
        self.logger.info(f"Cancelled item {file_index} in batch job {job_id}")
        return True
    
    def get_job(self, job_id: str) -> Optional[BatchJob]:
        """Get a batch job by ID.
        
        Args:
            job_id: Job ID to retrieve
            
        Returns:
            Batch job if found
        """
        return self._jobs.get(job_id)
    
    async def cleanup_job(self, job_id: str) -> None:
        """Clean up resources for a completed job.
        
        Args:
            job_id: Job ID to clean up
        """
        # Cancel and remove workers
        workers = self._job_workers.pop(job_id, [])
        for worker in workers:
            worker.cancel()
        
        # Remove queue
        self._job_queues.pop(job_id, None)
        
        # Remove semaphore
        self._job_semaphores.pop(job_id, None)
        
        # Remove progress callback
        self._progress_callbacks.pop(job_id, None)
        
        # Note: We keep the job in _jobs for status queries
        # It should be removed by a cleanup process after expiry
        
        self.logger.debug(f"Cleaned up resources for job {job_id}")
    
    async def shutdown(self) -> None:
        """Shutdown the batch manager and clean up all resources."""
        self.logger.info("Shutting down BatchManager")
        
        # Cancel all jobs
        for job_id in list(self._jobs.keys()):
            await self.cancel_job(job_id)
        
        # Clean up all jobs
        for job_id in list(self._jobs.keys()):
            await self.cleanup_job(job_id)
        
        self.logger.info("BatchManager shutdown complete")
    
    async def is_cancelled(self, job_id: str) -> bool:
        """Check if a job is cancelled.
        
        Args:
            job_id: Job ID to check
            
        Returns:
            True if job is cancelled
        """
        return job_id in self._cancelled_jobs
    
    async def is_item_cancelled(self, job_id: str, file_index: int) -> bool:
        """Check if a specific item in a job is cancelled.
        
        Args:
            job_id: Job ID
            file_index: Index of file to check
            
        Returns:
            True if item is cancelled
        """
        if job_id in self._cancelled_items:
            return file_index in self._cancelled_items[job_id]
        return False
    
    async def update_file_status(
        self, 
        job_id: str, 
        file_index: int, 
        status: str,
        processing_time: Optional[float] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Update the status of a specific file in a batch job.
        
        Args:
            job_id: Job ID
            file_index: Index of file to update
            status: New status (completed/failed)
            processing_time: Optional processing time in seconds
            error_message: Optional error message for failed items
        """
        job = self._jobs.get(job_id)
        if not job or file_index >= len(job.items):
            return
        
        item = job.items[file_index]
        
        # Map string status to enum
        if status == "completed":
            item.status = BatchItemStatus.COMPLETED
            item.progress = 100
            if processing_time is not None:
                item.processing_time = processing_time
        elif status == "failed":
            item.status = BatchItemStatus.FAILED
            if error_message:
                item.error_message = error_message[:200]  # Limit length
        
        item.completed_at = datetime.utcnow()
        
        # Update job counters
        job.update_status()
        
        # Send progress update
        await self._send_progress(job_id, file_index, item)
    
    async def get_progress(self, job_id: str) -> Optional[BatchProgress]:
        """Get current progress for a batch job.
        
        Args:
            job_id: Job ID
            
        Returns:
            BatchProgress object with current status
        """
        job = self._jobs.get(job_id)
        if not job:
            return None
        
        # Calculate overall progress
        total_progress = 0
        for item in job.items:
            total_progress += item.progress
        
        overall_progress = int(total_progress / len(job.items)) if job.items else 0
        
        return BatchProgress(
            job_id=job_id,
            file_index=-1,  # -1 indicates overall progress
            filename="",
            status=job.status,
            progress=overall_progress,
            message=f"{job.completed_files + job.failed_files}/{job.total_files} files processed"
        )
    
    async def complete_job(self, job_id: str) -> None:
        """Mark a job as completed.
        
        Args:
            job_id: Job ID to complete
        """
        job = self._jobs.get(job_id)
        if not job:
            return
        
        # Update status based on results
        if job.failed_files == 0:
            job.status = BatchStatus.COMPLETED
        else:
            job.status = BatchStatus.FAILED
        
        job.completed_at = datetime.utcnow()
        
        # Cancel any remaining workers
        if job_id in self._job_workers:
            for worker in self._job_workers[job_id]:
                if not worker.done():
                    worker.cancel()
        
        self.logger.info(
            f"Batch job {job_id} completed: "
            f"{job.completed_files} successful, {job.failed_files} failed"
        )
    
    async def update_job_status(self, job_id: str, status: str) -> None:
        """Update the status of a batch job.
        
        Args:
            job_id: Job ID
            status: New status string
        """
        job = self._jobs.get(job_id)
        if not job:
            return
        
        # Map string status to enum
        status_map = {
            "pending": BatchStatus.PENDING,
            "processing": BatchStatus.PROCESSING,
            "completed": BatchStatus.COMPLETED,
            "failed": BatchStatus.FAILED,
            "cancelled": BatchStatus.CANCELLED
        }
        
        if status in status_map:
            job.status = status_map[status]
            
            if status in ["completed", "failed", "cancelled"]:
                job.completed_at = datetime.utcnow()
    
    def get_job_results(self, job_id: str) -> Dict[int, Dict[str, Any]]:
        """Get conversion results for a job.
        
        Args:
            job_id: Job ID
            
        Returns:
            Dictionary mapping file index to result data
        """
        return self._job_results.get(job_id, {})
    
    def get_job_metrics(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get performance metrics for a job.
        
        Args:
            job_id: Job ID
            
        Returns:
            Performance metrics dictionary or None if job not found
        """
        if job_id not in self._job_metrics:
            return None
            
        metrics = self._job_metrics[job_id]
        job = self._jobs.get(job_id)
        
        # Calculate summary statistics
        current_time = time.time()
        elapsed_time = current_time - metrics["start_time"]
        
        # Memory statistics
        current_memory = self._get_memory_usage()
        memory_delta = current_memory - metrics["start_memory_mb"]
        
        # File processing statistics
        file_times = metrics["file_times"]
        avg_time_per_file = sum(file_times) / len(file_times) if file_times else 0
        
        # Worker efficiency
        completed_files = job.completed_files + job.failed_files if job else 0
        throughput = completed_files / elapsed_time if elapsed_time > 0 else 0
        
        # Calculate worker efficiency
        worker_stats = []
        for worker_id, activity in metrics["worker_activity"].items():
            if activity["files_processed"] > 0:
                avg_time = activity["total_time"] / activity["files_processed"]
                worker_stats.append({
                    "worker_id": str(worker_id),
                    "files_processed": activity["files_processed"],
                    "total_time": activity["total_time"],
                    "average_time": avg_time,
                    "efficiency": (avg_time_per_file / avg_time * 100) if avg_time > 0 and avg_time_per_file > 0 else 0
                })
        
        return {
            "job_id": job_id,
            "elapsed_time_seconds": elapsed_time,
            "memory_usage": {
                "start_mb": metrics["start_memory_mb"],
                "current_mb": current_memory,
                "peak_mb": metrics["peak_memory_mb"],
                "delta_mb": memory_delta
            },
            "file_processing": {
                "completed": job.completed_files if job else 0,
                "failed": job.failed_files if job else 0,
                "average_time_seconds": avg_time_per_file,
                "min_time_seconds": min(file_times) if file_times else 0,
                "max_time_seconds": max(file_times) if file_times else 0
            },
            "throughput": {
                "files_per_second": throughput,
                "estimated_completion_seconds": (job.total_files / throughput - elapsed_time) if throughput > 0 and job else 0
            },
            "worker_efficiency": worker_stats,
            "memory_samples": len(metrics["memory_samples"])
        }
    
    async def cleanup_job_results(self, job_id: str) -> None:
        """Clean up stored results for a job.
        
        Args:
            job_id: Job ID
        """
        if job_id in self._job_results:
            del self._job_results[job_id]
            self.logger.debug(f"Cleaned up results for job {job_id}")
        
        # Also cleanup metrics
        if job_id in self._job_metrics:
            del self._job_metrics[job_id]
        
        # Cleanup pending file data
        if job_id in self._pending_file_data:
            del self._pending_file_data[job_id]
    
    async def start_processing(self, job_id: str) -> bool:
        """Start processing a batch job with pre-read file data.
        
        This method is called after the WebSocket connection is established
        to avoid the race condition where files are processed before the
        client is ready to receive progress updates.
        
        Args:
            job_id: Job ID to start processing
            
        Returns:
            True if processing started successfully, False otherwise
        """
        # Check if job exists
        job = self._jobs.get(job_id)
        if not job:
            self.logger.error(f"Job {job_id} not found")
            return False
        
        # Check if we have pending file data
        if job_id not in self._pending_file_data:
            self.logger.warning(f"No pending file data found for job {job_id}")
            return False
        
        # Get the pre-read file data (already read in batch_service)
        file_data_list = self._pending_file_data.get(job_id, [])
        if not file_data_list:
            self.logger.error(f"Empty file data list for job {job_id}")
            return False
        
        try:
            # Remove from pending file data
            del self._pending_file_data[job_id]
            
            # Get the progress callback that was stored
            progress_callback = self._progress_callbacks.get(job_id)
            
            # Start actual processing with pre-read data
            await self.create_job(
                job_id=job_id,
                batch_job=job,
                file_data_list=file_data_list,
                progress_callback=progress_callback
            )
            
            self.logger.info(f"Started processing for job {job_id} with {len(file_data_list)} files")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start processing for job {job_id}: {e}")
            # Clean up pending file data on error
            if job_id in self._pending_file_data:
                del self._pending_file_data[job_id]
            return False
    
    async def cleanup_pending_job(self, job_id: str) -> None:
        """Clean up a pending job that failed to start processing.
        
        Args:
            job_id: Job ID to clean up
        """
        # Clean up pending file data
        if job_id in self._pending_file_data:
            del self._pending_file_data[job_id]
            self.logger.info(f"Cleaned up pending file data for job {job_id}")
        
        # Clean up progress callbacks
        if job_id in self._progress_callbacks:
            del self._progress_callbacks[job_id]
        
        # Mark job as failed if it exists
        job = self._jobs.get(job_id)
        if job and job.status == BatchStatus.PENDING:
            job.status = BatchStatus.FAILED
            job.completed_at = datetime.utcnow()
            for item in job.items:
                if item.status == BatchItemStatus.PENDING:
                    item.status = BatchItemStatus.FAILED
                    item.error_message = "Failed to start processing"
            self.logger.info(f"Marked job {job_id} as failed due to processing startup failure")