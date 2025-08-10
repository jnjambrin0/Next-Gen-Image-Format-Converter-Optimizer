"""Batch processing service for managing multiple image conversions."""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.api.websockets.progress import connection_manager
from app.core.batch.manager import BatchManager
from app.core.batch.models import BatchItemStatus, BatchJob, BatchProgress, BatchResult
from app.core.batch.results import BatchResultCollector
from app.services.batch_history_service import batch_history_service
from app.services.conversion_service import conversion_service

logger = logging.getLogger(__name__)


class BatchService:
    """Service for managing batch image conversions."""

    def __init__(self):
        """Initialize the batch service."""
        self.batch_manager = BatchManager()
        self.result_collector = BatchResultCollector()
        self.conversion_service = None  # Will be injected
        self._results_storage: Dict[str, BatchResult] = {}

    def set_conversion_service(self, service):
        """Inject the conversion service dependency."""
        self.conversion_service = service
        # Also inject into BatchManager
        self.batch_manager.set_conversion_service(service)

    async def create_batch_job(
        self,
        files: List[Any],  # UploadFile objects
        output_format: str,
        settings: Optional[Dict[str, Any]] = None,
        user_ip: Optional[str] = None,
    ) -> BatchJob:
        """Create a new batch conversion job."""
        # Create the batch job
        import uuid
        from datetime import datetime

        from app.core.batch.models import BatchItem, BatchItemStatus

        job_id = str(uuid.uuid4())

        # CRITICAL FIX: Read file data IMMEDIATELY before request completes
        # FastAPI will close file handles after request, so we must read now
        file_data_list = []
        items = []

        for i, file in enumerate(files):
            # Read file data NOW while handle is still open
            try:
                file_data = await file.read()
                file_data_list.append(file_data)
                # Reset file position in case it's needed elsewhere
                await file.seek(0)
            except Exception as e:
                logger.error(f"Failed to read file {file.filename}: {e}")
                file_data_list.append(b"")  # Add empty data for failed reads

            # Create batch item
            item = BatchItem(
                file_index=i,
                filename=file.filename or f"file_{i}",
                status=BatchItemStatus.PENDING,
            )
            items.append(item)

        # Create batch job
        job = BatchJob(
            job_id=job_id,
            total_files=len(files),
            settings={"output_format": output_format, **(settings or {})},
            items=items,
            created_at=datetime.utcnow(),
            user_ip=user_ip,
        )

        # Store the job immediately
        self.batch_manager._jobs[job_id] = job

        # Persist job to database
        await batch_history_service.create_job(
            job_id=job_id,
            total_files=len(files),
            settings=job.settings,
            user_ip=user_ip,
        )

        # Add file records to database
        for item in items:
            await batch_history_service.add_file_record(
                job_id=job_id,
                file_index=item.file_index,
                filename=item.filename,
                status=item.status.value,
            )

        # Store the READ file data (not file handles) for later processing
        # This fixes the "read of closed file" error
        self.batch_manager._pending_file_data[job_id] = file_data_list

        # Create progress callback for WebSocket updates and persistence
        async def progress_callback(progress: BatchProgress):
            # Broadcast to WebSocket
            await connection_manager.broadcast_progress(progress)

            # Update database
            await batch_history_service.update_file_status(
                job_id=progress.job_id,
                file_index=progress.file_index,
                status=progress.status.value,
                error_message=(
                    progress.message
                    if progress.status == BatchItemStatus.FAILED
                    else None
                ),
            )

            # Update job status if needed
            job = self.batch_manager.get_job(progress.job_id)
            if job:
                await batch_history_service.update_job_status(
                    job_id=progress.job_id,
                    status=job.status.value,
                    completed_files=job.completed_files,
                    failed_files=job.failed_files,
                )

        # Store callback for later use
        self.batch_manager._progress_callbacks[job_id] = progress_callback

        # Don't start processing yet - wait for client to be ready
        # Processing will start when start_processing() is called

        return job

    def get_job(self, job_id: str) -> Optional[BatchJob]:
        """Get batch job by ID."""
        return self.batch_manager.get_job(job_id)

    async def get_progress(self, job_id: str) -> Optional[BatchProgress]:
        """Get batch job progress."""
        return await self.batch_manager.get_progress(job_id)

    async def cancel_job(self, job_id: str):
        """Cancel an entire batch job."""
        await self.batch_manager.cancel_job(job_id)

    async def cancel_job_item(self, job_id: str, file_index: int):
        """Cancel a specific file in a batch job."""
        await self.batch_manager.cancel_item(job_id, file_index)

    async def get_results(self, job_id: str) -> Optional[BatchResult]:
        """Get batch job results."""
        # Check if we have compiled results
        if job_id in self._results_storage:
            return self._results_storage[job_id]

        # Otherwise, compile results from BatchManager
        job = self.get_job(job_id)
        if not job:
            return None

        # Get results from BatchManager
        results = self.batch_manager.get_job_results(job_id)

        # Separate successful and failed
        successful_files = []
        failed_files = []

        for file_index, item in enumerate(job.items):
            if item.status == BatchItemStatus.COMPLETED and file_index in results:
                # Include the index in the successful file info
                file_result = results[file_index].copy()
                file_result["index"] = file_index
                successful_files.append(file_result)
            elif item.status == BatchItemStatus.FAILED:
                failed_files.append(
                    {
                        "index": file_index,
                        "filename": item.filename,
                        "error": item.error_message or "Unknown error",
                    }
                )

        # Compile and cache results
        batch_result = self.result_collector.compile_results(
            job, successful_files, failed_files
        )
        self._results_storage[job_id] = batch_result

        return batch_result

    async def cleanup_old_results(self, max_age_hours: int = 24):
        """Clean up old batch results from memory."""
        # This would be called periodically to free memory
        # For now, we'll keep it simple - in production, you'd check timestamps
        pass

    async def get_download_zip(self, job_id: str) -> Optional[bytes]:
        """Get ZIP file with batch results.

        Args:
            job_id: Batch job ID

        Returns:
            ZIP file content as bytes, or None if not found
        """
        result = self._results_storage.get(job_id)
        if not result:
            # Try to compile results if not cached
            result = await self.get_results(job_id)
            if not result:
                return None

        # Get job to get output format
        job = self.batch_manager.get_job(job_id)
        output_format = job.settings.get("output_format", "webp") if job else "webp"

        # Generate ZIP file
        try:
            zip_content = self.result_collector.create_zip_archive(
                result, include_report=True, output_format=output_format
            )
            return zip_content
        except Exception as e:
            logger.error(f"Failed to create ZIP for job {job_id}: {str(e)}")
            return None


# Create singleton instance
batch_service = BatchService()
