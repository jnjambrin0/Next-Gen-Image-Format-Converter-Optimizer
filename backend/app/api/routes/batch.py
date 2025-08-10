"""Batch processing API endpoints."""

import asyncio
import json
import os
import uuid
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from sse_starlette.sse import EventSourceResponse

from app.api.utils.error_handling import EndpointErrorHandler
from app.config import settings
from app.core.batch.models import (
    BatchCreateRequest,
    BatchCreateResponse,
    BatchItem,
    BatchItemStatus,
    BatchJob,
    BatchJobStatus,
    BatchResult,
    BatchStatus,
    BatchStatusResponse,
)
from app.core.exceptions import ValidationError
from app.models import ErrorResponse
from app.services.batch_service import batch_service
from app.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/batch", tags=["batch"])


# Error handlers for batch endpoints
batch_create_error_handler = EndpointErrorHandler("batch", "create_batch_job")
batch_status_error_handler = EndpointErrorHandler("batch", "get_batch_status")
batch_cancel_error_handler = EndpointErrorHandler("batch", "cancel_batch_job")
batch_download_error_handler = EndpointErrorHandler("batch", "download_batch_results")
batch_results_error_handler = EndpointErrorHandler("batch", "get_batch_results")
batch_metrics_error_handler = EndpointErrorHandler("batch", "get_batch_metrics")
batch_token_error_handler = EndpointErrorHandler("batch", "create_websocket_token")


def validate_batch_request(
    files: List[UploadFile],
    output_format: str,
    request: Request,
) -> None:
    """Validate batch request parameters.

    Args:
        files: List of uploaded files
        output_format: Target conversion format
        request: FastAPI request object

    Raises:
        HTTPException: If validation fails
    """
    # Check number of files
    if not files:
        raise batch_create_error_handler.validation_error(
            "No files provided for batch processing", request
        )

    if len(files) > settings.MAX_BATCH_SIZE:
        raise batch_create_error_handler.validation_error(
            f"Maximum {settings.MAX_BATCH_SIZE} files allowed per batch",
            request,
            details={"file_count": len(files), "max_allowed": settings.MAX_BATCH_SIZE},
        )

    # Validate output format
    valid_output_formats = [
        "webp",
        "avif",
        "jpeg",
        "png",
        "jxl",
        "heif",
        "jpeg_optimized",
        "png_optimized",
        "webp2",
        "jpeg2000",
    ]
    if output_format not in valid_output_formats:
        raise batch_create_error_handler.validation_error(
            "Invalid output format specified",
            request,
            details={
                "requested_format": output_format,
                "valid_formats": valid_output_formats,
            },
        )

    # Check total size
    total_size = sum(file.size or 0 for file in files)
    max_total_size = settings.MAX_BATCH_SIZE * settings.max_file_size

    if total_size > max_total_size:
        raise batch_create_error_handler.payload_too_large_error(
            f"Total batch size exceeds maximum allowed limit",
            request,
            details={
                "total_size": total_size,
                "max_allowed": max_total_size,
                "size_mb": round(total_size / 1024 / 1024, 2),
            },
        )

    # Validate individual files
    for i, file in enumerate(files):
        if not file.filename:
            raise batch_create_error_handler.validation_error(
                f"File at index {i} missing filename",
                request,
                details={"file_index": i},
            )

        # Check file size
        if file.size and file.size > settings.max_file_size:
            raise batch_create_error_handler.payload_too_large_error(
                f"Individual file exceeds size limit",
                request,
                details={
                    "file_index": i,
                    "file_size": file.size,
                    "max_allowed": settings.max_file_size,
                },
            )

        # Check file extension (basic validation)
        valid_extensions = [
            ".jpg",
            ".jpeg",
            ".png",
            ".webp",
            ".heif",
            ".heic",
            ".bmp",
            ".tiff",
            ".gif",
            ".avif",
        ]
        ext = os.path.splitext(file.filename.lower())[1]
        if ext not in valid_extensions:
            raise batch_create_error_handler.validation_error(
                f"Unsupported file type at index {i}",
                request,
                details={
                    "file_index": i,
                    "extension": ext,
                    "supported_extensions": valid_extensions,
                },
            )


@router.post(
    "/", response_model=BatchCreateResponse, status_code=status.HTTP_202_ACCEPTED
)
async def create_batch_job(
    request: Request,
    files: List[UploadFile] = File(...),
    output_format: str = Form(...),
    quality: int = Form(None),
    optimization_mode: str = Form(None),
    preset_id: str = Form(None),
    preserve_metadata: bool = Form(False),
) -> BatchCreateResponse:
    """Create a new batch conversion job.

    Args:
        request: FastAPI request object
        files: List of image files to convert
        output_format: Target format for all conversions
        quality: Optional quality setting (1-100)
        optimization_mode: Optional optimization mode
        preset_id: Optional preset to apply
        preserve_metadata: Whether to preserve metadata

    Returns:
        BatchCreateResponse with job details
    """
    try:
        # Validate request
        validate_batch_request(files, output_format, request)

        # Build conversion settings
        conversion_settings = {
            "output_format": output_format,
            "remove_metadata": not preserve_metadata,  # Convert to remove_metadata
        }
        if quality is not None:
            conversion_settings["quality"] = quality
        if optimization_mode:
            conversion_settings["optimization_mode"] = optimization_mode
        if preset_id:
            conversion_settings["preset_id"] = preset_id

        # Create batch job using batch service
        batch_job = await batch_service.create_batch_job(
            files=files,
            output_format=output_format,
            settings=conversion_settings,
            user_ip=request.client.host if request.client else None,
        )

        logger.info(
            "Batch job created",
            extra={
                "job_id": batch_job.job_id,
                "total_files": batch_job.total_files,
                "output_format": output_format,
            },
        )

        # Build response
        base_url = str(request.base_url).rstrip("/")

        # Generate WebSocket token if authentication is enabled
        websocket_url = f"ws://{request.headers.get('host', 'localhost')}/ws/batch/{batch_job.job_id}"
        if settings.batch_websocket_auth_enabled:
            # Import here to avoid circular imports
            from app.api.websockets.secure_progress import secure_connection_manager

            token = secure_connection_manager.generate_job_token(batch_job.job_id)
            websocket_url = f"{websocket_url}?token={token}"

        return BatchCreateResponse(
            job_id=batch_job.job_id,
            total_files=batch_job.total_files,
            status=batch_job.status,
            status_url=f"{base_url}/api/batch/{batch_job.job_id}/status",
            websocket_url=websocket_url,
            created_at=batch_job.created_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create batch job: {e}")
        raise batch_create_error_handler.internal_server_error(
            "Failed to create batch job", request
        )


@router.get("/{job_id}/status", response_model=BatchStatusResponse)
async def get_batch_status(
    job_id: str,
    request: Request,
    status_filter: Optional[str] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = 0,
) -> BatchStatusResponse:
    """Get status of a batch job with optional filtering and pagination.

    Args:
        job_id: Batch job ID
        request: FastAPI request object
        status_filter: Filter items by status (pending, processing, completed, failed, cancelled)
        limit: Maximum number of items to return
        offset: Number of items to skip

    Returns:
        BatchStatusResponse with current job status and filtered items
    """
    try:
        # Get job from batch service
        batch_job = batch_service.get_job(job_id)
        if not batch_job:
            raise batch_status_error_handler.not_found_error(
                "Batch job not found", request, details={"job_id": job_id}
            )

        # Filter items if status_filter is provided
        filtered_items = batch_job.items
        if status_filter:
            try:
                # Validate status filter
                valid_statuses = [
                    "pending",
                    "processing",
                    "completed",
                    "failed",
                    "cancelled",
                ]
                if status_filter not in valid_statuses:
                    raise batch_status_error_handler.validation_error(
                        "Invalid status filter",
                        request,
                        details={
                            "provided_status": status_filter,
                            "valid_statuses": valid_statuses,
                        },
                    )

                # Filter items by status
                filtered_items = [
                    item
                    for item in batch_job.items
                    if item.status.value.lower() == status_filter.lower()
                ]
            except Exception as e:
                logger.warning(f"Error filtering by status: {e}")
                # Continue with unfiltered items if filtering fails

        # Apply pagination
        total_items = len(filtered_items)
        paginated_items = filtered_items

        if limit is not None or offset > 0:
            start_idx = max(0, offset)
            end_idx = start_idx + limit if limit is not None else len(filtered_items)
            paginated_items = filtered_items[start_idx:end_idx]

        # Build download URL if completed
        download_url = None
        if batch_job.status == BatchStatus.COMPLETED:
            base_url = str(request.base_url).rstrip("/")
            download_url = f"{base_url}/api/batch/{job_id}/download"

        # Create response with pagination metadata
        response = BatchStatusResponse(
            job_id=batch_job.job_id,
            status=batch_job.status,
            total_files=batch_job.total_files,
            completed_files=batch_job.completed_files,
            failed_files=batch_job.failed_files,
            processing_files=batch_job.processing_files,
            pending_files=batch_job.pending_files,
            progress_percentage=batch_job.progress_percentage,
            items=paginated_items,
            created_at=batch_job.created_at,
            completed_at=batch_job.completed_at,
            download_url=download_url,
        )

        # Add pagination info if filtering/pagination was applied
        if status_filter or limit is not None or offset > 0:
            # Add custom headers for pagination metadata
            response_headers = {
                "X-Total-Items": str(total_items),
                "X-Returned-Items": str(len(paginated_items)),
                "X-Offset": str(offset),
            }
            if limit is not None:
                response_headers["X-Limit"] = str(limit)
            if status_filter:
                response_headers["X-Status-Filter"] = status_filter

            # Store headers in request state for middleware to add
            request.state.response_headers = response_headers

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error getting batch status: {e}")
        raise batch_status_error_handler.internal_server_error(
            "Failed to retrieve batch status", request
        )


@router.delete("/{job_id}")
async def cancel_batch_job(job_id: str, request: Request) -> Dict[str, Any]:
    """Cancel a batch job with enhanced cleanup.

    Args:
        job_id: Batch job ID to cancel
        request: FastAPI request object

    Returns:
        Cancellation confirmation
    """
    try:
        # Get job from batch service
        batch_job = batch_service.get_job(job_id)
        if not batch_job:
            raise batch_cancel_error_handler.not_found_error(
                "Batch job not found", request, details={"job_id": job_id}
            )

        # Check if job can be cancelled
        if batch_job.status in [BatchStatus.COMPLETED, BatchStatus.FAILED]:
            raise batch_cancel_error_handler.validation_error(
                f"Cannot cancel job in {batch_job.status.value} status",
                request,
                details={
                    "current_status": batch_job.status.value,
                    "cancellable_statuses": ["pending", "processing"],
                },
            )

        # Cancel job through batch service with enhanced cleanup
        await batch_service.cancel_job(job_id)

        # Get updated job status
        updated_job = batch_service.get_job(job_id)
        cancelled_items = 0
        if updated_job:
            cancelled_items = sum(
                1
                for item in updated_job.items
                if item.status == BatchItemStatus.CANCELLED
            )

        logger.info(
            "Batch job cancelled",
            job_id=job_id,
            cancelled_items=cancelled_items,
            correlation_id=request.state.correlation_id,
        )

        return {
            "job_id": job_id,
            "status": "cancelled",
            "message": "Batch job cancelled successfully",
            "cancelled_items": cancelled_items,
            "cleanup_completed": True,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error cancelling batch job: {e}")
        raise batch_cancel_error_handler.internal_server_error(
            "Failed to cancel batch job", request
        )


@router.delete("/{job_id}/items/{file_index}")
async def cancel_batch_item(
    job_id: str, file_index: int, request: Request
) -> Dict[str, Any]:
    """Cancel a specific item in a batch job.

    Args:
        job_id: Batch job ID
        file_index: Index of file to cancel
        request: FastAPI request object

    Returns:
        Cancellation confirmation
    """
    try:
        # Get job from batch service
        batch_job = batch_service.get_job(job_id)
        if not batch_job:
            raise batch_cancel_error_handler.not_found_error(
                "Batch job not found", request, details={"job_id": job_id}
            )

        # Validate file index
        if file_index < 0 or file_index >= len(batch_job.items):
            raise batch_cancel_error_handler.validation_error(
                "Invalid file index",
                request,
                details={
                    "file_index": file_index,
                    "valid_range": f"0-{len(batch_job.items)-1}",
                    "total_items": len(batch_job.items),
                },
            )

        # Get item
        item = batch_job.items[file_index]

        # Check if item can be cancelled
        if item.status not in [BatchItemStatus.PENDING, BatchItemStatus.PROCESSING]:
            raise batch_cancel_error_handler.validation_error(
                f"Cannot cancel item in {item.status.value} status",
                request,
                details={
                    "current_status": item.status.value,
                    "cancellable_statuses": ["pending", "processing"],
                },
            )

        # Cancel item through batch service
        await batch_service.cancel_job_item(job_id, file_index)

        logger.info(
            "Batch item cancelled",
            job_id=job_id,
            file_index=file_index,
            correlation_id=request.state.correlation_id,
        )

        return {
            "job_id": job_id,
            "file_index": file_index,
            "status": "cancelled",
            "message": "Batch item cancelled successfully",
            "filename": item.filename,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error cancelling batch item: {e}")
        raise batch_cancel_error_handler.internal_server_error(
            "Failed to cancel batch item", request
        )


@router.get("/{job_id}/download")
async def download_batch_results(
    job_id: str,
    request: Request,
    format: Optional[str] = "zip",
) -> StreamingResponse:
    """Download batch processing results with enhanced content-type handling.

    Args:
        job_id: Batch job ID
        request: FastAPI request object
        format: Download format (zip, json) - defaults to zip

    Returns:
        StreamingResponse with requested format
    """
    try:
        # Get job from batch service
        batch_job = batch_service.get_job(job_id)
        if not batch_job:
            raise batch_download_error_handler.not_found_error(
                "Batch job not found", request, details={"job_id": job_id}
            )

        # Check if job is completed
        if batch_job.status != BatchStatus.COMPLETED:
            raise batch_download_error_handler.validation_error(
                f"Cannot download results for job in {batch_job.status.value} status",
                request,
                details={
                    "current_status": batch_job.status.value,
                    "required_status": "completed",
                },
            )

        if format == "json":
            # Return JSON summary instead of ZIP
            summary = {
                "job_id": job_id,
                "status": batch_job.status.value,
                "total_files": batch_job.total_files,
                "completed_files": batch_job.completed_files,
                "failed_files": batch_job.failed_files,
                "processing_time": (
                    (batch_job.completed_at - batch_job.created_at).total_seconds()
                    if batch_job.completed_at
                    else None
                ),
                "files": [
                    {
                        "filename": item.filename,
                        "status": item.status.value,
                        "error": (
                            item.error
                            if item.status == BatchItemStatus.FAILED
                            else None
                        ),
                    }
                    for item in batch_job.items
                ],
            }

            import io
            import json

            json_content = json.dumps(summary, indent=2, default=str)

            return StreamingResponse(
                io.BytesIO(json_content.encode("utf-8")),
                media_type="application/json",
                headers={
                    "Content-Disposition": f"attachment; filename=batch_{job_id[:8]}_summary.json",
                    "X-Content-Format": "json",
                    "X-Total-Files": str(batch_job.total_files),
                    "X-Successful-Files": str(batch_job.completed_files),
                },
            )

        # Default ZIP download
        zip_content = await batch_service.get_download_zip(job_id)
        if not zip_content:
            raise batch_download_error_handler.not_found_error(
                "Results not found for this job",
                request,
                details={"job_id": job_id, "format": format},
            )

        # Enhanced headers with batch metadata
        headers = {
            "Content-Disposition": f"attachment; filename=batch_{job_id[:8]}_results.zip",
            "X-Content-Format": "zip",
            "X-Job-ID": job_id,
            "X-Total-Files": str(batch_job.total_files),
            "X-Successful-Files": str(batch_job.completed_files),
            "X-Failed-Files": str(batch_job.failed_files),
            "X-Content-Length": str(len(zip_content)),
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
        }

        # Return as streaming response
        import io

        return StreamingResponse(
            io.BytesIO(zip_content), media_type="application/zip", headers=headers
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error downloading batch results: {e}")
        raise batch_download_error_handler.internal_server_error(
            "Failed to download batch results", request
        )


@router.get("/{job_id}/results")
async def get_batch_results(job_id: str, request: Request) -> BatchResult:
    """Get batch job results with enhanced error handling.

    Args:
        job_id: Batch job ID
        request: FastAPI request object

    Returns:
        BatchResult with processing summary
    """
    try:
        # Import here to avoid circular dependency
        from app.core.batch.models import BatchResult
        from app.services.batch_history_service import batch_history_service

        # Try to get from history service first
        result = await batch_history_service.get_job_results(job_id)
        if result:
            return result

        # Fallback to in-memory batch service
        batch_job = batch_service.get_job(job_id)
        if not batch_job:
            raise batch_results_error_handler.not_found_error(
                "Batch job not found", request, details={"job_id": job_id}
            )

        # Check if job is completed
        if batch_job.status not in [
            BatchStatus.COMPLETED,
            BatchStatus.FAILED,
            BatchStatus.CANCELLED,
        ]:
            raise batch_results_error_handler.validation_error(
                f"Results not available for job in {batch_job.status.value} status",
                request,
                details={
                    "current_status": batch_job.status.value,
                    "required_statuses": ["completed", "failed", "cancelled"],
                },
            )

        # Build result
        successful_files = []
        failed_files = []

        for idx, item in enumerate(batch_job.items):
            if item.status == BatchItemStatus.COMPLETED:
                successful_files.append(
                    {
                        "filename": item.filename,
                        "index": idx,
                        "output_size": 0,  # Not tracked in memory
                    }
                )
            elif item.status == BatchItemStatus.FAILED:
                failed_files.append(
                    {
                        "filename": item.filename,
                        "index": idx,
                        "error": item.error or "Unknown error",
                    }
                )

        # Calculate processing time
        processing_time = 0.0
        if batch_job.created_at and batch_job.completed_at:
            processing_time = (
                batch_job.completed_at - batch_job.created_at
            ).total_seconds()

        return BatchResult(
            job_id=job_id,
            total_files=batch_job.total_files,
            successful_files=successful_files,
            failed_files=failed_files,
            processing_time_seconds=processing_time,
            report_format="json",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error getting batch results: {e}")
        raise batch_results_error_handler.internal_server_error(
            "Failed to retrieve batch results", request
        )


@router.get("/{job_id}/metrics")
async def get_batch_metrics(job_id: str, request: Request) -> Dict[str, Any]:
    """Get performance metrics for a batch job.

    Args:
        job_id: Batch job ID
        request: FastAPI request object

    Returns:
        Performance metrics including memory usage and throughput
    """
    try:
        # Get metrics from batch manager
        metrics = batch_service.batch_manager.get_job_metrics(job_id)

        if not metrics:
            raise batch_metrics_error_handler.not_found_error(
                "Metrics not found for this job", request, details={"job_id": job_id}
            )

        # Enhance metrics with additional metadata
        enhanced_metrics = {
            **metrics,
            "job_id": job_id,
            "retrieved_at": datetime.utcnow().isoformat(),
            "metrics_version": "1.0",
        }

        return enhanced_metrics

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error getting batch metrics: {e}")
        raise batch_metrics_error_handler.internal_server_error(
            "Failed to retrieve batch metrics", request
        )


@router.post("/{job_id}/websocket-token")
async def create_websocket_token(job_id: str, request: Request) -> Dict[str, str]:
    """Create a new authentication token for WebSocket access.

    This endpoint allows clients to get a fresh token for WebSocket connections,
    useful when the original token has expired or was not saved.

    Args:
        job_id: Batch job ID
        request: FastAPI request object

    Returns:
        New authentication token with WebSocket URL
    """
    try:
        # Verify job exists
        batch_job = batch_service.get_job(job_id)
        if not batch_job:
            raise batch_token_error_handler.not_found_error(
                "Batch job not found", request, details={"job_id": job_id}
            )

        # Only allow token generation if auth is enabled
        if not settings.batch_websocket_auth_enabled:
            raise batch_token_error_handler.validation_error(
                "WebSocket authentication is not enabled",
                request,
                details={"auth_enabled": False},
            )

        # Import here to avoid circular imports
        from app.api.websockets.secure_progress import secure_connection_manager

        # Generate new token
        token = secure_connection_manager.generate_job_token(job_id)

        logger.info(
            "WebSocket token generated",
            job_id=job_id,
            correlation_id=request.state.correlation_id,
        )

        return {
            "job_id": job_id,
            "token": token,
            "expires_in": 86400,  # 24 hours
            "websocket_url": f"/ws/batch/{job_id}?token={token}",
            "sse_url": f"/api/batch/{job_id}/events",  # Alternative SSE endpoint
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error creating WebSocket token: {e}")
        raise batch_token_error_handler.internal_server_error(
            "Failed to create WebSocket token", request
        )


@router.get("/{job_id}/events")
async def batch_events_stream(
    job_id: str,
    request: Request,
) -> EventSourceResponse:
    """Server-Sent Events stream for real-time batch progress updates.

    This endpoint provides an HTTP/1.1 alternative to WebSocket connections
    for receiving real-time progress updates during batch processing.

    Args:
        job_id: Batch job ID
        request: FastAPI request object

    Returns:
        EventSourceResponse with real-time progress events
    """
    try:
        # Verify job exists
        batch_job = batch_service.get_job(job_id)
        if not batch_job:
            raise batch_status_error_handler.not_found_error(
                "Batch job not found", request, details={"job_id": job_id}
            )

        async def event_generator() -> AsyncGenerator[str, None]:
            """Generate Server-Sent Events for batch progress."""
            try:
                last_progress_percentage = -1
                last_status = None
                check_interval = 1.0  # Check every second

                # Send initial status
                current_job = batch_service.get_job(job_id)
                if current_job:
                    initial_data = {
                        "job_id": job_id,
                        "status": current_job.status.value,
                        "progress_percentage": current_job.progress_percentage,
                        "completed_files": current_job.completed_files,
                        "failed_files": current_job.failed_files,
                        "total_files": current_job.total_files,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    yield f"data: {json.dumps(initial_data)}\n\n"
                    last_progress_percentage = current_job.progress_percentage
                    last_status = current_job.status

                # Monitor job progress
                while True:
                    try:
                        # Check if client disconnected
                        if await request.is_disconnected():
                            logger.info(
                                f"Client disconnected from SSE stream: {job_id}"
                            )
                            break

                        # Get current job status
                        current_job = batch_service.get_job(job_id)
                        if not current_job:
                            # Job no longer exists, send final event and close
                            final_data = {
                                "job_id": job_id,
                                "status": "not_found",
                                "message": "Job no longer exists",
                                "timestamp": datetime.utcnow().isoformat(),
                            }
                            yield f"data: {json.dumps(final_data)}\n\n"
                            break

                        # Check if progress or status changed
                        if (
                            current_job.progress_percentage != last_progress_percentage
                            or current_job.status != last_status
                        ):

                            progress_data = {
                                "job_id": job_id,
                                "status": current_job.status.value,
                                "progress_percentage": current_job.progress_percentage,
                                "completed_files": current_job.completed_files,
                                "failed_files": current_job.failed_files,
                                "processing_files": current_job.processing_files,
                                "pending_files": current_job.pending_files,
                                "total_files": current_job.total_files,
                                "timestamp": datetime.utcnow().isoformat(),
                            }

                            # Add download URL if completed
                            if current_job.status == BatchStatus.COMPLETED:
                                base_url = str(request.base_url).rstrip("/")
                                progress_data["download_url"] = (
                                    f"{base_url}/api/batch/{job_id}/download"
                                )

                            yield f"data: {json.dumps(progress_data)}\n\n"

                            last_progress_percentage = current_job.progress_percentage
                            last_status = current_job.status

                        # Check if job is in terminal state
                        if current_job.status in [
                            BatchStatus.COMPLETED,
                            BatchStatus.FAILED,
                            BatchStatus.CANCELLED,
                        ]:
                            logger.info(
                                f"Job reached terminal state: {current_job.status.value}"
                            )
                            break

                        # Wait before next check
                        await asyncio.sleep(check_interval)

                    except asyncio.CancelledError:
                        logger.info(f"SSE stream cancelled for job: {job_id}")
                        break
                    except Exception as e:
                        logger.warning(f"Error in SSE event generation: {e}")
                        error_data = {
                            "job_id": job_id,
                            "error": "Stream error occurred",
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                        yield f"data: {json.dumps(error_data)}\n\n"
                        break

                # Send final close event
                close_data = {
                    "job_id": job_id,
                    "event": "close",
                    "message": "Event stream closed",
                    "timestamp": datetime.utcnow().isoformat(),
                }
                yield f"data: {json.dumps(close_data)}\n\n"

            except Exception as e:
                logger.exception(f"Fatal error in SSE event generator: {e}")
                error_data = {
                    "job_id": job_id,
                    "error": "Fatal stream error",
                    "timestamp": datetime.utcnow().isoformat(),
                }
                yield f"data: {json.dumps(error_data)}\n\n"

        # Return EventSourceResponse
        return EventSourceResponse(
            event_generator(),
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Job-ID": job_id,
                "X-Stream-Type": "batch-progress",
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error setting up SSE stream: {e}")
        raise batch_status_error_handler.internal_server_error(
            "Failed to establish event stream", request
        )
