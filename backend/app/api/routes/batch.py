"""Batch processing API endpoints."""

import os
import uuid
from datetime import datetime
from typing import List, Dict, Any
from fastapi import APIRouter, File, UploadFile, Form, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse, StreamingResponse

from app.core.batch.models import (
    BatchCreateRequest,
    BatchCreateResponse,
    BatchStatusResponse,
    BatchStatus,
    BatchJob,
    BatchItem,
    BatchItemStatus,
    BatchJobStatus,
    BatchResult,
)
from app.core.exceptions import ValidationError
from app.models import ErrorResponse
from app.config import settings
from app.utils.logging import get_logger
from app.services.batch_service import batch_service

logger = get_logger(__name__)

router = APIRouter(prefix="/batch", tags=["batch"])


def validate_batch_request(
    files: List[UploadFile],
    output_format: str,
) -> None:
    """Validate batch request parameters.
    
    Args:
        files: List of uploaded files
        output_format: Target conversion format
        
    Raises:
        HTTPException: If validation fails
    """
    # Check number of files
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No files provided"
        )
    
    if len(files) > settings.MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Maximum {settings.MAX_BATCH_SIZE} files allowed per batch"
        )
    
    # Validate output format
    valid_output_formats = ["webp", "avif", "jpeg", "png", "jxl", "heif", "jpeg_optimized", "png_optimized", "webp2", "jpeg2000"]
    if output_format not in valid_output_formats:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid output format: {output_format}"
        )
    
    # Check total size
    total_size = sum(file.size or 0 for file in files)
    max_total_size = settings.MAX_BATCH_SIZE * settings.max_file_size
    
    if total_size > max_total_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Total batch size exceeds maximum allowed ({max_total_size} bytes)"
        )
    
    # Validate individual files
    for i, file in enumerate(files):
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File at index {i} has no filename"
            )
        
        # Check file size
        if file.size and file.size > settings.max_file_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large: index {i}"
            )
        
        # Check file extension (basic validation)
        valid_extensions = [".jpg", ".jpeg", ".png", ".webp", ".heif", ".heic", ".bmp", ".tiff", ".gif", ".avif"]
        ext = os.path.splitext(file.filename.lower())[1]
        if ext not in valid_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type at index {i}: {ext}"
            )


@router.post("/", response_model=BatchCreateResponse, status_code=status.HTTP_202_ACCEPTED)
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
        validate_batch_request(files, output_format)
        
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
            user_ip=request.client.host if request.client else None
        )
        
        logger.info(
            "Batch job created",
            extra={
                "job_id": batch_job.job_id,
                "total_files": batch_job.total_files,
                "output_format": output_format,
            }
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create batch job"
        )


@router.get("/{job_id}/status", response_model=BatchStatusResponse)
async def get_batch_status(
    job_id: str,
    request: Request,
) -> BatchStatusResponse:
    """Get status of a batch job.
    
    Args:
        job_id: Batch job ID
        request: FastAPI request object
        
    Returns:
        BatchStatusResponse with current job status
    """
    # Get job from batch service
    batch_job = batch_service.get_job(job_id)
    if not batch_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Batch job not found"
        )
    
    # Build download URL if completed
    download_url = None
    if batch_job.status == BatchStatus.COMPLETED:
        base_url = str(request.base_url).rstrip("/")
        download_url = f"{base_url}/api/batch/{job_id}/download"
    
    return BatchStatusResponse(
        job_id=batch_job.job_id,
        status=batch_job.status,
        total_files=batch_job.total_files,
        completed_files=batch_job.completed_files,
        failed_files=batch_job.failed_files,
        processing_files=batch_job.processing_files,
        pending_files=batch_job.pending_files,
        progress_percentage=batch_job.progress_percentage,
        items=batch_job.items,
        created_at=batch_job.created_at,
        completed_at=batch_job.completed_at,
        download_url=download_url,
    )


@router.delete("/{job_id}")
async def cancel_batch_job(job_id: str) -> Dict[str, Any]:
    """Cancel a batch job.
    
    Args:
        job_id: Batch job ID to cancel
        
    Returns:
        Cancellation confirmation
    """
    # Get job from batch service
    batch_job = batch_service.get_job(job_id)
    if not batch_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Batch job not found"
        )
    
    # Check if job can be cancelled
    if batch_job.status in [BatchStatus.COMPLETED, BatchStatus.FAILED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel job in {batch_job.status} status"
        )
    
    # Cancel job through batch service
    await batch_service.cancel_job(job_id)
    
    logger.info(f"Batch job cancelled: {job_id}")
    
    return {
        "job_id": job_id,
        "status": "cancelled",
        "message": "Batch job cancelled successfully"
    }


@router.delete("/{job_id}/items/{file_index}")
async def cancel_batch_item(job_id: str, file_index: int) -> Dict[str, Any]:
    """Cancel a specific item in a batch job.
    
    Args:
        job_id: Batch job ID
        file_index: Index of file to cancel
        
    Returns:
        Cancellation confirmation
    """
    # Get job from batch service
    batch_job = batch_service.get_job(job_id)
    if not batch_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Batch job not found"
        )
    
    # Validate file index
    if file_index < 0 or file_index >= len(batch_job.items):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file index"
        )
    
    # Get item
    item = batch_job.items[file_index]
    
    # Check if item can be cancelled
    if item.status not in [BatchItemStatus.PENDING, BatchItemStatus.PROCESSING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel item in {item.status} status"
        )
    
    # Cancel item through batch service
    await batch_service.cancel_job_item(job_id, file_index)
    
    logger.info(f"Batch item cancelled: job={job_id}, index={file_index}")
    
    return {
        "job_id": job_id,
        "file_index": file_index,
        "status": "cancelled",
        "message": "Batch item cancelled successfully"
    }


@router.get("/{job_id}/download")
async def download_batch_results(
    job_id: str,
    request: Request,
) -> StreamingResponse:
    """Download batch processing results as ZIP file.
    
    Args:
        job_id: Batch job ID
        request: FastAPI request object
        
    Returns:
        StreamingResponse with ZIP file
    """
    # Get job from batch service
    batch_job = batch_service.get_job(job_id)
    if not batch_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Batch job not found"
        )
    
    # Check if job is completed
    if batch_job.status != BatchStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot download results for job in {batch_job.status} status"
        )
    
    # Get ZIP content
    zip_content = await batch_service.get_download_zip(job_id)
    if not zip_content:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Results not found for this job"
        )
    
    # Return as streaming response
    import io
    return StreamingResponse(
        io.BytesIO(zip_content),
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=batch_{job_id[:8]}_results.zip"
        }
    )


@router.get("/{job_id}/results")
async def get_batch_results(job_id: str) -> BatchResult:
    """Get batch job results.
    
    Args:
        job_id: Batch job ID
        
    Returns:
        BatchResult with processing summary
    """
    # Import here to avoid circular dependency
    from app.services.batch_history_service import batch_history_service
    from app.core.batch.models import BatchResult
    
    # Try to get from history service first
    result = await batch_history_service.get_job_results(job_id)
    if result:
        return result
    
    # Fallback to in-memory batch service
    batch_job = batch_service.get_job(job_id)
    if not batch_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Batch job not found"
        )
    
    # Check if job is completed
    if batch_job.status not in [BatchStatus.COMPLETED, BatchStatus.FAILED, BatchStatus.CANCELLED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Results not available for job in {batch_job.status} status"
        )
    
    # Build result
    successful_files = []
    failed_files = []
    
    for idx, item in enumerate(batch_job.items):
        if item.status == BatchItemStatus.COMPLETED:
            successful_files.append({
                "filename": item.filename,
                "index": idx,
                "output_size": 0  # Not tracked in memory
            })
        elif item.status == BatchItemStatus.FAILED:
            failed_files.append({
                "filename": item.filename,
                "index": idx,
                "error": item.error or "Unknown error"
            })
    
    # Calculate processing time
    processing_time = 0.0
    if batch_job.created_at and batch_job.completed_at:
        processing_time = (batch_job.completed_at - batch_job.created_at).total_seconds()
    
    return BatchResult(
        job_id=job_id,
        total_files=batch_job.total_files,
        successful_files=successful_files,
        failed_files=failed_files,
        processing_time_seconds=processing_time,
        report_format="json"
    )


@router.get("/{job_id}/metrics")
async def get_batch_metrics(job_id: str) -> Dict[str, Any]:
    """Get performance metrics for a batch job.
    
    Args:
        job_id: Batch job ID
        
    Returns:
        Performance metrics including memory usage and throughput
    """
    # Get metrics from batch manager
    metrics = batch_service.batch_manager.get_job_metrics(job_id)
    
    if not metrics:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Metrics not found for this job"
        )
    
    return metrics


@router.post("/{job_id}/websocket-token")
async def create_websocket_token(job_id: str) -> Dict[str, str]:
    """Create a new authentication token for WebSocket access.
    
    This endpoint allows clients to get a fresh token for WebSocket connections,
    useful when the original token has expired or was not saved.
    
    Args:
        job_id: Batch job ID
        
    Returns:
        New authentication token with WebSocket URL
    """
    # Verify job exists
    batch_job = batch_service.get_job(job_id)
    if not batch_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Batch job not found"
        )
    
    # Only allow token generation if auth is enabled
    if not settings.batch_websocket_auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="WebSocket authentication is not enabled"
        )
    
    # Import here to avoid circular imports
    from app.api.websockets.secure_progress import secure_connection_manager
    
    # Generate new token
    token = secure_connection_manager.generate_job_token(job_id)
    
    return {
        "job_id": job_id,
        "token": token,
        "expires_in": 86400,  # 24 hours
        "websocket_url": f"/ws/batch/{job_id}?token={token}"
    }