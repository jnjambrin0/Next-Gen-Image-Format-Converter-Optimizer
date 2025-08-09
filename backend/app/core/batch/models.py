"""Data models for batch processing system."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class BatchStatus(str, Enum):
    """Status of a batch job."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class BatchItemStatus(str, Enum):
    """Status of an individual item in a batch."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BatchItem(BaseModel):
    """Model for an individual file in a batch job."""

    model_config = ConfigDict(from_attributes=True)

    file_index: int = Field(..., description="Index of file in batch (0-based)")
    filename: str = Field(..., description="Original filename for display")
    status: BatchItemStatus = Field(default=BatchItemStatus.PENDING)
    progress: int = Field(default=0, ge=0, le=100, description="Progress percentage")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    processing_time: Optional[float] = Field(
        None, description="Processing time in seconds"
    )
    output_size: Optional[int] = Field(
        None, description="Size of converted file in bytes"
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    @field_validator("filename")
    @classmethod
    def sanitize_filename(cls, v: str) -> str:
        """Sanitize filename for display (remove path components)."""
        # Extract just the filename, no path components
        import os

        return os.path.basename(v)


class BatchProgress(BaseModel):
    """WebSocket progress update message."""

    job_id: str = Field(..., description="Batch job ID")
    file_index: int = Field(..., description="Index of file being processed")
    filename: str = Field(..., description="Sanitized filename")
    status: BatchItemStatus = Field(..., description="Current status")
    progress: int = Field(..., ge=0, le=100, description="Progress percentage")
    message: Optional[str] = Field(None, description="Status message")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class BatchJob(BaseModel):
    """Model for a batch conversion job."""

    model_config = ConfigDict(from_attributes=True)

    job_id: str = Field(..., description="Unique job identifier")
    total_files: int = Field(..., gt=0, le=100, description="Total number of files")
    completed_files: int = Field(
        default=0, ge=0, description="Number of completed files"
    )
    failed_files: int = Field(default=0, ge=0, description="Number of failed files")
    status: BatchStatus = Field(default=BatchStatus.PENDING)
    settings: Dict[str, Any] = Field(
        default_factory=dict, description="Conversion settings"
    )
    items: List[BatchItem] = Field(
        default_factory=list, description="Individual file items"
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    user_ip: Optional[str] = Field(None, description="User IP for rate limiting")

    @field_validator("total_files")
    @classmethod
    def validate_total_files(cls, v: int) -> int:
        """Validate total files is within allowed range."""
        if v > 100:
            raise ValueError("Maximum 100 files allowed per batch")
        return v

    @property
    def processing_files(self) -> int:
        """Get number of files currently processing."""
        return sum(
            1 for item in self.items if item.status == BatchItemStatus.PROCESSING
        )

    @property
    def pending_files(self) -> int:
        """Get number of files pending processing."""
        return sum(1 for item in self.items if item.status == BatchItemStatus.PENDING)

    @property
    def progress_percentage(self) -> int:
        """Calculate overall progress percentage."""
        if self.total_files == 0:
            return 0
        return int((self.completed_files + self.failed_files) / self.total_files * 100)

    def update_status(self) -> None:
        """Update job status based on item statuses."""
        if self.status == BatchStatus.CANCELLED:
            return

        if all(
            item.status in [BatchItemStatus.COMPLETED, BatchItemStatus.FAILED]
            for item in self.items
        ):
            if self.failed_files == self.total_files:
                self.status = BatchStatus.FAILED
            else:
                self.status = BatchStatus.COMPLETED
            self.completed_at = datetime.utcnow()
        elif any(item.status == BatchItemStatus.PROCESSING for item in self.items):
            self.status = BatchStatus.PROCESSING


class BatchCreateRequest(BaseModel):
    """Request model for creating a batch job."""

    output_format: str = Field(..., description="Target format for all conversions")
    quality: Optional[int] = Field(None, ge=1, le=100, description="Quality setting")
    optimization_mode: Optional[str] = Field(None, description="Optimization mode")
    preset_id: Optional[str] = Field(None, description="Preset to apply to all files")
    preserve_metadata: bool = Field(False, description="Whether to preserve metadata")


class BatchCreateResponse(BaseModel):
    """Response model for batch job creation."""

    job_id: str = Field(..., description="Unique job identifier")
    total_files: int = Field(..., description="Number of files in batch")
    status: BatchStatus = Field(..., description="Initial job status")
    status_url: str = Field(..., description="URL to check job status")
    websocket_url: str = Field(..., description="WebSocket URL for progress updates")
    created_at: datetime = Field(..., description="Job creation timestamp")


class BatchStatusResponse(BaseModel):
    """Response model for batch job status query."""

    job_id: str = Field(..., description="Batch job ID")
    status: BatchStatus = Field(..., description="Current job status")
    total_files: int = Field(..., description="Total number of files")
    completed_files: int = Field(..., description="Number of completed files")
    failed_files: int = Field(..., description="Number of failed files")
    processing_files: int = Field(..., description="Number of files processing")
    pending_files: int = Field(..., description="Number of files pending")
    progress_percentage: int = Field(..., ge=0, le=100, description="Overall progress")
    items: List[BatchItem] = Field(..., description="Individual file statuses")
    created_at: datetime = Field(..., description="Job creation time")
    completed_at: Optional[datetime] = Field(None, description="Job completion time")
    download_url: Optional[str] = Field(
        None, description="URL to download results (if completed)"
    )


class BatchResultDownload(BaseModel):
    """Model for batch result download information."""

    job_id: str = Field(..., description="Batch job ID")
    download_url: str = Field(..., description="URL to download ZIP file")
    expires_at: datetime = Field(..., description="Download expiration time")
    file_size: int = Field(..., description="Size of ZIP file in bytes")
    successful_files: int = Field(..., description="Number of successful conversions")
    failed_files: int = Field(..., description="Number of failed conversions")


class BatchJobStatus(BaseModel):
    """Model for batch job status from database."""

    job_id: str = Field(..., description="Batch job ID")
    status: str = Field(..., description="Current job status")
    total_files: int = Field(..., description="Total number of files")
    completed_files: int = Field(..., description="Number of completed files")
    failed_files: int = Field(..., description="Number of failed files")
    progress: int = Field(..., ge=0, le=100, description="Overall progress percentage")
    files: List[Dict[str, Any]] = Field(..., description="Individual file statuses")
    created_at: Optional[str] = Field(
        None, description="Job creation time (ISO format)"
    )
    completed_at: Optional[str] = Field(
        None, description="Job completion time (ISO format)"
    )
    processing_time_seconds: Optional[float] = Field(
        None, description="Total processing time"
    )


class BatchResult(BaseModel):
    """Model for batch processing results."""

    job_id: str = Field(..., description="Batch job ID")
    total_files: int = Field(..., description="Total number of files")
    successful_files: List[Dict[str, Any]] = Field(
        ..., description="Successfully converted files"
    )
    failed_files: List[Dict[str, Any]] = Field(
        ..., description="Failed files with errors"
    )
    processing_time_seconds: float = Field(
        ..., description="Total processing time in seconds"
    )
    report_format: str = Field(default="json", description="Format of the report")
