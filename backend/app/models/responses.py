"""Response models for API endpoints."""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime

from app.models.conversion import ConversionStatus, InputFormat, OutputFormat


class ErrorResponse(BaseModel):
    """Standard error response model."""

    error_code: str = Field(..., description="Error code (e.g., CONV201)")
    message: str = Field(..., description="Human-readable error message")
    correlation_id: str = Field(..., description="Request correlation ID for tracking")
    details: Optional[Dict[str, Any]] = Field(
        None, description="Additional error details"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Error timestamp"
    )


class ConversionApiResponse(BaseModel):
    """Response model for successful conversion (metadata only)."""

    id: str = Field(..., description="Conversion ID")
    input_format: InputFormat = Field(..., description="Original image format")
    output_format: OutputFormat = Field(..., description="Converted image format")
    input_size: int = Field(..., description="Original file size in bytes")
    output_size: int = Field(..., description="Converted file size in bytes")
    compression_ratio: float = Field(..., description="Output/input size ratio")
    processing_time: float = Field(..., description="Processing time in seconds")
    status: ConversionStatus = Field(..., description="Conversion status")


class FormatInfo(BaseModel):
    """Information about a supported format."""

    format: str = Field(..., description="Format identifier")
    mime_type: str = Field(..., description="MIME type")
    extensions: List[str] = Field(..., description="File extensions")
    description: str = Field(..., description="Format description")
    supports_transparency: bool = Field(
        False, description="Whether format supports transparency"
    )
    supports_animation: bool = Field(
        False, description="Whether format supports animation"
    )
    max_dimensions: Optional[Dict[str, int]] = Field(
        None, description="Maximum supported dimensions"
    )


class SupportedFormatsResponse(BaseModel):
    """Response model for supported formats endpoint."""

    input_formats: List[FormatInfo] = Field(..., description="Supported input formats")
    output_formats: List[FormatInfo] = Field(
        ..., description="Supported output formats"
    )


class BatchConversionResponse(BaseModel):
    """Response model for batch conversion."""

    batch_id: str = Field(..., description="Batch operation ID")
    total_files: int = Field(..., description="Total number of files")
    processed: int = Field(0, description="Number of files processed")
    successful: int = Field(0, description="Number of successful conversions")
    failed: int = Field(0, description="Number of failed conversions")
    status: str = Field(..., description="Batch status")
    results: List[ConversionApiResponse] = Field(
        default_factory=list, description="Individual conversion results"
    )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    uptime: float = Field(..., description="Service uptime in seconds")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Current timestamp"
    )

