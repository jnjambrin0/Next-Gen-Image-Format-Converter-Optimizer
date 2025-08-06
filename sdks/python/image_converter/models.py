"""Data models for Image Converter SDK."""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, UUID4, validator


class OutputFormat(str, Enum):
    """Supported output formats."""
    WEBP = "webp"
    AVIF = "avif"
    JPEG = "jpeg"
    PNG = "png"
    HEIF = "heif"
    JXL = "jxl"
    WEBP2 = "webp2"


class ContentType(str, Enum):
    """Content classification types."""
    PHOTO = "photo"
    ILLUSTRATION = "illustration"
    SCREENSHOT = "screenshot"
    DOCUMENT = "document"
    UNKNOWN = "unknown"


class UseCaseType(str, Enum):
    """Use case types for optimization."""
    WEB = "web"
    PRINT = "print"
    ARCHIVE = "archive"


class ConversionRequest(BaseModel):
    """Request model for image conversion."""
    
    output_format: OutputFormat
    quality: Optional[int] = Field(default=85, ge=1, le=100)
    strip_metadata: bool = True
    preserve_metadata: bool = False
    preserve_gps: bool = False
    preset_id: Optional[UUID4] = None
    
    @validator("quality")
    def validate_quality(cls, v: Optional[int]) -> Optional[int]:
        """Ensure quality is within valid range."""
        if v is not None and (v < 1 or v > 100):
            raise ValueError("Quality must be between 1 and 100")
        return v
    
    @validator("preserve_gps")
    def validate_gps_preservation(cls, v: bool, values: Dict[str, Any]) -> bool:
        """GPS can only be preserved if metadata is preserved."""
        if v and not values.get("preserve_metadata", False):
            raise ValueError("Cannot preserve GPS without preserving metadata")
        return v


class ConversionResponse(BaseModel):
    """Response model for successful conversion."""
    
    conversion_id: str
    processing_time: float
    compression_ratio: float
    input_format: str
    output_format: str
    input_size: int
    output_size: int
    quality_used: Optional[int] = None
    metadata_removed: bool
    
    class Config:
        """Pydantic config."""
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class BatchRequest(BaseModel):
    """Request model for batch conversion."""
    
    output_format: OutputFormat
    quality: Optional[int] = Field(default=85, ge=1, le=100)
    strip_metadata: bool = True
    preserve_metadata: bool = False
    preserve_gps: bool = False
    preset_id: Optional[UUID4] = None
    max_concurrent: Optional[int] = Field(default=5, ge=1, le=10)


class BatchStatus(BaseModel):
    """Status model for batch job."""
    
    job_id: str
    status: str
    total_files: int
    completed_files: int
    failed_files: int
    progress_percentage: float
    created_at: datetime
    updated_at: datetime
    estimated_completion: Optional[datetime] = None
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    
    class Config:
        """Pydantic config."""
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class FormatInfo(BaseModel):
    """Information about a supported format."""
    
    format: str
    mime_type: str
    extensions: List[str]
    supports_transparency: bool
    supports_animation: bool
    lossy: bool
    max_dimensions: Optional[Dict[str, int]] = None
    recommended_use_cases: List[str] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """Standard error response model."""
    
    error: str
    error_code: str
    message: str
    correlation_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    
    @validator("message")
    def sanitize_message(cls, v: str) -> str:
        """Ensure no PII in error messages."""
        # Remove any potential file paths or names
        import re
        # Remove absolute paths
        v = re.sub(r'[/\\][\w/\\.-]+\.\w+', '[file]', v)
        # Remove relative paths
        v = re.sub(r'[\w.-]+\.\w+', '[file]', v)
        return v


class ContentClassification(BaseModel):
    """Content classification result."""
    
    content_type: ContentType
    confidence: float = Field(ge=0.0, le=1.0)
    processing_time_ms: float
    face_regions: List[Dict[str, int]] = Field(default_factory=list)
    text_regions: List[Dict[str, int]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FormatRecommendation(BaseModel):
    """Format recommendation result."""
    
    recommended_formats: List[Dict[str, Any]]
    reasoning: Dict[str, str]
    trade_offs: Dict[str, List[str]]
    size_predictions: Dict[str, float]
    quality_predictions: Dict[str, float]
    
    
class APIKeyInfo(BaseModel):
    """API key information (sanitized)."""
    
    key_id: str
    name: str
    created_at: datetime
    last_used: Optional[datetime] = None
    usage_count: int
    active: bool
    
    class Config:
        """Pydantic config."""
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }