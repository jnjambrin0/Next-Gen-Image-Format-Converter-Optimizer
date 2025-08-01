"""Data models for image conversion."""

from typing import Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, field_validator, ConfigDict
from datetime import datetime, timezone
import uuid


class InputFormat(str, Enum):
    """Supported input image formats."""

    JPEG = "jpeg"
    JPG = "jpg"
    PNG = "png"
    WEBP = "webp"
    HEIF = "heif"
    HEIC = "heic"
    BMP = "bmp"
    TIFF = "tiff"
    GIF = "gif"
    AVIF = "avif"


class OutputFormat(str, Enum):
    """Supported output image formats."""

    WEBP = "webp"
    AVIF = "avif"
    JPEG = "jpeg"
    JPG = "jpg"
    PNG = "png"
    HEIF = "heif"
    JPEGXL = "jpegxl"
    JXL = "jxl"
    WEBP2 = "webp2"
    JP2 = "jp2"


class ConversionStatus(str, Enum):
    """Status of image conversion."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ConversionSettings(BaseModel):
    """Settings for image conversion."""

    quality: int = Field(default=85, ge=1, le=100, description="Output quality (1-100)")
    strip_metadata: bool = Field(
        default=True, description="Remove EXIF and other metadata"
    )
    optimize: bool = Field(
        default=True, description="Apply format-specific optimizations"
    )

    @field_validator("quality")
    @classmethod
    def validate_quality(cls, v: int) -> int:
        """Ensure quality is within valid range."""
        if not 1 <= v <= 100:
            raise ValueError("Quality must be between 1 and 100")
        return v


class ConversionRequest(BaseModel):
    """Request model for image conversion."""

    model_config = ConfigDict(use_enum_values=True)

    output_format: OutputFormat
    settings: Optional[ConversionSettings] = None


class ConversionResult(BaseModel):
    """Result of image conversion."""

    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    input_format: InputFormat
    output_format: OutputFormat
    input_size: int = Field(description="Original file size in bytes")
    output_size: Optional[int] = Field(None, description="Converted file size in bytes")
    quality_settings: Dict[str, Any] = Field(default_factory=dict)
    processing_time: Optional[float] = Field(
        None, description="Processing time in seconds"
    )
    status: ConversionStatus = ConversionStatus.PENDING
    error_message: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

    @property
    def compression_ratio(self) -> Optional[float]:
        """Calculate compression ratio if both sizes are available."""
        if self.output_size and self.input_size:
            return round(self.output_size / self.input_size, 3)
        return None


class ImageMetadata(BaseModel):
    """Metadata extracted from an image."""

    format: str
    width: int
    height: int
    color_mode: str
    has_transparency: bool = False
    has_animation: bool = False
    frame_count: Optional[int] = None
    exif: Optional[Dict[str, Any]] = None

    @property
    def dimensions(self) -> tuple[int, int]:
        """Return dimensions as tuple."""
        return (self.width, self.height)

    @property
    def aspect_ratio(self) -> float:
        """Calculate aspect ratio."""
        if self.height > 0:
            return round(self.width / self.height, 3)
        return 0.0
