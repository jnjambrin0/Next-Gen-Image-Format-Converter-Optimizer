"""Data models for image conversion."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
    JPEG_XL = "jpeg_xl"
    WEBP2 = "webp2"
    JP2 = "jp2"
    JPEG2000 = "jpeg2000"
    PNG_OPTIMIZED = "png_optimized"
    JPEG_OPTIMIZED = "jpeg_optimized"
    JPG_OPTIMIZED = "jpg_optimized"


class ConversionStatus(str, Enum):
    """Status of image conversion."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ContentType(str, Enum):
    """Detected image content type."""

    PHOTO = "photo"
    ILLUSTRATION = "illustration"
    SCREENSHOT = "screenshot"
    DOCUMENT = "document"


class ConversionSettings(BaseModel):
    """Settings for image conversion."""

    quality: int = Field(default=85, ge=1, le=100, description="Output quality (1-100)")
    strip_metadata: bool = Field(
        default=True, description="Remove EXIF and other metadata"
    )
    preserve_metadata: bool = Field(
        default=False,
        description="Preserve non-GPS metadata (overrides strip_metadata)",
    )
    preserve_gps: bool = Field(
        default=False,
        description="Preserve GPS location data (only if preserve_metadata is True)",
    )
    optimize: bool = Field(
        default=True, description="Apply format-specific optimizations"
    )
    # Reference to advanced optimization settings
    optimization_preset: Optional[str] = Field(
        default=None, description="Optimization preset: 'fast', 'balanced', 'best'"
    )

    # Advanced optimization options (Story 3.5)
    advanced_optimization: Optional[Dict[str, Any]] = Field(
        default=None, description="Advanced optimization parameters"
    )

    @field_validator("quality")
    @classmethod
    def validate_quality(cls, v: int) -> int:
        """Ensure quality is within valid range."""
        if not 1 <= v <= 100:
            raise ValueError("Quality must be between 1 and 100")
        return v


class OptimizationSettings(BaseModel):
    """Format-specific optimization settings."""

    # General optimization options
    algorithm: Optional[str] = Field(
        None,
        description="Optimization algorithm (e.g., 'pngquant', 'optipng', 'mozjpeg')",
    )
    effort: Optional[int] = Field(
        None,
        ge=1,
        le=10,
        description="Optimization effort level (1-10, higher = slower but better)",
    )

    # Lossy compression options
    lossless: Optional[bool] = Field(
        None, description="Use lossless compression if available"
    )

    # Progressive/interlaced encoding
    progressive: Optional[bool] = Field(
        None, description="Use progressive/interlaced encoding"
    )

    # Format-specific options
    # PNG options
    png_color_type: Optional[str] = Field(
        None, description="PNG color type: 'auto', 'grayscale', 'rgb', 'palette'"
    )
    png_palette_size: Optional[int] = Field(
        None, ge=2, le=256, description="Maximum colors in PNG palette (2-256)"
    )

    # JPEG options
    jpeg_subsampling: Optional[str] = Field(
        None, description="JPEG chroma subsampling: '4:4:4', '4:2:2', '4:2:0'"
    )
    jpeg_trellis: Optional[bool] = Field(
        None, description="Use trellis quantization for JPEG"
    )
    jpeg_overshoot: Optional[bool] = Field(
        None, description="Use overshooting for JPEG"
    )

    # WebP/WebP2 options
    webp_method: Optional[int] = Field(
        None,
        ge=0,
        le=6,
        description="WebP compression method (0-6, higher = slower but better)",
    )
    webp_segments: Optional[int] = Field(
        None, ge=1, le=4, description="WebP segment count (1-4)"
    )
    webp_sns: Optional[int] = Field(
        None, ge=0, le=100, description="WebP spatial noise shaping (0-100)"
    )

    # HEIF options
    heif_preset: Optional[str] = Field(
        None,
        description="HEIF encoder preset: 'ultrafast', 'fast', 'medium', 'slow', 'slower'",
    )
    heif_chroma: Optional[str] = Field(
        None, description="HEIF chroma format: '420', '422', '444'"
    )

    # JPEG XL options
    jxl_distance: Optional[float] = Field(
        None,
        ge=0.0,
        le=25.0,
        description="JPEG XL distance parameter (0=lossless, higher=more lossy)",
    )
    jxl_modular: Optional[bool] = Field(None, description="Use JPEG XL modular mode")

    # JPEG 2000 options
    jp2_rate: Optional[float] = Field(
        None, ge=0.1, le=10.0, description="JPEG 2000 compression rate (bits per pixel)"
    )
    jp2_layers: Optional[int] = Field(
        None, ge=1, le=10, description="JPEG 2000 quality layers"
    )

    # AVIF options
    avif_speed: Optional[int] = Field(
        None, ge=0, le=10, description="AVIF encoding speed (0-10, higher = faster)"
    )
    avif_pixel_format: Optional[str] = Field(
        None, description="AVIF pixel format: 'yuv420', 'yuv422', 'yuv444'"
    )

    # Custom options for advanced users
    custom_options: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="Custom format-specific options"
    )

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: Optional[str]) -> Optional[str]:
        """Validate optimization algorithm."""
        if v is None:
            return v

        valid_algorithms = {
            "pngquant",
            "optipng",
            "pngcrush",
            "advpng",
            "mozjpeg",
            "jpegoptim",
            "jpegtran",
            "cwebp",
            "gif2webp",
            "gifsicle",
            "avifenc",
            "heif-enc",
            "cjxl",
        }

        if v.lower() not in valid_algorithms:
            raise ValueError(f"Unknown optimization algorithm: {v}")

        return v.lower()


class ConversionRequest(BaseModel):
    """Request model for image conversion."""

    model_config = ConfigDict(use_enum_values=True)

    output_format: OutputFormat
    settings: Optional[ConversionSettings] = None
    optimization_settings: Optional[OptimizationSettings] = None
    preset_id: Optional[str] = Field(None, description="UUID of preset to apply")


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
    metadata_removed: bool = Field(
        default=False, description="Whether metadata was stripped from the image"
    )

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


class BoundingBox(BaseModel):
    """Bounding box for detected regions."""

    x: int = Field(ge=0, description="X coordinate of top-left corner")
    y: int = Field(ge=0, description="Y coordinate of top-left corner")
    width: int = Field(gt=0, description="Width of the bounding box")
    height: int = Field(gt=0, description="Height of the bounding box")
    confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Detection confidence"
    )

    @property
    def area(self) -> int:
        """Calculate area of the bounding box."""
        return self.width * self.height

    @property
    def center(self) -> Tuple[int, int]:
        """Calculate center point of the bounding box."""
        return (self.x + self.width // 2, self.y + self.height // 2)


class ContentClassification(BaseModel):
    """Classification result for image content detection."""

    primary_type: ContentType = Field(description="Primary detected content type")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score for primary type"
    )
    secondary_types: Optional[List[Tuple[ContentType, float]]] = Field(
        None, description="Secondary content types with confidence scores"
    )
    has_text: bool = Field(
        default=False, description="Whether text regions were detected"
    )
    text_regions: Optional[List[BoundingBox]] = Field(
        None, description="Detected text regions"
    )
    has_faces: bool = Field(default=False, description="Whether faces were detected")
    face_regions: Optional[List[BoundingBox]] = Field(
        None, description="Detected face regions"
    )
    processing_time_ms: float = Field(description="Processing time in milliseconds")

    # Additional content analysis
    complexity_score: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Image complexity score"
    )
    dominant_colors: Optional[List[str]] = Field(
        None, description="List of dominant colors in hex format"
    )

    @property
    def mixed_content(self) -> bool:
        """Check if image contains mixed content types."""
        return self.secondary_types is not None and len(self.secondary_types) > 0

    @property
    def text_coverage(self) -> float:
        """Calculate percentage of image covered by text regions."""
        if not self.text_regions:
            return 0.0
        # This would need image dimensions to calculate actual coverage
        # For now, return a placeholder
        return 0.0
