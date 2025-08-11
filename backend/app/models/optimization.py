"""Data models for advanced optimization features."""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.core.optimization.encoding_options import ChromaSubsampling
from app.core.optimization.optimization_engine import OptimizationMode


class OptimizationRequest(BaseModel):
    """Request model for advanced optimization."""

    output_format: str = Field(..., description="Target output format")
    optimization_mode: OptimizationMode = Field(
        default=OptimizationMode.BALANCED, description="Optimization strategy"
    )
    multi_pass: bool = Field(
        default=False, description="Enable multi-pass optimization"
    )
    target_size_kb: Optional[int] = Field(
        None,
        ge=1,
        le=102400,  # 100MB max
        description="Target file size in KB for multi-pass",
    )
    region_optimization: bool = Field(
        default=False, description="Enable region-based optimization"
    )
    perceptual_metrics: bool = Field(
        default=True, description="Calculate perceptual quality metrics"
    )

    # Advanced encoding options
    chroma_subsampling: Optional[ChromaSubsampling] = Field(
        None, description="Chroma subsampling mode"
    )
    progressive: Optional[bool] = Field(None, description="Enable progressive encoding")
    lossless: Optional[bool] = Field(None, description="Enable lossless compression")
    alpha_quality: Optional[int] = Field(
        None, ge=1, le=100, description="Alpha channel quality (1-100)"
    )
    custom_quantization: Optional[Dict[str, Any]] = Field(
        None, description="Custom quantization tables"
    )

    # Quality settings
    min_quality: int = Field(
        default=40, ge=1, le=100, description="Minimum quality for optimization"
    )
    max_quality: int = Field(
        default=95, ge=1, le=100, description="Maximum quality for optimization"
    )
    base_quality: int = Field(
        default=85, ge=1, le=100, description="Base quality setting"
    )

    @field_validator("max_quality")
    @classmethod
    def validate_quality_range(cls, v, info):
        """Ensure max_quality >= min_quality."""
        if info.data.get("min_quality") and v < info.data["min_quality"]:
            raise ValueError("max_quality must be >= min_quality")
        return v


class QualityMetrics(BaseModel):
    """Perceptual quality metrics."""

    ssim_score: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Structural Similarity Index (0-1)"
    )
    psnr_value: Optional[float] = Field(
        None, ge=0.0, le=100.0, description="Peak Signal-to-Noise Ratio in dB"
    )
    file_size_reduction: float = Field(
        ..., ge=0.0, le=100.0, description="File size reduction percentage"
    )
    visual_quality: Literal["high", "medium", "low"] = Field(
        ..., description="Visual quality rating"
    )


class OptimizationPass(BaseModel):
    """Single optimization pass details."""

    pass_number: int = Field(..., description="Pass number")
    quality: int = Field(..., ge=1, le=100, description="Quality setting used")
    file_size: int = Field(..., ge=0, description="Resulting file size in bytes")
    ssim_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    psnr_value: Optional[float] = Field(None, ge=0.0)
    processing_time: float = Field(
        ..., ge=0.0, description="Pass processing time in seconds"
    )


class RegionInfo(BaseModel):
    """Information about detected regions."""

    region_type: Literal["face", "text", "foreground", "background"]
    bbox: List[int] = Field(
        ..., min_items=4, max_items=4, description="Bounding box [x1, y1, x2, y2]"
    )
    confidence: float = Field(..., ge=0.0, le=1.0)
    quality_factor: float = Field(..., ge=0.0, le=1.0)


class AlphaChannelInfo(BaseModel):
    """Alpha channel analysis information."""

    has_alpha: bool = Field(..., description="Whether image has alpha channel")
    alpha_usage: Literal[
        "none", "unnecessary", "binary", "mostly_binary", "simple", "complex"
    ]
    transparent_pixel_count: int = Field(..., ge=0)
    alpha_complexity: float = Field(..., ge=0.0, le=1.0)
    removed_alpha: bool = Field(default=False)
    alpha_compressed: bool = Field(default=False)
    recommended_action: Optional[str] = None


class OptimizationResponse(BaseModel):
    """Response model for advanced optimization."""

    conversion_id: UUID = Field(..., description="Unique conversion ID")
    success: bool = Field(..., description="Whether optimization succeeded")

    # File information
    original_size: int = Field(..., description="Original file size in bytes")
    optimized_size: int = Field(..., description="Optimized file size in bytes")
    output_format: str = Field(..., description="Output format")

    # Quality metrics
    quality_metrics: Optional[QualityMetrics] = None

    # Optimization details
    optimization_mode: OptimizationMode
    total_passes: Optional[int] = Field(
        None, description="Number of optimization passes"
    )
    converged: Optional[bool] = Field(
        None, description="Whether optimization converged"
    )
    passes: Optional[List[OptimizationPass]] = Field(
        None, description="Details of each pass"
    )

    # Region optimization
    regions_detected: Optional[List[RegionInfo]] = None
    region_optimization_applied: bool = Field(default=False)

    # Alpha channel
    alpha_info: Optional[AlphaChannelInfo] = None

    # Performance
    total_processing_time: float = Field(
        ..., description="Total processing time in seconds"
    )

    # Encoding details
    encoding_options_applied: Dict[str, Any] = Field(default_factory=dict)

    # Error information (if failed)
    error_message: Optional[str] = None
    error_code: Optional[str] = None


class OptimizationProgressUpdate(BaseModel):
    """Progress update for SSE streaming."""

    conversion_id: UUID
    status: Literal[
        "started", "analyzing", "optimizing", "finalizing", "completed", "failed"
    ]
    current_pass: Optional[int] = None
    total_passes: Optional[int] = None
    current_quality: Optional[int] = None
    current_size: Optional[int] = None
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
