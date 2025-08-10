"""
Intelligence models for ML-based content analysis.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class ContentType(str, Enum):
    """Types of image content."""

    PHOTO = "photo"
    ILLUSTRATION = "illustration"
    SCREENSHOT = "screenshot"
    DOCUMENT = "document"
    UNKNOWN = "unknown"


class BoundingBox(BaseModel):
    """Bounding box for detected regions."""

    x: int = Field(..., description="X coordinate of top-left corner")
    y: int = Field(..., description="Y coordinate of top-left corner")
    width: int = Field(..., description="Width of the box")
    height: int = Field(..., description="Height of the box")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Detection confidence")
    label: Optional[str] = Field(None, description="Label for the detected object")


class ContentClassification(BaseModel):
    """Result of content classification."""

    content_type: ContentType = Field(..., description="Detected content type")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Classification confidence"
    )

    # Detection results
    face_regions: List[BoundingBox] = Field(
        default_factory=list, description="Detected face regions"
    )
    text_regions: List[BoundingBox] = Field(
        default_factory=list, description="Detected text regions"
    )

    # Content characteristics
    has_text: bool = Field(False, description="Whether text was detected")
    has_faces: bool = Field(False, description="Whether faces were detected")
    has_ui_elements: bool = Field(
        False, description="Whether UI elements were detected"
    )

    # Color analysis
    dominant_colors: List[str] = Field(
        default_factory=list, description="List of dominant colors in hex format"
    )
    color_complexity: float = Field(
        0.0, ge=0.0, le=1.0, description="Color complexity score"
    )

    # Quality metrics
    sharpness_score: float = Field(
        0.0, ge=0.0, le=1.0, description="Image sharpness score"
    )
    noise_level: float = Field(
        0.0, ge=0.0, le=1.0, description="Noise level in the image"
    )

    # Metadata
    analyzed_at: datetime = Field(
        default_factory=datetime.now, description="Timestamp of analysis"
    )
    model_version: Optional[str] = Field(None, description="ML model version used")

    class Config:
        use_enum_values = True


class OptimizationRecommendation(BaseModel):
    """Optimization recommendations based on content analysis."""

    recommended_format: str = Field(..., description="Recommended output format")
    recommended_quality: int = Field(
        ..., ge=1, le=100, description="Recommended quality"
    )

    # Format-specific recommendations
    use_lossless: bool = Field(False, description="Whether to use lossless compression")
    use_progressive: bool = Field(
        False, description="Whether to use progressive encoding"
    )

    # Optimization settings
    preserve_transparency: bool = Field(
        False, description="Whether to preserve transparency"
    )
    optimize_for: str = Field(
        "balanced", description="Optimization target: 'size', 'quality', 'balanced'"
    )

    # Reasoning
    reasoning: str = Field(..., description="Explanation for recommendations")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Recommendation confidence"
    )

    # Expected results
    estimated_size_reduction: float = Field(
        0.0, ge=0.0, le=1.0, description="Estimated size reduction percentage"
    )
    estimated_quality_loss: float = Field(
        0.0, ge=0.0, le=1.0, description="Estimated quality loss percentage"
    )


class ModelInfo(BaseModel):
    """Information about ML models."""

    name: str = Field(..., description="Model name")
    version: str = Field(..., description="Model version")
    type: str = Field(..., description="Model type (e.g., 'onnx', 'tensorflow')")
    size_mb: float = Field(..., description="Model size in megabytes")
    accuracy: float = Field(..., ge=0.0, le=1.0, description="Model accuracy")

    # Performance metrics
    inference_time_ms: float = Field(
        ..., description="Average inference time in milliseconds"
    )
    memory_usage_mb: float = Field(..., description="Memory usage in megabytes")

    # Capabilities
    supports_gpu: bool = Field(
        False, description="Whether GPU acceleration is supported"
    )
    supports_batch: bool = Field(
        False, description="Whether batch processing is supported"
    )
    max_batch_size: int = Field(1, description="Maximum batch size")

    # Metadata
    loaded_at: Optional[datetime] = Field(None, description="When model was loaded")
    last_used: Optional[datetime] = Field(None, description="Last time model was used")


class IntelligenceCapabilities(BaseModel):
    """Available intelligence capabilities."""

    content_detection: bool = Field(
        True, description="Content type detection available"
    )
    face_detection: bool = Field(False, description="Face detection available")
    text_detection: bool = Field(False, description="Text/OCR detection available")
    object_detection: bool = Field(False, description="Object detection available")

    # Quality analysis
    quality_assessment: bool = Field(True, description="Quality assessment available")
    blur_detection: bool = Field(True, description="Blur detection available")

    # Advanced features
    scene_recognition: bool = Field(False, description="Scene recognition available")
    sentiment_analysis: bool = Field(
        False, description="Image sentiment analysis available"
    )

    # Model information
    models: List[ModelInfo] = Field(
        default_factory=list, description="Available ML models"
    )

    # System info
    gpu_available: bool = Field(False, description="GPU acceleration available")
    max_image_size: int = Field(50000, description="Maximum image dimension in pixels")
    supported_formats: List[str] = Field(
        default_factory=lambda: ["jpeg", "png", "webp", "gif", "bmp"],
        description="Supported image formats",
    )
