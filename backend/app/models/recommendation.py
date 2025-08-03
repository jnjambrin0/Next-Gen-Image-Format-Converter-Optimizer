"""Data models for format recommendations."""

from typing import Optional, Dict, Any, List
from enum import Enum
from pydantic import BaseModel, Field, field_validator

from app.models.conversion import ContentClassification, OutputFormat, InputFormat


class UseCaseType(str, Enum):
    """Use case for image conversion."""
    
    WEB = "web"
    PRINT = "print" 
    ARCHIVE = "archive"
    

class FormatCharacteristics(BaseModel):
    """Characteristics and capabilities of an image format."""
    
    compression_efficiency: float = Field(
        ge=0.0, le=1.0,
        description="Compression efficiency (0-1, higher is better)"
    )
    browser_support: float = Field(
        ge=0.0, le=1.0,
        description="Browser/device support level (0-1)"
    )
    quality_preservation: float = Field(
        ge=0.0, le=1.0,
        description="Quality preservation capability (0-1)"
    )
    features: Dict[str, bool] = Field(
        default_factory=dict,
        description="Supported features (transparency, animation, HDR, etc.)"
    )
    processing_speed: float = Field(
        ge=0.0, le=1.0,
        description="Encoding/decoding speed (0-1, higher is faster)"
    )
    future_proof: float = Field(
        ge=0.0, le=1.0,
        description="Future compatibility likelihood (0-1)"
    )
    

class TradeOffAnalysis(BaseModel):
    """Trade-off analysis between different factors."""
    
    size_reduction: float = Field(
        ge=0.0, le=1.0,
        description="Expected size reduction (0-1, higher is better)"
    )
    quality_score: float = Field(
        ge=0.0, le=1.0,
        description="Expected quality score (0-1)"
    )
    compatibility_score: float = Field(
        ge=0.0, le=1.0,
        description="Compatibility score (0-1)"
    )
    feature_score: float = Field(
        ge=0.0, le=1.0,
        description="Feature support score (0-1)"
    )
    performance_score: float = Field(
        ge=0.0, le=1.0,
        description="Processing performance score (0-1)"
    )
    

class FormatRecommendation(BaseModel):
    """Recommendation for a specific output format."""
    
    format: OutputFormat = Field(description="Recommended output format")
    score: float = Field(
        ge=0.0, le=1.0,
        description="Overall recommendation score (0-1)"
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable reasons for recommendation"
    )
    estimated_size_kb: int = Field(
        gt=0,
        description="Estimated output file size in KB"
    )
    quality_score: float = Field(
        ge=0.0, le=1.0,
        description="Predicted quality score (0-1)"
    )
    compatibility_score: float = Field(
        ge=0.0, le=1.0,
        description="Browser/device compatibility score (0-1)"
    )
    features: Dict[str, bool] = Field(
        default_factory=dict,
        description="Supported features for this format"
    )
    trade_offs: TradeOffAnalysis = Field(
        description="Detailed trade-off analysis"
    )
    pros: List[str] = Field(
        default_factory=list,
        description="Advantages of this format for the use case"
    )
    cons: List[str] = Field(
        default_factory=list,
        description="Disadvantages of this format"
    )
    
    @field_validator("reasons", "pros", "cons")
    @classmethod
    def validate_non_empty_strings(cls, v: List[str]) -> List[str]:
        """Ensure all strings in list are non-empty."""
        return [s for s in v if s and s.strip()]
    

class RecommendationRequest(BaseModel):
    """Request for format recommendations."""
    
    content_classification: ContentClassification = Field(
        description="Content classification from intelligence engine"
    )
    use_case: Optional[UseCaseType] = Field(
        None,
        description="Intended use case (web/print/archive)"
    )
    original_format: InputFormat = Field(
        description="Original image format"
    )
    original_size_kb: int = Field(
        gt=0,
        description="Original file size in KB"
    )
    prioritize: Optional[str] = Field(
        None,
        description="What to prioritize: size/quality/compatibility"
    )
    exclude_formats: Optional[List[OutputFormat]] = Field(
        default_factory=list,
        description="Formats to exclude from recommendations"
    )
    

class RecommendationResponse(BaseModel):
    """Response containing format recommendations."""
    
    recommendations: List[FormatRecommendation] = Field(
        description="Top format recommendations (max 3)"
    )
    comparison_matrix: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Comparison matrix for recommended formats"
    )
    content_type: str = Field(
        description="Detected content type"
    )
    use_case: Optional[str] = Field(
        None,
        description="Applied use case"
    )
    processing_time_ms: float = Field(
        ge=0,
        description="Processing time in milliseconds"
    )
    

class UserFormatPreference(BaseModel):
    """User's format preference for a content type."""
    
    content_type: str = Field(description="Content type")
    chosen_format: OutputFormat = Field(description="Format chosen by user")
    use_case: Optional[UseCaseType] = Field(None, description="Use case if specified")
    timestamp: float = Field(description="Unix timestamp of choice")
    score_adjustment: float = Field(
        default=0.0,
        ge=-0.5,
        le=0.5,
        description="Score adjustment based on user preference"
    )
    

class FormatComparisonMetric(BaseModel):
    """Metric for comparing formats."""
    
    metric_name: str = Field(description="Name of the metric")
    metric_value: float = Field(
        ge=0.0,
        le=1.0,
        description="Normalized metric value (0-1)"
    )
    display_value: str = Field(
        description="Human-readable display value"
    )
    is_better_higher: bool = Field(
        default=True,
        description="Whether higher values are better"
    )