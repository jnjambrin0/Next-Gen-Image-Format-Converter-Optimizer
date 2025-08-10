"""Request models for API endpoints."""

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from app.models.conversion import ConversionSettings, OptimizationSettings, OutputFormat


class ConversionApiRequest(BaseModel):
    """Request model for image conversion API."""

    filename: str = Field(..., description="Original filename")
    input_format: str = Field(..., description="Input image format")
    output_format: OutputFormat = Field(..., description="Target output format")
    settings: Optional[ConversionSettings] = Field(
        None, description="Conversion settings"
    )
    optimization_settings: Optional[OptimizationSettings] = Field(
        None, description="Format-specific optimization settings"
    )
    preset_id: Optional[str] = Field(None, description="UUID of preset to apply")

    @field_validator("input_format")
    @classmethod
    def validate_input_format(cls, v: str) -> str:
        """Normalize input format."""
        return v.lower().strip(".")

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        """Validate filename is not empty."""
        if not v or not v.strip():
            raise ValueError("Filename cannot be empty")
        return v.strip()


class BatchConversionRequest(BaseModel):
    """Request model for batch image conversion."""

    output_format: OutputFormat = Field(..., description="Target output format")
    settings: Optional[ConversionSettings] = Field(
        None, description="Conversion settings"
    )
    optimization_settings: Optional[OptimizationSettings] = Field(
        None, description="Format-specific optimization settings"
    )
    preset_id: Optional[str] = Field(None, description="UUID of preset to apply")
    parallel: bool = Field(True, description="Process images in parallel")
    max_parallel: int = Field(
        5, ge=1, le=10, description="Maximum parallel conversions"
    )
