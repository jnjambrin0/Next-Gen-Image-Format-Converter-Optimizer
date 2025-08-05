"""Pydantic schemas for API requests and responses."""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime
import re
import json


class PresetSettings(BaseModel):
    """Schema for preset conversion settings."""
    output_format: str = Field(..., description="Target format for conversion")
    quality: int = Field(85, ge=1, le=100, description="Conversion quality (1-100)")
    optimization_mode: str = Field("balanced", description="Optimization mode: balanced, file_size, or quality")
    preserve_metadata: bool = Field(False, description="Whether to preserve image metadata")
    resize_options: Optional[Dict[str, Any]] = Field(None, description="Optional resize configuration")
    advanced_settings: Optional[Dict[str, Any]] = Field(None, description="Format-specific advanced settings")
    
    @field_validator('output_format')
    @classmethod
    def validate_output_format(cls, v: str) -> str:
        """Validate output format is supported."""
        supported_formats = ["jpeg", "png", "webp", "avif", "heif", "jxl", "webp2", "jp2"]
        if v.lower() not in supported_formats:
            raise ValueError(f"Unsupported output format: {v}")
        return v.lower()
    
    @field_validator('optimization_mode')
    @classmethod
    def validate_optimization_mode(cls, v: str) -> str:
        """Validate optimization mode."""
        valid_modes = ["balanced", "file_size", "quality"]
        if v not in valid_modes:
            raise ValueError(f"Invalid optimization mode: {v}. Must be one of {valid_modes}")
        return v


class PresetBase(BaseModel):
    """Base schema for preset data."""
    name: str = Field(..., min_length=1, max_length=100, description="Preset name")
    description: Optional[str] = Field(None, max_length=500, description="Preset description")
    settings: PresetSettings = Field(..., description="Conversion settings for this preset")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate preset name - alphanumeric, spaces, hyphens, and underscores only."""
        if not re.match(r'^[\w\s\-]+$', v):
            raise ValueError("Preset name can only contain letters, numbers, spaces, hyphens, and underscores")
        return v.strip()


class PresetCreate(PresetBase):
    """Schema for creating a new preset."""
    pass


class PresetUpdate(BaseModel):
    """Schema for updating an existing preset."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    settings: Optional[PresetSettings] = None
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v: Optional[str]) -> Optional[str]:
        """Validate preset name if provided."""
        if v is not None:
            if not re.match(r'^[\w\s\-]+$', v):
                raise ValueError("Preset name can only contain letters, numbers, spaces, hyphens, and underscores")
            return v.strip()
        return v


class PresetResponse(PresetBase):
    """Schema for preset response."""
    id: str = Field(..., description="Preset UUID")
    is_builtin: bool = Field(..., description="Whether this is a built-in preset")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    model_config = ConfigDict(from_attributes=True)


class PresetImport(BaseModel):
    """Schema for importing presets."""
    presets: List[PresetBase] = Field(..., description="List of presets to import")
    
    @field_validator('presets')
    @classmethod
    def validate_presets(cls, v: List[PresetBase]) -> List[PresetBase]:
        """Validate imported presets."""
        if not v:
            raise ValueError("At least one preset must be provided")
        if len(v) > 50:
            raise ValueError("Cannot import more than 50 presets at once")
        
        # Check for duplicate names
        names = [preset.name for preset in v]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate preset names found in import")
        
        return v


class PresetExport(BaseModel):
    """Schema for exporting presets."""
    preset: PresetResponse = Field(..., description="Preset data")
    export_version: str = Field("1.0", description="Export format version")
    exported_at: datetime = Field(default_factory=datetime.utcnow, description="Export timestamp")


class PresetListResponse(BaseModel):
    """Schema for listing presets."""
    presets: List[PresetResponse] = Field(..., description="List of all presets")
    total: int = Field(..., description="Total number of presets")