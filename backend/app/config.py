from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import List, Optional
import os


class Settings(BaseSettings):
    # Application
    app_name: str = Field(default="Image Converter", description="Application name")
    env: str = Field(
        default="development", description="Environment (development/production)"
    )
    debug: bool = Field(default=True, description="Enable debug mode")
    log_level: str = Field(default="INFO", description="Logging level")

    # API Configuration
    api_host: str = Field(default="0.0.0.0", description="API host to bind to")
    api_port: int = Field(default=8000, description="API port (per architecture spec)")
    api_workers: int = Field(default=1, description="Number of worker processes")
    api_prefix: str = Field(default="/api", description="API route prefix")

    # Security
    secret_key: str = Field(
        default="your-secret-key-here-change-in-production",
        description="Secret key for security operations",
    )
    cors_origins: List[str] = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
        description="Allowed CORS origins",
    )
    max_request_size: int = Field(
        default=104857600, description="Max request size (100MB)"
    )
    rate_limit_per_minute: int = Field(
        default=60, description="Rate limit per IP per minute"
    )

    # File Processing
    max_upload_size: int = Field(
        default=104857600, description="Max upload size in bytes (100MB)"
    )
    allowed_input_formats: List[str] = Field(
        default=[
            "jpg",
            "jpeg",
            "png",
            "gif",
            "webp",
            "bmp",
            "tiff",
            "heic",
            "heif",
            "avif",
        ],
        description="Allowed input image formats",
    )
    allowed_output_formats: List[str] = Field(
        default=["webp", "avif", "jpeg", "png", "heif", "jxl", "webp2", "jp2"],
        description="Allowed output image formats",
    )
    temp_dir: str = Field(
        default="/tmp/image-converter", description="Temporary directory"
    )
    cleanup_interval: int = Field(
        default=3600, description="Cleanup interval in seconds"
    )

    # Performance
    conversion_timeout: int = Field(
        default=300, description="Conversion timeout in seconds"
    )
    max_concurrent_conversions: int = Field(
        default=4, description="Max concurrent conversions"
    )
    memory_limit_mb: int = Field(
        default=512, description="Memory limit per conversion in MB"
    )
    cpu_limit_percent: int = Field(default=80, description="CPU limit percentage")

    # Process Sandboxing
    enable_sandboxing: bool = Field(
        default=True, description="Enable process sandboxing"
    )
    sandbox_uid: Optional[int] = Field(default=None, description="Sandbox user ID")
    sandbox_gid: Optional[int] = Field(default=None, description="Sandbox group ID")

    # ML Models
    ml_models_path: str = Field(default="./ml_models", description="Path to ML models")
    enable_ai_features: bool = Field(default=True, description="Enable AI features")
    model_cache_size: int = Field(default=2, description="Number of models to cache")
    content_detection_model: str = Field(
        default="content_classifier.onnx",
        description="Content detection model filename",
    )
    quality_prediction_model: str = Field(
        default="quality_predictor.onnx",
        description="Quality prediction model filename",
    )

    # Database
    database_url: str = Field(
        default="sqlite:///./data/app.db", description="Database connection URL"
    )
    database_pool_size: int = Field(
        default=5, description="Database connection pool size"
    )
    database_pool_timeout: int = Field(default=30, description="Database pool timeout")

    # Feature Flags
    enable_batch_processing: bool = Field(
        default=True, description="Enable batch processing"
    )
    enable_websocket_progress: bool = Field(
        default=True, description="Enable WebSocket progress"
    )
    enable_preset_sharing: bool = Field(
        default=False, description="Enable preset sharing"
    )
    enable_history_tracking: bool = Field(
        default=True, description="Enable conversion history"
    )

    # Privacy
    strip_metadata_default: bool = Field(
        default=True, description="Strip EXIF by default"
    )
    anonymize_logs: bool = Field(
        default=True, description="Anonymize sensitive data in logs"
    )
    retain_history_days: int = Field(
        default=30, description="Days to retain conversion history"
    )

    @validator("env")
    def validate_env(cls, v):
        allowed = ["development", "production", "testing"]
        if v not in allowed:
            raise ValueError(f"env must be one of {allowed}")
        return v

    @validator("log_level")
    def validate_log_level(cls, v):
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v.upper()

    @validator("api_port")
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError("api_port must be between 1 and 65535")
        return v

    @validator("cors_origins", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

        # Custom env prefix
        env_prefix = "IMAGE_CONVERTER_"


settings = Settings()
