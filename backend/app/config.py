import os
from typing import Any, Dict, List, Optional, Union

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Import constants to avoid magic numbers
try:
    from app.core.constants import (
        DEFAULT_MONITORING_INTERVAL,
        ERROR_RETENTION_DAYS,
    )
    from app.core.constants import MAX_BATCH_SIZE as DEFAULT_MAX_BATCH_SIZE
    from app.core.constants import (
        MONITORING_INTERVAL_SECONDS,
        SANDBOX_CPU_LIMITS,
        SANDBOX_MEMORY_LIMITS,
        SANDBOX_OUTPUT_LIMITS,
        SANDBOX_TIMEOUTS,
    )
except ImportError:
    # Fallback values if constants can't be imported (e.g., during initial setup)
    SANDBOX_MEMORY_LIMITS = {"standard": 512, "strict": 256, "paranoid": 128}
    SANDBOX_CPU_LIMITS = {"standard": 80, "strict": 60, "paranoid": 40}
    SANDBOX_TIMEOUTS = {"standard": 30, "strict": 20, "paranoid": 10}
    SANDBOX_OUTPUT_LIMITS = {"standard": 100, "strict": 50, "paranoid": 25}
    ERROR_RETENTION_DAYS = 30
    DEFAULT_MONITORING_INTERVAL = 5
    MONITORING_INTERVAL_SECONDS = 5.0
    DEFAULT_MAX_BATCH_SIZE = 100


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
    cors_origins: Union[str, List[str]] = Field(
        default="http://localhost:5173,http://localhost:3000",
        description="Allowed CORS origins",
    )
    max_request_size: int = Field(
        default=104857600, description="Max request size (100MB)"
    )
    rate_limit_per_minute: int = Field(
        default=60, description="Rate limit per IP per minute"
    )
    max_requests_per_minute: int = Field(
        default=60, description="Maximum requests per minute per IP"
    )
    max_requests_per_hour: int = Field(
        default=1000, description="Maximum requests per hour per IP"
    )
    max_request_body_size: int = Field(
        default=104857600, description="Maximum request body size in bytes (100MB)"
    )
    request_timeout: int = Field(default=120, description="Request timeout in seconds")

    # File Processing
    max_upload_size: int = Field(
        default=104857600, description="Max upload size in bytes (100MB)"
    )
    max_file_size: int = Field(
        default=52428800, description="Max file size in bytes (50MB)"
    )
    allowed_input_formats: Union[str, List[str]] = Field(
        default="jpg,jpeg,png,gif,webp,bmp,tiff,heic,heif,avif",
        description="Allowed input image formats",
    )
    allowed_output_formats: Union[str, List[str]] = Field(
        default="webp,avif,jpeg,png,heif,jxl,webp2,jp2",
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
        default=SANDBOX_TIMEOUTS["standard"],
        description="Conversion timeout in seconds",
    )
    max_concurrent_conversions: int = Field(
        default=10, description="Max concurrent conversions"
    )
    memory_limit_mb: int = Field(
        default=SANDBOX_MEMORY_LIMITS["standard"],
        description="Memory limit per conversion in MB",
    )
    cpu_limit_percent: int = Field(
        default=SANDBOX_CPU_LIMITS["standard"], description="CPU limit percentage"
    )

    # Process Sandboxing
    enable_sandboxing: bool = Field(
        default=True, description="Enable process sandboxing"
    )
    sandbox_uid: Optional[int] = Field(default=None, description="Sandbox user ID")
    sandbox_gid: Optional[int] = Field(default=None, description="Sandbox group ID")
    sandbox_strictness: str = Field(
        default="standard",
        description="Sandbox strictness level: standard, strict, paranoid",
    )
    # Sandbox resource limits per strictness level
    sandbox_limits_standard: Dict[str, int] = Field(
        default={
            "memory_mb": SANDBOX_MEMORY_LIMITS["standard"],
            "cpu_percent": SANDBOX_CPU_LIMITS["standard"],
            "timeout_seconds": SANDBOX_TIMEOUTS["standard"],
            "max_output_mb": SANDBOX_OUTPUT_LIMITS["standard"],
        },
        description="Resource limits for standard sandbox mode",
    )
    sandbox_limits_strict: Dict[str, int] = Field(
        default={
            "memory_mb": SANDBOX_MEMORY_LIMITS["strict"],
            "cpu_percent": SANDBOX_CPU_LIMITS["strict"],
            "timeout_seconds": SANDBOX_TIMEOUTS["strict"],
            "max_output_mb": SANDBOX_OUTPUT_LIMITS["strict"],
        },
        description="Resource limits for strict sandbox mode",
    )
    sandbox_limits_paranoid: Dict[str, int] = Field(
        default={
            "memory_mb": SANDBOX_MEMORY_LIMITS["paranoid"],
            "cpu_percent": SANDBOX_CPU_LIMITS["paranoid"],
            "timeout_seconds": SANDBOX_TIMEOUTS["paranoid"],
            "max_output_mb": SANDBOX_OUTPUT_LIMITS["paranoid"],
        },
        description="Resource limits for paranoid sandbox mode",
    )

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

    # Batch Processing
    MAX_BATCH_SIZE: int = Field(
        default=DEFAULT_MAX_BATCH_SIZE, description="Maximum files per batch"
    )
    batch_websocket_auth_enabled: bool = Field(
        default=True, description="Enable WebSocket authentication for batch jobs"
    )

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
        default=ERROR_RETENTION_DAYS, description="Days to retain conversion history"
    )

    # Logging Configuration
    logging_enabled: bool = Field(
        default=True, description="Enable file logging (False for paranoia mode)"
    )
    log_dir: str = Field(default="./logs", description="Directory for log files")
    max_log_size_mb: int = Field(
        default=10, description="Maximum size of each log file in MB"
    )
    log_backup_count: int = Field(
        default=3, description="Number of backup log files to keep"
    )
    log_retention_hours: int = Field(
        default=24, description="Hours to retain log files"
    )

    # Network Isolation
    network_verification_enabled: bool = Field(
        default=True, description="Enable network isolation verification"
    )
    network_verification_strictness: str = Field(
        default="standard",
        description="Network verification strictness: standard, strict, paranoid",
    )
    network_monitoring_enabled: bool = Field(
        default=False,
        description="Enable real-time network monitoring (strict/paranoid modes)",
    )
    network_monitoring_interval: int = Field(
        default=DEFAULT_MONITORING_INTERVAL,
        description="Network monitoring check interval in seconds",
    )
    terminate_on_network_violation: bool = Field(
        default=False,
        description="Terminate processes on network violation (paranoid mode only)",
    )

    @field_validator("env")
    @classmethod
    def validate_env(cls, v):
        allowed = ["development", "production", "testing"]
        if v not in allowed:
            raise ValueError(f"env must be one of {allowed}")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v):
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v.upper()

    @field_validator("api_port")
    @classmethod
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError("api_port must be between 1 and 65535")
        return v

    @field_validator("sandbox_strictness")
    @classmethod
    def validate_sandbox_strictness(cls, v):
        allowed = ["standard", "strict", "paranoid"]
        if v not in allowed:
            raise ValueError(f"sandbox_strictness must be one of {allowed}")
        return v

    @field_validator("network_verification_strictness")
    @classmethod
    def validate_network_strictness(cls, v):
        allowed = ["standard", "strict", "paranoid"]
        if v not in allowed:
            raise ValueError(
                f"network_verification_strictness must be one of {allowed}"
            )
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_prefix="IMAGE_CONVERTER_",
        protected_namespaces=("settings_",),
        # Disable JSON parsing for environment variables
        env_parse_none_str=None,
        json_schema_serialization_defaults_required=True,
    )

    @field_validator(
        "cors_origins", "allowed_input_formats", "allowed_output_formats", mode="before"
    )
    @classmethod
    def parse_comma_separated_list(cls, v):
        """Parse comma-separated string into list."""
        if isinstance(v, str):
            # Handle empty strings
            if not v:
                return []
            # Split by comma and strip whitespace
            return [item.strip() for item in v.split(",") if item.strip()]
        elif isinstance(v, list):
            # If already a list, return as-is
            return v
        else:
            # For any other type, try to convert to string first
            return cls.parse_comma_separated_list(str(v))

    def __init__(self, **values):
        super().__init__(**values)
        # Ensure list fields are lists after initialization
        for field in [
            "cors_origins",
            "allowed_input_formats",
            "allowed_output_formats",
        ]:
            val = getattr(self, field)
            if isinstance(val, str):
                setattr(self, field, self.parse_comma_separated_list(val))


settings = Settings()
