import logging
import logging.handlers
import os
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import structlog


def filter_sensitive_data(_, __, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Remove or mask sensitive data from logs."""
    sensitive_keys = {
        "password",
        "token",
        "api_key",
        "secret",
        "authorization",
        "file_path",
        "filename",
        "file_name",
        "path",
        "user_id",
        "email",
        "ip_address",
        "exif",
        "metadata",
        "gps",
        "location",
        "coordinates",
        "content",
        "image_data",
        "hash",
        "checksum",
        "directory",
        "folder",
        "username",
        "name",
    }

    def _recursive_filter(obj: Any, depth: int = 0) -> Any:
        """Recursively filter sensitive data from nested structures."""
        if depth > 10:  # Prevent infinite recursion
            return "***DEPTH_LIMIT***"

        if isinstance(obj, dict):
            filtered = {}
            for key, value in obj.items():
                # Check if key contains sensitive information
                key_lower = str(key).lower()
                # Special handling for metadata-related keys
                if "metadata" in key_lower or "exif" in key_lower:
                    filtered[key] = "***REDACTED***"
                elif any(
                    sensitive == key_lower
                    or f"_{sensitive}" in key_lower
                    or f"{sensitive}_" in key_lower
                    for sensitive in sensitive_keys
                ):
                    filtered[key] = "***REDACTED***"
                else:
                    # Recursively filter the value
                    filtered[key] = _recursive_filter(value, depth + 1)
            return filtered
        elif isinstance(obj, list):
            return [_recursive_filter(item, depth + 1) for item in obj]
        elif isinstance(obj, str):
            # Check for patterns that might contain PII
            import re

            # File path patterns (Unix and Windows)
            if re.match(r"^(/|[A-Za-z]:\\|\\\\)", obj):
                return "***PATH_REDACTED***"
            # Email pattern
            if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", obj):
                return "***EMAIL_REDACTED***"
            # IP address pattern
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", obj):
                return "***IP_REDACTED***"
            # File extensions that might indicate file names
            if re.search(
                r"\.(jpg|jpeg|png|gif|webp|heic|heif|avif|bmp|tiff)$",
                obj,
                re.IGNORECASE,
            ):
                return "***FILENAME_REDACTED***"
        return obj

    return _recursive_filter(event_dict)


def add_correlation_id(_, __, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add correlation ID to log entries."""
    if "correlation_id" not in event_dict:
        # Try to get from context, otherwise generate new
        event_dict["correlation_id"] = structlog.contextvars.get_contextvars().get(
            "correlation_id", str(uuid.uuid4())
        )
    return event_dict


def setup_logging(
    log_level: str = "INFO",
    json_logs: bool = True,
    enable_file_logging: bool = True,
    log_dir: str = "./logs",
    max_log_size_mb: int = 10,
    backup_count: int = 3,
    retention_hours: int = 24,
) -> None:
    """Configure structured logging for the application with privacy-focused features.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_logs: Use JSON format for logs
        enable_file_logging: Enable logging to files (disabled in paranoia mode)
        log_dir: Directory for log files
        max_log_size_mb: Maximum size of each log file in MB
        backup_count: Number of backup files to keep
        retention_hours: Hours to retain logs (for scheduled cleanup)
    """
    # Skip file logging if disabled (paranoia mode)
    handlers = []

    # Always use stderr for console output
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    handlers.append(console_handler)

    # Add file handler if enabled
    if enable_file_logging:
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "app.log")

        # Rotating file handler with size-based rotation
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=max_log_size_mb * 1024 * 1024,  # Convert MB to bytes
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(getattr(logging, log_level.upper()))
        handlers.append(file_handler)

    # Configure structlog
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        add_correlation_id,
        filter_sensitive_data,
    ]

    if json_logs:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging with handlers
    logging.basicConfig(
        format="%(message)s",
        handlers=handlers,
        level=getattr(logging, log_level.upper()),
        force=True,  # Force reconfiguration
    )

    # Suppress noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)
    logging.getLogger("multipart").setLevel(logging.WARNING)


def get_logger(name: Optional[str] = None) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance."""
    return structlog.get_logger(name)


class LoggingContext:
    """Context manager for adding context to logs."""

    def __init__(self, **kwargs) -> None:
        self.context = kwargs
        self.tokens = []

    def __enter__(self) -> None:
        for key, value in self.context.items():
            token = structlog.contextvars.bind_contextvars(**{key: value})
            self.tokens.append(token)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        for token in self.tokens:
            structlog.contextvars.unbind_contextvars(token)


def cleanup_old_logs(log_dir: str, retention_hours: int = 24) -> None:
    """Clean up log files older than retention period.

    Args:
        log_dir: Directory containing log files
        retention_hours: Hours to retain logs
    """
    if not os.path.exists(log_dir):
        return

    cutoff_time = datetime.now() - timedelta(hours=retention_hours)

    for filename in os.listdir(log_dir):
        if filename.endswith(".log"):
            filepath = os.path.join(log_dir, filename)
            try:
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                if file_time < cutoff_time:
                    os.remove(filepath)
                    # Use print instead of logging to avoid recursion
                    print(f"Cleaned up old log file: {filename}")
            except Exception:
                # Silently ignore errors during cleanup
                pass
