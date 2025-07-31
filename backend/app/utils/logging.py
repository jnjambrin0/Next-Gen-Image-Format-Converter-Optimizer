import structlog
import logging
import sys
from typing import Dict, Any, Optional
import uuid


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
        "user_id",
        "email",
        "ip_address",
    }

    for key in list(event_dict.keys()):
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            event_dict[key] = "***REDACTED***"

    return event_dict


def add_correlation_id(_, __, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add correlation ID to log entries."""
    if "correlation_id" not in event_dict:
        # Try to get from context, otherwise generate new
        event_dict["correlation_id"] = structlog.contextvars.get_contextvars().get(
            "correlation_id", str(uuid.uuid4())
        )
    return event_dict


def setup_logging(log_level: str = "INFO", json_logs: bool = True) -> None:
    """Configure structured logging for the application."""

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

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper()),
    )

    # Suppress noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)


def get_logger(name: Optional[str] = None) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance."""
    return structlog.get_logger(name)


class LoggingContext:
    """Context manager for adding context to logs."""

    def __init__(self, **kwargs):
        self.context = kwargs
        self.tokens = []

    def __enter__(self):
        for key, value in self.context.items():
            token = structlog.contextvars.bind_contextvars(**{key: value})
            self.tokens.append(token)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for token in self.tokens:
            structlog.contextvars.unbind_contextvars(token)
