from fastapi import Request
from time import time
import uuid
from typing import Callable

from ...utils.logging import get_logger, LoggingContext
from ...services.api_key_service import api_key_service

logger = get_logger(__name__)


def _sanitize_endpoint_path(path: str) -> str:
    """Sanitize endpoint path for statistics by removing IDs and sensitive data.

    Args:
        path: Original endpoint path

    Returns:
        Sanitized path with IDs replaced by placeholders
    """
    import re

    # Replace UUIDs with placeholder
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/{id}", path
    )

    # Replace numeric IDs with placeholder
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)

    # Replace file indexes in batch endpoints
    path = re.sub(r"/items/\d+", "/items/{index}", path)

    # Remove query parameters if any got through
    if "?" in path:
        path = path.split("?")[0]

    return path


async def logging_middleware(request: Request, call_next: Callable):
    """Log all requests and responses with correlation ID."""
    start_time = time()

    # Generate correlation ID if not present
    correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
    request.state.correlation_id = correlation_id

    # Extract request metadata (privacy-aware)
    request_info = {
        "method": request.method,
        "path": request.url.path,
        "query_params": dict(request.query_params) if request.query_params else {},
        "correlation_id": correlation_id,
    }

    # Log request
    with LoggingContext(correlation_id=correlation_id):
        logger.info("Request received", **request_info)

        try:
            # Process request
            response = await call_next(request)

            # Calculate duration
            duration_ms = (time() - start_time) * 1000

            # Get API key info for privacy-aware logging
            api_key_record = getattr(request.state, "api_key", None)
            api_key_id = api_key_record.id if api_key_record else None

            # Enhanced logging with API key context (privacy-aware)
            log_data = {
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "authenticated": getattr(request.state, "authenticated", False),
                **request_info,
            }

            # Add API key hash for correlation (never log the actual key)
            if api_key_record:
                log_data["api_key_hash"] = api_key_record.key_hash[
                    :8
                ]  # First 8 chars for correlation

            # Log response
            logger.info("Request completed", **log_data)

            # Record API usage statistics (async, non-blocking)
            try:
                # Sanitize endpoint path for statistics (remove IDs, etc.)
                sanitized_path = _sanitize_endpoint_path(request.url.path)

                api_key_service.record_usage(
                    api_key_id=api_key_id,
                    endpoint=sanitized_path,
                    method=request.method,
                    status_code=response.status_code,
                    response_time_ms=int(duration_ms),
                )
            except Exception as usage_error:
                # Don't let usage tracking failures break the API
                logger.warning(
                    "Failed to record API usage statistics",
                    error=str(usage_error),
                    correlation_id=correlation_id,
                )

            # Add correlation ID to response headers
            response.headers["X-Correlation-ID"] = correlation_id

            return response

        except Exception as exc:
            # Calculate duration
            duration_ms = (time() - start_time) * 1000

            # Log error
            logger.error(
                "Request failed",
                error=str(exc),
                duration_ms=round(duration_ms, 2),
                **request_info
            )

            # Re-raise to be handled by error middleware
            raise
