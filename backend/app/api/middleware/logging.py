from fastapi import Request
from time import time
import uuid
from typing import Callable

from ...utils.logging import get_logger, LoggingContext

logger = get_logger(__name__)


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

            # Log response
            logger.info(
                "Request completed",
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
                **request_info
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
