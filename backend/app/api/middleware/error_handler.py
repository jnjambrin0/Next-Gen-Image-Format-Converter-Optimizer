import json
import traceback
import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ...core.exceptions import ImageConverterError
from ...models.responses import ErrorResponse
from ..routes.monitoring import error_reporter

logger = structlog.get_logger()


async def error_handler_middleware(request: Request, call_next):
    """Global error handling middleware."""
    correlation_id = str(uuid.uuid4())
    request.state.correlation_id = correlation_id

    try:
        response = await call_next(request)
        return response
    except Exception as exc:
        return await handle_exception(exc, correlation_id)


async def handle_exception(exc: Exception, correlation_id: str) -> JSONResponse:
    """Handle exceptions and return formatted error response using ErrorResponse model."""
    # Default error response
    error_code = "SRV500"
    message = "An unexpected error occurred"
    details = None
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    # Record error for local monitoring (privacy-safe)
    try:
        context = {
            "correlation_id": correlation_id,
            "error_type": type(exc).__name__,
        }
        await error_reporter.record_error(exc, context)
    except Exception as e:
        logger.warning("Failed to record error", error=str(e))

    # Handle custom exceptions
    if isinstance(exc, ImageConverterError):
        error_code = exc.error_code
        message = exc.message
        details = exc.details
        status_code = exc.status_code
        logger.bind(
            correlation_id=correlation_id,
            error_code=exc.error_code,
            error_type=exc.__class__.__name__,
        ).warning("Application error", message=exc.message)

    # Handle FastAPI validation errors
    elif isinstance(exc, RequestValidationError):
        error_code = "VAL422"
        message = "Request validation failed"
        details = {"validation_errors": exc.errors()}
        status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        logger.bind(
            correlation_id=correlation_id, validation_errors=exc.errors()
        ).warning("Request validation error")

    # Handle Starlette HTTP exceptions (including FastAPI HTTPException)
    elif isinstance(exc, StarletteHTTPException):
        error_code = f"HTTP{exc.status_code}"
        status_code = exc.status_code

        # Check if detail is already in ErrorResponse format (from our APIError)
        if isinstance(exc.detail, dict) and "error_code" in exc.detail:
            # Use the standardized error format from APIError/endpoint
            error_response = ErrorResponse(**exc.detail)
            return JSONResponse(
                status_code=status_code,
                content=json.loads(error_response.json()),
                headers={"X-Correlation-ID": correlation_id},
            )
        else:
            # Legacy format - convert to standard
            message = str(exc.detail) if exc.detail else "HTTP error"

        logger.bind(correlation_id=correlation_id, status_code=exc.status_code).warning(
            "HTTP exception", detail=exc.detail
        )

    # Handle all other exceptions
    else:
        logger.bind(
            correlation_id=correlation_id,
            error_type=type(exc).__name__,
            traceback=traceback.format_exc(),
        ).error("Unexpected error", error=str(exc))

    # Create standardized error response
    error_response = ErrorResponse(
        error_code=error_code,
        message=message,
        correlation_id=correlation_id,
        details=details,
        timestamp=datetime.utcnow(),
    )

    return JSONResponse(
        status_code=status_code,
        content=json.loads(error_response.json()),
        headers={"X-Correlation-ID": correlation_id},
    )


def setup_exception_handlers(app) -> None:
    """Set up exception handlers for the FastAPI app."""

    @app.exception_handler(ImageConverterError)
    async def custom_exception_handler(request: Request, exc: ImageConverterError):
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        return await handle_exception(exc, correlation_id)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ):
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        return await handle_exception(exc, correlation_id)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        return await handle_exception(exc, correlation_id)

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        correlation_id = getattr(request.state, "correlation_id", str(uuid.uuid4()))
        return await handle_exception(exc, correlation_id)
