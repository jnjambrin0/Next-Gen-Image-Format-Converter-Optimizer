from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import traceback
import uuid
from typing import Dict, Any
import logging

from ...core.exceptions import ImageConverterError

logger = logging.getLogger(__name__)


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
    """Handle exceptions and return formatted error response."""
    error_response: Dict[str, Any] = {
        "correlation_id": correlation_id,
        "error": {
            "message": "An unexpected error occurred",
            "code": "CONV999",
            "type": "InternalServerError",
        },
    }

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    # Handle custom exceptions
    if isinstance(exc, ImageConverterError):
        error_response["error"] = {
            "message": exc.message,
            "code": exc.error_code,
            "type": exc.__class__.__name__,
            "details": exc.details,
        }
        status_code = exc.status_code
        logger.warning(
            f"Application error: {exc.message}",
            extra={
                "correlation_id": correlation_id,
                "error_code": exc.error_code,
                "error_type": exc.__class__.__name__,
            },
        )

    # Handle FastAPI validation errors
    elif isinstance(exc, RequestValidationError):
        error_response["error"] = {
            "message": "Validation error",
            "code": "CONV002",
            "type": "ValidationError",
            "details": {"validation_errors": exc.errors()},
        }
        status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        logger.warning(
            "Request validation error",
            extra={"correlation_id": correlation_id, "validation_errors": exc.errors()},
        )

    # Handle Starlette HTTP exceptions
    elif isinstance(exc, StarletteHTTPException):
        error_response["error"] = {
            "message": exc.detail,
            "code": f"HTTP{exc.status_code}",
            "type": "HTTPException",
        }
        status_code = exc.status_code
        logger.warning(
            f"HTTP exception: {exc.detail}",
            extra={"correlation_id": correlation_id, "status_code": exc.status_code},
        )

    # Handle all other exceptions
    else:
        logger.error(
            f"Unexpected error: {str(exc)}",
            extra={
                "correlation_id": correlation_id,
                "traceback": traceback.format_exc(),
            },
        )

    return JSONResponse(
        status_code=status_code,
        content=error_response,
        headers={"X-Correlation-ID": correlation_id},
    )


def setup_exception_handlers(app):
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
