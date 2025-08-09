"""Standardized error handling utilities for consistent API responses."""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

import structlog
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from app.models.responses import ErrorResponse

logger = structlog.get_logger()


class APIError(HTTPException):
    """Standardized API error that uses ErrorResponse format."""

    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.error_code = error_code
        self.error_message = message
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.error_details = details

        # Create ErrorResponse for detail
        error_response = ErrorResponse(
            error_code=error_code,
            message=message,
            correlation_id=self.correlation_id,
            details=details,
            timestamp=datetime.utcnow(),
        )

        super().__init__(status_code=status_code, detail=error_response.dict())


class ErrorFactory:
    """Factory for creating standardized API errors."""

    @staticmethod
    def create_validation_error(
        message: str,
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> APIError:
        """Create a 400 validation error."""
        return APIError(
            status_code=400,
            error_code=error_code or "VAL400",
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    @staticmethod
    def create_unauthorized_error(
        message: str = "Authentication required",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> APIError:
        """Create a 401 authentication error."""
        return APIError(
            status_code=401,
            error_code=error_code or "AUTH401",
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    @staticmethod
    def create_forbidden_error(
        message: str = "Access denied",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> APIError:
        """Create a 403 authorization error."""
        return APIError(
            status_code=403,
            error_code=error_code or "AUTH403",
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    @staticmethod
    def create_not_found_error(
        message: str = "Resource not found",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> APIError:
        """Create a 404 not found error."""
        return APIError(
            status_code=404,
            error_code=error_code or "RES404",
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    @staticmethod
    def create_conflict_error(
        message: str = "Resource conflict",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> APIError:
        """Create a 409 conflict error."""
        return APIError(
            status_code=409,
            error_code=error_code or "RES409",
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    @staticmethod
    def create_payload_too_large_error(
        message: str = "Payload too large",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> APIError:
        """Create a 413 payload too large error."""
        return APIError(
            status_code=413,
            error_code=error_code or "REQ413",
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    @staticmethod
    def create_unsupported_media_type_error(
        message: str = "Unsupported media type",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> APIError:
        """Create a 415 unsupported media type error."""
        return APIError(
            status_code=415,
            error_code=error_code or "REQ415",
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    @staticmethod
    def create_unprocessable_entity_error(
        message: str = "Unprocessable entity",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> APIError:
        """Create a 422 unprocessable entity error."""
        return APIError(
            status_code=422,
            error_code=error_code or "VAL422",
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    @staticmethod
    def create_rate_limit_error(
        message: str = "Rate limit exceeded",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
        retry_after: Optional[int] = None,
    ) -> APIError:
        """Create a 429 rate limit error."""
        error_details = details or {}
        if retry_after:
            error_details["retry_after"] = retry_after

        return APIError(
            status_code=429,
            error_code=error_code or "RATE429",
            message=message,
            correlation_id=correlation_id,
            details=error_details,
        )

    @staticmethod
    def create_internal_server_error(
        message: str = "Internal server error",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> APIError:
        """Create a 500 internal server error."""
        return APIError(
            status_code=500,
            error_code=error_code or "SRV500",
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    @staticmethod
    def create_service_unavailable_error(
        message: str = "Service temporarily unavailable",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
        retry_after: Optional[int] = None,
    ) -> APIError:
        """Create a 503 service unavailable error."""
        error_details = details or {}
        if retry_after:
            error_details["retry_after"] = retry_after

        return APIError(
            status_code=503,
            error_code=error_code or "SRV503",
            message=message,
            correlation_id=correlation_id,
            details=error_details,
        )


def get_correlation_id(request: Request) -> str:
    """Get correlation ID from request, generating one if needed."""
    correlation_id = getattr(request.state, "correlation_id", None)
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id
    return correlation_id


def log_api_error(
    error_code: str,
    message: str,
    correlation_id: str,
    status_code: int,
    details: Optional[Dict[str, Any]] = None,
    endpoint: Optional[str] = None,
):
    """Log API error in a consistent format."""
    log_data = {
        "error_code": error_code,
        "status_code": status_code,
        "correlation_id": correlation_id,
        "endpoint": endpoint,
    }

    if details:
        log_data["details"] = details

    # Choose log level based on status code
    if status_code >= 500:
        logger.error("API server error", message=message, **log_data)
    elif status_code >= 400:
        logger.warning("API client error", message=message, **log_data)
    else:
        logger.info("API response", message=message, **log_data)


# Error code patterns for different service areas
ERROR_CODE_PATTERNS = {
    "conversion": "CONV",
    "detection": "DET",
    "recommendation": "REC",
    "compatibility": "COMP",
    "batch": "BAT",
    "preset": "PRE",
    "intelligence": "INT",
    "optimization": "OPT",
    "monitoring": "MON",
    "security": "SEC",
    "validation": "VAL",
    "authentication": "AUTH",
    "authorization": "AUTHZ",
    "resource": "RES",
    "request": "REQ",
    "server": "SRV",
    "rate_limit": "RATE",
}


def generate_error_code(
    service_area: str, status_code: int, sequence: Optional[int] = None
) -> str:
    """Generate standardized error code."""
    prefix = ERROR_CODE_PATTERNS.get(service_area, service_area.upper())
    if sequence:
        return f"{prefix}{status_code}_{sequence:02d}"
    return f"{prefix}{status_code}"


class EndpointErrorHandler:
    """Helper class for handling errors within endpoint functions."""

    def __init__(self, service_area: str, endpoint_name: str):
        self.service_area = service_area
        self.endpoint_name = endpoint_name

    def create_error(
        self,
        status_code: int,
        message: str,
        request: Request,
        sequence: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> APIError:
        """Create a standardized error for this endpoint."""
        correlation_id = get_correlation_id(request)
        error_code = generate_error_code(self.service_area, status_code, sequence)

        # Log the error
        log_api_error(
            error_code=error_code,
            message=message,
            correlation_id=correlation_id,
            status_code=status_code,
            details=details,
            endpoint=self.endpoint_name,
        )

        return APIError(
            status_code=status_code,
            error_code=error_code,
            message=message,
            correlation_id=correlation_id,
            details=details,
        )

    def validation_error(
        self,
        message: str,
        request: Request,
        details: Optional[Dict[str, Any]] = None,
    ) -> APIError:
        """Create a validation error (400)."""
        return self.create_error(400, message, request, details=details)

    def payload_too_large_error(
        self,
        message: str,
        request: Request,
        details: Optional[Dict[str, Any]] = None,
    ) -> APIError:
        """Create a payload too large error (413)."""
        return self.create_error(413, message, request, details=details)

    def unsupported_media_type_error(
        self,
        message: str,
        request: Request,
        details: Optional[Dict[str, Any]] = None,
    ) -> APIError:
        """Create an unsupported media type error (415)."""
        return self.create_error(415, message, request, details=details)

    def unprocessable_entity_error(
        self,
        message: str,
        request: Request,
        details: Optional[Dict[str, Any]] = None,
    ) -> APIError:
        """Create an unprocessable entity error (422)."""
        return self.create_error(422, message, request, details=details)

    def internal_server_error(
        self,
        message: str,
        request: Request,
        details: Optional[Dict[str, Any]] = None,
    ) -> APIError:
        """Create an internal server error (500)."""
        return self.create_error(500, message, request, details=details)

    def service_unavailable_error(
        self,
        message: str,
        request: Request,
        details: Optional[Dict[str, Any]] = None,
        retry_after: Optional[int] = None,
    ) -> APIError:
        """Create a service unavailable error (503)."""
        error_details = details or {}
        if retry_after:
            error_details["retry_after"] = retry_after
        return self.create_error(503, message, request, details=error_details)
