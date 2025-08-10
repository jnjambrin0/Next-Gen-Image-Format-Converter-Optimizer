"""Common validation and utility functions for API endpoints."""

import asyncio
from typing import Optional, Tuple
from fastapi import HTTPException, Request, UploadFile
import structlog

from app.config import settings
from app.core.security.memory import secure_clear as security_secure_clear
from app.core.constants import ALLOWED_UPLOAD_MIME_TYPES

logger = structlog.get_logger()


async def validate_uploaded_file(
    file: UploadFile,
    request: Request,
    error_prefix: str = "FILE",
    max_size: Optional[int] = None,
) -> Tuple[bytes, int]:
    """
    Validate an uploaded file and return its contents.

    Args:
        file: The uploaded file
        request: The request object for correlation ID
        error_prefix: Prefix for error codes (e.g., "DET", "REC", "CONV")
        max_size: Maximum allowed file size (defaults to settings.max_file_size)

    Returns:
        Tuple of (file contents, file size)

    Raises:
        HTTPException: If validation fails
    """
    if max_size is None:
        max_size = settings.max_file_size

    # Read file contents
    contents = await file.read()
    file_size = len(contents)

    # Validate file is not empty
    if file_size == 0:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": f"{error_prefix}400",
                "message": "The uploaded file is empty",
                "correlation_id": request.state.correlation_id,
            },
        )

    # Validate file size
    if file_size > max_size:
        raise HTTPException(
            status_code=413,
            detail={
                "error_code": f"{error_prefix}413",
                "message": f"File size exceeds maximum allowed size of {max_size / 1024 / 1024}MB",
                "correlation_id": request.state.correlation_id,
                "details": {
                    "file_size": file_size,
                    "max_size": max_size,
                },
            },
        )

    return contents, file_size


def secure_memory_clear(data: Optional[bytes]) -> None:
    """
    Securely clear sensitive data from memory using the project's standard 5-pass pattern.

    This is a wrapper around the canonical secure_clear implementation that:
    - Uses 5-pass overwrite patterns (0x00, 0xFF, 0xAA, 0x55, 0x00)
    - Handles both mutable (bytearray) and immutable (bytes) data
    - Designed to prevent memory-based data recovery attacks

    Args:
        data: The data to clear (typically image bytes)
    """
    if data is not None:
        # Use the canonical implementation from security module
        security_secure_clear(data)


class SemaphoreContextManager:
    """Context manager for safely acquiring and releasing semaphores with timeout."""

    def __init__(
        self,
        semaphore: asyncio.Semaphore,
        timeout: float,
        error_code: str,
        service_name: str,
        request: Request,
    ):
        self.semaphore = semaphore
        self.timeout = timeout
        self.error_code = error_code
        self.service_name = service_name
        self.request = request
        self.acquired = False

    async def __aenter__(self):
        try:
            await asyncio.wait_for(self.semaphore.acquire(), timeout=self.timeout)
            self.acquired = True
            return self
        except asyncio.TimeoutError:
            logger.warning(f"{self.service_name} at capacity")
            raise HTTPException(
                status_code=503,
                detail={
                    "error_code": self.error_code,
                    "message": f"{self.service_name} temporarily unavailable due to high load",
                    "correlation_id": self.request.state.correlation_id,
                },
            )

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.acquired:
            self.semaphore.release()


def validate_content_type(
    file: UploadFile, allowed_types: Optional[list] = None
) -> bool:
    """
    Validate the content type of an uploaded file.

    Args:
        file: The uploaded file
        allowed_types: List of allowed MIME types (if None, uses project defaults)

    Returns:
        True if valid, False otherwise
    """
    if allowed_types is None:
        allowed_types = ALLOWED_UPLOAD_MIME_TYPES

    if file.content_type:
        return file.content_type.lower() in [t.lower() for t in allowed_types]

    # If no content type, allow it (will be detected from content)
    return True


def create_error_response(
    status_code: int,
    error_code: str,
    message: str,
    correlation_id: str,
    details: Optional[dict] = None,
) -> dict:
    """
    Create a standardized error response.

    Args:
        status_code: HTTP status code
        error_code: Application-specific error code
        message: Human-readable error message
        correlation_id: Request correlation ID
        details: Optional additional details

    Returns:
        Error response dict
    """
    response = {
        "error_code": error_code,
        "message": message,
        "correlation_id": correlation_id,
    }

    if details:
        response["details"] = details

    return response
