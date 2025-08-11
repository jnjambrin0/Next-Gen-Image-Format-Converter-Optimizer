"""
Simplified security error handling for the image converter.

This module provides a category-based error handling framework for all
security-related errors with privacy-aware messaging.
"""

import asyncio
import traceback
from typing import Any, Dict, Optional

import structlog

logger = structlog.get_logger()


class SecurityError(Exception):
    """Base security error with category-based approach."""

    CATEGORIES = {
        "network": "Network access violation",
        "sandbox": "Sandbox security violation",
        "rate_limit": "Rate limit exceeded",
        "verification": "Security verification failed",
        "file": "File security violation",
    }

    def __init__(
        self,
        category: str,
        details: Optional[Dict[str, Any]] = None,
        message: Optional[str] = None,
    ):
        """
        Initialize security error.

        Args:
            category: Error category (network, sandbox, rate_limit, verification, file)
            details: Optional context details (no PII allowed)
            message: Optional custom message (defaults to category description)
        """
        self.category = category
        self.details = details or {}

        # Use custom message or default category description
        error_message = message or self.CATEGORIES.get(category, "Security violation")
        super().__init__(error_message)

        # Log error with category and details (no PII)
        logger.warning("Security error occurred", category=category, **self.details)


def create_network_error(reason: str = "access_denied", **kwargs) -> SecurityError:
    """Create a network security error."""
    details = {"reason": reason, **kwargs}
    return SecurityError("network", details)


def create_sandbox_error(reason: str = "violation", **kwargs) -> SecurityError:
    """Create a sandbox security error."""
    details = {"reason": reason, **kwargs}
    return SecurityError("sandbox", details)


def create_rate_limit_error(limit_type: str = "request", **kwargs) -> SecurityError:
    """Create a rate limit error."""
    details = {"limit_type": limit_type, **kwargs}
    return SecurityError("rate_limit", details)


def create_verification_error(check_type: str = "unknown", **kwargs) -> SecurityError:
    """Create a verification error."""
    details = {"check_type": check_type, **kwargs}
    return SecurityError("verification", details)


def create_file_error(operation: str = "access", **kwargs) -> SecurityError:
    """Create a file security error."""
    details = {"operation": operation, **kwargs}
    return SecurityError("file", details)


class SecurityErrorHandler:
    """Handler for consistent security error responses."""

    @staticmethod
    def handle_error(error: Exception) -> Dict[str, Any]:
        """
        Convert an exception to a standardized error response.

        Args:
            error: The exception to handle

        Returns:
            Dict with error details (no PII)
        """
        if isinstance(error, SecurityError):
            return {
                "error": "security_violation",
                "category": error.category,
                "message": str(error),
                "details": error.details,
            }

        # Handle specific Python exceptions
        error_mappings = {
            TimeoutError: ("sandbox", "timeout"),
            MemoryError: ("sandbox", "memory_limit"),
            PermissionError: ("file", "permission_denied"),
            OSError: ("network", "system_error"),
            asyncio.TimeoutError: ("sandbox", "async_timeout"),
        }

        for error_type, (category, reason) in error_mappings.items():
            if isinstance(error, error_type):
                return {
                    "error": "security_violation",
                    "category": category,
                    "message": SecurityError.CATEGORIES[category],
                    "details": {"reason": reason},
                }

        # Unknown error - don't expose details
        logger.error("Unexpected error in security module", error=str(error))
        return {
            "error": "security_violation",
            "category": "unknown",
            "message": "Security check failed",
            "details": {},
        }


def handle_security_errors(func):
    """
    Decorator to handle security errors consistently.

    Wraps async functions to catch and convert exceptions to SecurityError.
    """

    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except SecurityError:
            raise  # Re-raise security errors as-is
        except Exception as e:
            # Convert to security error
            handler = SecurityErrorHandler()
            error_info = handler.handle_error(e)
            raise SecurityError(
                error_info["category"], error_info["details"], error_info["message"]
            )

    return wrapper
