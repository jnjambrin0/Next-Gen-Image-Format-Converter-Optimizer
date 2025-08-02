"""
Standardized security error handling for the image converter.

This module provides a consistent error handling framework for all
security-related errors with privacy-aware messaging.
"""

import asyncio
from enum import Enum
from typing import Optional, Dict, Any, Type
import traceback
import structlog

logger = structlog.get_logger()


class SecurityErrorCode(Enum):
    """Standardized security error codes."""
    
    # Network-related errors
    NETWORK_ACCESS_DENIED = "SEC001"
    DNS_RESOLUTION_BLOCKED = "SEC002"
    SOCKET_CREATION_BLOCKED = "SEC003"
    P2P_MODULE_BLOCKED = "SEC004"
    NETWORK_VIOLATION = "SEC005"
    
    # Verification errors
    VERIFICATION_FAILED = "SEC010"
    VERIFICATION_TIMEOUT = "SEC011"
    VERIFICATION_CONFIG_ERROR = "SEC012"
    
    # Monitoring errors
    MONITORING_ERROR = "SEC020"
    MONITORING_PROCESS_ERROR = "SEC021"
    MONITORING_RESOURCE_ERROR = "SEC022"
    
    # Rate limiting errors
    RATE_LIMIT_EXCEEDED = "SEC030"
    RATE_LIMIT_CONFIG_ERROR = "SEC031"
    
    # Sandbox errors
    SANDBOX_VIOLATION = "SEC040"
    SANDBOX_TIMEOUT = "SEC041"
    SANDBOX_MEMORY_VIOLATION = "SEC042"
    SANDBOX_CPU_VIOLATION = "SEC043"
    SANDBOX_OUTPUT_VIOLATION = "SEC044"
    SANDBOX_PROCESS_ERROR = "SEC045"
    
    # File/Path errors
    PATH_TRAVERSAL_ATTEMPT = "SEC050"
    INVALID_FILE_ACCESS = "SEC051"
    SUSPICIOUS_FILE_CONTENT = "SEC052"
    
    # Memory errors
    MEMORY_LOCK_FAILED = "SEC060"
    MEMORY_CLEAR_FAILED = "SEC061"
    MEMORY_TRACKING_ERROR = "SEC062"
    
    # Generic errors
    UNKNOWN_SECURITY_ERROR = "SEC999"


class SecurityError(Exception):
    """
    Base security exception with standardized handling.
    
    All security errors should inherit from this class to ensure
    consistent error handling and privacy-aware messaging.
    """
    
    def __init__(
        self,
        code: SecurityErrorCode,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        """
        Initialize security error.
        
        Args:
            code: Security error code
            message: Privacy-safe error message (no PII)
            details: Additional error details (no PII)
            cause: Original exception that caused this error
        """
        self.code = code
        self.message = message
        self.details = details or {}
        self.cause = cause
        
        # Construct full message
        full_message = self.format_message()
        super().__init__(full_message)
        
        # Log the error (privacy-aware)
        self._log_error()
    
    def format_message(self) -> str:
        """Format error message with code."""
        return f"[{self.code.value}] {self.message}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "error": "security_error",
            "code": self.code.value,
            "message": self.message,
            "details": self.details
        }
    
    def _log_error(self) -> None:
        """Log error with appropriate context."""
        log_data = {
            "error_code": self.code.value,
            "error_type": self.__class__.__name__,
            **self.details
        }
        
        # Add cause information if available
        if self.cause:
            log_data["cause_type"] = type(self.cause).__name__
            log_data["cause_message"] = str(self.cause)[:100]  # Truncate
        
        logger.error(self.message, **log_data)


# Specific error classes for different security domains

class NetworkSecurityError(SecurityError):
    """Network-related security errors."""
    pass


class SandboxSecurityError(SecurityError):
    """Sandbox-related security errors."""
    pass


class RateLimitError(SecurityError):
    """Rate limiting errors."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        details: Optional[Dict[str, Any]] = None,
        retry_after: Optional[int] = None
    ):
        """
        Initialize rate limit error.
        
        Args:
            message: Error message
            details: Additional details
            retry_after: Seconds until retry is allowed
        """
        if retry_after:
            details = details or {}
            details["retry_after"] = retry_after
            
        super().__init__(
            code=SecurityErrorCode.RATE_LIMIT_EXCEEDED,
            message=message,
            details=details
        )


class VerificationError(SecurityError):
    """Verification-related errors."""
    pass


class MemorySecurityError(SecurityError):
    """Memory security errors."""
    pass


# Error factory functions

def create_network_error(
    message: str,
    code: SecurityErrorCode = SecurityErrorCode.NETWORK_ACCESS_DENIED,
    **details
) -> NetworkSecurityError:
    """Create a network security error."""
    return NetworkSecurityError(
        code=code,
        message=message,
        details=details
    )


def create_sandbox_error(
    message: str,
    code: SecurityErrorCode = SecurityErrorCode.SANDBOX_VIOLATION,
    **details
) -> SandboxSecurityError:
    """Create a sandbox security error."""
    return SandboxSecurityError(
        code=code,
        message=message,
        details=details
    )


def create_verification_error(
    message: str,
    code: SecurityErrorCode = SecurityErrorCode.VERIFICATION_FAILED,
    **details
) -> VerificationError:
    """Create a verification error."""
    return VerificationError(
        code=code,
        message=message,
        details=details
    )


# Error handlers

class SecurityErrorHandler:
    """
    Centralized security error handler.
    
    Provides consistent error handling, logging, and response
    formatting for all security errors.
    """
    
    def __init__(self, log_errors: bool = True):
        """
        Initialize error handler.
        
        Args:
            log_errors: Whether to log errors
        """
        self.log_errors = log_errors
        self._error_counts: Dict[str, int] = {}
    
    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Handle an error and return standardized response.
        
        Args:
            error: The error to handle
            context: Additional context for error handling
            
        Returns:
            Standardized error response
        """
        context = context or {}
        
        # Handle SecurityError instances
        if isinstance(error, SecurityError):
            return self._handle_security_error(error, context)
        
        # Handle other known error types
        error_mapping = {
            TimeoutError: (SecurityErrorCode.SANDBOX_TIMEOUT, "Operation timed out"),
            MemoryError: (SecurityErrorCode.SANDBOX_MEMORY_VIOLATION, "Memory limit exceeded"),
            PermissionError: (SecurityErrorCode.INVALID_FILE_ACCESS, "Permission denied"),
            ValueError: (SecurityErrorCode.UNKNOWN_SECURITY_ERROR, "Invalid input"),
        }
        
        for error_type, (code, message) in error_mapping.items():
            if isinstance(error, error_type):
                security_error = SecurityError(
                    code=code,
                    message=message,
                    details=context,
                    cause=error
                )
                return self._handle_security_error(security_error, context)
        
        # Handle unknown errors
        security_error = SecurityError(
            code=SecurityErrorCode.UNKNOWN_SECURITY_ERROR,
            message="An unexpected security error occurred",
            details=context,
            cause=error
        )
        return self._handle_security_error(security_error, context)
    
    def _handle_security_error(
        self,
        error: SecurityError,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle a SecurityError instance."""
        # Track error counts
        error_code = error.code.value
        self._error_counts[error_code] = self._error_counts.get(error_code, 0) + 1
        
        # Create response
        response = error.to_dict()
        response["request_id"] = context.get("request_id")
        
        return response
    
    def get_error_stats(self) -> Dict[str, int]:
        """Get error statistics."""
        return self._error_counts.copy()
    
    @staticmethod
    def format_traceback(exc: Exception, limit: int = 3) -> str:
        """
        Format exception traceback in privacy-safe way.
        
        Args:
            exc: Exception to format
            limit: Number of stack frames to include
            
        Returns:
            Formatted traceback without sensitive paths
        """
        tb_lines = traceback.format_exception(
            type(exc), exc, exc.__traceback__, limit=limit
        )
        
        # Sanitize paths in traceback
        sanitized_lines = []
        for line in tb_lines:
            # Replace absolute paths with relative ones
            if "/home/" in line or "/Users/" in line:
                line = line.split("/app/")[-1] if "/app/" in line else "..."
            sanitized_lines.append(line)
        
        return "".join(sanitized_lines)


# Global error handler instance
error_handler = SecurityErrorHandler()


# Decorator for automatic error handling
def handle_security_errors(
    default_code: SecurityErrorCode = SecurityErrorCode.UNKNOWN_SECURITY_ERROR,
    default_message: str = "A security error occurred"
):
    """
    Decorator to automatically handle security errors.
    
    Args:
        default_code: Default error code if none specified
        default_message: Default message if none specified
    """
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except SecurityError:
                raise  # Re-raise security errors as-is
            except Exception as e:
                raise SecurityError(
                    code=default_code,
                    message=default_message,
                    cause=e
                )
        
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except SecurityError:
                raise  # Re-raise security errors as-is
            except Exception as e:
                raise SecurityError(
                    code=default_code,
                    message=default_message,
                    cause=e
                )
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator