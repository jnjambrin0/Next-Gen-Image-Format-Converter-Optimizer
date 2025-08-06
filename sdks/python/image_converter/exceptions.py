"""Exception classes for Image Converter SDK - Privacy-aware error handling."""

from typing import Optional, Dict, Any


class ImageConverterError(Exception):
    """Base exception for all Image Converter SDK errors."""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize exception with privacy-aware message.
        
        Args:
            message: Error message (must not contain PII)
            error_code: Error category code
            details: Additional error details (no PII)
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        
    def __str__(self) -> str:
        """Return privacy-safe string representation."""
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message


class NetworkSecurityError(ImageConverterError):
    """Raised when attempting to connect to non-localhost addresses."""
    
    def __init__(self, message: str = "Network access blocked - only localhost connections allowed"):
        super().__init__(message, error_code="network")


class RateLimitError(ImageConverterError):
    """Raised when API rate limit is exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
    ):
        details = {}
        if retry_after:
            details["retry_after"] = retry_after
        super().__init__(message, error_code="rate_limit", details=details)


class ValidationError(ImageConverterError):
    """Raised when request validation fails."""
    
    def __init__(self, message: str = "Invalid request parameters"):
        super().__init__(message, error_code="verification")


class ServiceUnavailableError(ImageConverterError):
    """Raised when the local service is unavailable."""
    
    def __init__(self, message: str = "Local service temporarily unavailable"):
        super().__init__(message, error_code="service_unavailable")


class FileError(ImageConverterError):
    """Raised for file-related errors."""
    
    def __init__(self, message: str = "File operation failed"):
        # Never include filename in error message for privacy
        super().__init__(message, error_code="file")


class SandboxError(ImageConverterError):
    """Raised when sandbox security is violated."""
    
    def __init__(self, message: str = "Security sandbox violation"):
        super().__init__(message, error_code="sandbox")