from typing import Optional, Dict, Any


class ImageConverterError(Exception):
    """Base exception for all Image Converter errors."""

    def __init__(
        self,
        message: str,
        error_code: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}


class ConversionError(ImageConverterError):
    """Raised when image conversion fails."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message, error_code="CONV001", status_code=422, details=details
        )


class ValidationError(ImageConverterError):
    """Raised when input validation fails."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message, error_code="CONV002", status_code=400, details=details
        )


class SecurityError(ImageConverterError):
    """Raised when security checks fail."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message, error_code="CONV003", status_code=403, details=details
        )


class ResourceLimitError(ImageConverterError):
    """Raised when resource limits are exceeded."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message, error_code="CONV004", status_code=413, details=details
        )


class FormatNotSupportedError(ImageConverterError):
    """Raised when image format is not supported."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message, error_code="CONV005", status_code=415, details=details
        )


class ProcessingTimeoutError(ImageConverterError):
    """Raised when processing exceeds timeout."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message, error_code="CONV006", status_code=408, details=details
        )


class ConfigurationError(ImageConverterError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message, error_code="CONV007", status_code=500, details=details
        )
