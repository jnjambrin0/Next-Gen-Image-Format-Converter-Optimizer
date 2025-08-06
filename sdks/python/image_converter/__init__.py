"""Image Converter SDK for Python - Local-only, privacy-focused image conversion."""

from .client import ImageConverterClient
from .async_client import AsyncImageConverterClient
from .models import (
    ConversionRequest,
    ConversionResponse,
    BatchRequest,
    BatchStatus,
    FormatInfo,
    ContentType,
    ErrorResponse,
)
from .exceptions import (
    ImageConverterError,
    NetworkSecurityError,
    RateLimitError,
    ValidationError,
    ServiceUnavailableError,
)
from .auth import SecureAPIKeyManager

__version__ = "1.0.0"
__all__ = [
    "ImageConverterClient",
    "AsyncImageConverterClient",
    "ConversionRequest",
    "ConversionResponse",
    "BatchRequest",
    "BatchStatus",
    "FormatInfo",
    "ContentType",
    "ErrorResponse",
    "ImageConverterError",
    "NetworkSecurityError",
    "RateLimitError",
    "ValidationError",
    "ServiceUnavailableError",
    "SecureAPIKeyManager",
]