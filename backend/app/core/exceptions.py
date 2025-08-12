from typing import Dict, List, Optional, TypedDict, Union


class ConversionDetails(TypedDict, total=False):
    """Type-safe details for conversion errors."""

    input_format: str
    output_format: str
    file_size: int
    dimensions: tuple[int, int]
    quality: int
    error_code: str


class ValidationDetails(TypedDict, total=False):
    """Type-safe details for validation errors."""

    field_name: str
    field_value: Union[str, int, float, bool]
    expected_type: str
    expected_values: List[Union[str, int]]
    constraints: str


class SecurityDetails(TypedDict, total=False):
    """Type-safe details for security errors."""

    violation_type: str
    blocked_operation: str
    resource_limits: Dict[str, int]
    sandbox_mode: str
    detection_method: str


class ResourceDetails(TypedDict, total=False):
    """Type-safe details for resource limit errors."""

    resource_type: str
    current_usage: Union[int, float]
    limit: Union[int, float]
    unit: str
    duration_seconds: float


class FormatDetails(TypedDict, total=False):
    """Type-safe details for format errors."""

    requested_format: str
    supported_formats: List[str]
    file_extension: str
    mime_type: str
    format_capabilities: Dict[str, bool]


class ProcessingDetails(TypedDict, total=False):
    """Type-safe details for processing timeout errors."""

    timeout_seconds: int
    elapsed_seconds: float
    operation: str
    stage: str
    progress_percent: int


class ConfigDetails(TypedDict, total=False):
    """Type-safe details for configuration errors."""

    config_key: str
    config_value: Union[str, int, float, bool]
    valid_options: List[Union[str, int]]
    config_section: str
    validation_rule: str


class NetworkDetails(TypedDict, total=False):
    """Type-safe details for network errors."""

    blocked_host: str
    blocked_port: int
    protocol: str
    reason: str
    isolation_level: str


# Union type for all possible error details
ErrorDetails = Union[
    ConversionDetails,
    ValidationDetails,
    SecurityDetails,
    ResourceDetails,
    FormatDetails,
    ProcessingDetails,
    ConfigDetails,
    NetworkDetails,
    Dict[str, Union[str, int, float, bool, List[str]]],  # Fallback for edge cases
]


class ImageConverterError(Exception):
    """Base exception for all Image Converter errors."""

    def __init__(
        self,
        message: str,
        error_code: str,
        status_code: int = 500,
        details: Optional[ErrorDetails] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}


class ConversionError(ImageConverterError):
    """Raised when image conversion fails."""

    def __init__(self, message: str, details: Optional[ConversionDetails] = None):
        super().__init__(
            message=message, error_code="CONV001", status_code=422, details=details
        )


class ValidationError(ImageConverterError):
    """Raised when input validation fails."""

    def __init__(self, message: str, details: Optional[ValidationDetails] = None):
        super().__init__(
            message=message, error_code="CONV002", status_code=400, details=details
        )


class SecurityError(ImageConverterError):
    """Raised when security checks fail."""

    def __init__(self, message: str, details: Optional[SecurityDetails] = None):
        super().__init__(
            message=message, error_code="CONV003", status_code=403, details=details
        )


class ResourceLimitError(ImageConverterError):
    """Raised when resource limits are exceeded."""

    def __init__(self, message: str, details: Optional[ResourceDetails] = None):
        super().__init__(
            message=message, error_code="CONV004", status_code=413, details=details
        )


# Deprecated: Use UnsupportedFormatError instead
class FormatNotSupportedError(ImageConverterError):
    """Raised when image format is not supported.

    DEPRECATED: Use UnsupportedFormatError instead for consistency.
    """

    def __init__(self, message: str, details: Optional[FormatDetails] = None):
        super().__init__(
            message=message, error_code="CONV005", status_code=415, details=details
        )


class ProcessingTimeoutError(ImageConverterError):
    """Raised when processing exceeds timeout."""

    def __init__(self, message: str, details: Optional[ProcessingDetails] = None):
        super().__init__(
            message=message, error_code="CONV006", status_code=408, details=details
        )


class ConfigurationError(ImageConverterError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, details: Optional[ConfigDetails] = None):
        super().__init__(
            message=message, error_code="CONV007", status_code=500, details=details
        )


class InvalidImageError(ImageConverterError):
    """Raised when image data is invalid or corrupted."""

    def __init__(self, message: str, details: Optional[ValidationDetails] = None):
        super().__init__(
            message=message, error_code="CONV101", status_code=400, details=details
        )


class UnsupportedFormatError(ImageConverterError):
    """Raised when image format is not supported."""

    def __init__(self, message: str, details: Optional[FormatDetails] = None):
        super().__init__(
            message=message, error_code="CONV102", status_code=415, details=details
        )


class ConversionFailedError(ImageConverterError):
    """Raised when image conversion process fails."""

    def __init__(self, message: str, details: Optional[ConversionDetails] = None):
        super().__init__(
            message=message, error_code="CONV103", status_code=500, details=details
        )


# Format-specific exceptions
class FormatError(ImageConverterError):
    """Base class for format-specific errors."""

    pass


class WebPDecodingError(FormatError):
    """Raised when WebP decoding fails."""

    def __init__(
        self,
        message: str = "Failed to decode WebP image",
        details: Optional[FormatDetails] = None,
    ):
        super().__init__(
            message=message, error_code="CONV201", status_code=422, details=details
        )


class HeifDecodingError(FormatError):
    """Raised when HEIF/HEIC decoding fails."""

    def __init__(
        self,
        message: str = "Failed to decode HEIF/HEIC image",
        details: Optional[FormatDetails] = None,
    ):
        super().__init__(
            message=message, error_code="CONV202", status_code=422, details=details
        )


class BmpDecodingError(FormatError):
    """Raised when BMP decoding fails."""

    def __init__(
        self,
        message: str = "Failed to decode BMP image",
        details: Optional[FormatDetails] = None,
    ):
        super().__init__(
            message=message, error_code="CONV203", status_code=422, details=details
        )


class TiffDecodingError(FormatError):
    """Raised when TIFF decoding fails."""

    def __init__(
        self,
        message: str = "Failed to decode TIFF image",
        details: Optional[FormatDetails] = None,
    ):
        super().__init__(
            message=message, error_code="CONV204", status_code=422, details=details
        )


class GifDecodingError(FormatError):
    """Raised when GIF decoding fails."""

    def __init__(
        self,
        message: str = "Failed to decode GIF image",
        details: Optional[FormatDetails] = None,
    ):
        super().__init__(
            message=message, error_code="CONV205", status_code=422, details=details
        )


class AvifDecodingError(FormatError):
    """Raised when AVIF decoding fails."""

    def __init__(
        self,
        message: str = "Failed to decode AVIF image",
        details: Optional[FormatDetails] = None,
    ):
        super().__init__(
            message=message, error_code="CONV206", status_code=422, details=details
        )


class NetworkError(ImageConverterError):
    """Raised when network operations fail or are blocked."""

    def __init__(self, message: str, details: Optional[NetworkDetails] = None):
        super().__init__(
            message=message, error_code="NET001", status_code=403, details=details
        )
