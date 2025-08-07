"""Async client for Image Converter API - Local-only, privacy-focused."""

import asyncio
from typing import Optional, Dict, Any, List, BinaryIO, Union
from pathlib import Path
import httpx
from urllib.parse import urlparse

from .models import (
    ConversionRequest,
    ConversionResponse,
    BatchRequest,
    BatchStatus,
    FormatInfo,
    ContentClassification,
    FormatRecommendation,
    ErrorResponse,
)
from .exceptions import (
    ImageConverterError,
    NetworkSecurityError,
    RateLimitError,
    ValidationError,
    ServiceUnavailableError,
    FileError,
)
from .auth import SecureAPIKeyManager


class AsyncImageConverterClient:
    """Async client for Image Converter API with localhost-only enforcement."""

    ALLOWED_HOSTS = ["localhost", "127.0.0.1", "::1", "[::1]"]
    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8000,
        api_key: Optional[str] = None,
        api_version: str = "v1",
        timeout: float = DEFAULT_TIMEOUT,
        verify_localhost: bool = True,
    ):
        """Initialize async client with security checks.

        Args:
            host: API host (must be localhost)
            port: API port
            api_key: Optional API key for authentication
            api_version: API version to use
            timeout: Request timeout in seconds
            verify_localhost: Enforce localhost-only connections

        Raises:
            NetworkSecurityError: If non-localhost host is provided
        """
        self.verify_localhost = verify_localhost

        # Security check: Enforce localhost only
        if self.verify_localhost and host not in self.ALLOWED_HOSTS:
            raise NetworkSecurityError(f"Connection to non-localhost host blocked for security")

        self.base_url = f"http://{host}:{port}/api"
        if api_version:
            self.base_url = f"{self.base_url}/{api_version}"

        self.api_key = api_key
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._key_manager = SecureAPIKeyManager()

        # If no API key provided, try to get from secure storage or env
        if not self.api_key:
            self.api_key = self._key_manager.get_from_env() or self._key_manager.retrieve_api_key(
                "default"
            )

    async def __aenter__(self):
        """Context manager entry."""
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.close()

    async def _ensure_client(self) -> None:
        """Ensure HTTP client is initialized."""
        if not self._client:
            headers = {}
            if self.api_key:
                headers["X-API-Key"] = self.api_key

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
                follow_redirects=False,  # Security: Don't follow redirects
            )

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _verify_url_security(self, url: str) -> None:
        """Verify URL is localhost only.

        Args:
            url: URL to verify

        Raises:
            NetworkSecurityError: If URL is not localhost
        """
        if not self.verify_localhost:
            return

        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname not in self.ALLOWED_HOSTS:
            raise NetworkSecurityError("Attempted connection to non-localhost address blocked")

    async def _handle_response(self, response: httpx.Response) -> Any:
        """Handle API response with proper error handling.

        Args:
            response: HTTP response

        Returns:
            Response data

        Raises:
            Various ImageConverterError subclasses based on status
        """
        if response.status_code == 200:
            # For binary responses, return raw content
            content_type = response.headers.get("content-type", "")
            if content_type.startswith("image/"):
                return response.content
            return response.json()

        # Handle errors
        try:
            error_data = response.json()
            error_msg = error_data.get("message", "Unknown error")
            error_code = error_data.get("error_code", "unknown")
        except Exception:
            error_msg = f"HTTP {response.status_code}"
            error_code = str(response.status_code)

        if response.status_code == 413:
            raise ValidationError("File too large")
        elif response.status_code == 415:
            raise ValidationError("Unsupported file format")
        elif response.status_code == 422:
            raise ValidationError(error_msg)
        elif response.status_code == 429:
            retry_after = response.headers.get("X-RateLimit-Reset")
            raise RateLimitError(error_msg, retry_after=int(retry_after) if retry_after else None)
        elif response.status_code == 503:
            raise ServiceUnavailableError(error_msg)
        else:
            raise ImageConverterError(error_msg, error_code=error_code)

    async def convert_image(
        self,
        image_path: Union[str, Path],
        output_format: str,
        quality: Optional[int] = None,
        strip_metadata: bool = True,
        preset_id: Optional[str] = None,
    ) -> tuple[bytes, ConversionResponse]:
        """Convert a single image.

        Args:
            image_path: Path to input image
            output_format: Target format
            quality: Quality setting (1-100)
            strip_metadata: Remove metadata
            preset_id: Optional preset ID

        Returns:
            Tuple of (converted image bytes, conversion metadata)

        Raises:
            FileError: If file cannot be read
            Various API errors
        """
        await self._ensure_client()

        # Read file
        image_path = Path(image_path)
        if not image_path.exists():
            raise FileError("Input file not found")

        try:
            image_data = image_path.read_bytes()
        except Exception:
            raise FileError("Failed to read input file")

        # Prepare multipart data
        files = {"file": (image_path.name, image_data, "application/octet-stream")}

        data = {
            "output_format": output_format,
            "strip_metadata": str(strip_metadata).lower(),
        }

        if quality is not None:
            data["quality"] = str(quality)
        if preset_id:
            data["preset_id"] = preset_id

        # Make request
        response = await self._client.post(
            "/convert",
            files=files,
            data=data,
        )

        converted_data = await self._handle_response(response)

        # Extract metadata from headers
        metadata = ConversionResponse(
            conversion_id=response.headers.get("X-Conversion-Id", ""),
            processing_time=float(response.headers.get("X-Processing-Time", "0")),
            compression_ratio=float(response.headers.get("X-Compression-Ratio", "1")),
            input_format=response.headers.get("X-Input-Format", ""),
            output_format=response.headers.get("X-Output-Format", output_format),
            input_size=int(response.headers.get("X-Input-Size", "0")),
            output_size=int(response.headers.get("X-Output-Size", len(converted_data))),
            quality_used=int(response.headers.get("X-Quality-Used", quality or 85)),
            metadata_removed=response.headers.get("X-Metadata-Removed", "true") == "true",
        )

        return converted_data, metadata

    async def create_batch(
        self,
        image_paths: List[Union[str, Path]],
        output_format: str,
        quality: Optional[int] = None,
        strip_metadata: bool = True,
        preset_id: Optional[str] = None,
        max_concurrent: int = 5,
    ) -> BatchStatus:
        """Create a batch conversion job.

        Args:
            image_paths: List of image file paths
            output_format: Target format for all images
            quality: Quality setting (1-100)
            strip_metadata: Remove metadata from all images
            preset_id: Optional preset ID
            max_concurrent: Max concurrent conversions

        Returns:
            Batch job status

        Raises:
            FileError: If any file cannot be read
            Various API errors
        """
        await self._ensure_client()

        # Prepare files
        files = []
        for path in image_paths:
            path = Path(path)
            if not path.exists():
                raise FileError(f"File not found: [file]")

            try:
                image_data = path.read_bytes()
                files.append(("files", (path.name, image_data, "application/octet-stream")))
            except Exception:
                raise FileError("Failed to read input file")

        # Prepare form data
        data = {
            "output_format": output_format,
            "strip_metadata": str(strip_metadata).lower(),
            "max_concurrent": str(max_concurrent),
        }

        if quality is not None:
            data["quality"] = str(quality)
        if preset_id:
            data["preset_id"] = preset_id

        # Create batch job
        response = await self._client.post(
            "/batch",
            files=files,
            data=data,
        )

        result = await self._handle_response(response)
        return BatchStatus(**result)

    async def get_batch_status(self, job_id: str) -> BatchStatus:
        """Get batch job status.

        Args:
            job_id: Batch job ID

        Returns:
            Current batch status
        """
        await self._ensure_client()

        response = await self._client.get(f"/batch/{job_id}/status")
        result = await self._handle_response(response)
        return BatchStatus(**result)

    async def analyze_image(
        self,
        image_path: Union[str, Path],
        debug: bool = False,
    ) -> ContentClassification:
        """Analyze image content using ML models.

        Args:
            image_path: Path to image to analyze
            debug: Include debug information

        Returns:
            Content classification result
        """
        await self._ensure_client()

        # Read file
        image_path = Path(image_path)
        if not image_path.exists():
            raise FileError("Input file not found")

        try:
            image_data = image_path.read_bytes()
        except Exception:
            raise FileError("Failed to read input file")

        # Prepare request
        files = {"file": (image_path.name, image_data, "application/octet-stream")}

        params = {"debug": str(debug).lower()} if debug else {}

        response = await self._client.post(
            "/intelligence/analyze",
            files=files,
            params=params,
        )

        result = await self._handle_response(response)
        return ContentClassification(**result)

    async def get_format_recommendations(
        self,
        content_classification: ContentClassification,
        original_format: str,
        original_size_kb: float,
        use_case: Optional[str] = None,
        prioritize: Optional[str] = None,
    ) -> FormatRecommendation:
        """Get AI-powered format recommendations.

        Args:
            content_classification: Result from analyze_image
            original_format: Current image format
            original_size_kb: Current size in KB
            use_case: Optional use case (web/print/archive)
            prioritize: Optional priority (size/quality/compatibility)

        Returns:
            Format recommendations
        """
        await self._ensure_client()

        # Prepare request
        data = {
            "content_classification": content_classification.model_dump(),
            "original_format": original_format,
            "original_size_kb": original_size_kb,
        }

        if use_case:
            data["use_case"] = use_case
        if prioritize:
            data["prioritize"] = prioritize

        response = await self._client.post(
            "/intelligence/recommend",
            json=data,
        )

        result = await self._handle_response(response)
        return FormatRecommendation(**result)

    async def get_supported_formats(self) -> List[FormatInfo]:
        """Get list of supported formats.

        Returns:
            List of format information
        """
        await self._ensure_client()

        response = await self._client.get("/formats")
        result = await self._handle_response(response)

        return [FormatInfo(**fmt) for fmt in result.get("formats", [])]

    async def health_check(self) -> Dict[str, Any]:
        """Check API health status.

        Returns:
            Health status information
        """
        await self._ensure_client()

        response = await self._client.get("/health")
        return await self._handle_response(response)

    def store_api_key(self, api_key: str, key_name: str = "default") -> bool:
        """Store API key securely.

        Args:
            api_key: API key to store
            key_name: Name for the key

        Returns:
            True if stored successfully
        """
        return self._key_manager.store_api_key(key_name, api_key)

    def retrieve_api_key(self, key_name: str = "default") -> Optional[str]:
        """Retrieve stored API key.

        Args:
            key_name: Name of the key

        Returns:
            API key if found
        """
        return self._key_manager.retrieve_api_key(key_name)
