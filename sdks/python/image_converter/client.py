"""Synchronous client for Image Converter API - Local-only, privacy-focused."""

import asyncio
from typing import Optional, List, Union, Dict, Any
from pathlib import Path
from functools import wraps

from .async_client import AsyncImageConverterClient
from .models import (
    ConversionResponse,
    BatchStatus,
    FormatInfo,
    ContentClassification,
    FormatRecommendation,
)


def sync_wrapper(async_func):
    """Wrapper to run async functions synchronously."""

    @wraps(async_func)
    def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is already running, create a new one in a thread
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, async_func(*args, **kwargs))
                return future.result()
        else:
            # Run in the current loop
            return loop.run_until_complete(async_func(*args, **kwargs))

    return wrapper


class ImageConverterClient:
    """Synchronous client for Image Converter API with localhost-only enforcement."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8000,
        api_key: Optional[str] = None,
        api_version: str = "v1",
        timeout: float = 30.0,
        verify_localhost: bool = True,
    ):
        """Initialize synchronous client with security checks.

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
        self._async_client = AsyncImageConverterClient(
            host=host,
            port=port,
            api_key=api_key,
            api_version=api_version,
            timeout=timeout,
            verify_localhost=verify_localhost,
        )

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    @sync_wrapper
    async def close(self) -> None:
        """Close the client."""
        await self._async_client.close()

    @sync_wrapper
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
        return await self._async_client.convert_image(
            image_path=image_path,
            output_format=output_format,
            quality=quality,
            strip_metadata=strip_metadata,
            preset_id=preset_id,
        )

    @sync_wrapper
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
        return await self._async_client.create_batch(
            image_paths=image_paths,
            output_format=output_format,
            quality=quality,
            strip_metadata=strip_metadata,
            preset_id=preset_id,
            max_concurrent=max_concurrent,
        )

    @sync_wrapper
    async def get_batch_status(self, job_id: str) -> BatchStatus:
        """Get batch job status.

        Args:
            job_id: Batch job ID

        Returns:
            Current batch status
        """
        return await self._async_client.get_batch_status(job_id)

    @sync_wrapper
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
        return await self._async_client.analyze_image(
            image_path=image_path,
            debug=debug,
        )

    @sync_wrapper
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
        return await self._async_client.get_format_recommendations(
            content_classification=content_classification,
            original_format=original_format,
            original_size_kb=original_size_kb,
            use_case=use_case,
            prioritize=prioritize,
        )

    @sync_wrapper
    async def get_supported_formats(self) -> List[FormatInfo]:
        """Get list of supported formats.

        Returns:
            List of format information
        """
        return await self._async_client.get_supported_formats()

    @sync_wrapper
    async def health_check(self) -> Dict[str, Any]:
        """Check API health status.

        Returns:
            Health status information
        """
        return await self._async_client.health_check()

    def store_api_key(self, api_key: str, key_name: str = "default") -> bool:
        """Store API key securely.

        Args:
            api_key: API key to store
            key_name: Name for the key

        Returns:
            True if stored successfully
        """
        return self._async_client.store_api_key(api_key, key_name)

    def retrieve_api_key(self, key_name: str = "default") -> Optional[str]:
        """Retrieve stored API key.

        Args:
            key_name: Name of the key

        Returns:
            API key if found
        """
        return self._async_client.retrieve_api_key(key_name)
