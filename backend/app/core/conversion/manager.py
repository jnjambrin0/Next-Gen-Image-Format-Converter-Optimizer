"""Conversion manager for orchestrating image conversions."""

import asyncio
import os
import sys
import time
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional, Set, Tuple, Type

import structlog

from app.config import settings
from app.core.constants import FORMAT_ALIASES
from app.core.conversion.formats.base import BaseFormatHandler
from app.core.conversion.image_processor import ImageProcessor
from app.core.exceptions import (
    ConversionError,
    ConversionFailedError,
    InvalidImageError,
    UnsupportedFormatError,
)
from app.core.monitoring import metrics_collector, stats_collector
from app.core.security.engine import SecurityEngine
from app.core.security.memory import SecureMemoryManager
from app.models.conversion import (
    ConversionRequest,
    ConversionResult,
    ConversionSettings,
    ConversionStatus,
    InputFormat,
)

logger = structlog.get_logger()


class ConversionManager:
    """Manages the image conversion pipeline."""

    # Default timeout for conversion operations (in seconds)
    DEFAULT_CONVERSION_TIMEOUT = 30.0

    def __init__(self) -> None:
        """Initialize conversion manager."""
        self.format_handlers: Dict[str, Type[BaseFormatHandler]] = {}
        self.image_processor = ImageProcessor()
        self.security_engine = SecurityEngine() if settings.enable_sandboxing else None
        self._memory_manager: Optional[SecureMemoryManager] = None

        # Format fallback mapping (using canonical names)
        self.format_fallbacks: Dict[str, List[str]] = {
            "webp2": ["webp", "png"],
            "jxl": ["webp", "png"],
            "jpeg_opt": ["jpeg"],
            "png_opt": ["png"],
            "heif": ["jpeg", "png"],
            "avif": ["webp", "png"],
            "jp2": ["jpeg", "png"],
        }

        # Track available formats
        self.available_formats: Set[str] = set()

        self._initialize_handlers()

    def _initialize_handlers(self) -> None:
        """Initialize format handlers."""
        # Import handlers here to avoid circular imports
        from app.core.conversion.formats.avif_handler import AVIFHandler
        from app.core.conversion.formats.bmp_handler import BmpHandler
        from app.core.conversion.formats.gif_handler import GifHandler
        from app.core.conversion.formats.heif_handler import HeifHandler
        from app.core.conversion.formats.jpeg_handler import JPEGHandler
        from app.core.conversion.formats.jpeg_optimized_handler import (
            JPEGOptimizedHandler,
        )
        from app.core.conversion.formats.jxl_handler import JxlHandler
        from app.core.conversion.formats.png_handler import PNGHandler
        from app.core.conversion.formats.png_optimized_handler import (
            PNGOptimizedHandler,
        )
        from app.core.conversion.formats.tiff_handler import TiffHandler
        from app.core.conversion.formats.webp2_handler import WebP2Handler
        from app.core.conversion.formats.webp_handler import WebPHandler

        # Register core handlers (all handlers support both input and output)
        self.register_handler("jpeg", JPEGHandler)  # Also registers jpg via alias
        self.register_handler("png", PNGHandler)
        self.register_handler("webp", WebPHandler)
        self.register_handler("avif", AVIFHandler)
        self.register_handler(
            "heif", HeifHandler
        )  # Also registers heic, heix, hevc, hevx via aliases
        self.register_handler("bmp", BmpHandler)
        self.register_handler("tiff", TiffHandler)  # Also registers tif via alias
        self.register_handler("gif", GifHandler)

        # New format handlers - handle availability gracefully
        try:
            self.register_handler(
                "jxl", JxlHandler
            )  # Also registers jpegxl, jpeg_xl via aliases
        except Exception as e:
            logger.warning("JPEG XL support not available", error=str(e))

        # Optimized format handlers
        try:
            self.register_handler("png_opt", PNGOptimizedHandler)  # Canonical name
        except Exception as e:
            logger.warning("PNG optimization support not available", error=str(e))

        try:
            self.register_handler("jpeg_opt", JPEGOptimizedHandler)  # Canonical name
        except Exception as e:
            logger.warning("JPEG optimization support not available", error=str(e))

        # WebP2 handler with fallback
        try:
            self.register_handler("webp2", WebP2Handler)
        except Exception as e:
            logger.warning("WebP2 support not available", error=str(e))

        # JPEG 2000 handler - Disabled due to low usage and complexity
        # Legacy format with <1% usage - keeping code but not registering
        # try:
        #     self.register_handler("jp2", Jpeg2000Handler)  # Also registers jpeg2000, j2k, etc via aliases
        # except Exception as e:
        #     logger.warning("JPEG 2000 support not available", error=str(e))

    def _estimate_memory_requirements(
        self, input_size: int, input_format: str, output_format: str
    ) -> int:
        """
        Estimate memory requirements for conversion.

        Args:
            input_size: Size of input image in bytes
            input_format: Input format name (unused but kept for compatibility)
            output_format: Target output format (unused but kept for compatibility)

        Returns:
            Estimated memory requirement in MB
        """
        # Simple formula: 3x input size + 64MB overhead
        estimated_mb = int((input_size * 3) / (1024 * 1024)) + 64

        # Minimum 64MB, maximum 1GB
        return max(64, min(estimated_mb, 1024))

    def _initialize_memory_manager(self, max_memory_mb: int) -> None:
        """Initialize memory manager with specified limits."""
        if not self._memory_manager:
            self._memory_manager = SecureMemoryManager(max_memory_mb)
            logger.debug("Memory manager initialized", max_memory_mb=max_memory_mb)

    def _resolve_format_name(self, format_name: str) -> str:
        """Resolve format name to canonical name."""
        format_lower = format_name.lower()
        return FORMAT_ALIASES.get(format_lower, format_lower)

    def register_handler(
        self, format_name: str, handler_class: Type[BaseFormatHandler]
    ) -> None:
        """Register a format handler."""
        format_lower = format_name.lower()
        canonical_name = self._resolve_format_name(format_lower)

        # Register under the canonical name
        self.format_handlers[canonical_name] = handler_class
        self.available_formats.add(canonical_name)

        # If format_lower is different from canonical, also register it
        if format_lower != canonical_name:
            self.format_handlers[format_lower] = handler_class
            self.available_formats.add(format_lower)

        # Also register all aliases that point to this canonical format
        for alias, target in FORMAT_ALIASES.items():
            if target == canonical_name and alias not in self.format_handlers:
                self.format_handlers[alias] = handler_class
                self.available_formats.add(alias)

    def get_format_with_fallback(self, requested_format: str) -> Tuple[str, bool]:
        """
        Get the format to use, applying fallback if necessary.

        Args:
            requested_format: The format requested by the user

        Returns:
            Tuple of (format_to_use, is_fallback)
        """
        requested_lower = requested_format.lower()
        canonical_name = self._resolve_format_name(requested_lower)

        # Prefer canonical name if available
        if canonical_name in self.available_formats:
            return (canonical_name, False)

        # Otherwise check if requested format is directly available
        if requested_lower in self.available_formats:
            return (requested_lower, False)

        # Check fallback chain using canonical name
        if canonical_name in self.format_fallbacks:
            for fallback_format in self.format_fallbacks[canonical_name]:
                if fallback_format in self.available_formats:
                    logger.info(
                        "Using format fallback",
                        requested=requested_format,
                        canonical=canonical_name,
                        fallback=fallback_format,
                    )
                    return (fallback_format, True)

        # No fallback available
        raise UnsupportedFormatError(
            f"Format '{requested_format}' is not available and no fallback found",
            details={
                "requested_format": requested_format,
                "canonical_name": canonical_name,
                "available_formats": sorted(self.available_formats),
                "tried_fallbacks": self.format_fallbacks.get(canonical_name, []),
            },
        )

    def is_format_available(self, format_name: str) -> bool:
        """Check if a format is available (directly or via fallback)."""
        try:
            self.get_format_with_fallback(format_name)
            return True
        except UnsupportedFormatError:
            return False

    def get_available_formats(self) -> List[str]:
        """Get list of all available formats including those with fallbacks."""
        available = set(self.available_formats)

        # Add formats that have working fallbacks
        for format_name, fallbacks in self.format_fallbacks.items():
            if any(fb in self.available_formats for fb in fallbacks):
                available.add(format_name)

        return sorted(available)

    async def convert_image(
        self, input_data: bytes, input_format: str, request: ConversionRequest
    ) -> ConversionResult:
        """
        Convert an image from one format to another.

        Args:
            input_data: Input image data as bytes
            input_format: Input format name
            request: Conversion request with output format and settings

        Returns:
            ConversionResult with conversion details and output data
        """
        start_time = time.time()

        # Estimate memory requirements
        estimated_memory_mb = self._estimate_memory_requirements(
            len(input_data), input_format, request.output_format
        )

        # Initialize memory manager with estimated requirements
        self._initialize_memory_manager(estimated_memory_mb)

        # Initialize result
        result = ConversionResult(
            input_format=InputFormat(input_format.lower()),
            output_format=request.output_format,
            input_size=len(input_data),
            status=ConversionStatus.PROCESSING,
            quality_settings=request.settings.model_dump() if request.settings else {},
        )

        # Add memory estimation to quality settings
        result.quality_settings["estimated_memory_mb"] = estimated_memory_mb

        # Start metrics collection
        output_format_str = (
            request.output_format.value
            if hasattr(request.output_format, "value")
            else str(request.output_format)
        )
        metrics = metrics_collector.start_conversion(
            conversion_id=result.id,
            input_format=input_format,
            output_format=output_format_str,
            requested_format=output_format_str,
            input_size=len(input_data),
            estimated_memory_mb=estimated_memory_mb,
        )

        try:
            # Validate input
            await self._validate_input(input_data, input_format)

            # Security scan (always enabled for safety)
            if self.security_engine:
                scan_report = await self.security_engine.scan_file(input_data)
                if not scan_report["is_safe"]:
                    raise ConversionError(
                        f"Security scan failed: {', '.join(scan_report['threats_found'])}"
                    )

            # Get handlers
            input_handler = self._get_handler(input_format.lower())

            # Get output format with fallback if needed
            output_format_str = (
                request.output_format.value
                if hasattr(request.output_format, "value")
                else str(request.output_format)
            )
            actual_output_format, is_fallback = self.get_format_with_fallback(
                output_format_str
            )

            if is_fallback:
                logger.info(
                    "Using fallback format",
                    requested_format=output_format_str,
                    actual_format=actual_output_format,
                    conversion_id=result.id,
                )
                # Update result to reflect actual format used
                result.quality_settings["format_fallback"] = {
                    "requested": output_format_str,
                    "actual": actual_output_format,
                    "reason": "Requested format not available",
                }

                # Update metrics for fallback
                metrics.fallback_used = True
                metrics.fallback_reason = "Requested format not available"
                metrics.output_format = actual_output_format

            output_handler = self._get_handler(actual_output_format)

            # Handle metadata analysis and stripping BEFORE conversion
            conversion_settings = request.settings or ConversionSettings()
            processed_input_data = input_data

            if self.security_engine:
                # Analyze and optionally strip metadata from input image
                processed_input_data, metadata_summary = (
                    await self.security_engine.analyze_and_process_metadata(
                        input_data,
                        input_format,
                        strip_metadata=conversion_settings.strip_metadata,
                        preserve_metadata=conversion_settings.preserve_metadata,
                        preserve_gps=conversion_settings.preserve_gps,
                    )
                )

                # Update result with metadata information
                result.metadata_removed = (
                    len(metadata_summary.get("metadata_removed", [])) > 0
                )
                result.quality_settings["metadata_summary"] = metadata_summary

                if metadata_summary.get("gps_removed"):
                    logger.info("GPS data removed from image", conversion_id=result.id)

                logger.info(
                    "Metadata processing completed",
                    conversion_id=result.id,
                    had_metadata=any(
                        [
                            metadata_summary.get("had_exif", False),
                            metadata_summary.get("had_gps", False),
                            metadata_summary.get("had_xmp", False),
                            metadata_summary.get("had_iptc", False),
                        ]
                    ),
                    metadata_removed=result.metadata_removed,
                )

            # Choose conversion method based on sandboxing
            if self.security_engine and settings.enable_sandboxing:
                # Sandboxed conversion with pre-processed input
                output_data = await self._process_sandboxed(
                    processed_input_data,
                    input_format,
                    request,
                    result,
                    actual_output_format,
                )
            else:
                # Direct conversion (legacy mode) with pre-processed input
                # Load image
                image = await self._load_image(processed_input_data, input_handler)

                # Process image
                # Update quality_settings in result to reflect what was actually used
                result.quality_settings.update(conversion_settings.model_dump())
                output_data = await self._process_image(
                    image, output_handler, conversion_settings
                )

            # Update result
            result.output_size = len(output_data)
            result.processing_time = time.time() - start_time
            result.status = ConversionStatus.COMPLETED
            result.completed_at = datetime.now(timezone.utc)

            # Add memory usage statistics if available
            peak_memory_mb = 0
            if self._memory_manager:
                memory_stats = self._memory_manager.get_memory_stats()
                result.quality_settings.update(
                    {
                        "actual_memory_mb": memory_stats.get("current_usage_mb", 0),
                        "peak_memory_mb": memory_stats.get("peak_memory_mb", 0),
                        "memory_utilization_percent": memory_stats.get(
                            "memory_utilization_percent", 0
                        ),
                    }
                )
                peak_memory_mb = memory_stats.get("peak_memory_mb", 0)

            # Complete metrics collection
            metrics_collector.complete_conversion(
                conversion_id=result.id,
                output_size=len(output_data),
                peak_memory_mb=peak_memory_mb,
            )

            # Record stats for aggregate tracking
            await stats_collector.record_conversion(
                input_format=input_format,
                output_format=actual_output_format,
                input_size=len(input_data),
                processing_time=result.processing_time,
                success=True,
            )

            logger.info(
                "Image conversion completed",
                conversion_id=result.id,
                input_format=input_format,
                output_format=request.output_format,
                compression_ratio=result.compression_ratio,
                processing_time=result.processing_time,
            )

            # TEMPORARY: Attach output data for backward compatibility
            # This allows callers to access the converted image data directly from the result.
            # The preferred method is to use convert_with_output() which returns both the
            # result and the output data as a tuple, avoiding the use of private attributes.
            # TODO: Migrate all callers to use convert_with_output method instead
            result._output_data = output_data

            return result

        except Exception as e:
            result.status = ConversionStatus.FAILED
            result.error_message = str(e)
            result.processing_time = time.time() - start_time

            # Record failure in metrics
            metrics_collector.fail_conversion(
                conversion_id=result.id,
                error_type=type(e).__name__,
                error_message=str(e),
            )

            # Record stats for aggregate tracking
            await stats_collector.record_conversion(
                input_format=input_format,
                output_format=(
                    actual_output_format
                    if "actual_output_format" in locals()
                    else output_format_str
                ),
                input_size=len(input_data),
                processing_time=result.processing_time,
                success=False,
                error_type=type(e).__name__,
            )

            logger.error(
                "Image conversion failed",
                conversion_id=result.id,
                error=str(e),
                error_type=type(e).__name__,
            )

            raise

        finally:
            # Ensure memory cleanup
            self._cleanup_memory()

    def _cleanup_memory(self) -> None:
        """Clean up memory manager resources."""
        if self._memory_manager:
            try:
                self._memory_manager.cleanup_all()
                logger.debug("Conversion memory cleaned up")
            except Exception as e:
                logger.warning(f"Failed to cleanup memory manager: {e}")
            finally:
                self._memory_manager = None

    async def _process_sandboxed(
        self,
        input_data: bytes,
        input_format: str,
        request: ConversionRequest,
        result: ConversionResult,
        actual_output_format: str,
    ) -> bytes:
        """
        Process image conversion in a sandboxed environment.

        Args:
            input_data: Input image data
            input_format: Input format name
            request: Conversion request
            result: Result object to update

        Returns:
            Converted image data
        """
        sandbox = None
        try:
            # Create sandbox for this conversion
            sandbox = self.security_engine.create_sandbox(
                conversion_id=result.id, strictness=settings.sandbox_strictness
            )
            # Build conversion command
            command = self._build_conversion_command(
                "",  # Not used anymore
                "",  # Not used anymore
                input_format,
                actual_output_format,  # Use actual format after fallback
                request.settings or ConversionSettings(),
            )

            # Execute conversion in sandbox with input data via stdin
            output_data, process_sandbox = (
                await self.security_engine.execute_sandboxed_conversion(
                    sandbox=sandbox,
                    conversion_id=result.id,
                    command=command,
                    input_data=input_data,  # Pass image data via stdin
                )
            )

            # Validate output
            if not output_data:
                raise ConversionFailedError("Conversion produced no output")

            # Update result with sandbox metrics
            result.quality_settings.update(
                {
                    "sandbox_execution_time": process_sandbox.execution_time,
                    "sandbox_memory_used_mb": process_sandbox.actual_usage.get(
                        "memory_mb", 0
                    ),
                    "sandbox_violations": process_sandbox.security_violations,
                }
            )

            # Update metrics with sandbox info
            if metrics := metrics_collector.get_metrics(result.id):
                metrics.sandbox_used = True
                metrics.sandbox_execution_time = process_sandbox.execution_time
                metrics.sandbox_violations = process_sandbox.security_violations

            return output_data

        except Exception as e:
            logger.error(
                "Sandboxed conversion failed",
                conversion_id=result.id,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

        finally:
            # Ensure cleanup happens even if an exception occurs
            if sandbox:
                try:
                    self.security_engine.cleanup_sandbox(result.id)
                except Exception as cleanup_error:
                    logger.warning(
                        "Failed to cleanup sandbox",
                        conversion_id=result.id,
                        error=str(cleanup_error),
                    )

    def _build_conversion_command(
        self,
        input_path: str,
        output_path: str,
        input_format: str,
        output_format: str,
        settings: ConversionSettings,
    ) -> List[str]:
        """
        Build the image conversion command.

        Metadata stripping is handled by SecurityEngine after conversion.

        Args:
            input_path: Input file path (not used)
            output_path: Output file path (not used)
            input_format: Input format
            output_format: Output format
            settings: Conversion settings

        Returns:
            Command list for subprocess
        """
        # Use Python to run our sandboxed conversion script
        # Run the script directly to avoid module imports that might initialize logging
        script_path = os.path.join(os.path.dirname(__file__), "sandboxed_convert.py")
        command = [
            sys.executable,  # Use the same Python interpreter
            script_path,
            input_format,
            output_format,
            str(settings.quality),
        ]

        # Add advanced optimization parameters if present (Story 3.5)
        if settings.advanced_optimization:
            import json

            command.append(json.dumps(settings.advanced_optimization))

        return command

    async def _validate_input(self, input_data: bytes, input_format: str) -> None:
        """Validate input data."""
        if not input_data:
            raise InvalidImageError("Empty input data")

        # Check size limit (50MB)
        max_size = 50 * 1024 * 1024
        if len(input_data) > max_size:
            raise InvalidImageError(
                f"Image size exceeds maximum allowed size of {max_size} bytes",
                details={"size": len(input_data), "max_size": max_size},
            )

        # Validate format is supported
        if input_format.lower() not in self.format_handlers:
            raise UnsupportedFormatError(
                f"Input format '{input_format}' is not supported",
                details={"format": input_format},
            )

    def _get_handler(self, format_name: str) -> BaseFormatHandler:
        """Get handler for format."""
        handler_class = self.format_handlers.get(format_name.lower())
        if not handler_class:
            raise UnsupportedFormatError(
                f"Format '{format_name}' is not supported",
                details={"format": format_name},
            )

        # Create handler instance
        handler = handler_class()

        # Validate handler actually supports the format
        if not handler.can_handle(format_name):
            raise UnsupportedFormatError(
                f"Handler {handler_class.__name__} cannot handle format '{format_name}'",
                details={"format": format_name, "handler": handler_class.__name__},
            )

        return handler

    async def _load_image(self, input_data: bytes, handler: BaseFormatHandler) -> Any:
        """Load image using handler."""
        try:
            # Validate image data first
            if not handler.validate_image(input_data):
                raise InvalidImageError(
                    "Image validation failed",
                    details={"handler": handler.__class__.__name__},
                )

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, handler.load_image, input_data)
        except InvalidImageError:
            raise
        except Exception as e:
            raise ConversionFailedError(
                f"Failed to load image: {str(e)}", details={"error": str(e)}
            )

    async def _process_image(
        self,
        image: Any,
        output_handler: BaseFormatHandler,
        settings: ConversionSettings,
    ) -> bytes:
        """Process and convert image."""
        try:
            # Prepare image for output format
            prepared_image = output_handler.prepare_image(image)

            # Convert to output format
            output_buffer = BytesIO()

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, output_handler.save_image, prepared_image, output_buffer, settings
            )

            # Get output data
            output_buffer.seek(0)
            output_data = output_buffer.read()

            # Clean up
            output_buffer.close()

            # Close images carefully to avoid comparing closed images
            try:
                if hasattr(prepared_image, "close") and prepared_image is not image:
                    prepared_image.close()
                if hasattr(image, "close"):
                    image.close()
            except Exception as e:
                # Log cleanup errors but don't fail the conversion
                logger.debug(
                    "Error during image cleanup",
                    error=str(e),
                    error_type=type(e).__name__,
                )

            return output_data

        except Exception as e:
            raise ConversionFailedError(
                f"Failed to process image: {str(e)}", details={"error": str(e)}
            )

    async def convert_with_output(
        self,
        input_data: bytes,
        input_format: str,
        request: ConversionRequest,
        timeout: Optional[float] = None,
    ) -> Tuple[ConversionResult, Optional[bytes]]:
        """
        Convert an image and return both result and output data.

        This is the preferred method for conversions as it properly handles
        the output data without using private attributes.

        Args:
            input_data: Input image data as bytes
            input_format: Input format name
            request: Conversion request with output format and settings
            timeout: Optional[Any] timeout in seconds (defaults to DEFAULT_CONVERSION_TIMEOUT)

        Returns:
            Tuple of (ConversionResult, output_bytes or None if failed)

        Raises:
            asyncio.TimeoutError: If conversion exceeds timeout
        """
        timeout = timeout or self.DEFAULT_CONVERSION_TIMEOUT

        try:
            # Run conversion with timeout
            result = await asyncio.wait_for(
                self.convert_image(input_data, input_format, request), timeout=timeout
            )

            # Extract output data if successful
            output_data = getattr(result, "_output_data", None)
            return result, output_data

        except asyncio.TimeoutError:
            logger.error(
                "Image conversion timed out",
                timeout=timeout,
                input_format=input_format,
                output_format=request.output_format,
            )
            # Create failed result
            result = ConversionResult(
                input_format=InputFormat(input_format.lower()),
                output_format=request.output_format,
                input_size=len(input_data),
                status=ConversionStatus.FAILED,
                error_message=f"Conversion timed out after {timeout} seconds",
                processing_time=timeout,
            )
            return result, None
