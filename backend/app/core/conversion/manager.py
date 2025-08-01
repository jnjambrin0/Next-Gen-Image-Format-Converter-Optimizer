"""Conversion manager for orchestrating image conversions."""

import asyncio
import time
from typing import Dict, Type, Optional, Any, Tuple, List
from io import BytesIO
from datetime import datetime, timezone
import tempfile
import os
import structlog

from app.models.conversion import (
    ConversionRequest,
    ConversionResult,
    ConversionStatus,
    ConversionSettings,
    InputFormat,
    OutputFormat,
)
from app.core.exceptions import (
    ConversionError,
    ValidationError,
    InvalidImageError,
    UnsupportedFormatError,
    ConversionFailedError,
)
from app.core.conversion.formats.base import BaseFormatHandler
from app.core.conversion.image_processor import ImageProcessor
from app.core.security.engine import SecurityEngine
from app.config import settings

logger = structlog.get_logger()


class ConversionManager:
    """Manages the image conversion pipeline."""

    # Default timeout for conversion operations (in seconds)
    DEFAULT_CONVERSION_TIMEOUT = 30.0

    def __init__(self):
        """Initialize conversion manager."""
        self.format_handlers: Dict[str, Type[BaseFormatHandler]] = {}
        self.image_processor = ImageProcessor()
        self.security_engine = SecurityEngine() if settings.enable_sandboxing else None
        self._initialize_handlers()

    def _initialize_handlers(self) -> None:
        """Initialize format handlers."""
        # Import handlers here to avoid circular imports
        from app.core.conversion.formats.jpeg_handler import JPEGHandler
        from app.core.conversion.formats.png_handler import PNGHandler
        from app.core.conversion.formats.webp_handler import WebPHandler
        from app.core.conversion.formats.avif_handler import AVIFHandler

        # Register input handlers
        self.register_handler("jpeg", JPEGHandler)
        self.register_handler("jpg", JPEGHandler)
        self.register_handler("png", PNGHandler)

        # Register output handlers
        self.register_handler("webp", WebPHandler)
        self.register_handler("avif", AVIFHandler)

    def register_handler(
        self, format_name: str, handler_class: Type[BaseFormatHandler]
    ) -> None:
        """Register a format handler."""
        self.format_handlers[format_name.lower()] = handler_class

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

        # Initialize result
        result = ConversionResult(
            input_format=InputFormat(input_format.lower()),
            output_format=request.output_format,
            input_size=len(input_data),
            status=ConversionStatus.PROCESSING,
            quality_settings=request.settings.model_dump() if request.settings else {},
        )

        try:
            # Validate input
            await self._validate_input(input_data, input_format)

            # Security scan if enabled
            if self.security_engine and settings.enable_sandboxing:
                scan_report = await self.security_engine.scan_file(input_data)
                if not scan_report["is_safe"]:
                    raise ConversionError(
                        f"Security scan failed: {', '.join(scan_report['threats_found'])}"
                    )

            # Get handlers
            input_handler = self._get_handler(input_format.lower())
            output_handler = self._get_handler(request.output_format.lower())

            # Choose conversion method based on sandboxing
            if self.security_engine and settings.enable_sandboxing:
                # Sandboxed conversion
                output_data = await self._process_sandboxed(
                    input_data, input_format, request, result
                )
            else:
                # Direct conversion (legacy mode)
                # Load image
                image = await self._load_image(input_data, input_handler)

                # Process image
                conversion_settings = request.settings or ConversionSettings()
                # Update quality_settings in result to reflect what was actually used
                result.quality_settings = conversion_settings.model_dump()
                output_data = await self._process_image(image, output_handler, conversion_settings)

            # Strip metadata if requested
            if self.security_engine and (request.settings and request.settings.strip_metadata):
                output_data = await self.security_engine.strip_metadata(
                    output_data, request.output_format
                )

            # Update result
            result.output_size = len(output_data)
            result.processing_time = time.time() - start_time
            result.status = ConversionStatus.COMPLETED
            result.completed_at = datetime.now(timezone.utc)

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

            logger.error(
                "Image conversion failed",
                conversion_id=result.id,
                error=str(e),
                error_type=type(e).__name__,
            )

            raise

    async def _process_sandboxed(
        self,
        input_data: bytes,
        input_format: str,
        request: ConversionRequest,
        result: ConversionResult,
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
        # Create sandbox for this conversion
        sandbox = self.security_engine.create_sandbox(
            conversion_id=result.id,
            strictness=settings.sandbox_strictness
        )
        
        try:
            # Write input data to temporary file
            with tempfile.NamedTemporaryFile(
                suffix=f".{input_format}",
                delete=False
            ) as input_file:
                input_file.write(input_data)
                input_path = input_file.name
                
            # Create output file path
            output_path = input_path.replace(
                f".{input_format}",
                f"_converted.{request.output_format}"
            )
            
            # Build conversion command
            command = self._build_conversion_command(
                input_path,
                output_path,
                input_format,
                request.output_format,
                request.settings or ConversionSettings()
            )
            
            # Execute conversion in sandbox
            sandbox_result, process_sandbox = await self.security_engine.execute_sandboxed_conversion(
                sandbox=sandbox,
                conversion_id=result.id,
                command=command,
            )
            
            # Read output file
            if os.path.exists(output_path):
                with open(output_path, 'rb') as f:
                    output_data = f.read()
            else:
                raise ConversionFailedError("Conversion produced no output file")
                
            # Update result with sandbox metrics
            result.quality_settings.update({
                "sandbox_execution_time": process_sandbox.execution_time,
                "sandbox_memory_used_mb": process_sandbox.actual_usage.get("memory_mb", 0),
                "sandbox_violations": process_sandbox.security_violations,
            })
            
            return output_data
            
        finally:
            # Cleanup
            self.security_engine.cleanup_sandbox(result.id)
            
            # Remove temporary files
            for path in [input_path, output_path]:
                try:
                    if os.path.exists(path):
                        os.unlink(path)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp file {path}: {e}")
                    
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
        
        This uses ImageMagick's convert command for now.
        In production, this would use the actual format handlers.
        
        Args:
            input_path: Input file path
            output_path: Output file path
            input_format: Input format
            output_format: Output format
            settings: Conversion settings
            
        Returns:
            Command list for subprocess
        """
        # Basic convert command
        command = ["convert", input_path]
        
        # Add quality setting if applicable
        if output_format.lower() in ["jpeg", "jpg", "webp"]:
            command.extend(["-quality", str(settings.quality)])
            
        # Add optimization if requested
        if settings.optimize:
            command.append("-strip")  # Remove metadata
            if output_format.lower() in ["png"]:
                command.extend(["-define", "png:compression-level=9"])
                
        # Add output path
        command.append(output_path)
        
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
        return handler_class()

    async def _load_image(self, input_data: bytes, handler: BaseFormatHandler) -> Any:
        """Load image using handler."""
        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, handler.load_image, input_data)
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
            timeout: Optional timeout in seconds (defaults to DEFAULT_CONVERSION_TIMEOUT)

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
