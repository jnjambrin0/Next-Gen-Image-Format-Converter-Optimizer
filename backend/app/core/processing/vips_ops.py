"""
Memory-efficient image processing using libvips for large files.
Provides streaming operations for files > 100MB to minimize memory usage.
"""

import io
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional, Tuple

try:
    import pyvips

    VIPS_AVAILABLE = True
except ImportError:
    VIPS_AVAILABLE = False
    pyvips = None

import psutil
from PIL import Image

from app.core.exceptions import ConversionError
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Constants for memory management
STREAMING_THRESHOLD_MB = 100  # Use streaming for files > 100MB
CHUNK_SIZE_MB = 10  # Process in 10MB chunks
MAX_MEMORY_MB = 512  # Maximum memory per operation
MEMORY_CHECK_INTERVAL = 100  # Check memory every N operations


class VipsOperations:
    """
    Memory-efficient image operations using libvips.
    Falls back to PIL for smaller files or when vips is unavailable.
    """

    def __init__(self):
        """Initialize vips operations handler."""
        self.vips_available = VIPS_AVAILABLE
        self._memory_process = psutil.Process()
        self._initial_memory = self._get_memory_usage()

        if self.vips_available:
            # Configure vips for memory efficiency
            pyvips.cache_set_max(0)  # Disable operation cache
            pyvips.cache_set_max_mem(MAX_MEMORY_MB * 1024 * 1024)
            pyvips.cache_set_max_files(0)
            # Set concurrency to match CPU cores for better parallel processing
            pyvips.concurrency_set(psutil.cpu_count())
            logger.info("libvips initialized for streaming operations")
        else:
            logger.warning("libvips not available, falling back to PIL")

    def _get_memory_usage(self) -> float:
        """Get current process memory usage in MB."""
        return self._memory_process.memory_info().rss / 1024 / 1024

    def _check_memory_limit(self) -> None:
        """Check if memory usage is within limits."""
        current_memory = self._get_memory_usage()
        memory_delta = current_memory - self._initial_memory

        if memory_delta > MAX_MEMORY_MB:
            raise ConversionError(
                f"Memory limit exceeded: {memory_delta:.1f}MB > {MAX_MEMORY_MB}MB"
            )

    def estimate_memory_usage(
        self, width: int, height: int, channels: int = 4
    ) -> float:
        """
        Estimate memory usage for an image in MB.

        Args:
            width: Image width in pixels
            height: Image height in pixels
            channels: Number of color channels (3 for RGB, 4 for RGBA)

        Returns:
            Estimated memory usage in MB
        """
        # Basic calculation: width * height * channels * bytes_per_channel
        bytes_per_pixel = channels  # Assuming 8-bit per channel
        base_memory = width * height * bytes_per_pixel

        # Convert to MB
        base_memory_mb = base_memory / (1024 * 1024)

        # Add 20% overhead for processing
        estimated_mb = base_memory_mb * 1.2

        return estimated_mb

    def monitor_memory(self, operation_name: str) -> Dict[str, Any]:
        """
        Monitor memory usage for an operation.

        Args:
            operation_name: Name of the operation being monitored

        Returns:
            Dictionary with memory statistics
        """
        current_memory = self._get_memory_usage()
        delta = current_memory - self._initial_memory
        usage_percent = (delta / MAX_MEMORY_MB) * 100 if MAX_MEMORY_MB > 0 else 0

        return {
            "operation": operation_name,
            "current_mb": round(current_memory, 2),
            "initial_mb": round(self._initial_memory, 2),
            "delta_mb": round(delta, 2),
            "limit_mb": MAX_MEMORY_MB,
            "usage_percent": round(usage_percent, 2),
        }

    def should_use_streaming(
        self, file_path: str = None, file_size: int = None
    ) -> bool:
        """
        Determine if streaming should be used based on file size.

        Args:
            file_path: Path to image file
            file_size: Size in bytes (if already known)

        Returns:
            True if streaming should be used (based on size threshold)
        """
        # Determine file size
        if file_size is None and file_path:
            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                return False

        if file_size is None:
            return False

        # Check if size exceeds streaming threshold
        size_mb = file_size / (1024 * 1024)
        should_stream = size_mb > STREAMING_THRESHOLD_MB

        # Note: Actual streaming requires vips, but this method indicates
        # whether streaming *would* be appropriate based on file size
        return should_stream

    def process_large_image(
        self,
        input_path: str,
        output_format: str,
        quality: int = 85,
        resize: Optional[Tuple[int, int]] = None,
        **kwargs,
    ) -> bytes:
        """
        Process large image using streaming to minimize memory usage.

        Args:
            input_path: Path to input image
            output_format: Output format (webp, avif, jpeg, etc.)
            quality: Quality for lossy formats (1-100)
            resize: Optional (width, height) tuple for resizing
            **kwargs: Additional format-specific options

        Returns:
            Processed image data as bytes
        """
        if not self.vips_available:
            return self._process_with_pil(
                input_path, output_format, quality, resize, **kwargs
            )

        try:
            # Load image with sequential access for streaming
            image = pyvips.Image.new_from_file(
                input_path,
                access="sequential",  # Stream from disk
                memory=False,  # Don't load into memory
            )

            # Check memory before operations
            self._check_memory_limit()

            # Apply resize if needed
            if resize:
                width, height = resize
                if width and not height:
                    # Calculate height maintaining aspect ratio
                    scale = width / image.width
                    image = image.resize(scale)
                elif height and not width:
                    # Calculate width maintaining aspect ratio
                    scale = height / image.height
                    image = image.resize(scale)
                elif width and height:
                    # Resize to exact dimensions
                    x_scale = width / image.width
                    y_scale = height / image.height
                    image = image.resize(x_scale, vscale=y_scale)

            # Check memory after resize
            self._check_memory_limit()

            # Convert to output format with streaming
            output_options = self._get_vips_save_options(
                output_format, quality, **kwargs
            )

            # Use buffer for output to avoid temporary files
            buffer = image.write_to_buffer(f".{output_format}", **output_options)

            # Final memory check
            self._check_memory_limit()

            logger.info(
                f"Processed large image with vips: {len(buffer) / 1024 / 1024:.1f}MB output",
                format=output_format,
                streaming=True,
            )

            return buffer

        except Exception as e:
            logger.warning(f"Vips processing failed, falling back to PIL: {e}")
            return self._process_with_pil(
                input_path, output_format, quality, resize, **kwargs
            )

    def process_in_chunks(
        self, input_data: bytes, output_format: str, quality: int = 85, **kwargs
    ) -> bytes:
        """
        Process image data in chunks to minimize memory usage.

        Args:
            input_data: Image data as bytes
            output_format: Output format
            quality: Quality for lossy formats
            **kwargs: Additional options

        Returns:
            Processed image data
        """
        if not self.vips_available:
            # Fall back to PIL for in-memory processing
            img = Image.open(io.BytesIO(input_data))
            output_buffer = io.BytesIO()

            save_kwargs = {"format": output_format.upper()}
            if output_format.lower() in ["jpeg", "jpg", "webp"]:
                save_kwargs["quality"] = quality
            if output_format.lower() == "png":
                save_kwargs["optimize"] = True

            img.save(output_buffer, **save_kwargs)
            return output_buffer.getvalue()

        try:
            # Create temporary file for streaming (vips needs file access)
            with tempfile.NamedTemporaryFile(suffix=".tmp", delete=False) as tmp_input:
                # Write in chunks to avoid memory spike
                chunk_size = CHUNK_SIZE_MB * 1024 * 1024
                offset = 0
                while offset < len(input_data):
                    chunk = input_data[offset : offset + chunk_size]
                    tmp_input.write(chunk)
                    offset += len(chunk)
                    self._check_memory_limit()

                tmp_input_path = tmp_input.name

            try:
                # Process using streaming
                result = self.process_large_image(
                    tmp_input_path, output_format, quality, **kwargs
                )
                return result
            finally:
                # Clean up temp file
                try:
                    os.unlink(tmp_input_path)
                except OSError:
                    pass

        except Exception as e:
            logger.error(f"Chunked processing failed: {e}")
            raise ConversionError(f"Failed to process image in chunks: {str(e)}")

    def _process_with_pil(
        self,
        input_path: str,
        output_format: str,
        quality: int,
        resize: Optional[Tuple[int, int]],
        **kwargs,
    ) -> bytes:
        """
        Fallback processing using PIL.

        Args:
            input_path: Path to input image
            output_format: Output format
            quality: Quality setting
            resize: Optional resize dimensions
            **kwargs: Additional options

        Returns:
            Processed image data
        """
        try:
            with Image.open(input_path) as img:
                # Apply resize if needed
                if resize:
                    width, height = resize
                    if width and not height:
                        # Maintain aspect ratio
                        ratio = width / img.width
                        height = int(img.height * ratio)
                    elif height and not width:
                        # Maintain aspect ratio
                        ratio = height / img.height
                        width = int(img.width * ratio)

                    if width and height:
                        img = img.resize((width, height), Image.Resampling.LANCZOS)

                # Convert to output format
                output_buffer = io.BytesIO()
                save_kwargs = {"format": output_format.upper()}

                if output_format.lower() in ["jpeg", "jpg", "webp"]:
                    save_kwargs["quality"] = quality
                if output_format.lower() == "png":
                    save_kwargs["optimize"] = True

                img.save(output_buffer, **save_kwargs)

                logger.info(
                    f"Processed with PIL fallback: {output_buffer.tell() / 1024 / 1024:.1f}MB output",
                    format=output_format,
                )

                return output_buffer.getvalue()

        except Exception as e:
            raise ConversionError(f"PIL processing failed: {str(e)}")

    def _get_vips_save_options(
        self, output_format: str, quality: int, **kwargs
    ) -> Dict[str, Any]:
        """
        Get vips-specific save options for different formats.

        Args:
            output_format: Target format
            quality: Quality setting
            **kwargs: Additional options

        Returns:
            Dictionary of vips save options
        """
        options = {}

        format_lower = output_format.lower()

        if format_lower in ["jpeg", "jpg"]:
            options["Q"] = quality
            options["optimize_coding"] = True
            options["strip"] = kwargs.get("strip_metadata", True)
            options["interlace"] = kwargs.get("progressive", False)

        elif format_lower == "webp":
            options["Q"] = quality
            options["lossless"] = quality == 100
            options["strip"] = kwargs.get("strip_metadata", True)
            options["effort"] = kwargs.get("effort", 4)  # 0-6, higher = slower/better

        elif format_lower == "png":
            options["compression"] = 9  # Max compression
            options["strip"] = kwargs.get("strip_metadata", True)
            options["interlace"] = kwargs.get("interlace", False)

        elif format_lower == "avif":
            options["Q"] = quality
            options["lossless"] = quality == 100
            options["effort"] = kwargs.get("effort", 4)
            options["strip"] = kwargs.get("strip_metadata", True)

        elif format_lower in ["heif", "heic"]:
            options["Q"] = quality
            options["lossless"] = quality == 100
            options["compression"] = "av1" if format_lower == "avif" else "hevc"

        elif format_lower == "tiff":
            options["compression"] = "lzw"
            options["strip"] = kwargs.get("strip_metadata", True)

        return options

    def estimate_memory_usage(self, width: int, height: int, channels: int = 4) -> int:
        """
        Estimate memory usage for an image.

        Args:
            width: Image width in pixels
            height: Image height in pixels
            channels: Number of color channels (default 4 for RGBA)

        Returns:
            Estimated memory usage in MB
        """
        # Basic formula: width * height * channels * bytes_per_channel
        # Add 20% overhead for processing
        bytes_needed = width * height * channels * 1  # 1 byte per channel for 8-bit
        overhead = 1.2
        return int((bytes_needed * overhead) / (1024 * 1024))

    def monitor_memory(self, operation_name: str) -> Dict[str, float]:
        """
        Monitor memory usage during an operation.

        Args:
            operation_name: Name of the operation being monitored

        Returns:
            Dictionary with memory statistics
        """
        current_memory = self._get_memory_usage()
        memory_delta = current_memory - self._initial_memory

        stats = {
            "operation": operation_name,
            "current_mb": current_memory,
            "initial_mb": self._initial_memory,
            "delta_mb": memory_delta,
            "limit_mb": MAX_MEMORY_MB,
            "usage_percent": (
                (memory_delta / MAX_MEMORY_MB) * 100 if MAX_MEMORY_MB > 0 else 0
            ),
        }

        if memory_delta > MAX_MEMORY_MB * 0.8:
            logger.warning(f"High memory usage in {operation_name}", **stats)

        return stats


# Create singleton instance
vips_ops = VipsOperations()
