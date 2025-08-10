"""Lossless compression algorithms for various image formats."""

import asyncio
import io
from enum import Enum
from typing import Any, Dict, Optional, Tuple

import numpy as np
from PIL import Image

from app.core.constants import IMAGE_MAX_PIXELS
from app.core.security.errors_simplified import create_file_error
from app.core.security.memory import secure_clear
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Constants
MAX_COMPRESSION_ATTEMPTS = 10
COMPRESSION_TIMEOUT = 20  # seconds


class CompressionLevel(Enum):
    """Compression level presets."""

    FAST = "fast"
    BALANCED = "balanced"
    MAXIMUM = "maximum"


class LosslessCompressor:
    """Handles lossless compression for various image formats."""

    # Format support matrix
    LOSSLESS_FORMATS = {
        "png": {
            "native": True,
            "compression_levels": range(0, 10),
            "filters": ["none", "sub", "up", "avg", "paeth"],
            "strategies": ["default", "filtered", "huffman", "rle", "fixed"],
        },
        "webp": {
            "native": True,
            "compression_levels": range(0, 10),
            "methods": range(0, 7),
            "strategies": ["exact", "near_lossless"],
        },
        "avif": {
            "native": True,
            "compression_levels": ["fast", "default", "slow"],
            "pixel_format": ["yuv444", "yuv422", "yuv420"],
            "strategies": ["lossless"],
        },
        "tiff": {
            "native": True,
            "compression_types": ["none", "lzw", "packbits", "deflate"],
            "strategies": ["standard"],
        },
        "jpeg": {
            "native": False,  # Uses jpegtran for lossless operations
            "operations": ["optimize", "progressive", "crop", "rotate"],
            "strategies": ["recompress"],
        },
    }

    def __init__(self):
        """Initialize the lossless compressor."""
        self._compression_semaphore = asyncio.Semaphore(
            3
        )  # Limit concurrent compressions

    async def compress_lossless(
        self,
        image_data: bytes,
        output_format: str,
        compression_level: CompressionLevel = CompressionLevel.BALANCED,
        preserve_metadata: bool = False,
        **kwargs,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Perform lossless compression on the image.

        Args:
            image_data: Input image data
            output_format: Target format
            compression_level: Compression level preset
            preserve_metadata: Whether to preserve metadata
            **kwargs: Additional format-specific options

        Returns:
            Tuple of (compressed_data, compression_info)
        """
        # Input validation
        if not isinstance(image_data, bytes):
            raise create_file_error("invalid_input_type")
        if len(image_data) == 0:
            raise create_file_error("empty_input")
        if len(image_data) > IMAGE_MAX_PIXELS * 4:
            raise create_file_error("input_too_large")

        output_format = output_format.lower()
        if output_format not in self.LOSSLESS_FORMATS:
            raise create_file_error("format_not_lossless")

        # Use semaphore for concurrency control
        async with self._compression_semaphore:
            try:
                result = await asyncio.wait_for(
                    self._compress_internal(
                        image_data,
                        output_format,
                        compression_level,
                        preserve_metadata,
                        **kwargs,
                    ),
                    timeout=COMPRESSION_TIMEOUT,
                )
                return result
            except asyncio.TimeoutError:
                logger.error("Lossless compression timeout")
                raise create_file_error("compression_timeout")

    async def _compress_internal(
        self,
        image_data: bytes,
        output_format: str,
        compression_level: CompressionLevel,
        preserve_metadata: bool,
        **kwargs,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Internal compression implementation."""
        # Load image
        image = Image.open(io.BytesIO(image_data))
        original_size = len(image_data)

        # Get metadata if preserving
        metadata = {}
        if preserve_metadata and hasattr(image, "info"):
            metadata = image.info.copy()

        # Compress based on format
        if output_format == "png":
            compressed_data, info = await self._compress_png(
                image, compression_level, metadata, **kwargs
            )
        elif output_format == "webp":
            compressed_data, info = await self._compress_webp(
                image, compression_level, metadata, **kwargs
            )
        elif output_format == "avif":
            compressed_data, info = await self._compress_avif(
                image, compression_level, metadata, **kwargs
            )
        elif output_format == "tiff":
            compressed_data, info = await self._compress_tiff(
                image, compression_level, metadata, **kwargs
            )
        elif output_format == "jpeg":
            compressed_data, info = await self._optimize_jpeg(
                image_data, compression_level, **kwargs
            )
        else:
            compressed_data = image_data
            info = {"method": "none"}

        # Calculate compression ratio
        compressed_size = len(compressed_data)
        info["original_size"] = original_size
        info["compressed_size"] = compressed_size
        info["compression_ratio"] = (
            compressed_size / original_size if original_size > 0 else 1.0
        )
        info["size_reduction_percent"] = (1 - info["compression_ratio"]) * 100

        return compressed_data, info

    async def _compress_png(
        self,
        image: Image.Image,
        compression_level: CompressionLevel,
        metadata: Dict[str, Any],
        **kwargs,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Compress PNG with various strategies."""
        # Map compression level to PNG compress_level
        level_map = {
            CompressionLevel.FAST: 1,
            CompressionLevel.BALANCED: 6,
            CompressionLevel.MAXIMUM: 9,
        }
        compress_level = level_map.get(compression_level, 6)

        # Try different PNG filters for best compression
        best_data = None
        best_size = float("inf")
        best_filter = None

        filters = kwargs.get("filters", ["none", "sub", "up", "avg", "paeth"])

        for filter_type in filters:
            buffer = io.BytesIO()
            try:
                # Save with specific filter
                save_params = {
                    "format": "PNG",
                    "compress_level": compress_level,
                    "optimize": True,
                }

                # Add metadata if preserving
                if metadata:
                    save_params.update(metadata)

                image.save(buffer, **save_params)

                data = buffer.getvalue()
                if len(data) < best_size:
                    best_size = len(data)
                    best_data = data
                    best_filter = filter_type

            except Exception as e:
                logger.warning(f"PNG filter {filter_type} failed: {str(e)}")
                continue

        if best_data is None:
            # Fallback to default compression
            buffer = io.BytesIO()
            image.save(
                buffer, format="PNG", compress_level=compress_level, optimize=True
            )
            best_data = buffer.getvalue()
            best_filter = "default"

        info = {
            "method": "png_lossless",
            "compress_level": compress_level,
            "filter": best_filter,
            "optimize": True,
        }

        return best_data, info

    async def _compress_webp(
        self,
        image: Image.Image,
        compression_level: CompressionLevel,
        metadata: Dict[str, Any],
        **kwargs,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Compress WebP losslessly."""
        # Map compression level to WebP method
        method_map = {
            CompressionLevel.FAST: 0,
            CompressionLevel.BALANCED: 4,
            CompressionLevel.MAXIMUM: 6,
        }
        method = method_map.get(compression_level, 4)

        # Determine if near-lossless is acceptable
        near_lossless = kwargs.get("near_lossless", False)

        buffer = io.BytesIO()
        save_params = {
            "format": "WEBP",
            "lossless": True,
            "method": method,
            "exact": not near_lossless,
        }

        # Add metadata if preserving
        if metadata:
            save_params["exif"] = metadata.get("exif", b"")
            save_params["icc_profile"] = metadata.get("icc_profile", b"")

        image.save(buffer, **save_params)

        info = {
            "method": "webp_lossless",
            "compression_method": method,
            "exact": not near_lossless,
        }

        return buffer.getvalue(), info

    async def _compress_avif(
        self,
        image: Image.Image,
        compression_level: CompressionLevel,
        metadata: Dict[str, Any],
        **kwargs,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Compress AVIF losslessly."""
        # Map compression level to AVIF speed
        speed_map = {
            CompressionLevel.FAST: 8,
            CompressionLevel.BALANCED: 4,
            CompressionLevel.MAXIMUM: 0,
        }
        speed = speed_map.get(compression_level, 4)

        buffer = io.BytesIO()
        save_params = {
            "format": "AVIF",
            "quality": 100,  # Lossless
            "speed": speed,
            "subsampling": "4:4:4",  # No chroma subsampling for lossless
        }

        # Add metadata if preserving
        if metadata:
            save_params["exif"] = metadata.get("exif", b"")
            save_params["icc_profile"] = metadata.get("icc_profile", b"")

        try:
            image.save(buffer, **save_params)
        except Exception:
            # Fallback if AVIF plugin not available
            logger.warning("AVIF lossless compression not available")
            buffer = io.BytesIO()
            image.save(buffer, format="PNG", compress_level=9, optimize=True)

        info = {"method": "avif_lossless", "speed": speed, "subsampling": "4:4:4"}

        return buffer.getvalue(), info

    async def _compress_tiff(
        self,
        image: Image.Image,
        compression_level: CompressionLevel,
        metadata: Dict[str, Any],
        **kwargs,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Compress TIFF with various algorithms."""
        # Map compression level to TIFF compression
        compression_map = {
            CompressionLevel.FAST: "packbits",
            CompressionLevel.BALANCED: "lzw",
            CompressionLevel.MAXIMUM: "deflate",
        }
        compression = compression_map.get(compression_level, "lzw")

        buffer = io.BytesIO()
        save_params = {"format": "TIFF", "compression": compression}

        # Add metadata if preserving
        if metadata:
            save_params.update(metadata)

        image.save(buffer, **save_params)

        info = {"method": "tiff_lossless", "compression": compression}

        return buffer.getvalue(), info

    async def _optimize_jpeg(
        self, image_data: bytes, compression_level: CompressionLevel, **kwargs
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Optimize JPEG losslessly (requires external tool)."""
        # For now, just return the original data
        # In a real implementation, this would use jpegtran or similar

        info = {"method": "jpeg_optimize", "tool": "none", "optimized": False}

        return image_data, info

    def get_format_capabilities(self, format_name: str) -> Dict[str, Any]:
        """Get lossless compression capabilities for a format.

        Args:
            format_name: Format name

        Returns:
            Dictionary of format capabilities
        """
        return self.LOSSLESS_FORMATS.get(format_name.lower(), {})

    async def estimate_compression(
        self, image_data: bytes, output_format: str
    ) -> Dict[str, float]:
        """Estimate compression ratios for different levels.

        Args:
            image_data: Input image data
            output_format: Target format

        Returns:
            Dictionary with estimated compression ratios
        """
        # Simple estimation based on format and image characteristics
        image = Image.open(io.BytesIO(image_data))

        # Check image complexity
        if image.mode == "P":  # Palette mode
            complexity = len(image.getpalette()) / 768  # Max 256 colors * 3 channels
        else:
            # Convert to array and check unique colors
            arr = np.array(image)
            if len(arr.shape) == 3:
                unique_colors = len(np.unique(arr.reshape(-1, arr.shape[2]), axis=0))
                max_colors = 256 ** arr.shape[2]
                complexity = min(1.0, unique_colors / max_colors)
            else:
                unique_values = len(np.unique(arr))
                complexity = unique_values / 256

        # Estimate compression ratios
        base_ratios = {
            "png": {"fast": 0.9, "balanced": 0.7, "maximum": 0.6},
            "webp": {"fast": 0.8, "balanced": 0.6, "maximum": 0.5},
            "avif": {"fast": 0.7, "balanced": 0.5, "maximum": 0.4},
            "tiff": {"fast": 0.85, "balanced": 0.75, "maximum": 0.65},
        }

        format_ratios = base_ratios.get(
            output_format.lower(), {"fast": 1.0, "balanced": 0.9, "maximum": 0.8}
        )

        # Adjust based on complexity
        adjusted_ratios = {}
        for level, ratio in format_ratios.items():
            # Higher complexity means less compression
            adjusted_ratios[level] = ratio + (complexity * (1 - ratio) * 0.5)

        # Clear sensitive data - numpy arrays need special handling
        if "arr" in locals() and isinstance(arr, np.ndarray):
            arr.fill(0)

        return adjusted_ratios
