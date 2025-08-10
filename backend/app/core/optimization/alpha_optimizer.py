"""Alpha channel optimization for transparent images."""

import io
from typing import Any, Dict, Optional, Tuple

import numpy as np
from PIL import Image

from app.core.constants import IMAGE_MAX_PIXELS
from app.core.security.errors_simplified import create_file_error
from app.core.security.memory import secure_clear
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Constants
ALPHA_THRESHOLD = 254  # Threshold for considering pixel fully opaque
MIN_TRANSPARENT_PIXELS = 100  # Minimum transparent pixels to keep alpha


class AlphaOptimizer:
    """Optimizes alpha channel in transparent images."""

    def __init__(self):
        """Initialize the alpha optimizer."""
        pass

    async def optimize_alpha(
        self,
        image_data: bytes,
        output_format: str,
        alpha_quality: Optional[int] = None,
        remove_unnecessary: bool = True,
        separate_quality: bool = True,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Optimize alpha channel in the image.

        Args:
            image_data: Input image data
            output_format: Target format
            alpha_quality: Quality for alpha channel (1-100)
            remove_unnecessary: Remove alpha if fully opaque
            separate_quality: Use separate quality for alpha

        Returns:
            Tuple of (optimized_data, optimization_info)
        """
        # Input validation
        if not isinstance(image_data, bytes):
            raise create_file_error("invalid_input_type")
        if len(image_data) == 0:
            raise create_file_error("empty_input")
        if len(image_data) > IMAGE_MAX_PIXELS * 4:
            raise create_file_error("input_too_large")

        # Load image
        image = Image.open(io.BytesIO(image_data))

        # Check if image has alpha channel
        has_alpha = image.mode in ("RGBA", "LA", "PA") or (
            image.mode == "P" and "transparency" in image.info
        )

        info = {
            "has_alpha": has_alpha,  # Changed from had_alpha to has_alpha
            "alpha_usage": (
                "none" if not has_alpha else "simple"
            ),  # Added required field
            "removed_alpha": False,
            "alpha_compressed": False,
            "transparent_pixel_count": 0,
            "alpha_complexity": 0.0,
        }

        if not has_alpha:
            # No alpha channel to optimize
            return image_data, info

        # Convert to RGBA for processing
        if image.mode != "RGBA":
            image = image.convert("RGBA")

        # Analyze alpha channel
        alpha_array = np.array(image.split()[-1])
        transparent_pixels = np.sum(alpha_array < 255)
        semi_transparent_pixels = np.sum((alpha_array > 0) & (alpha_array < 255))

        info["transparent_pixel_count"] = int(transparent_pixels)
        info["alpha_complexity"] = float(semi_transparent_pixels / alpha_array.size)

        # Determine alpha usage type
        if transparent_pixels == 0:
            info["alpha_usage"] = "unnecessary"
        elif semi_transparent_pixels == 0:
            info["alpha_usage"] = "binary"  # Only fully transparent/opaque
        elif info["alpha_complexity"] < 0.1:
            info["alpha_usage"] = "mostly_binary"
        elif info["alpha_complexity"] < 0.5:
            info["alpha_usage"] = "simple"
        else:
            info["alpha_usage"] = "complex"

        # Check if alpha channel can be removed
        if remove_unnecessary and transparent_pixels < MIN_TRANSPARENT_PIXELS:
            # Alpha channel is unnecessary, convert to RGB
            image = image.convert("RGB")
            info["removed_alpha"] = True

            # Save without alpha
            buffer = io.BytesIO()
            self._save_image(image, buffer, output_format, quality=85)

            # Clear sensitive data - numpy arrays need special handling
            if isinstance(alpha_array, np.ndarray):
                alpha_array.fill(0)

            return buffer.getvalue(), info

        # Optimize alpha channel
        if separate_quality and alpha_quality is not None:
            # Formats that support separate alpha quality
            if output_format.lower() in ["webp", "jxl"]:
                info["alpha_compressed"] = True

                # Save with separate alpha quality
                buffer = io.BytesIO()
                save_params = {
                    "format": output_format.upper(),
                    "quality": 85,
                    "alpha_quality": alpha_quality,
                }

                if output_format.lower() == "webp":
                    save_params["method"] = 4  # Better compression

                image.save(buffer, **save_params)

                # Clear sensitive data - numpy arrays need special handling
                if isinstance(alpha_array, np.ndarray):
                    alpha_array.fill(0)

                return buffer.getvalue(), info

        # For other formats or no separate quality, optimize by reducing complexity
        if info["alpha_complexity"] < 0.1:  # Less than 10% semi-transparent
            # Quantize alpha to reduce complexity
            alpha_quantized = self._quantize_alpha(alpha_array)

            # Reconstruct image with quantized alpha
            r, g, b, _ = image.split()
            alpha_image = Image.fromarray(alpha_quantized, mode="L")
            image = Image.merge("RGBA", (r, g, b, alpha_image))
            info["alpha_compressed"] = True

        # Save optimized image
        buffer = io.BytesIO()
        self._save_image(image, buffer, output_format, quality=85)

        # Clear sensitive data - numpy arrays need special handling
        if isinstance(alpha_array, np.ndarray):
            alpha_array.fill(0)

        return buffer.getvalue(), info

    def _quantize_alpha(self, alpha_array: np.ndarray, levels: int = 16) -> np.ndarray:
        """Quantize alpha channel to reduce complexity.

        Args:
            alpha_array: Alpha channel array
            levels: Number of quantization levels

        Returns:
            Quantized alpha array
        """
        # Create quantization bins
        bins = np.linspace(0, 255, levels)

        # Quantize alpha values
        quantized = np.digitize(alpha_array, bins) - 1
        quantized = np.clip(quantized, 0, levels - 1)

        # Map back to 0-255 range
        step = 255 / (levels - 1)
        quantized = (quantized * step).astype(np.uint8)

        # Ensure fully transparent stays transparent
        quantized[alpha_array == 0] = 0
        # Ensure fully opaque stays opaque
        quantized[alpha_array == 255] = 255

        return quantized

    def _save_image(
        self,
        image: Image.Image,
        buffer: io.BytesIO,
        format_name: str,
        quality: int = 85,
    ) -> None:
        """Save image with format-specific optimizations."""
        save_params = {"format": format_name.upper()}

        if format_name.lower() in ["jpeg", "jpg"]:
            save_params["quality"] = quality
            save_params["optimize"] = True
        elif format_name.lower() == "png":
            save_params["compress_level"] = 9
            save_params["optimize"] = True
        elif format_name.lower() == "webp":
            save_params["quality"] = quality
            save_params["method"] = 4
        else:
            save_params["quality"] = quality

        image.save(buffer, **save_params)
        buffer.seek(0)

    async def analyze_alpha_channel(self, image_data: bytes) -> Dict[str, Any]:
        """Analyze alpha channel characteristics.

        Args:
            image_data: Input image data

        Returns:
            Dictionary with alpha channel analysis
        """
        # Load image
        image = Image.open(io.BytesIO(image_data))

        # Check for alpha
        if image.mode not in ("RGBA", "LA", "PA"):
            return {"has_alpha": False, "alpha_usage": "none"}

        # Convert to RGBA for consistent processing
        if image.mode != "RGBA":
            image = image.convert("RGBA")

        # Get alpha channel
        alpha_array = np.array(image.split()[-1])

        # Calculate statistics
        total_pixels = alpha_array.size
        fully_transparent = np.sum(alpha_array == 0)
        fully_opaque = np.sum(alpha_array == 255)
        semi_transparent = total_pixels - fully_transparent - fully_opaque

        # Determine alpha usage pattern
        if fully_transparent == 0 and semi_transparent == 0:
            alpha_usage = "unnecessary"
        elif semi_transparent == 0:
            alpha_usage = "binary"  # Only fully transparent or opaque
        elif semi_transparent < total_pixels * 0.01:
            alpha_usage = "mostly_binary"
        elif semi_transparent < total_pixels * 0.1:
            alpha_usage = "simple"
        else:
            alpha_usage = "complex"

        # Calculate alpha histogram for complexity
        hist, _ = np.histogram(alpha_array, bins=256, range=(0, 256))
        non_zero_bins = np.sum(hist > 0)

        result = {
            "has_alpha": True,
            "alpha_usage": alpha_usage,
            "fully_transparent_pixels": int(fully_transparent),
            "fully_opaque_pixels": int(fully_opaque),
            "semi_transparent_pixels": int(semi_transparent),
            "transparency_ratio": float(fully_transparent / total_pixels),
            "alpha_complexity": float(non_zero_bins / 256),
            "recommended_action": self._get_recommendation(
                alpha_usage, semi_transparent, total_pixels
            ),
        }

        # Clear sensitive data - numpy arrays need special handling
        if isinstance(alpha_array, np.ndarray):
            alpha_array.fill(0)

        return result

    def _get_recommendation(
        self, alpha_usage: str, semi_transparent: int, total_pixels: int
    ) -> str:
        """Get optimization recommendation based on alpha usage."""
        if alpha_usage == "unnecessary":
            return "remove_alpha"
        elif alpha_usage == "binary":
            return "use_palette_transparency"
        elif alpha_usage == "mostly_binary":
            return "quantize_alpha"
        elif semi_transparent < total_pixels * 0.05:
            return "reduce_alpha_quality"
        else:
            return "preserve_alpha"
