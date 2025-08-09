"""JPEG optimized format handler with mozjpeg support."""

import os
import tempfile
from typing import Any, BinaryIO, Dict

import structlog
from PIL import Image

from app.core.conversion.formats.jpeg_handler import JPEGHandler
from app.core.conversion.tools import ExternalToolExecutor
from app.core.exceptions import ConversionFailedError
from app.models.conversion import ConversionSettings

logger = structlog.get_logger()


class JPEGOptimizedHandler(JPEGHandler):
    """Handler for optimized JPEG format using mozjpeg."""

    def __init__(self) -> None:
        """Initialize optimized JPEG handler."""
        super().__init__()
        self.supported_formats = ["jpeg_opt", "jpeg_optimized", "jpg_optimized"]
        self.format_name = "JPEG_OPTIMIZED"

        # Initialize mozjpeg executor with different possible names
        self.mozjpeg = ExternalToolExecutor(
            "mozjpeg", tool_variants=["cjpeg", "mozjpeg", "mozjpeg-cjpeg"]
        )

        if not self.mozjpeg.is_available:
            logger.warning("mozjpeg not available for JPEG optimization")

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as optimized JPEG using mozjpeg."""
        # If mozjpeg not available, fall back to regular JPEG
        if not self.mozjpeg.is_available:
            super().save_image(image, output_buffer, settings)
            return

        try:
            # Prepare image (convert to RGB if needed)
            if image.mode not in ("RGB", "L"):
                if image.mode == "RGBA" or "transparency" in image.info:
                    # Create white background for transparency
                    background = Image.new("RGB", image.size, (255, 255, 255))
                    if image.mode == "RGBA":
                        background.paste(image, mask=image.split()[3])
                    else:
                        background.paste(image)
                    image = background
                else:
                    image = image.convert("RGB")

            # Optimize using mozjpeg
            optimized_data = self._optimize_with_mozjpeg(image, settings)
            output_buffer.write(optimized_data)
            output_buffer.seek(0)

        except Exception as e:
            logger.warning(
                "mozjpeg optimization failed, falling back to regular JPEG",
                error=str(e),
            )
            super().save_image(image, output_buffer, settings)

    def _optimize_with_mozjpeg(
        self, image: Image.Image, settings: ConversionSettings
    ) -> bytes:
        """Optimize JPEG using mozjpeg."""
        # Create temporary file for input
        with tempfile.NamedTemporaryFile(suffix=".ppm", delete=False) as temp_in:
            # Save as PPM (uncompressed) for mozjpeg input
            image.save(temp_in, format="PPM")
            temp_in.flush()
            temp_in_path = temp_in.name

        temp_out_path = None

        try:
            # Build mozjpeg command args
            args = []

            # Quality setting
            args.extend(["-quality", str(settings.quality)])

            # Progressive encoding for better web performance
            if settings.optimize or settings.quality < 90:
                args.append("-progressive")

            # Optimize Huffman tables
            args.append("-optimize")

            # Use trellis quantization for better quality/size ratio
            if settings.optimize:
                args.extend(["-trellis", "1"])
                args.extend(["-overshoot", "1"])

            # Color subsampling settings
            if settings.quality >= 90:
                # High quality: use 4:4:4 (no subsampling)
                args.extend(["-sample", "1x1"])
            elif settings.quality >= 70:
                # Medium quality: use 4:2:2
                args.extend(["-sample", "2x1"])
            else:
                # Lower quality: use 4:2:0 (default)
                args.extend(["-sample", "2x2"])

            # Custom quantization tables for better compression
            if settings.optimize:
                args.append("-quant-table")
                args.append("2")  # Use improved quantization table

            # Output to stdout
            args.extend(["-outfile", "-"])

            # Input file
            args.append(temp_in_path)

            # Execute using unified executor
            result = self.mozjpeg.execute(
                args,
                timeout=(
                    settings.conversion_timeout
                    if hasattr(settings, "conversion_timeout")
                    else 30
                ),
            )

            if result.returncode == 0:
                return result.stdout
            else:
                raise ConversionFailedError(
                    "mozjpeg optimization failed", details={"stderr": result.stderr}
                )

        finally:
            # Clean up temp files
            if os.path.exists(temp_in_path):
                os.unlink(temp_in_path)
            if temp_out_path and os.path.exists(temp_out_path):
                os.unlink(temp_out_path)

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get JPEG-specific quality parameters."""
        params = super().get_quality_param(settings)

        # Add mozjpeg-specific hints
        params["optimize_with_mozjpeg"] = self.mozjpeg.is_available

        if self.mozjpeg.is_available:
            params["progressive"] = settings.optimize or settings.quality < 90
            params["trellis_quantization"] = settings.optimize

            # Subsampling info
            if settings.quality >= 90:
                params["subsampling"] = "4:4:4"
            elif settings.quality >= 70:
                params["subsampling"] = "4:2:2"
            else:
                params["subsampling"] = "4:2:0"

        return params
