"""PNG optimized format handler with pngquant and optipng support."""

import os
import tempfile
from io import BytesIO
from typing import Any, BinaryIO, Dict

import structlog
from PIL import Image

from app.core.conversion.formats.png_handler import PNGHandler
from app.core.conversion.tools import ExternalToolExecutor
from app.core.exceptions import ConversionFailedError
from app.models.conversion import ConversionSettings

logger = structlog.get_logger()


class PNGOptimizedHandler(PNGHandler):
    """Handler for optimized PNG format using external tools."""

    def __init__(self) -> None:
        """Initialize optimized PNG handler."""
        super().__init__()
        self.supported_formats = ["png_opt", "png_optimized"]
        self.format_name = "PNG_OPTIMIZED"

        # Initialize external tool executors
        self.pngquant = ExternalToolExecutor("pngquant")
        self.optipng = ExternalToolExecutor("optipng")

        if not self.pngquant.is_available and not self.optipng.is_available:
            logger.warning(
                "PNG optimization tools not available",
                pngquant=self.pngquant.is_available,
                optipng=self.optipng.is_available,
            )

    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""
        return format_name.lower() in self.supported_formats

    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image as optimized PNG."""
        # First save as regular PNG
        temp_buffer = BytesIO()
        super().save_image(image, temp_buffer, settings)
        temp_buffer.seek(0)

        # If no optimization tools available, return regular PNG
        if not self.pngquant.is_available and not self.optipng.is_available:
            output_buffer.write(temp_buffer.getvalue())
            output_buffer.seek(0)
            return

        # Optimize using external tools
        try:
            optimized_data = self._optimize_png(temp_buffer.getvalue(), settings)
            output_buffer.write(optimized_data)
            output_buffer.seek(0)
        except Exception as e:
            logger.warning(
                "PNG optimization failed, falling back to regular PNG", error=str(e)
            )
            output_buffer.write(temp_buffer.getvalue())
            output_buffer.seek(0)

    def _optimize_png(self, png_data: bytes, settings: ConversionSettings) -> bytes:
        """Optimize PNG using external tools."""
        best_result = png_data
        best_size = len(png_data)

        # Try multiple optimization strategies
        strategies = []

        # Strategy 1: pngquant for lossy compression
        if self.pngquant.is_available and settings.quality < 100:
            strategies.append(("pngquant", self._optimize_with_pngquant))

        # Strategy 2: optipng for lossless optimization
        if self.optipng.is_available:
            strategies.append(("optipng", self._optimize_with_optipng))

        # Strategy 3: Combined (pngquant + optipng)
        if (
            self.pngquant.is_available
            and self.optipng.is_available
            and settings.quality < 100
        ):
            strategies.append(("combined", self._optimize_combined))

        # Try each strategy and keep the smallest result
        for strategy_name, strategy_func in strategies:
            try:
                optimized = strategy_func(png_data, settings)
                size = len(optimized)

                # Verify the optimized image is valid
                try:
                    Image.open(BytesIO(optimized))
                    if size < best_size:
                        best_result = optimized
                        best_size = size
                        logger.debug(
                            "PNG optimization strategy succeeded",
                            strategy=strategy_name,
                            original_size=len(png_data),
                            optimized_size=size,
                            reduction_pct=round((1 - size / len(png_data)) * 100, 1),
                        )
                except Exception:
                    logger.debug(
                        "PNG optimization produced invalid image",
                        strategy=strategy_name,
                    )
            except Exception as e:
                logger.debug(
                    "PNG optimization strategy failed",
                    strategy=strategy_name,
                    error=str(e),
                )

        return best_result

    def _optimize_with_pngquant(
        self, png_data: bytes, settings: ConversionSettings
    ) -> bytes:
        """Optimize PNG using pngquant (lossy)."""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temp_in:
            temp_in.write(png_data)
            temp_in.flush()
            temp_in_path = temp_in.name

        temp_out_path = temp_in_path + ".out.png"

        try:
            # Map quality to pngquant quality range
            # pngquant uses min-max quality (0-100)
            min_quality = max(0, settings.quality - 20)
            max_quality = settings.quality

            args = [
                "--quality",
                f"{min_quality}-{max_quality}",
                "--speed",
                "1" if settings.optimize else "3",
                "--output",
                temp_out_path,
                "--force",
                temp_in_path,
            ]

            # Execute using unified executor
            result = self.pngquant.execute(
                args,
                timeout=(
                    settings.conversion_timeout
                    if hasattr(settings, "conversion_timeout")
                    else 30
                ),
            )

            if result.returncode == 0 and os.path.exists(temp_out_path):
                with open(temp_out_path, "rb") as f:
                    return f.read()
            else:
                raise ConversionFailedError(
                    "pngquant optimization failed", details={"stderr": result.stderr}
                )
        finally:
            # Clean up temp files
            for path in [temp_in_path, temp_out_path]:
                if os.path.exists(path):
                    os.unlink(path)

    def _optimize_with_optipng(
        self, png_data: bytes, settings: ConversionSettings
    ) -> bytes:
        """Optimize PNG using optipng (lossless)."""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temp_file:
            temp_file.write(png_data)
            temp_file.flush()
            temp_path = temp_file.name

        try:
            # Optimization level: 1 (fast) to 7 (best)
            opt_level = 7 if settings.optimize else 2

            args = [f"-o{opt_level}", "-quiet", temp_path]

            # Execute using unified executor
            result = self.optipng.execute(
                args,
                timeout=(
                    settings.conversion_timeout
                    if hasattr(settings, "conversion_timeout")
                    else 30
                ),
            )

            if result.returncode == 0:
                with open(temp_path, "rb") as f:
                    return f.read()
            else:
                raise ConversionFailedError(
                    "optipng optimization failed", details={"stderr": result.stderr}
                )
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _optimize_combined(
        self, png_data: bytes, settings: ConversionSettings
    ) -> bytes:
        """Optimize PNG using both pngquant and optipng."""
        # First apply pngquant
        pngquant_result = self._optimize_with_pngquant(png_data, settings)

        # Then apply optipng to the result
        return self._optimize_with_optipng(pngquant_result, settings)

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get PNG-specific quality parameters."""
        params = super().get_quality_param(settings)

        # Add optimization hints
        params["optimize_externally"] = True
        params["tools_available"] = {
            "pngquant": self.pngquant.is_available,
            "optipng": self.optipng.is_available,
        }

        return params
