"""Advanced encoding options for image formats."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from app.core.security.errors_simplified import create_file_error
from app.utils.logging import get_logger

logger = get_logger(__name__)


class ChromaSubsampling(Enum):
    """Chroma subsampling modes."""

    YUV444 = "444"  # No subsampling (highest quality)
    YUV422 = "422"  # 2:1 horizontal subsampling
    YUV420 = "420"  # 2:1 horizontal and vertical subsampling
    AUTO = "auto"  # Let encoder decide


@dataclass
class QuantizationTable:
    """Custom quantization table for JPEG."""

    luminance: List[List[int]]
    chrominance: List[List[int]]

    def validate(self) -> bool:
        """Validate quantization table dimensions."""
        if len(self.luminance) != 8 or any(len(row) != 8 for row in self.luminance):
            return False
        if len(self.chrominance) != 8 or any(len(row) != 8 for row in self.chrominance):
            return False
        return True


class EncodingOptions:
    """Advanced encoding options for various formats."""

    # Format capabilities
    FORMAT_CAPABILITIES = {
        "jpeg": {
            "chroma_subsampling": True,
            "progressive": True,
            "custom_quantization": True,
            "lossless": False,
            "alpha": False,
        },
        "webp": {
            "chroma_subsampling": True,
            "progressive": False,
            "custom_quantization": False,
            "lossless": True,
            "alpha": True,
        },
        "png": {
            "chroma_subsampling": False,
            "progressive": True,
            "custom_quantization": False,
            "lossless": True,
            "alpha": True,
        },
        "avif": {
            "chroma_subsampling": True,
            "progressive": False,
            "custom_quantization": False,
            "lossless": True,
            "alpha": True,
        },
        "heif": {
            "chroma_subsampling": True,
            "progressive": False,
            "custom_quantization": False,
            "lossless": True,
            "alpha": True,
        },
        "jxl": {
            "chroma_subsampling": True,
            "progressive": True,
            "custom_quantization": False,
            "lossless": True,
            "alpha": True,
        },
    }

    # Default quantization tables (standard JPEG)
    DEFAULT_LUMINANCE_TABLE = [
        [16, 11, 10, 16, 24, 40, 51, 61],
        [12, 12, 14, 19, 26, 58, 60, 55],
        [14, 13, 16, 24, 40, 57, 69, 56],
        [14, 17, 22, 29, 51, 87, 80, 62],
        [18, 22, 37, 56, 68, 109, 103, 77],
        [24, 35, 55, 64, 81, 104, 113, 92],
        [49, 64, 78, 87, 103, 121, 120, 101],
        [72, 92, 95, 98, 112, 100, 103, 99],
    ]

    DEFAULT_CHROMINANCE_TABLE = [
        [17, 18, 24, 47, 99, 99, 99, 99],
        [18, 21, 26, 66, 99, 99, 99, 99],
        [24, 26, 56, 99, 99, 99, 99, 99],
        [47, 66, 99, 99, 99, 99, 99, 99],
        [99, 99, 99, 99, 99, 99, 99, 99],
        [99, 99, 99, 99, 99, 99, 99, 99],
        [99, 99, 99, 99, 99, 99, 99, 99],
        [99, 99, 99, 99, 99, 99, 99, 99],
    ]

    def __init__(self) -> None:
        """Initialize encoding options."""

    def validate_options(
        self,
        format_name: str,
        chroma_subsampling: Optional[ChromaSubsampling] = None,
        progressive: Optional[bool] = None,
        custom_quantization: Optional[QuantizationTable] = None,
        lossless: Optional[bool] = None,
        alpha_quality: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Validate and prepare encoding options for a format.

        Args:
            format_name: Target format name
            chroma_subsampling: Chroma subsampling mode
            progressive: Enable progressive encoding
            custom_quantization: Custom quantization tables
            lossless: Enable lossless compression
            alpha_quality: Alpha channel quality (1-100)

        Returns:
            Validated encoding options dictionary
        """
        format_name = format_name.lower()
        if format_name not in self.FORMAT_CAPABILITIES:
            raise create_file_error("unsupported_format")

        capabilities = self.FORMAT_CAPABILITIES[format_name]
        options = {}

        # Validate chroma subsampling
        if chroma_subsampling and capabilities["chroma_subsampling"]:
            options["chroma_subsampling"] = chroma_subsampling
        elif chroma_subsampling and not capabilities["chroma_subsampling"]:
            logger.warning(f"Chroma subsampling not supported for {format_name}")

        # Validate progressive encoding
        if progressive is not None and capabilities["progressive"]:
            options["progressive"] = progressive
        elif progressive and not capabilities["progressive"]:
            logger.warning(f"Progressive encoding not supported for {format_name}")

        # Validate custom quantization
        if custom_quantization and capabilities["custom_quantization"]:
            if custom_quantization.validate():
                options["custom_quantization"] = custom_quantization
            else:
                raise create_file_error("invalid_quantization_table")
        elif custom_quantization and not capabilities["custom_quantization"]:
            logger.warning(f"Custom quantization not supported for {format_name}")

        # Validate lossless mode
        if lossless is not None and capabilities["lossless"]:
            options["lossless"] = lossless
        elif lossless and not capabilities["lossless"]:
            logger.warning(f"Lossless compression not supported for {format_name}")

        # Validate alpha quality
        if alpha_quality is not None:
            if capabilities["alpha"]:
                if 1 <= alpha_quality <= 100:
                    options["alpha_quality"] = alpha_quality
                else:
                    raise create_file_error("invalid_alpha_quality")
            else:
                logger.warning(f"Alpha channel not supported for {format_name}")

        return options

    def get_pillow_save_params(
        self, format_name: str, options: Dict[str, Any], quality: int = 85
    ) -> Dict[str, Any]:
        """Convert encoding options to Pillow save parameters.

        Args:
            format_name: Target format name
            options: Validated encoding options
            quality: Base quality setting

        Returns:
            Parameters for PIL Image.save()
        """
        params = {"quality": quality}
        format_name = format_name.lower()

        if format_name == "jpeg":
            # JPEG-specific parameters
            if "progressive" in options:
                params["progressive"] = options["progressive"]

            if "chroma_subsampling" in options:
                subsampling = options["chroma_subsampling"]
                if isinstance(subsampling, ChromaSubsampling):
                    if subsampling == ChromaSubsampling.YUV444:
                        params["subsampling"] = 0  # 4:4:4
                    elif subsampling == ChromaSubsampling.YUV422:
                        params["subsampling"] = 1  # 4:2:2
                    elif subsampling == ChromaSubsampling.YUV420:
                        params["subsampling"] = 2  # 4:2:0

            if "custom_quantization" in options:
                # Custom quantization tables would need special handling
                # This is a placeholder - actual implementation would need
                # to use PIL's qtables parameter
                pass

        elif format_name == "png":
            # PNG-specific parameters
            if "progressive" in options and options["progressive"]:
                params["progressive"] = True

            if "lossless" in options:
                # PNG is always lossless, but we can control compression
                params["compress_level"] = 9 if options["lossless"] else 6

        elif format_name == "webp":
            # WebP-specific parameters
            if "lossless" in options:
                params["lossless"] = options["lossless"]
                if options["lossless"]:
                    params.pop("quality", None)  # Quality not used in lossless mode

            if "alpha_quality" in options:
                params["alpha_quality"] = options["alpha_quality"]

        elif format_name == "avif":
            # AVIF-specific parameters
            if "lossless" in options and options["lossless"]:
                params["quality"] = 100
                params["subsampling"] = "4:4:4"

            if "chroma_subsampling" in options:
                subsampling = options["chroma_subsampling"]
                if isinstance(subsampling, ChromaSubsampling):
                    if subsampling == ChromaSubsampling.YUV444:
                        params["subsampling"] = "4:4:4"
                    elif subsampling == ChromaSubsampling.YUV422:
                        params["subsampling"] = "4:2:2"
                    elif subsampling == ChromaSubsampling.YUV420:
                        params["subsampling"] = "4:2:0"

        return params

    def scale_quantization_table(
        self, table: List[List[int]], quality: int
    ) -> List[List[int]]:
        """Scale a quantization table based on quality setting.

        Args:
            table: Base quantization table
            quality: Quality setting (1-100)

        Returns:
            Scaled quantization table
        """
        if quality < 1 or quality > 100:
            raise create_file_error("invalid_quality")

        # JPEG quality scaling formula
        if quality < 50:
            scale = 5000 / quality
        else:
            scale = 200 - 2 * quality

        scaled_table = []
        for row in table:
            scaled_row = []
            for value in row:
                scaled_value = int((value * scale + 50) / 100)
                # Clamp to valid range
                scaled_value = max(1, min(255, scaled_value))
                scaled_row.append(scaled_value)
            scaled_table.append(scaled_row)

        return scaled_table

    def get_format_capabilities(self, format_name: str) -> Dict[str, bool]:
        """Get capabilities for a specific format.

        Args:
            format_name: Format name

        Returns:
            Dictionary of format capabilities
        """
        return self.FORMAT_CAPABILITIES.get(format_name.lower(), {})
