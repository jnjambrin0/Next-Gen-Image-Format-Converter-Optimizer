"""Format analysis for quality prediction and compatibility assessment."""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from app.models.conversion import ContentType, OutputFormat, InputFormat
from app.models.recommendation import FormatCharacteristics, FormatComparisonMetric
from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class FormatCompatibility:
    """Format compatibility information."""

    format_from: str
    format_to: str
    compatibility_score: float
    quality_retention: float
    feature_preservation: Dict[str, bool]
    conversion_notes: List[str]


class FormatAnalyzer:
    """Analyzer for format characteristics and compatibility."""

    # Format conversion compatibility matrix
    COMPATIBILITY_MATRIX: Dict[Tuple[str, str], FormatCompatibility] = {}

    # Speed score thresholds
    SPEED_VERY_FAST_THRESHOLD = 0.9
    SPEED_FAST_THRESHOLD = 0.7
    SPEED_MODERATE_THRESHOLD = 0.5
    SPEED_SLOW_THRESHOLD = 0.3

    # Quality prediction factors
    QUALITY_FACTORS = {
        "compression_type": {
            "lossless": 1.0,
            "lossy_high": 0.85,
            "lossy_medium": 0.7,
            "lossy_low": 0.5,
        },
        "color_space": {"rgb": 1.0, "yuv444": 0.95, "yuv422": 0.85, "yuv420": 0.75},
        "bit_depth": {16: 1.0, 12: 0.9, 10: 0.85, 8: 0.8},
    }

    def __init__(self):
        """Initialize format analyzer."""
        self._init_compatibility_matrix()

    def _init_compatibility_matrix(self):
        """Initialize format compatibility matrix."""
        # JPEG to other formats
        self._add_compatibility(
            "jpeg",
            "webp",
            compatibility_score=0.95,
            quality_retention=0.9,
            feature_preservation={
                "color": True,
                "metadata": True,
                "transparency": False,
            },
            notes=["WebP provides better compression", "No transparency in source"],
        )
        self._add_compatibility(
            "jpeg",
            "avif",
            compatibility_score=0.9,
            quality_retention=0.85,
            feature_preservation={
                "color": True,
                "metadata": True,
                "transparency": False,
            },
            notes=[
                "AVIF offers superior compression",
                "Some quality loss in conversion",
            ],
        )
        self._add_compatibility(
            "jpeg",
            "png",
            compatibility_score=0.8,
            quality_retention=1.0,
            feature_preservation={
                "color": True,
                "metadata": True,
                "transparency": False,
            },
            notes=["Lossless but larger files", "No compression artifacts added"],
        )

        # PNG to other formats
        self._add_compatibility(
            "png",
            "webp",
            compatibility_score=0.95,
            quality_retention=1.0,
            feature_preservation={
                "color": True,
                "metadata": True,
                "transparency": True,
            },
            notes=["WebP preserves transparency", "Can use lossless mode"],
        )
        self._add_compatibility(
            "png",
            "avif",
            compatibility_score=0.9,
            quality_retention=0.95,
            feature_preservation={
                "color": True,
                "metadata": True,
                "transparency": True,
            },
            notes=["AVIF supports transparency", "Excellent compression"],
        )
        self._add_compatibility(
            "png",
            "jpeg",
            compatibility_score=0.7,
            quality_retention=0.8,
            feature_preservation={
                "color": True,
                "metadata": False,
                "transparency": False,
            },
            notes=["Transparency will be lost", "Lossy compression applied"],
        )

        # WebP to other formats
        self._add_compatibility(
            "webp",
            "avif",
            compatibility_score=0.85,
            quality_retention=0.9,
            feature_preservation={
                "color": True,
                "metadata": True,
                "transparency": True,
            },
            notes=["Modern format upgrade", "Better compression possible"],
        )
        self._add_compatibility(
            "webp",
            "jpeg",
            compatibility_score=0.8,
            quality_retention=0.85,
            feature_preservation={
                "color": True,
                "metadata": False,
                "transparency": False,
            },
            notes=["Fallback for compatibility", "Features may be lost"],
        )

        # HEIF/HEIC to other formats
        self._add_compatibility(
            "heif",
            "jpeg",
            compatibility_score=0.85,
            quality_retention=0.8,
            feature_preservation={
                "color": True,
                "metadata": True,
                "transparency": False,
            },
            notes=["Common conversion path", "Some quality loss expected"],
        )
        self._add_compatibility(
            "heif",
            "avif",
            compatibility_score=0.9,
            quality_retention=0.9,
            feature_preservation={
                "color": True,
                "metadata": True,
                "transparency": True,
            },
            notes=["Similar compression technology", "Good compatibility"],
        )

    def _add_compatibility(
        self,
        format_from: str,
        format_to: str,
        compatibility_score: float,
        quality_retention: float,
        feature_preservation: Dict[str, bool],
        notes: List[str],
    ):
        """Add format compatibility entry."""
        key = (format_from.lower(), format_to.lower())
        self.COMPATIBILITY_MATRIX[key] = FormatCompatibility(
            format_from=format_from,
            format_to=format_to,
            compatibility_score=compatibility_score,
            quality_retention=quality_retention,
            feature_preservation=feature_preservation,
            conversion_notes=notes,
        )

    def analyze_format_compatibility(
        self, input_format: InputFormat, output_format: OutputFormat
    ) -> FormatCompatibility:
        """Analyze compatibility between input and output formats.

        Args:
            input_format: Source format
            output_format: Target format

        Returns:
            Format compatibility analysis
        """
        # Normalize format names
        input_key = input_format.value.lower()
        output_key = output_format.value.lower()

        # Handle format aliases
        if input_key in ["jpg", "jpeg"]:
            input_key = "jpeg"
        if output_key in ["jpg", "jpeg", "jpeg_optimized", "jpg_optimized"]:
            output_key = "jpeg"
        if output_key in ["jpegxl", "jxl", "jpeg_xl"]:
            output_key = "jpegxl"
        if output_key in ["jp2", "jpeg2000"]:
            output_key = "jpeg2000"
        if output_key == "png_optimized":
            output_key = "png"

        # Check direct compatibility
        key = (input_key, output_key)
        if key in self.COMPATIBILITY_MATRIX:
            return self.COMPATIBILITY_MATRIX[key]

        # Same format conversion
        if input_key == output_key:
            return FormatCompatibility(
                format_from=input_key,
                format_to=output_key,
                compatibility_score=1.0,
                quality_retention=1.0,
                feature_preservation={
                    "color": True,
                    "metadata": True,
                    "transparency": True,
                },
                conversion_notes=["Same format optimization"],
            )

        # Default compatibility
        return self._calculate_default_compatibility(input_key, output_key)

    def _calculate_default_compatibility(
        self, input_format: str, output_format: str
    ) -> FormatCompatibility:
        """Calculate default compatibility for unknown combinations."""
        # Determine if formats are lossy or lossless
        lossless_formats = ["png", "webp", "avif", "jpegxl", "tiff", "bmp"]
        lossy_formats = ["jpeg", "jpg", "heif", "heic"]

        input_lossless = input_format in lossless_formats
        output_lossless = output_format in lossless_formats

        # Calculate scores
        if input_lossless and output_lossless:
            compatibility_score = 0.9
            quality_retention = 1.0
        elif not input_lossless and not output_lossless:
            compatibility_score = 0.8
            quality_retention = 0.85
        else:
            compatibility_score = 0.75
            quality_retention = 0.9 if output_lossless else 0.8

        return FormatCompatibility(
            format_from=input_format,
            format_to=output_format,
            compatibility_score=compatibility_score,
            quality_retention=quality_retention,
            feature_preservation={
                "color": True,
                "metadata": False,
                "transparency": output_format in ["png", "webp", "avif", "jpegxl"],
            },
            conversion_notes=["Generic format conversion"],
        )

    def predict_quality_score(
        self,
        output_format: OutputFormat,
        content_type: ContentType,
        quality_setting: int = 85,
    ) -> float:
        """Predict output quality score based on format and content.

        Args:
            output_format: Target format
            content_type: Type of content
            quality_setting: Quality setting (1-100)

        Returns:
            Predicted quality score (0-1)
        """
        # Base quality from setting
        base_quality = quality_setting / 100.0

        # Format-specific adjustments
        format_key = output_format.value.lower()

        # Lossless formats
        if format_key in ["png", "png_optimized", "bmp", "tiff"]:
            return 1.0  # Always perfect quality

        # Modern lossy formats
        if format_key in ["avif", "jpegxl", "jxl", "jpeg_xl"]:
            # Better quality preservation
            quality_multiplier = 1.1
        elif format_key in ["webp", "webp2"]:
            quality_multiplier = 1.05
        elif format_key in ["jpeg", "jpg", "jpeg_optimized", "jpg_optimized"]:
            quality_multiplier = 0.95
        elif format_key in ["heif", "heic"]:
            quality_multiplier = 1.0
        else:
            quality_multiplier = 1.0

        # Content-specific adjustments
        if content_type == ContentType.DOCUMENT:
            # Text needs higher quality
            if format_key in ["jpeg", "jpg"]:
                quality_multiplier *= 0.9  # JPEG bad for text
            else:
                quality_multiplier *= 1.05
        elif content_type == ContentType.ILLUSTRATION:
            # Graphics with flat colors
            if format_key in ["png", "webp"]:
                quality_multiplier *= 1.1
        elif content_type == ContentType.PHOTO:
            # Natural images
            if format_key in ["avif", "heif", "webp"]:
                quality_multiplier *= 1.05

        predicted_quality = base_quality * quality_multiplier
        return min(1.0, max(0.0, predicted_quality))

    def estimate_compression_ratio(
        self,
        input_format: InputFormat,
        output_format: OutputFormat,
        content_type: ContentType,
    ) -> float:
        """Estimate compression ratio for format conversion.

        Args:
            input_format: Source format
            output_format: Target format
            content_type: Type of content

        Returns:
            Estimated compression ratio (0-1, lower is better compression)
        """
        # Base compression ratios
        compression_base = {
            "png": 1.0,  # Reference
            "jpeg": 0.15,
            "webp": 0.12,
            "avif": 0.08,
            "jpegxl": 0.09,
            "heif": 0.10,
            "webp2": 0.07,
            "jpeg2000": 0.11,
            "bmp": 3.0,
            "tiff": 2.5,
            "gif": 0.8,
        }

        input_key = input_format.value.lower()
        output_key = output_format.value.lower()

        # Get base ratios
        input_ratio = compression_base.get(input_key, 1.0)
        output_ratio = compression_base.get(output_key, 1.0)

        # Calculate relative compression
        if input_ratio > 0:
            relative_ratio = output_ratio / input_ratio
        else:
            relative_ratio = output_ratio

        # Adjust for content type
        if content_type == ContentType.PHOTO:
            if output_key in ["png"]:
                relative_ratio *= 3.0  # PNG terrible for photos
            elif output_key in ["avif", "webp"]:
                relative_ratio *= 0.8  # Extra good for photos
        elif content_type == ContentType.DOCUMENT:
            if output_key in ["png"]:
                relative_ratio *= 0.5  # PNG good for documents
            elif output_key in ["jpeg"]:
                relative_ratio *= 1.5  # JPEG poor for text
        elif content_type == ContentType.ILLUSTRATION:
            if output_key in ["png", "webp"]:
                relative_ratio *= 0.7  # Good for graphics

        return min(1.0, max(0.01, relative_ratio))

    def get_format_features(self, format_enum: OutputFormat) -> Dict[str, bool]:
        """Get detailed feature support for a format.

        Args:
            format_enum: Output format

        Returns:
            Dictionary of supported features
        """
        # Extended feature database
        feature_db = {
            OutputFormat.PNG: {
                "transparency": True,
                "animation": False,
                "hdr": False,
                "lossless": True,
                "progressive": True,
                "metadata": True,
                "color_profiles": True,
                "16bit": True,
            },
            OutputFormat.JPEG: {
                "transparency": False,
                "animation": False,
                "hdr": False,
                "lossless": False,
                "progressive": True,
                "metadata": True,
                "color_profiles": True,
                "16bit": False,
            },
            OutputFormat.WEBP: {
                "transparency": True,
                "animation": True,
                "hdr": False,
                "lossless": True,
                "progressive": False,
                "metadata": True,
                "color_profiles": True,
                "16bit": False,
            },
            OutputFormat.AVIF: {
                "transparency": True,
                "animation": True,
                "hdr": True,
                "lossless": True,
                "progressive": False,
                "metadata": True,
                "color_profiles": True,
                "16bit": True,
            },
            OutputFormat.JPEGXL: {
                "transparency": True,
                "animation": True,
                "hdr": True,
                "lossless": True,
                "progressive": True,
                "metadata": True,
                "color_profiles": True,
                "16bit": True,
                "32bit": True,
            },
            OutputFormat.HEIF: {
                "transparency": True,
                "animation": True,
                "hdr": True,
                "lossless": False,
                "progressive": False,
                "metadata": True,
                "color_profiles": True,
                "16bit": True,
            },
        }

        # Handle aliases
        if format_enum in [
            OutputFormat.JPG,
            OutputFormat.JPEG_OPTIMIZED,
            OutputFormat.JPG_OPTIMIZED,
        ]:
            format_enum = OutputFormat.JPEG
        elif format_enum == OutputFormat.PNG_OPTIMIZED:
            format_enum = OutputFormat.PNG
        elif format_enum in [OutputFormat.JXL, OutputFormat.JPEG_XL]:
            format_enum = OutputFormat.JPEGXL

        return feature_db.get(
            format_enum,
            {
                "transparency": False,
                "animation": False,
                "hdr": False,
                "lossless": False,
                "progressive": False,
                "metadata": True,
                "color_profiles": False,
                "16bit": False,
            },
        )

    def create_comparison_metrics(
        self,
        formats: List[OutputFormat],
        content_type: ContentType,
        original_size_kb: int,
    ) -> Dict[str, List[FormatComparisonMetric]]:
        """Create comparison metrics for multiple formats.

        Args:
            formats: List of formats to compare
            content_type: Type of content
            original_size_kb: Original file size

        Returns:
            Dictionary of metrics for each format
        """
        metrics = {}

        for format_enum in formats:
            format_metrics = []

            # File size metric
            compression_ratio = self.estimate_compression_ratio(
                InputFormat.PNG, format_enum, content_type  # Use PNG as baseline
            )
            estimated_size = int(original_size_kb * compression_ratio)
            format_metrics.append(
                FormatComparisonMetric(
                    metric_name="File Size",
                    metric_value=1.0 - compression_ratio,  # Invert so higher is better
                    display_value=f"{estimated_size} KB",
                    is_better_higher=False,
                )
            )

            # Quality metric
            quality_score = self.predict_quality_score(format_enum, content_type)
            format_metrics.append(
                FormatComparisonMetric(
                    metric_name="Quality",
                    metric_value=quality_score,
                    display_value=f"{int(quality_score * 100)}%",
                    is_better_higher=True,
                )
            )

            # Browser support metric
            from .recommendation_engine import RecommendationEngine

            characteristics = RecommendationEngine.FORMAT_CHARACTERISTICS.get(
                format_enum
            )
            if characteristics:
                format_metrics.append(
                    FormatComparisonMetric(
                        metric_name="Browser Support",
                        metric_value=characteristics.browser_support,
                        display_value=f"{int(characteristics.browser_support * 100)}%",
                        is_better_higher=True,
                    )
                )

                # Processing speed metric
                format_metrics.append(
                    FormatComparisonMetric(
                        metric_name="Encoding Speed",
                        metric_value=characteristics.processing_speed,
                        display_value=self._speed_label(
                            characteristics.processing_speed
                        ),
                        is_better_higher=True,
                    )
                )

            # Feature support metric
            features = self.get_format_features(format_enum)
            feature_count = sum(1 for v in features.values() if v)
            feature_score = feature_count / len(features) if features else 0
            format_metrics.append(
                FormatComparisonMetric(
                    metric_name="Features",
                    metric_value=feature_score,
                    display_value=f"{feature_count}/{len(features)}",
                    is_better_higher=True,
                )
            )

            metrics[format_enum.value] = format_metrics

        return metrics

    def _speed_label(self, speed_score: float) -> str:
        """Convert speed score to human-readable label."""
        if speed_score >= self.SPEED_VERY_FAST_THRESHOLD:
            return "Very Fast"
        elif speed_score >= self.SPEED_FAST_THRESHOLD:
            return "Fast"
        elif speed_score >= self.SPEED_MODERATE_THRESHOLD:
            return "Moderate"
        elif speed_score >= self.SPEED_SLOW_THRESHOLD:
            return "Slow"
        else:
            return "Very Slow"
