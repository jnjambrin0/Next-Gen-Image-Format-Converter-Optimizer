"""Unit tests for format analyzer."""

from typing import Any

import pytest

from app.core.intelligence.format_analyzer import (FormatAnalyzer,
                                                   FormatCompatibility)
from app.models.conversion import ContentType, InputFormat, OutputFormat


class TestFormatAnalyzer:
    """Test cases for FormatAnalyzer."""

    @pytest.fixture
    def analyzer(self) -> None:
        """Create format analyzer instance."""
        return FormatAnalyzer()

    def test_format_compatibility_jpeg_to_webp(self, analyzer) -> None:
        """Test JPEG to WebP compatibility analysis."""
        compatibility = analyzer.analyze_format_compatibility(
            InputFormat.JPEG, OutputFormat.WEBP
        )

        assert isinstance(compatibility, FormatCompatibility)
        assert compatibility.compatibility_score >= 0.9
        assert compatibility.quality_retention >= 0.85
        assert compatibility.feature_preservation["color"] is True
        assert compatibility.feature_preservation["transparency"] is False
        assert len(compatibility.conversion_notes) > 0

    def test_format_compatibility_png_to_jpeg(self, analyzer) -> None:
        """Test PNG to JPEG compatibility (lossy conversion)."""
        compatibility = analyzer.analyze_format_compatibility(
            InputFormat.PNG, OutputFormat.JPEG
        )

        assert compatibility.compatibility_score < 0.8
        assert compatibility.quality_retention < 0.9
        assert compatibility.feature_preservation["transparency"] is False
        assert "Transparency will be lost" in str(compatibility.conversion_notes)

    def test_format_compatibility_same_format(self, analyzer) -> None:
        """Test same format compatibility."""
        compatibility = analyzer.analyze_format_compatibility(
            InputFormat.PNG, OutputFormat.PNG
        )

        assert compatibility.compatibility_score == 1.0
        assert compatibility.quality_retention == 1.0
        assert all(compatibility.feature_preservation.values())

    def test_format_compatibility_unknown_combination(self, analyzer) -> None:
        """Test compatibility for unknown format combination."""
        compatibility = analyzer.analyze_format_compatibility(
            InputFormat.BMP, OutputFormat.AVIF
        )

        # Should return reasonable defaults
        assert 0.5 <= compatibility.compatibility_score <= 1.0
        assert 0.5 <= compatibility.quality_retention <= 1.0
        assert isinstance(compatibility.feature_preservation, dict)

    def test_quality_prediction_lossless(self, analyzer) -> None:
        """Test quality prediction for lossless formats."""
        # PNG is always lossless
        quality = analyzer.predict_quality_score(
            OutputFormat.PNG, ContentType.PHOTO, quality_setting=50  # Should be ignored
        )
        assert quality == 1.0

    def test_quality_prediction_modern_formats(self, analyzer) -> None:
        """Test quality prediction for modern formats."""
        # AVIF with high quality setting
        quality = analyzer.predict_quality_score(
            OutputFormat.AVIF, ContentType.PHOTO, quality_setting=90
        )
        assert quality > 0.9

        # WebP with medium quality
        quality = analyzer.predict_quality_score(
            OutputFormat.WEBP, ContentType.PHOTO, quality_setting=75
        )
        assert 0.7 < quality < 0.9

    def test_quality_prediction_content_specific(self, analyzer) -> None:
        """Test content-specific quality adjustments."""
        # JPEG for documents (poor choice)
        doc_quality = analyzer.predict_quality_score(
            OutputFormat.JPEG, ContentType.DOCUMENT, quality_setting=85
        )

        # JPEG for photos (good choice)
        photo_quality = analyzer.predict_quality_score(
            OutputFormat.JPEG, ContentType.PHOTO, quality_setting=85
        )

        assert doc_quality < photo_quality

    def test_compression_ratio_estimation(self, analyzer) -> None:
        """Test compression ratio estimation."""
        # PNG to JPEG for photos (high compression)
        ratio = analyzer.estimate_compression_ratio(
            InputFormat.PNG, OutputFormat.JPEG, ContentType.PHOTO
        )
        assert ratio < 0.3  # JPEG much smaller than PNG for photos

        # PNG to PNG (no change)
        ratio = analyzer.estimate_compression_ratio(
            InputFormat.PNG, OutputFormat.PNG, ContentType.PHOTO
        )
        assert ratio == 1.0

    def test_compression_ratio_content_aware(self, analyzer) -> None:
        """Test content-aware compression ratios."""
        # PNG for documents (efficient)
        doc_ratio = analyzer.estimate_compression_ratio(
            InputFormat.BMP, OutputFormat.PNG, ContentType.DOCUMENT
        )

        # PNG for photos (inefficient)
        photo_ratio = analyzer.estimate_compression_ratio(
            InputFormat.BMP, OutputFormat.PNG, ContentType.PHOTO
        )

        assert doc_ratio < photo_ratio  # PNG better for documents

    def test_format_features_comprehensive(self, analyzer) -> None:
        """Test comprehensive format feature detection."""
        # PNG features
        png_features = analyzer.get_format_features(OutputFormat.PNG)
        assert png_features["transparency"] is True
        assert png_features["animation"] is False
        assert png_features["lossless"] is True
        assert png_features["16bit"] is True

        # JPEG features
        jpeg_features = analyzer.get_format_features(OutputFormat.JPEG)
        assert jpeg_features["transparency"] is False
        assert jpeg_features["lossless"] is False
        assert jpeg_features["progressive"] is True

        # AVIF features
        avif_features = analyzer.get_format_features(OutputFormat.AVIF)
        assert avif_features["hdr"] is True
        assert avif_features["animation"] is True
        assert avif_features["transparency"] is True

    def test_format_features_aliases(self, analyzer) -> None:
        """Test format feature detection with aliases."""
        # JPEG aliases
        jpg_features = analyzer.get_format_features(OutputFormat.JPG)
        jpeg_features = analyzer.get_format_features(OutputFormat.JPEG)
        assert jpg_features == jpeg_features

        # PNG optimized
        png_opt_features = analyzer.get_format_features(OutputFormat.PNG_OPTIMIZED)
        png_features = analyzer.get_format_features(OutputFormat.PNG)
        assert png_opt_features == png_features

    def test_comparison_metrics_creation(self, analyzer) -> None:
        """Test creation of comparison metrics."""
        formats = [OutputFormat.WEBP, OutputFormat.AVIF, OutputFormat.JPEG]
        metrics = analyzer.create_comparison_metrics(
            formats, ContentType.PHOTO, original_size_kb=1000
        )

        assert len(metrics) == 3

        # Check WebP metrics
        webp_metrics = metrics[OutputFormat.WEBP.value]
        assert len(webp_metrics) >= 4

        # Verify metric structure
        for metric in webp_metrics:
            assert metric.metric_name
            assert 0 <= metric.metric_value <= 1
            assert metric.display_value
            assert isinstance(metric.is_better_higher, bool)

    def test_comparison_metrics_values(self, analyzer) -> None:
        """Test comparison metric values."""
        formats = [OutputFormat.PNG, OutputFormat.JPEG]
        metrics = analyzer.create_comparison_metrics(
            formats, ContentType.PHOTO, original_size_kb=1000
        )

        # Find file size metrics
        png_metrics = metrics[OutputFormat.PNG.value]
        jpeg_metrics = metrics[OutputFormat.JPEG.value]

        png_size = next(m for m in png_metrics if m.metric_name == "File Size")
        jpeg_size = next(m for m in jpeg_metrics if m.metric_name == "File Size")

        # JPEG should show smaller size for photos
        assert "KB" in png_size.display_value
        assert "KB" in jpeg_size.display_value

        # Extract numeric values
        png_kb = int(png_size.display_value.split()[0])
        jpeg_kb = int(jpeg_size.display_value.split()[0])
        assert jpeg_kb < png_kb

    def test_speed_label_conversion(self, analyzer) -> None:
        """Test speed score to label conversion."""
        assert analyzer._speed_label(0.95) == "Very Fast"
        assert analyzer._speed_label(0.8) == "Fast"
        assert analyzer._speed_label(0.6) == "Moderate"
        assert analyzer._speed_label(0.4) == "Slow"
        assert analyzer._speed_label(0.2) == "Very Slow"

    def test_compatibility_matrix_initialization(self, analyzer) -> None:
        """Test that compatibility matrix is properly initialized."""
        # Check some key conversions exist
        assert ("jpeg", "webp") in analyzer.COMPATIBILITY_MATRIX
        assert ("png", "webp") in analyzer.COMPATIBILITY_MATRIX
        assert ("webp", "avif") in analyzer.COMPATIBILITY_MATRIX
        assert ("heif", "jpeg") in analyzer.COMPATIBILITY_MATRIX

    def test_feature_preservation_logic(self, analyzer) -> None:
        """Test feature preservation in conversions."""
        # PNG to JPEG loses transparency
        compat = analyzer.analyze_format_compatibility(
            InputFormat.PNG, OutputFormat.JPEG
        )
        assert compat.feature_preservation["transparency"] is False

        # PNG to WebP preserves transparency
        compat = analyzer.analyze_format_compatibility(
            InputFormat.PNG, OutputFormat.WEBP
        )
        assert compat.feature_preservation["transparency"] is True

    def test_quality_factors(self, analyzer) -> None:
        """Test quality factor constants."""
        assert analyzer.QUALITY_FACTORS["compression_type"]["lossless"] == 1.0
        assert analyzer.QUALITY_FACTORS["compression_type"]["lossy_high"] < 1.0
        assert analyzer.QUALITY_FACTORS["color_space"]["rgb"] == 1.0
        assert (
            analyzer.QUALITY_FACTORS["bit_depth"][16]
            > analyzer.QUALITY_FACTORS["bit_depth"][8]
        )
