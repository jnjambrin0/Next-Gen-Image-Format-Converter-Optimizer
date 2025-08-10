"""Unit tests for the Image Analyzer module (ML content detection)."""

import io
from typing import Any
from unittest.mock import Mock, patch

import numpy as np
import pytest
from PIL import Image

# Import fixtures - these will be available when conftest.py is in tests/ directory
# The fixtures are automatically discovered by pytest


class TestImageAnalyzer:
    """Test suite for ImageAnalyzer class with ML content detection."""

    @pytest.fixture
    def image_analyzer(self) -> None:
        """Create an ImageAnalyzer instance for testing."""
        # TODO: Uncomment when ImageAnalyzer is implemented
        # from app.core.intelligence.analyzer import ImageAnalyzer
        # return ImageAnalyzer()

        # Mock for now
        mock_analyzer = Mock()
        mock_analyzer.model_loaded = True
        mock_analyzer.content_classifier = Mock()
        mock_analyzer.quality_predictor = Mock()
        mock_analyzer.content_types = [
            "photograph",
            "screenshot",
            "illustration",
            "document",
        ]
        mock_analyzer.analyze = Mock(
            return_value={
                "content_type": "photograph",
                "confidence": 0.95,
                "characteristics": {"has_faces": True},
                "optimization_suggestions": {"recommended_formats": ["webp", "avif"]},
            }
        )
        return mock_analyzer

    @pytest.fixture
    def mock_onnx_model(self) -> None:
        """Mock ONNX Runtime model."""
        with patch("onnxruntime.InferenceSession") as mock_session:
            mock_instance = Mock()
            mock_session.return_value = mock_instance

            # Mock model inputs/outputs
            mock_input = Mock()
            mock_input.name = "input"
            mock_input.shape = [1, 3, 224, 224]
            mock_instance.get_inputs.return_value = [mock_input]

            yield mock_instance

    def test_analyzer_initialization(self, image_analyzer) -> None:
        """Test analyzer initializes with models loaded."""
        # TODO: Enable when ImageAnalyzer is implemented
        pytest.skip("Waiting for ImageAnalyzer implementation")

        assert image_analyzer.model_loaded is True
        assert image_analyzer.content_classifier is not None
        assert image_analyzer.quality_predictor is not None
        assert len(image_analyzer.content_types) > 0

    def test_detect_photograph_content(
        self, image_analyzer, all_test_images, mock_ml_model_response
    ) -> None:
        """Test detection of photograph content type."""
        # Arrange
        photo_path = all_test_images["sample_photo"]["path"]
        with open(photo_path, "rb") as f:
            image_data = f.read()

        # Mock ML model response
        with patch.object(image_analyzer, "_run_inference") as mock_inference:
            mock_inference.return_value = mock_ml_model_response

            # Act
            result = image_analyzer.analyze(image_data)

            # Assert
            assert result["content_type"] == "photograph"
            assert result["confidence"] > 0.9
            assert "has_faces" in result["characteristics"]
            assert len(result["optimization_suggestions"]["recommended_formats"]) > 0

    def test_detect_screenshot_content(self, image_analyzer, all_test_images) -> None:
        """Test detection of screenshot content type."""
        # Arrange
        screenshot_path = all_test_images["screenshot"]["path"]
        with open(screenshot_path, "rb") as f:
            image_data = f.read()

        # Mock ML model to return screenshot classification
        with patch.object(image_analyzer, "_run_inference") as mock_inference:
            mock_inference.return_value = {
                "content_type": "screenshot",
                "confidence": 0.98,
                "characteristics": {
                    "has_text": True,
                    "has_ui_elements": True,
                    "is_computer_generated": True,
                },
            }

            # Act
            result = image_analyzer.analyze(image_data)

            # Assert
            assert result["content_type"] == "screenshot"
            assert result["confidence"] > 0.95
            assert result["characteristics"]["has_ui_elements"] is True
            assert "png" in result["optimization_suggestions"]["recommended_formats"]

    def test_detect_illustration_content(self, image_analyzer, all_test_images) -> None:
        """Test detection of illustration/graphic content type."""
        # Arrange
        illustration_path = all_test_images["illustration"]["path"]
        with open(illustration_path, "rb") as f:
            image_data = f.read()

        # Mock ML model response
        with patch.object(image_analyzer, "_run_inference") as mock_inference:
            mock_inference.return_value = {
                "content_type": "illustration",
                "confidence": 0.92,
                "characteristics": {
                    "is_vector_style": True,
                    "has_gradients": True,
                    "has_transparency": True,
                },
            }

            # Act
            result = image_analyzer.analyze(image_data)

            # Assert
            assert result["content_type"] == "illustration"
            assert result["characteristics"]["has_transparency"] is True
            assert result["optimization_suggestions"]["preserve_transparency"] is True

    def test_detect_document_content(self, image_analyzer, all_test_images) -> None:
        """Test detection of document/scan content type."""
        # Arrange
        document_path = all_test_images["document_scan"]["path"]
        with open(document_path, "rb") as f:
            image_data = f.read()

        # Mock ML model response
        with patch.object(image_analyzer, "_run_inference") as mock_inference:
            mock_inference.return_value = {
                "content_type": "document",
                "confidence": 0.96,
                "characteristics": {
                    "has_text": True,
                    "text_density": 0.85,
                    "is_monochrome": False,
                },
            }

            # Act
            result = image_analyzer.analyze(image_data)

            # Assert
            assert result["content_type"] == "document"
            assert result["characteristics"]["has_text"] is True
            assert result["optimization_suggestions"]["preserve_text_clarity"] is True

    def test_quality_prediction(self, image_analyzer, image_generator) -> None:
        """Test quality prediction for different compression levels."""
        # Arrange
        test_image = image_generator(width=800, height=600)

        # Act
        quality_predictions = image_analyzer.predict_quality_settings(test_image)

        # Assert
        assert "optimal_quality" in quality_predictions
        assert "file_size_estimates" in quality_predictions
        assert 70 <= quality_predictions["optimal_quality"] <= 95
        assert len(quality_predictions["file_size_estimates"]) > 0

    def test_face_detection(self, image_analyzer, mock_onnx_model) -> None:
        """Test face detection in images."""
        # Arrange
        # Create test image with face-like features
        test_image = image_generator(width=400, height=400)

        # Mock face detection model
        mock_onnx_model.run.return_value = [
            np.array([[0.95, 150, 150, 100, 100]])  # confidence, x, y, w, h
        ]

        # Act
        faces = image_analyzer.detect_faces(test_image)

        # Assert
        assert len(faces) == 1
        assert faces[0]["confidence"] > 0.9
        assert "bbox" in faces[0]

    def test_dominant_colors_extraction(self, image_analyzer, all_test_images) -> None:
        """Test extraction of dominant colors from image."""
        # Arrange
        photo_path = all_test_images["sample_photo"]["path"]
        with open(photo_path, "rb") as f:
            image_data = f.read()

        # Act
        colors = image_analyzer.extract_dominant_colors(image_data, n_colors=5)

        # Assert
        assert len(colors) == 5
        assert all(isinstance(color, str) and color.startswith("#") for color in colors)
        assert all(len(color) == 7 for color in colors)  # #RRGGBB format

    def test_optimization_suggestions(self, image_analyzer, all_test_images) -> None:
        """Test generation of optimization suggestions based on content."""
        # Test different content types
        test_cases = [
            ("sample_photo", ["webp", "avif"], 85),
            ("screenshot", ["png", "webp"], 95),
            ("document_scan", ["pdf", "png"], 95),
            ("illustration", ["png", "webp", "svg"], 90),
        ]

        for image_key, expected_formats, min_quality in test_cases:
            # Arrange
            image_path = all_test_images[image_key]["path"]
            with open(image_path, "rb") as f:
                image_data = f.read()

            # Act
            result = image_analyzer.analyze(image_data)
            suggestions = result["optimization_suggestions"]

            # Assert
            assert any(
                fmt in suggestions["recommended_formats"] for fmt in expected_formats
            )
            assert suggestions["recommended_quality"] >= min_quality

    def test_batch_analysis(self, image_analyzer, all_test_images) -> None:
        """Test batch analysis of multiple images."""
        # Arrange
        image_paths = [
            all_test_images["sample_photo"]["path"],
            all_test_images["screenshot"]["path"],
            all_test_images["illustration"]["path"],
        ]

        images = []
        for path in image_paths:
            with open(path, "rb") as f:
                images.append(f.read())

        # Act
        results = image_analyzer.analyze_batch(images)

        # Assert
        assert len(results) == 3
        assert all("content_type" in result for result in results)
        assert results[0]["content_type"] == "photograph"
        assert results[1]["content_type"] == "screenshot"
        assert results[2]["content_type"] == "illustration"

    @patch("onnxruntime.InferenceSession")
    def test_model_loading_failure(self, mock_session) -> None:
        """Test graceful handling of model loading failure."""
        # Arrange
        mock_session.side_effect = Exception("Model file not found")

        # Act & Assert
        from app.core.intelligence.analyzer import ImageAnalyzer

        analyzer = ImageAnalyzer(fallback_mode=True)

        # Should fall back to heuristic analysis
        assert analyzer.model_loaded is False
        assert analyzer.fallback_mode is True

    def test_heuristic_fallback(self, image_analyzer) -> None:
        """Test heuristic analysis when ML model unavailable."""
        # Arrange
        image_analyzer.model_loaded = False
        image_analyzer.fallback_mode = True

        test_image = image_generator(width=1920, height=1080)

        # Act
        result = image_analyzer.analyze(test_image)

        # Assert
        assert result["content_type"] in [
            "photograph",
            "screenshot",
            "illustration",
            "document",
        ]
        assert result["confidence"] < 0.8  # Lower confidence for heuristic
        assert "optimization_suggestions" in result

    def test_image_complexity_analysis(self, image_analyzer, image_generator) -> None:
        """Test image complexity analysis for optimization."""
        # Arrange
        # Simple image (solid color)
        simple_image = Image.new("RGB", (100, 100), color="red")
        simple_bytes = io.BytesIO()
        simple_image.save(simple_bytes, format="PNG")

        # Complex image (lots of detail)
        complex_image = image_generator(width=100, height=100)

        # Act
        simple_complexity = image_analyzer.analyze_complexity(simple_bytes.getvalue())
        complex_complexity = image_analyzer.analyze_complexity(complex_image)

        # Assert
        assert simple_complexity["entropy"] < complex_complexity["entropy"]
        assert simple_complexity["edge_density"] < complex_complexity["edge_density"]
        assert simple_complexity["color_variety"] < complex_complexity["color_variety"]

    def test_transparency_detection(self, image_analyzer) -> None:
        """Test detection of transparency in images."""
        # Arrange
        # Image with transparency
        transparent_img = Image.new("RGBA", (100, 100), (255, 0, 0, 128))
        trans_bytes = io.BytesIO()
        transparent_img.save(trans_bytes, format="PNG")

        # Image without transparency
        opaque_img = Image.new("RGB", (100, 100), (255, 0, 0))
        opaque_bytes = io.BytesIO()
        opaque_img.save(opaque_bytes, format="JPEG")

        # Act
        trans_result = image_analyzer.detect_transparency(trans_bytes.getvalue())
        opaque_result = image_analyzer.detect_transparency(opaque_bytes.getvalue())

        # Assert
        assert trans_result["has_transparency"] is True
        assert trans_result["transparency_percentage"] > 0
        assert opaque_result["has_transparency"] is False
        assert opaque_result["transparency_percentage"] == 0
