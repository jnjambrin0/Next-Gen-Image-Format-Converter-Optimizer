"""Unit tests for the Intelligence Engine module."""

from typing import Any
import asyncio
import io
from unittest.mock import Mock, patch

import numpy as np
import pytest
from PIL import Image

from app.core.intelligence.engine import IntelligenceEngine
from app.models.conversion import BoundingBox, ContentClassification, ContentType


class TestIntelligenceEngine:
    """Test suite for IntelligenceEngine class."""

    @pytest.fixture
    def intelligence_engine(self) -> None:
        """Create an IntelligenceEngine instance for testing."""
        # Create engine in fallback mode (no models)
        engine = IntelligenceEngine(
            models_dir="./test_models", fallback_mode=True, enable_caching=True
        )
        return engine

    @pytest.fixture
    def sample_image_bytes(self) -> None:
        """Create sample image bytes for testing."""
        # Create a simple test image
        image = Image.new("RGB", (100, 100), color="red")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()

    @pytest.mark.asyncio
    async def test_engine_initialization_fallback_mode(self):
        """Test engine initializes in fallback mode when models unavailable."""
        engine = IntelligenceEngine(models_dir="./nonexistent", fallback_mode=True)

        assert engine.fallback_mode is True
        assert engine.model_loaded is False
        assert engine.content_classifier is None

    @pytest.mark.asyncio
    async def test_classify_content_cascade_architecture(
        self, intelligence_engine, sample_image_bytes
    ):
        """Test cascade architecture classification."""
        result = await intelligence_engine.classify_content(sample_image_bytes)

        assert isinstance(result, ContentClassification)
        assert result.primary_type in [ContentType.PHOTO, ContentType.ILLUSTRATION]
        assert 0 <= result.confidence <= 1.0
        assert result.processing_time_ms > 0
        assert result.processing_time_ms < 500  # Must be under 500ms
        assert isinstance(result.has_text, bool)
        assert isinstance(result.has_faces, bool)

    @pytest.mark.asyncio
    async def test_classify_content_screenshot_heuristic(self, intelligence_engine):
        """Test heuristic detection of screenshot dimensions."""
        # Create image with common screenshot dimensions
        screenshot = Image.new("RGB", (1920, 1080), color="white")
        buffer = io.BytesIO()
        screenshot.save(buffer, format="PNG")

        result = await intelligence_engine.classify_content(buffer.getvalue())

        assert result.primary_type == ContentType.SCREENSHOT
        assert result.confidence > 0.5

    @pytest.mark.asyncio
    async def test_classify_content_document_heuristic(self, intelligence_engine):
        """Test heuristic detection of document (grayscale)."""
        # Create grayscale image (document-like)
        document = Image.new("L", (800, 1000), color=255)
        buffer = io.BytesIO()
        document.save(buffer, format="PNG")

        result = await intelligence_engine.classify_content(buffer.getvalue())

        assert result.primary_type == ContentType.DOCUMENT
        assert result.confidence > 0.5

    @pytest.mark.asyncio
    async def test_classify_content_caching(
        self, intelligence_engine, sample_image_bytes
    ):
        """Test that classification results are cached."""
        # First call
        result1 = await intelligence_engine.classify_content(sample_image_bytes)
        time1 = result1.processing_time_ms

        # Second call (should be cached)
        result2 = await intelligence_engine.classify_content(sample_image_bytes)
        time2 = result2.processing_time_ms

        # Cached result should be much faster
        assert time2 < time1
        assert result1.primary_type == result2.primary_type
        assert result1.confidence == result2.confidence

    @pytest.mark.asyncio
    async def test_classify_content_timeout(self, intelligence_engine):
        """Test classification timeout handling."""

        # Mock a slow classification
        async def slow_classification(*args, **kwargs):
            await asyncio.sleep(2)  # Longer than timeout
            return ContentClassification(
                primary_type=ContentType.PHOTO,
                confidence=1.0,
                processing_time_ms=0,
                has_text=False,
                has_faces=False,
            )

        intelligence_engine._run_classification = slow_classification

        # Should timeout and return default
        result = await intelligence_engine.classify_content(b"fake_image_data")

        assert result.primary_type == ContentType.PHOTO
        assert result.confidence == 0.5  # Default timeout confidence

    def test_recommend_settings_photo(self, intelligence_engine) -> None:
        """Test optimization recommendations for photos."""
        settings = intelligence_engine.recommend_settings(ContentType.PHOTO, "webp")

        assert settings["quality"] == 82  # WebP specific quality for photos
        assert settings["optimization_preset"] == "balanced"
        assert settings["preserve_metadata"] is True
        assert settings["strip_metadata"] is False
        assert settings["method"] == 6  # Maximum compression
        assert settings["sns"] == 50  # Spatial noise shaping

    def test_recommend_settings_screenshot(self, intelligence_engine) -> None:
        """Test optimization recommendations for screenshots."""
        settings = intelligence_engine.recommend_settings(ContentType.SCREENSHOT, "png")

        assert settings["quality"] == 95  # Base quality for screenshots
        assert settings["optimization_preset"] == "fast"
        assert settings["preserve_metadata"] is False
        assert settings["strip_metadata"] is True
        assert settings["compress_level"] == 6  # Balance speed/size
        assert settings["optimize"] is True

    def test_recommend_settings_document(self, intelligence_engine) -> None:
        """Test optimization recommendations for documents."""
        settings = intelligence_engine.recommend_settings(ContentType.DOCUMENT, "jpeg")

        assert settings["quality"] == 95
        assert settings["optimization_preset"] == "best"
        assert settings["preserve_metadata"] is False
        assert settings["strip_metadata"] is True
        assert settings["optimize"] is True
        assert settings["dpi"] == (300, 300)  # High DPI for documents

    def test_calculate_complexity(self, intelligence_engine) -> None:
        """Test image complexity calculation."""
        # Simple image (solid color)
        simple_image = Image.new("RGB", (100, 100), color="red")
        simple_complexity = intelligence_engine._calculate_complexity(simple_image)

        # Complex image (noise)
        complex_array = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
        complex_image = Image.fromarray(complex_array)
        complex_complexity = intelligence_engine._calculate_complexity(complex_image)

        assert 0 <= simple_complexity <= 1.0
        assert 0 <= complex_complexity <= 1.0
        assert complex_complexity > simple_complexity

    def test_softmax(self, intelligence_engine) -> None:
        """Test softmax function."""
        logits = np.array([2.0, 1.0, 0.1])
        probs = intelligence_engine._softmax(logits)

        assert abs(probs.sum() - 1.0) < 1e-6
        assert all(0 <= p <= 1.0 for p in probs)
        assert probs[0] > probs[1] > probs[2]

    def test_clear_cache(self, intelligence_engine, sample_image_bytes) -> None:
        """Test cache clearing functionality."""
        # Add to cache
        asyncio.run(intelligence_engine.classify_content(sample_image_bytes))
        assert len(intelligence_engine._cache) > 0

        # Clear cache
        intelligence_engine.clear_cache()
        assert len(intelligence_engine._cache) == 0

    @pytest.mark.asyncio
    async def test_model_loading_with_onnx(self):
        """Test model loading when ONNX Runtime is available."""
        with patch("onnxruntime.InferenceSession") as mock_session:
            # Mock successful model loading
            mock_model = Mock()
            mock_session.return_value = mock_model

            # Mock model file existence
            with patch("pathlib.Path.exists", return_value=True):
                with patch("pathlib.Path.stat") as mock_stat:
                    mock_stat.return_value.st_size = 1024 * 1024  # 1MB

                    engine = IntelligenceEngine(
                        models_dir="./test_models", fallback_mode=False
                    )

                    assert engine.model_loaded is True
                    assert engine.content_classifier is not None
                    assert engine.fallback_mode is False

    @pytest.mark.asyncio
    async def test_preprocess_for_model(self, intelligence_engine):
        """Test image preprocessing for model input."""
        # Mock content classifier
        mock_classifier = Mock()
        mock_input = Mock()
        mock_input.shape = [1, 3, 224, 224]
        mock_classifier.get_inputs.return_value = [mock_input]
        intelligence_engine.content_classifier = mock_classifier

        # Test preprocessing
        test_image = Image.new("RGB", (640, 480), color="blue")
        processed = intelligence_engine._preprocess_for_model(test_image)

        assert isinstance(processed, np.ndarray)
        assert processed.shape == (1, 3, 224, 224)
        assert processed.dtype == np.float32

    @pytest.mark.asyncio
    async def test_classify_content_invalid_image(self, intelligence_engine):
        """Test classification with invalid image data."""
        invalid_data = b"not an image"

        with pytest.raises(SecurityError) as exc_info:
            await intelligence_engine.classify_content(invalid_data)

        assert exc_info.value.category == "file"

    @pytest.mark.asyncio
    async def test_classify_content_oversized_image(self, intelligence_engine):
        """Test classification with oversized image."""
        # Create a large image that exceeds limits
        large_image = Image.new("RGB", (10000, 10000), color="white")
        buffer = io.BytesIO()
        large_image.save(buffer, format="PNG")

        # Should downsample automatically, not error
        result = await intelligence_engine.classify_content(buffer.getvalue())
        assert isinstance(result, ContentClassification)

    def test_cache_lru_eviction(self, intelligence_engine) -> None:
        """Test LRU cache eviction when cache is full."""
        # Manually set cache items to test eviction
        for i in range(150):  # More than MAX_CACHE_SIZE (100)
            key = f"test_hash_{i}"
            value = ContentClassification(
                primary_type=ContentType.PHOTO,
                confidence=0.9,
                processing_time_ms=10,
                has_text=False,
                has_faces=False,
            )
            # Add directly to cache to test eviction
            asyncio.run(intelligence_engine._add_to_cache(key, value))

        # Cache should be at max size
        assert len(intelligence_engine._cache) <= 100

    @pytest.mark.asyncio
    async def test_model_validation_checksum_mismatch(self):
        """Test model loading with checksum mismatch."""
        from unittest.mock import mock_open

        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.stat") as mock_stat:
                mock_stat.return_value.st_size = 1024 * 1024  # 1MB

                # Mock metadata with different checksum
                with patch(
                    "builtins.open", mock_open(read_data='{"checksum": "invalid"}')
                ):
                    with patch("hashlib.sha256") as mock_sha:
                        mock_sha.return_value.hexdigest.return_value = "different"

                        with pytest.raises(SecurityError) as exc_info:
                            engine = IntelligenceEngine(models_dir="./test")

                        assert exc_info.value.category == "verification"

    @pytest.mark.asyncio
    async def test_secure_memory_clearing(
        self, intelligence_engine, sample_image_bytes
    ):
        """Test that sensitive data is cleared from cache."""
        # Classify image
        result = await intelligence_engine.classify_content(sample_image_bytes)

        # Add some fake sensitive data
        result.face_regions = [
            BoundingBox(x=10, y=10, width=50, height=50, confidence=0.9)
        ]
        result._features = {"sensitive": bytearray(b"secret_data")}

        # Clear cache
        intelligence_engine.clear_cache()

        # Check sensitive data was cleared
        assert len(result.face_regions) == 0 if result.face_regions else True
        assert not hasattr(result, "_features")

    @pytest.mark.asyncio
    async def test_mixed_content_detection(self, intelligence_engine):
        """Test detection of mixed content (e.g., screenshot with faces)."""
        # Create a complex image
        mixed_image = Image.new("RGB", (800, 600), color="white")
        # Add some variation to trigger mixed content
        for x in range(0, 800, 100):
            for y in range(0, 600, 100):
                color = ((x // 100) * 30, (y // 100) * 40, 128)
                mixed_image.paste(Image.new("RGB", (50, 50), color=color), (x, y))

        buffer = io.BytesIO()
        mixed_image.save(buffer, format="PNG")

        result = await intelligence_engine.classify_content(buffer.getvalue())
        assert isinstance(result, ContentClassification)
        assert result.primary_type in [ContentType.SCREENSHOT, ContentType.PHOTO]

    def test_recommend_settings_unknown_format(self, intelligence_engine) -> None:
        """Test recommendations for unknown format."""
        settings = intelligence_engine.recommend_settings(
            ContentType.PHOTO, "unknown_format"
        )

        # Should return base settings
        assert "quality" in settings
        assert "optimization_preset" in settings
        assert settings["optimize"] is True
