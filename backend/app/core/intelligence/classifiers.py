"""Image classification algorithms and implementations."""

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import numpy as np
from PIL import Image

from app.core.intelligence.preprocessors import ImagePreprocessor
from app.models.conversion import ContentType

logger = logging.getLogger(__name__)


@dataclass
class ClassificationResult:
    """Result from a classification operation."""

    content_type: ContentType
    confidence: float
    processing_time_ms: float
    features: Dict[str, float]
    method: str  # 'quick' or 'ml'


class QuickClassifier:
    """Fast rule-based classifier for obvious cases."""

    # Common screenshot dimensions
    SCREENSHOT_DIMENSIONS = {
        (1920, 1080),
        (1366, 768),
        (1440, 900),
        (2560, 1440),
        (3840, 2160),
        (1280, 720),
        (1600, 900),
        (1680, 1050),
    }

    # Performance thresholds (all in milliseconds)
    FEATURE_TIME_BUDGET = {
        "entropy": 5,
        "histogram": 10,
        "edges": 15,
        "uniformity": 10,
        "gradients": 10,
    }

    def classify(self, image: Image.Image) -> ClassificationResult:
        """Perform quick classification based on rules.

        Args:
            image: PIL Image to classify

        Returns:
            ClassificationResult with confidence > 0.9 for obvious cases
        """
        start_time = time.time()
        features = {}

        # Extract quick features
        width, height = image.size
        features["width"] = width
        features["height"] = height
        features["aspect_ratio"] = width / height if height > 0 else 1.0

        # Convert to arrays for analysis
        img_array = np.array(image)
        if len(img_array.shape) == 2:  # Grayscale
            gray_array = img_array
        else:
            # Convert to grayscale for some analyses
            gray_array = np.mean(img_array, axis=2).astype(np.uint8)

        # 1. Entropy calculation (5ms budget)
        entropy = self._calculate_entropy_fast(gray_array)
        features["entropy"] = entropy

        # 2. Color analysis (10ms budget)
        unique_colors, color_variance, histogram_peaks = self._analyze_colors_fast(
            image, img_array
        )
        features["unique_colors"] = unique_colors
        features["color_variance"] = color_variance
        features["histogram_peaks"] = histogram_peaks

        # 3. Edge density (15ms budget)
        edge_density, edge_straightness = self._analyze_edges_fast(gray_array)
        features["edge_density"] = edge_density
        features["edge_straightness"] = edge_straightness

        # 4. Uniformity score (10ms budget)
        uniformity = self._calculate_uniformity_fast(img_array)
        features["uniformity"] = uniformity

        # 5. Additional advanced features (if time permits)
        if (time.time() - start_time) * 1000 < 40:  # Still within budget
            # UI pattern detection for screenshots
            ui_metrics = ImagePreprocessor.detect_ui_patterns(gray_array)
            features.update(ui_metrics)

            # Texture analysis for photo detection
            texture_metrics = ImagePreprocessor.calculate_texture_metrics(gray_array)
            features.update(texture_metrics)

        # Apply classification rules
        content_type, confidence = self._apply_rules(features, image)

        processing_time_ms = (time.time() - start_time) * 1000

        return ClassificationResult(
            content_type=content_type,
            confidence=confidence,
            processing_time_ms=processing_time_ms,
            features=features,
            method="quick",
        )

    def _calculate_entropy_fast(self, gray_array: np.ndarray) -> float:
        """Calculate Shannon entropy quickly."""
        return ImagePreprocessor.calculate_entropy_fast(gray_array)

    def _analyze_colors_fast(
        self, image: Image.Image, img_array: np.ndarray
    ) -> Tuple[int, float, int]:
        """Fast color analysis."""
        # Sample pixels for unique color count
        if img_array.size > 100000:
            # Sample 10% of pixels
            flat_pixels = img_array.reshape(-1, img_array.shape[-1])
            sample_indices = np.random.choice(
                len(flat_pixels), size=len(flat_pixels) // 10, replace=False
            )
            sampled_pixels = flat_pixels[sample_indices]
        else:
            sampled_pixels = img_array.reshape(-1, img_array.shape[-1])

        # Count unique colors
        unique_colors = len(np.unique(sampled_pixels, axis=0))

        # Calculate color variance
        color_variance = float(np.std(img_array))

        # Analyze histogram for peaks
        hist = image.histogram()
        if len(hist) >= 768:  # RGB
            # Combine RGB histograms
            r_hist = np.array(hist[0:256])
            g_hist = np.array(hist[256:512])
            b_hist = np.array(hist[512:768])
            combined_hist = (r_hist + g_hist + b_hist) / 3
        else:
            combined_hist = np.array(hist)

        # Count significant peaks
        threshold = np.max(combined_hist) * 0.1
        peaks = np.sum(combined_hist > threshold)

        return unique_colors, color_variance, int(peaks)

    def _analyze_edges_fast(self, gray_array: np.ndarray) -> Tuple[float, float]:
        """Fast edge analysis using optimized Sobel."""
        edge_metrics = ImagePreprocessor.detect_edges_sobel_optimized(gray_array)
        return edge_metrics["edge_density"], edge_metrics["edge_straightness"]

    def _calculate_uniformity_fast(self, img_array: np.ndarray) -> float:
        """Calculate how uniform the image is (for screenshots/documents)."""
        # Divide image into blocks
        block_size = 32
        h, w = img_array.shape[:2]

        uniformity_scores = []

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = img_array[y : y + block_size, x : x + block_size]
                # Calculate variance within block
                block_variance = np.var(block)
                # Low variance = high uniformity
                uniformity_scores.append(1.0 / (1.0 + block_variance))

        return float(np.mean(uniformity_scores))

    def _apply_rules(
        self, features: Dict[str, float], image: Image.Image
    ) -> Tuple[ContentType, float]:
        """Apply enhanced classification rules based on features."""
        width = features["width"]
        height = features["height"]
        entropy = features["entropy"]
        unique_colors = features["unique_colors"]
        edge_density = features["edge_density"]
        edge_straightness = features["edge_straightness"]
        uniformity = features["uniformity"]
        color_variance = features["color_variance"]

        # UI pattern score (if available)
        ui_score = features.get("ui_score", 0)
        texture_complexity = features.get("texture_complexity", 0)
        high_freq_energy = features.get("high_frequency_energy", 0)

        # Enhanced Rule 1: Screenshot detection with UI patterns
        if (width, height) in self.SCREENSHOT_DIMENSIONS:
            if edge_straightness > 0.3 and uniformity > 0.4:
                # Boost confidence if UI patterns detected
                confidence = 0.95 if ui_score > 0.3 else 0.92
                return ContentType.SCREENSHOT, confidence

        # Check UI patterns even without standard dimensions
        if ui_score > 0.4 and edge_straightness > 0.3:
            return ContentType.SCREENSHOT, 0.93

        # Enhanced Rule 2: Document detection
        if image.mode in ["L", "1"]:  # Grayscale or binary
            if entropy < 4.0 and uniformity > 0.6:
                return ContentType.DOCUMENT, 0.94
        elif unique_colors < 50 and uniformity > 0.7:
            # Color document with limited palette
            return ContentType.DOCUMENT, 0.92

        # High contrast with text-like patterns
        if features.get("horizontal_lines", 0) > 0.1 and uniformity > 0.5:
            return ContentType.DOCUMENT, 0.91

        # Enhanced Rule 3: Illustration detection
        if unique_colors < 256 and entropy < 4.0:
            # Low texture complexity indicates vector/digital art
            if texture_complexity < 5 and edge_density > 0.1:
                return ContentType.ILLUSTRATION, 0.95
            elif edge_density > 0.1 and color_variance < 50:
                return ContentType.ILLUSTRATION, 0.93

        # Enhanced Rule 4: Photo detection with texture analysis
        if entropy > 7.0 and unique_colors > 1000:
            # High frequency content indicates natural photo
            if high_freq_energy > 100 and texture_complexity > 10:
                return ContentType.PHOTO, 0.96
            elif edge_density < 0.3 and uniformity < 0.3:
                return ContentType.PHOTO, 0.94

        # Rule 5: Medium confidence photo (natural scenes)
        if entropy > 6.5 and texture_complexity > 8:
            return ContentType.PHOTO, 0.91

        # Rule 6: Screenshot patterns by aspect ratio
        aspect_ratio = features["aspect_ratio"]
        if 1.3 < aspect_ratio < 2.0:  # Common screen ratios
            if uniformity > 0.35 and edge_straightness > 0.25:
                return ContentType.SCREENSHOT, 0.90

        # Rule 7: Simple graphics/logos
        if unique_colors < 100 and uniformity > 0.5:
            return ContentType.ILLUSTRATION, 0.89

        # Default: low confidence photo
        return ContentType.PHOTO, 0.5

    def can_classify_quickly(self, features: Dict[str, float]) -> bool:
        """Check if we can make a quick decision."""
        # High entropy photos
        if features.get("entropy", 0) > 7.5:
            return True

        # Very uniform documents/screenshots
        if features.get("uniformity", 0) > 0.7:
            return True

        # Simple illustrations
        if features.get("unique_colors", 9999) < 100:
            return True

        return False


class MLClassifier:
    """ML-based classifier for ambiguous cases."""

    def __init__(self, model_path: Optional[str] = None) -> None:
        """Initialize ML classifier with ONNX model."""
        self.model_loaded = False
        self.session = None

        if model_path:
            self._load_model(model_path)

    def _load_model(self, model_path: str) -> None:
        """Load ONNX model for inference."""
        try:
            import onnxruntime as ort

            self.session = ort.InferenceSession(
                model_path, providers=["CPUExecutionProvider"]
            )
            self.model_loaded = True
            logger.info("ML model loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load ML model: {e}")
            self.model_loaded = False

    def classify(
        self, image: Image.Image, features: Dict[str, float]
    ) -> ClassificationResult:
        """Perform ML-based classification.

        Args:
            image: PIL Image to classify
            features: Pre-computed features from quick classifier

        Returns:
            ClassificationResult with ML predictions
        """
        start_time = time.time()

        if not self.model_loaded or not self.session:
            # Fallback to feature-based classification
            return self._fallback_classify(image, features)

        try:
            # Preprocess for model
            input_tensor = self._preprocess_for_model(image)

            # Run inference
            outputs = self.session.run(
                None, {self.session.get_inputs()[0].name: input_tensor}
            )

            # Process outputs
            probabilities = self._softmax(outputs[0][0])
            content_types = [
                ContentType.PHOTO,
                ContentType.ILLUSTRATION,
                ContentType.SCREENSHOT,
                ContentType.DOCUMENT,
            ]

            # Get best prediction
            best_idx = np.argmax(probabilities)
            content_type = content_types[best_idx]
            confidence = float(probabilities[best_idx])

            # Add ML-specific features
            features["ml_photo_prob"] = float(probabilities[0])
            features["ml_illustration_prob"] = float(probabilities[1])
            features["ml_screenshot_prob"] = float(probabilities[2])
            features["ml_document_prob"] = float(probabilities[3])

        except Exception as e:
            logger.warning(f"ML inference failed: {e}")
            return self._fallback_classify(image, features)

        processing_time_ms = (time.time() - start_time) * 1000

        return ClassificationResult(
            content_type=content_type,
            confidence=confidence,
            processing_time_ms=processing_time_ms,
            features=features,
            method="ml",
        )

    def _preprocess_for_model(self, image: Image.Image) -> np.ndarray:
        """Preprocess image for ML model (optimized for speed)."""
        # Fast resize with INTER_LINEAR
        target_size = (224, 224)

        # Convert to RGB if needed
        if image.mode != "RGB":
            image = image.convert("RGB")

        # Use fast bilinear resize for speed
        image = image.resize(target_size, Image.Resampling.BILINEAR)

        # Convert to array
        img_array = np.array(image, dtype=np.float32)

        # Use centralized normalization with different params for speed
        # Fast normalization: [-1, 1] range
        img_array = img_array / 255.0  # First to [0, 1]
        img_array = (img_array - 0.5) * 2.0  # Then to [-1, 1]

        # Transpose to CHW format
        img_array = np.transpose(img_array, (2, 0, 1))

        # Add batch dimension
        return np.expand_dims(img_array, axis=0)

    def _softmax(self, x: np.ndarray) -> np.ndarray:
        """Compute softmax values."""
        e_x = np.exp(x - np.max(x))
        return e_x / e_x.sum()

    def _fallback_classify(
        self, image: Image.Image, features: Dict[str, float]
    ) -> ClassificationResult:
        """Fallback classification using advanced heuristics."""
        # Use feature-based rules with lower confidence
        entropy = features.get("entropy", 5.0)
        unique_colors = features.get("unique_colors", 1000)
        edge_density = features.get("edge_density", 0.2)
        uniformity = features.get("uniformity", 0.3)

        # Decision tree based on features
        if entropy > 6.5 and unique_colors > 500:
            content_type = ContentType.PHOTO
            confidence = 0.75
        elif uniformity > 0.5 and edge_density > 0.15:
            content_type = ContentType.SCREENSHOT
            confidence = 0.70
        elif unique_colors < 200 and entropy < 5.0:
            content_type = ContentType.ILLUSTRATION
            confidence = 0.72
        else:
            content_type = ContentType.DOCUMENT
            confidence = 0.68

        return ClassificationResult(
            content_type=content_type,
            confidence=confidence,
            processing_time_ms=0,  # Will be set by caller
            features=features,
            method="ml",
        )
