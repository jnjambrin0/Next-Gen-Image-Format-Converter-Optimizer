"""Main Intelligence Engine for ML-based image content detection."""

import asyncio
import hashlib
import io
import os
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from PIL import Image

from app.core.constants import (
    IMAGE_MAX_PIXELS,
    INTELLIGENCE_MODEL_MAX_SIZE,
    INTELLIGENCE_TIMEOUT_MS,
)
from app.core.security.errors_simplified import (
    SecurityError,
    create_file_error,
    create_verification_error,
    handle_security_errors,
)
from app.core.security.memory import secure_clear
from app.models.conversion import BoundingBox, ContentClassification, ContentType
from app.utils.logging import get_logger

from .classifiers import ClassificationResult, MLClassifier, QuickClassifier
from .face_detector import FaceDetector
from .performance_monitor import PerformanceMetrics, performance_monitor
from .text_detector import TextDetector

logger = get_logger(__name__)

# Constants for intelligence engine
MAX_CACHE_SIZE = 100  # Maximum number of cached results
MAX_IMAGE_DIMENSION = 4096  # Maximum dimension before downsampling
MAX_CONCURRENT_CLASSIFICATIONS = 10  # Maximum concurrent classifications
MAX_MEMORY_PER_CLASSIFICATION = 200 * 1024 * 1024  # 200MB per classification


class IntelligenceEngine:
    """ML-based image content detection and analysis engine."""

    def __init__(
        self,
        models_dir: Optional[str] = None,
        fallback_mode: bool = False,
        enable_caching: bool = True,
        cascade_threshold: float = 0.9,
    ):
        """Initialize the Intelligence Engine.

        Args:
            models_dir: Directory containing ML models
            fallback_mode: Use heuristic analysis if models unavailable
            enable_caching: Enable result caching by image hash
            cascade_threshold: Confidence threshold for quick classifier
        """
        # Validate and sanitize models directory path
        if models_dir:
            try:
                models_path = Path(models_dir).resolve()
                # Prevent path traversal
                if ".." in str(models_path):
                    logger.warning(
                        "Invalid models directory path - contains parent references"
                    )
                    self.models_dir = Path("ml_models")
                else:
                    self.models_dir = models_path
            except Exception:
                logger.warning("Failed to resolve models directory")
                self.models_dir = Path("ml_models")
        else:
            self.models_dir = Path("ml_models")
        self.fallback_mode = fallback_mode
        self.enable_caching = enable_caching
        self.cascade_threshold = cascade_threshold
        # Use OrderedDict for LRU cache implementation
        self._cache: OrderedDict[str, ContentClassification] = OrderedDict()
        self._cache_lock = asyncio.Lock()

        # Concurrency control
        self._classification_semaphore = asyncio.Semaphore(
            MAX_CONCURRENT_CLASSIFICATIONS
        )
        self._active_classifications = 0
        self._total_memory_used = 0
        self._memory_lock = asyncio.Lock()

        # Initialize classifiers
        self.quick_classifier = QuickClassifier()
        self.ml_classifier = None

        # Model state
        self.model_loaded = False
        self.content_classifier = None
        self.face_detector_session = None
        self.text_detector_session = None

        # Initialize detectors (will use heuristics if no models)
        self.face_detector = FaceDetector()
        self.text_detector = TextDetector()

        # Try to load models
        self._load_models()

    def _load_models(self) -> None:
        """Load ML models with validation.

        Raises:
            SecurityError: If model validation fails
        """
        try:
            # Check if ONNX Runtime is available
            try:
                import onnxruntime as ort

                self.ort = ort
            except ImportError:
                logger.warning("ONNX Runtime not available, using fallback mode")
                self.fallback_mode = True
                return

            # Load content classification model
            content_model_path = (
                self.models_dir / "content" / "mobilenet_v3_content.onnx"
            )
            if content_model_path.exists():
                # Validate model size
                model_size = content_model_path.stat().st_size
                if model_size > INTELLIGENCE_MODEL_MAX_SIZE:
                    raise create_verification_error(
                        "model_size",
                        size_mb=model_size / 1024 / 1024,
                        limit_mb=INTELLIGENCE_MODEL_MAX_SIZE / 1024 / 1024,
                    )

                # Validate checksum if available
                if self._validate_model_checksum(content_model_path):
                    self.content_classifier = self.ort.InferenceSession(
                        str(content_model_path), providers=["CPUExecutionProvider"]
                    )
                    self.model_loaded = True
                    # Initialize ML classifier with the model
                    self.ml_classifier = MLClassifier(str(content_model_path))
                    logger.info(
                        "Content classifier model loaded",
                        model_size_mb=round(model_size / 1024 / 1024, 2),
                        provider="CPUExecutionProvider",
                    )
            else:
                logger.info(
                    "Content model not found - using heuristic mode",
                    expected_path=str(content_model_path),
                    fallback_enabled=True,
                )
                self.fallback_mode = True

            # Load face detection model (optional)
            face_model_path = self.models_dir / "face" / "blazeface_detector.onnx"
            if (
                face_model_path.exists()
                and face_model_path.stat().st_size <= INTELLIGENCE_MODEL_MAX_SIZE
            ):
                self.face_detector_session = self.ort.InferenceSession(
                    str(face_model_path), providers=["CPUExecutionProvider"]
                )
                # Re-initialize face detector with model
                self.face_detector = FaceDetector(
                    model_session=self.face_detector_session
                )
                logger.info(
                    "Face detector model loaded",
                    model_size_mb=round(
                        face_model_path.stat().st_size / 1024 / 1024, 2
                    ),
                )

            # Load text detection model (optional)
            text_model_path = self.models_dir / "text" / "dbnet_text_detector.onnx"
            if (
                text_model_path.exists()
                and text_model_path.stat().st_size <= INTELLIGENCE_MODEL_MAX_SIZE
            ):
                self.text_detector_session = self.ort.InferenceSession(
                    str(text_model_path), providers=["CPUExecutionProvider"]
                )
                # Re-initialize text detector with model
                self.text_detector = TextDetector(
                    model_session=self.text_detector_session
                )
                logger.info(
                    "Text detector model loaded",
                    model_size_mb=round(
                        text_model_path.stat().st_size / 1024 / 1024, 2
                    ),
                )

        except SecurityError:
            raise
        except Exception as e:
            logger.warning(
                "ML models initialization failed - using heuristic mode",
                error_type=type(e).__name__,
                fallback_enabled=True,
            )
            self.fallback_mode = True
            self.model_loaded = False

    def _validate_model_checksum(self, model_path: Path) -> bool:
        """Validate model file checksum if metadata available."""
        metadata_path = model_path.parent / "model_metadata.json"
        if not metadata_path.exists():
            # No metadata, assume model is valid
            return True

        try:
            import json

            with open(metadata_path, "r") as f:
                metadata = json.load(f)

            expected_checksum = metadata.get("checksum")
            if not expected_checksum:
                return True

            # Calculate actual checksum
            sha256_hash = hashlib.sha256()
            with open(model_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)

            actual_checksum = sha256_hash.hexdigest()

            if actual_checksum != expected_checksum:
                raise create_verification_error(
                    "checksum_mismatch", model=model_path.name
                )

            return True

        except SecurityError:
            raise
        except Exception as e:
            logger.warning(f"Failed to validate model checksum: {str(e)}")
            return True  # Assume valid if can't check

    @handle_security_errors
    async def classify_content(
        self, image_data: bytes, debug: bool = False
    ) -> ContentClassification:
        """Classify image content using cascade architecture.

        Args:
            image_data: Raw image bytes
            debug: Include debug information

        Returns:
            ContentClassification with detected content type and metadata

        Raises:
            SecurityError: If classification fails due to security constraints
        """
        start_time = time.time()

        # Validate input
        if not isinstance(image_data, bytes):
            raise create_file_error("invalid_input_type")

        if len(image_data) == 0:
            raise create_file_error("empty_input")

        if len(image_data) > 100 * 1024 * 1024:  # 100MB max
            raise create_file_error(
                "input_too_large", size_mb=len(image_data) / 1024 / 1024
            )

        # Check cache if enabled
        if self.enable_caching:
            # Use SHA256 for security (MD5 is deprecated for security purposes)
            image_hash = hashlib.sha256(image_data).hexdigest()
            async with self._cache_lock:
                if image_hash in self._cache:
                    # Move to end for LRU
                    try:
                        self._cache.move_to_end(image_hash)
                        cached_result = self._cache[image_hash]
                        # Deep copy to prevent cache poisoning
                        import copy

                        result_copy = copy.deepcopy(cached_result)
                        # Update processing time
                        result_copy.processing_time_ms = (
                            time.time() - start_time
                        ) * 1000

                        # Record cache hit
                        await performance_monitor.record_cache_access(hit=True)

                        return result_copy
                    except Exception:
                        # If cache access fails, continue without cache
                        pass
        else:
            image_hash = None

        # Acquire semaphore for concurrency control
        async with self._classification_semaphore:
            # Track memory usage
            async with self._memory_lock:
                self._active_classifications += 1
                estimated_memory = len(image_data) * 10  # Estimate 10x expansion
                if (
                    self._total_memory_used + estimated_memory
                    > MAX_MEMORY_PER_CLASSIFICATION * MAX_CONCURRENT_CLASSIFICATIONS
                ):
                    self._active_classifications -= 1
                    raise create_verification_error("memory_limit_exceeded")
                self._total_memory_used += estimated_memory

            try:
                return await self._classify_with_protection(
                    image_data, image_hash, start_time, debug
                )
            finally:
                # Release memory tracking
                async with self._memory_lock:
                    self._active_classifications -= 1
                    self._total_memory_used = max(
                        0, self._total_memory_used - estimated_memory
                    )

    async def _classify_with_protection(
        self,
        image_data: bytes,
        image_hash: Optional[str],
        start_time: float,
        debug: bool = False,
    ) -> ContentClassification:
        """Perform classification with protection measures."""
        try:
            # Load and validate image
            try:
                image = Image.open(io.BytesIO(image_data))

                # Validate image dimensions to prevent DoS
                if image.width <= 0 or image.height <= 0:
                    raise create_file_error("invalid_dimensions")

                if image.width > 50000 or image.height > 50000:
                    raise create_file_error("dimensions_too_large")

                # Prevent decompression bombs
                pixel_count = image.width * image.height
                if pixel_count > IMAGE_MAX_PIXELS:
                    raise create_file_error("image_too_large")

                # Check decompression ratio to prevent zip bombs
                # Only check for extremely suspicious ratios
                decompression_ratio = pixel_count * 3 / len(image_data)  # Approximate
                if decompression_ratio > 1000:  # 1000:1 max ratio for extreme cases
                    logger.warning(
                        f"Suspicious compression ratio detected: {decompression_ratio:.1f}:1"
                    )
                    raise create_file_error("suspicious_compression_ratio")

                # Downsample if needed for performance
                if (
                    image.width > MAX_IMAGE_DIMENSION
                    or image.height > MAX_IMAGE_DIMENSION
                ):
                    scale = MAX_IMAGE_DIMENSION / max(image.width, image.height)
                    new_size = (int(image.width * scale), int(image.height * scale))
                    image = image.resize(new_size, Image.Resampling.LANCZOS)
                    logger.debug(
                        f"Downsampled large image for classification from {(image.width, image.height)} to {new_size}"
                    )

            except OSError as e:
                raise create_file_error("invalid_image_format")

            # Phase 1: Quick classification (target: 50ms)
            quick_result = await asyncio.wait_for(
                self._run_quick_classification(image),
                timeout=0.1,  # 100ms max for quick classification
            )

            # If quick classifier is confident enough, use its result
            if quick_result.confidence >= self.cascade_threshold:
                logger.debug(
                    f"Quick classifier confident: {quick_result.content_type} ({quick_result.confidence:.2f})"
                )
                result = await self._create_classification_result(
                    quick_result, image, start_time
                )

                # Cache result with LRU eviction
                if self.enable_caching and image_hash:
                    await self._add_to_cache(image_hash, result)

                return result

            # Phase 2: ML classification for ambiguous cases (target: 150ms)
            if self.ml_classifier and not self.fallback_mode:
                try:
                    ml_result = await asyncio.wait_for(
                        self._run_ml_classification(image, quick_result.features),
                        timeout=0.3,  # 300ms max for ML
                    )

                    # Combine results for better accuracy
                    final_result = self._combine_results(quick_result, ml_result)
                    result = await self._create_classification_result(
                        final_result, image, start_time
                    )

                except asyncio.TimeoutError:
                    logger.warning("ML classification timed out, using quick result")
                    result = await self._create_classification_result(
                        quick_result, image, start_time
                    )
            else:
                # No ML available, enhance quick result with additional heuristics
                enhanced_result = await self._enhance_with_heuristics(
                    quick_result, image, image_data
                )
                result = await self._create_classification_result(
                    enhanced_result, image, start_time
                )

            # Cache result with LRU eviction
            if self.enable_caching and image_hash:
                await self._add_to_cache(image_hash, result)

            return result

        except asyncio.TimeoutError:
            # Overall timeout - return basic classification
            logger.warning(
                f"Classification timed out after {INTELLIGENCE_TIMEOUT_MS}ms"
            )
            processing_time_ms = (time.time() - start_time) * 1000
            return ContentClassification(
                primary_type=ContentType.PHOTO,
                confidence=0.5,
                processing_time_ms=processing_time_ms,
                has_text=False,
                has_faces=False,
            )
        except SecurityError:
            raise  # Re-raise security errors
        except Exception as e:
            logger.error(f"Classification failed: {str(e)}")
            # Don't expose internal errors
            raise create_verification_error("classification_failed")

    async def _run_quick_classification(
        self, image: Image.Image
    ) -> ClassificationResult:
        """Run quick rule-based classification."""
        return await asyncio.get_event_loop().run_in_executor(
            None, self.quick_classifier.classify, image
        )

    async def _run_ml_classification(
        self, image: Image.Image, features: Dict[str, float]
    ) -> ClassificationResult:
        """Run ML-based classification."""
        if not self.ml_classifier:
            raise RuntimeError("ML classifier not initialized")

        return await asyncio.get_event_loop().run_in_executor(
            None, self.ml_classifier.classify, image, features
        )

    def _combine_results(
        self, quick_result: ClassificationResult, ml_result: ClassificationResult
    ) -> ClassificationResult:
        """Combine quick and ML results for final decision."""
        # If ML is very confident, use it
        if ml_result.confidence > 0.85:
            return ml_result

        # If both agree, boost confidence
        if quick_result.content_type == ml_result.content_type:
            combined_confidence = min(
                0.99, (quick_result.confidence + ml_result.confidence) / 2 + 0.1
            )
            return ClassificationResult(
                content_type=quick_result.content_type,
                confidence=combined_confidence,
                processing_time_ms=quick_result.processing_time_ms
                + ml_result.processing_time_ms,
                features={**quick_result.features, **ml_result.features},
                method="combined",
            )

        # If they disagree, use weighted average
        if ml_result.confidence > quick_result.confidence:
            return ml_result
        else:
            return quick_result

    async def _enhance_with_heuristics(
        self, quick_result: ClassificationResult, image: Image.Image, image_data: bytes
    ) -> ClassificationResult:
        """Enhance quick result with additional heuristics."""
        # Run the old heuristic classification for additional signals
        heuristic_result = await self._heuristic_classification(image, image_data)

        # If heuristics strongly disagree with quick result, adjust confidence
        if heuristic_result.primary_type != quick_result.content_type:
            quick_result.confidence *= 0.8
        else:
            quick_result.confidence = min(0.95, quick_result.confidence * 1.1)

        return quick_result

    async def _create_classification_result(
        self, result: ClassificationResult, image: Image.Image, start_time: float
    ) -> ContentClassification:
        """Create ContentClassification from ClassificationResult."""
        processing_time_ms = (time.time() - start_time) * 1000

        # Extract additional metadata
        complexity_score = result.features.get("entropy", 5.0) / 8.0

        # Run detections based on content type
        text_regions = None
        face_regions = None

        # Text detection for documents/screenshots
        if result.content_type in [ContentType.DOCUMENT, ContentType.SCREENSHOT]:
            text_regions = await self._detect_text(image)

        # Face detection for photos
        if result.content_type == ContentType.PHOTO:
            face_regions = await self._detect_faces(image)

        # Calculate text density if text detected
        text_density = 0.0
        if text_regions and hasattr(self.text_detector, "calculate_text_density"):
            text_density = self.text_detector.calculate_text_density(
                image, text_regions
            )

        return ContentClassification(
            primary_type=result.content_type,
            confidence=result.confidence,
            processing_time_ms=processing_time_ms,
            has_text=bool(text_regions),
            text_regions=text_regions,
            has_faces=bool(face_regions),
            face_regions=face_regions,
            complexity_score=complexity_score,
        )

    async def _ml_classification(self, image: Image.Image) -> ContentClassification:
        """Classify using ML models."""
        # Preprocess image for model
        processed_image = self._preprocess_for_model(image)

        # Run inference
        outputs = self.content_classifier.run(
            None, {self.content_classifier.get_inputs()[0].name: processed_image}
        )

        # Process outputs
        probabilities = self._softmax(outputs[0][0])

        # Map to content types
        content_types = [
            ContentType.PHOTO,
            ContentType.ILLUSTRATION,
            ContentType.SCREENSHOT,
            ContentType.DOCUMENT,
        ]

        # Get primary type
        primary_idx = np.argmax(probabilities)
        primary_type = content_types[primary_idx]
        confidence = float(probabilities[primary_idx])

        # Get secondary types if confidence is not overwhelming
        secondary_types = []
        if confidence < 0.9:
            for i, prob in enumerate(probabilities):
                if i != primary_idx and prob > 0.1:
                    secondary_types.append((content_types[i], float(prob)))

        # Run additional detectors if available
        has_faces = False
        face_regions = None
        if self.face_detector and primary_type == ContentType.PHOTO:
            face_regions = await self._detect_faces(image)
            has_faces = len(face_regions) > 0 if face_regions else False

        has_text = False
        text_regions = None
        if self.text_detector:
            text_regions = await self._detect_text(image)
            has_text = len(text_regions) > 0 if text_regions else False

        # Analyze complexity
        complexity_score = self._calculate_complexity(image)

        return ContentClassification(
            primary_type=primary_type,
            confidence=confidence,
            secondary_types=secondary_types if secondary_types else None,
            has_text=has_text,
            text_regions=text_regions,
            has_faces=has_faces,
            face_regions=face_regions,
            processing_time_ms=0,  # Will be set by caller
            complexity_score=complexity_score,
        )

    async def _heuristic_classification(
        self, image: Image.Image, image_data: bytes
    ) -> ContentClassification:
        """Fallback heuristic classification when ML models unavailable."""
        # Basic heuristics based on image characteristics
        width, height = image.size
        aspect_ratio = width / height if height > 0 else 1.0

        # Check for common screenshot dimensions
        is_screenshot = (
            width in [1920, 1366, 1440, 2560, 3840]
            and height in [1080, 768, 900, 1440, 2160]
        ) or (aspect_ratio > 1.5 and aspect_ratio < 2.0)

        # Check for document characteristics
        is_document = False
        if image.mode in ["L", "1"]:  # Grayscale or binary
            is_document = True
        elif hasattr(image, "histogram"):
            # Check for high contrast (document-like)
            hist = image.histogram()
            # For RGB images, check each channel
            if len(hist) >= 768:  # RGB histogram
                # Split into R, G, B histograms
                r_hist = hist[0:256]
                g_hist = hist[256:512]
                b_hist = hist[512:768]

                # Check if it's mostly black/white (document-like)
                # High values at extremes (0 and 255)
                total_pixels = sum(r_hist)
                extreme_pixels = (
                    r_hist[0]
                    + r_hist[255]
                    + g_hist[0]
                    + g_hist[255]
                    + b_hist[0]
                    + b_hist[255]
                ) / 3

                if extreme_pixels > total_pixels * 0.8:
                    is_document = True

        # Determine content type
        if is_document:
            primary_type = ContentType.DOCUMENT
            confidence = 0.7
        elif is_screenshot:
            primary_type = ContentType.SCREENSHOT
            confidence = 0.75
        else:
            # Check for illustration characteristics
            # Convert to RGB if needed
            if image.mode != "RGB":
                image = image.convert("RGB")

            # Sample some pixels to check color variety
            pixels = []
            step = max(1, min(width, height) // 20)
            for x in range(0, width, step):
                for y in range(0, height, step):
                    pixels.append(image.getpixel((x, y)))

            # Count unique colors
            unique_colors = len(set(pixels))
            color_ratio = unique_colors / len(pixels) if pixels else 1.0

            # Also check overall image statistics
            img_array = np.array(image)
            color_std = np.std(img_array)

            # Solid colors with low variance are likely illustrations
            if unique_colors <= 5 and color_std < 10:
                primary_type = ContentType.ILLUSTRATION
                confidence = 0.65
            else:
                primary_type = ContentType.PHOTO
                confidence = 0.7

        # Basic text detection (very simple)
        has_text = is_document or is_screenshot

        # Calculate complexity
        complexity_score = self._calculate_complexity(image)

        return ContentClassification(
            primary_type=primary_type,
            confidence=confidence,
            has_text=has_text,
            has_faces=False,  # Can't detect without ML
            processing_time_ms=0,  # Will be set by caller
            complexity_score=complexity_score,
        )

    def _preprocess_for_model(self, image: Image.Image) -> np.ndarray:
        """Preprocess image for ML model input."""
        # Get expected input size from model
        input_shape = self.content_classifier.get_inputs()[0].shape
        target_size = (input_shape[2], input_shape[3])  # (H, W)

        # Use centralized preprocessing from preprocessors module
        from .preprocessors import ImagePreprocessor

        # Resize with padding to maintain aspect ratio
        image = ImagePreprocessor.resize_with_padding(image, target_size)

        # Convert to RGB if needed
        if image.mode != "RGB":
            image = image.convert("RGB")

        # Convert to numpy array
        img_array = np.array(image).astype(np.float32)

        # Normalize using centralized method
        img_array = ImagePreprocessor.normalize_image(img_array)

        # Transpose to CHW format
        img_array = np.transpose(img_array, (2, 0, 1))

        # Add batch dimension
        img_array = np.expand_dims(img_array, axis=0)

        return img_array

    def _softmax(self, x: np.ndarray) -> np.ndarray:
        """Compute softmax values for array x."""
        e_x = np.exp(x - np.max(x))
        return e_x / e_x.sum()

    async def _detect_faces(self, image: Image.Image) -> Optional[List[BoundingBox]]:
        """Detect faces in the image."""
        try:
            # Use the face detector (will use heuristics if no model)
            faces = await asyncio.get_event_loop().run_in_executor(
                None, self.face_detector.detect, image
            )
            return faces if faces else None

        except Exception as e:
            logger.warning(f"Face detection failed: {e}")
            return None

    async def _detect_text(self, image: Image.Image) -> Optional[List[BoundingBox]]:
        """Detect text regions in the image."""
        try:
            # Use the text detector (will use heuristics if no model)
            text_regions = await asyncio.get_event_loop().run_in_executor(
                None, self.text_detector.detect, image
            )
            return text_regions if text_regions else None

        except Exception as e:
            logger.warning(f"Text detection failed: {e}")
            return None

    def _preprocess_for_face_detector(self, image: Image.Image) -> np.ndarray:
        """Preprocess image for face detection model."""
        # Delegate to face detector's preprocessing
        return self.face_detector._preprocess_for_model(image)

    def _calculate_complexity(self, image: Image.Image) -> float:
        """Calculate image complexity score (0-1)."""
        try:
            # Convert to grayscale for edge detection
            if image.mode != "L":
                gray = image.convert("L")
            else:
                gray = image

            # Calculate image entropy (measure of information content)
            histogram = gray.histogram()
            total_pixels = sum(histogram)

            entropy = 0.0
            for count in histogram:
                if count > 0:
                    probability = count / total_pixels
                    entropy -= probability * np.log2(probability)

            # Normalize entropy (8-bit image max entropy is 8)
            normalized_entropy = entropy / 8.0

            # Simple edge detection using gradient
            # This is a simplified version - real implementation would use Sobel/Canny
            img_array = np.array(gray)

            # Calculate gradients
            dx = np.abs(np.diff(img_array, axis=1))
            dy = np.abs(np.diff(img_array, axis=0))

            # Edge density
            edge_threshold = 30  # Threshold for edge detection
            edges_x = np.sum(dx > edge_threshold)
            edges_y = np.sum(dy > edge_threshold)
            total_possible_edges = dx.size + dy.size
            edge_density = (
                (edges_x + edges_y) / total_possible_edges
                if total_possible_edges > 0
                else 0
            )

            # Combine metrics
            complexity = normalized_entropy * 0.6 + edge_density * 0.4

            return min(1.0, max(0.0, complexity))

        except Exception as e:
            logger.warning(f"Complexity calculation failed: {e}")
            return 0.5  # Default middle complexity

    async def _record_performance(
        self,
        result: ContentClassification,
        image: Image.Image,
        data_size: int,
        phase_times: Dict[str, float],
    ) -> None:
        """Record performance metrics."""
        try:
            import psutil

            process = psutil.Process()

            metrics = PerformanceMetrics(
                classification_time_ms=result.processing_time_ms,
                memory_usage_mb=process.memory_info().rss / 1024 / 1024,
                cache_hit_rate=0,  # Calculated by monitor
                concurrent_requests=self._active_classifications,
                cpu_percent=process.cpu_percent(interval=0),
                phase_times=phase_times,
                image_dimensions=(image.width, image.height),
                image_size_bytes=data_size,
                content_type=result.primary_type.value,
                confidence=result.confidence,
            )

            await performance_monitor.record_classification(metrics)

            # Log summary periodically
            if performance_monitor.total_classifications % 100 == 0:
                await performance_monitor.log_performance_summary()

        except Exception as e:
            # Don't let monitoring failures affect classification
            logger.debug(f"Failed to record performance metrics: {e}")

    def recommend_settings(
        self, content_type: ContentType, target_format: str
    ) -> Dict[str, Any]:
        """Recommend optimization settings based on content type.

        Args:
            content_type: Detected content type
            target_format: Target output format

        Returns:
            Dictionary of recommended settings
        """
        # Enhanced recommendations based on expert analysis
        content_settings = {
            ContentType.PHOTO: {
                "base_quality": 85,
                "preserve_metadata": True,
                "optimization_preset": "balanced",
                "specific": {
                    "jpeg": {
                        "quality": 85,
                        "optimize": True,
                        "progressive": True,
                        "subsampling": "4:2:0",
                    },
                    "webp": {
                        "quality": 82,
                        "method": 6,  # Maximum compression
                        "sns": 50,  # Spatial noise shaping
                        "segments": 4,
                    },
                    "avif": {"quality": 75, "speed": 6, "pixel_format": "yuv420"},
                    "jpegxl": {"distance": 1.0, "effort": 7},  # Lower = better quality
                },
            },
            ContentType.SCREENSHOT: {
                "base_quality": 95,
                "preserve_metadata": False,
                "optimization_preset": "fast",
                "specific": {
                    "png": {
                        "compress_level": 6,  # Balance speed/size
                        "optimize": True,
                        "quantize": False,  # Preserve UI colors
                    },
                    "webp": {
                        "quality": 95,
                        "method": 4,  # Better for graphics
                        "lossless": False,  # Near-lossless for text
                        "alpha_quality": 100,
                    },
                    "avif": {
                        "quality": 90,
                        "speed": 8,
                        "pixel_format": "yuv444",  # Better for text
                    },
                },
            },
            ContentType.DOCUMENT: {
                "base_quality": 95,
                "preserve_metadata": False,
                "optimization_preset": "best",
                "specific": {
                    "png": {
                        "compress_level": 9,
                        "bits": 8,
                        "dpi": (150, 150),  # Preserve for OCR
                    },
                    "jpeg": {"quality": 95, "optimize": True, "dpi": (300, 300)},
                    "webp": {
                        "quality": 98,
                        "method": 6,
                        "lossless": True,  # For text clarity
                    },
                },
            },
            ContentType.ILLUSTRATION: {
                "base_quality": 90,
                "preserve_metadata": False,
                "optimization_preset": "balanced",
                "specific": {
                    "png": {
                        "compress_level": 9,
                        "palette": True,  # PNG8 when possible
                        "colors": 256,
                        "quantize": True,
                    },
                    "webp": {"quality": 88, "method": 5, "alpha_quality": 95},
                    "avif": {"quality": 85, "speed": 7, "pixel_format": "yuv420"},
                },
            },
        }

        # Get content-specific settings
        content_config = content_settings.get(
            content_type, content_settings[ContentType.PHOTO]  # Default
        )

        # Base settings
        settings = {
            "quality": content_config["base_quality"],
            "optimization_preset": content_config["optimization_preset"],
            "preserve_metadata": content_config["preserve_metadata"],
            "strip_metadata": not content_config["preserve_metadata"],
            "optimize": True,
        }

        # Apply format-specific settings
        format_lower = target_format.lower()
        # Handle format aliases
        if format_lower in ["jpg", "jpeg_optimized", "jpg_optimized"]:
            format_lower = "jpeg"
        elif format_lower in ["png_optimized"]:
            format_lower = "png"
        elif format_lower in ["jpegxl", "jxl", "jpeg_xl"]:
            format_lower = "jpegxl"

        if format_lower in content_config["specific"]:
            settings.update(content_config["specific"][format_lower])

        return settings

    async def _add_to_cache(self, key: str, value: ContentClassification) -> None:
        """Add item to cache with LRU eviction.

        Args:
            key: Cache key (image hash)
            value: Classification result to cache
        """
        async with self._cache_lock:
            # Remove oldest if at capacity
            if len(self._cache) >= MAX_CACHE_SIZE:
                # Remove oldest (first) item
                oldest_key = next(iter(self._cache))
                old_value = self._cache.pop(oldest_key)
                # Clear sensitive data from old value
                self._secure_clear_classification(old_value)
                logger.debug(
                    f"Evicted oldest cache entry, cache size: {len(self._cache)}"
                )

            # Add new item at end
            self._cache[key] = value

    def _secure_clear_classification(
        self, classification: ContentClassification
    ) -> None:
        """Securely clear sensitive data from classification.

        Args:
            classification: Classification to clear
        """
        # Clear face and text regions which might contain sensitive data
        if classification.face_regions:
            classification.face_regions.clear()
        if classification.text_regions:
            classification.text_regions.clear()

        # Clear any cached feature data
        if hasattr(classification, "_features"):
            # If features contain image data, secure clear it
            features = getattr(classification, "_features")
            if isinstance(features, dict):
                for key, value in features.items():
                    if isinstance(value, (bytearray, memoryview)):
                        secure_clear(value)
            delattr(classification, "_features")

        # Clear any cached image data
        if hasattr(classification, "_image_data"):
            data = getattr(classification, "_image_data")
            if isinstance(data, (bytes, bytearray, memoryview)):
                secure_clear(data)
            delattr(classification, "_image_data")

    def clear_cache(self) -> None:
        """Clear the classification cache with secure data clearing."""
        # Securely clear all cached classifications
        for classification in self._cache.values():
            self._secure_clear_classification(classification)

        self._cache.clear()
        logger.info("Classification cache cleared")
