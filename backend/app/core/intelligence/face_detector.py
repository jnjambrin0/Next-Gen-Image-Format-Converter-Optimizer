"""Face detection module for privacy-aware photo analysis."""

import numpy as np
from PIL import Image
from typing import List, Optional, Tuple, Dict, Any
import logging
import time

from app.models.conversion import BoundingBox

logger = logging.getLogger(__name__)


class FaceDetector:
    """Face detection using lightweight BlazeFace-style approach."""

    # Pre-computed anchor parameters for BlazeFace
    ANCHORS_CONFIG = {
        128: {  # 128x128 input
            "strides": [8, 16],
            "anchor_counts": [2, 6],
            "min_scale": 0.1484375,
            "max_scale": 0.75,
            "aspect_ratios": [1.0],
        },
        256: {  # 256x256 input
            "strides": [8, 16, 32],
            "anchor_counts": [2, 6, 6],
            "min_scale": 0.1484375,
            "max_scale": 0.75,
            "aspect_ratios": [1.0],
        },
    }

    def __init__(
        self, model_session: Optional[Any] = None, input_size: int = 128
    ) -> None:
        """Initialize face detector.

        Args:
            model_session: ONNX Runtime session for face detection model
            input_size: Model input size (128 or 256)
        """
        self.model_session = model_session
        self.input_size = input_size
        self.config = self.ANCHORS_CONFIG.get(input_size, self.ANCHORS_CONFIG[128])
        self.anchors = self._generate_anchors()
        self.confidence_threshold = 0.35  # Minimum confidence to consider
        self.nms_threshold = 0.3  # IoU threshold for NMS
        self.min_confidence_final = 0.3  # Final threshold after importance scoring

    def detect(self, image: Image.Image) -> List[BoundingBox]:
        """Detect faces in image with privacy preservation.

        Args:
            image: PIL Image to process

        Returns:
            List of BoundingBox objects for face regions (no identity info)
        """
        start_time = time.time()

        try:
            if self.model_session:
                # ML-based detection
                faces = self._detect_with_model(image)
            else:
                # Fallback heuristic detection
                faces = self._detect_with_heuristics(image)

            # Calculate importance scores
            faces = self._calculate_importance_scores(faces, image.size)

            # Filter by final confidence threshold
            faces = [f for f in faces if f.confidence >= self.min_confidence_final]

            return faces

        except Exception as e:
            logger.warning(f"Face detection failed: {e}")
            return []
        finally:
            # Log processing time
            processing_time = (time.time() - start_time) * 1000
            logger.debug(f"Face detection took {processing_time:.1f}ms")

            # Clear any temporary data for privacy
            self._clear_sensitive_data()

    def _detect_with_model(self, image: Image.Image) -> List[BoundingBox]:
        """Detect faces using ML model (BlazeFace-style)."""
        # Preprocess image
        preprocessed = self._preprocess_for_model(image)

        # Run inference
        outputs = self.model_session.run(
            None, {self.model_session.get_inputs()[0].name: preprocessed}
        )

        # Process outputs
        # BlazeFace output format: [batch, num_anchors, 17]
        # 17 values: [score, cx, cy, w, h, landmarks...]
        # We only use first 5 for privacy (ignore landmarks)
        raw_detections = outputs[0][0]  # Shape: [num_anchors, 17]

        # Decode detections
        detections = self._decode_detections(raw_detections[:, :5])  # Only bbox info

        # Apply NMS
        faces = self._non_maximum_suppression(detections)

        # Convert to image coordinates
        bounding_boxes = []
        for face in faces:
            x, y, w, h, confidence = face

            # Convert from normalized to pixel coordinates
            x = int(x * image.width)
            y = int(y * image.height)
            w = int(w * image.width)
            h = int(h * image.height)

            # Ensure within bounds
            x = max(0, x)
            y = max(0, y)
            w = min(w, image.width - x)
            h = min(h, image.height - y)

            if w > 20 and h > 20:  # Minimum face size
                bounding_boxes.append(
                    BoundingBox(x=x, y=y, width=w, height=h, confidence=confidence)
                )

        return bounding_boxes[:10]  # Limit to 10 faces

    def _detect_with_heuristics(self, image: Image.Image) -> List[BoundingBox]:
        """Fallback face detection using color-based heuristics."""
        # Convert to RGB
        if image.mode != "RGB":
            image = image.convert("RGB")

        # Resize for faster processing if image is too large
        max_dim = 1000
        if image.width > max_dim or image.height > max_dim:
            scale = max_dim / max(image.width, image.height)
            new_size = (int(image.width * scale), int(image.height * scale))
            processed_image = image.resize(new_size, Image.Resampling.LANCZOS)
            scale_factor = 1 / scale
        else:
            processed_image = image
            scale_factor = 1.0

        img_array = np.array(processed_image)
        h, w = img_array.shape[:2]

        # Detect skin-tone regions (simplified approach)
        skin_mask = self._detect_skin_regions(img_array)

        # Find connected components that could be faces
        face_candidates = []

        # Multi-scale pyramid approach
        # Face sizes from 5% to 40% of image dimension
        scales = [0.4, 0.3, 0.2, 0.15, 0.1, 0.05]
        window_sizes = []

        for scale in scales:
            size = int(min(h, w) * scale)
            if size >= 40:  # Minimum 40x40 pixels
                window_sizes.append((size, size))

        # Remove duplicates and sort by size
        window_sizes = sorted(list(set(window_sizes)), reverse=True)

        # Adaptive stride - smaller for smaller windows
        base_stride = max(10, h // 50)

        for window_h, window_w in window_sizes:
            if window_h < 30 or window_w < 30:
                continue

            # Adaptive stride based on window size
            stride = max(base_stride, window_h // 10)

            for y in range(0, h - window_h, stride):
                for x in range(0, w - window_w, stride):
                    # Extract window
                    window_mask = skin_mask[y : y + window_h, x : x + window_w]

                    # Calculate skin pixel ratio
                    skin_ratio = np.sum(window_mask) / (window_h * window_w)

                    # Stricter face-like criteria
                    if 0.2 < skin_ratio < 0.85:
                        # Check for facial structure
                        window_img = img_array[y : y + window_h, x : x + window_w]

                        # Convert to grayscale for structure analysis
                        gray_window = np.mean(window_img, axis=2)

                        # Check variance (faces have features)
                        variance = np.var(gray_window)

                        # Check for symmetry (faces are somewhat symmetric)
                        mid = window_w // 2
                        if mid > 0:
                            left_half = gray_window[:, :mid]
                            right_half = gray_window[:, -mid:]
                            right_half_flipped = np.fliplr(right_half)
                            # Ensure same shape
                            min_width = min(
                                left_half.shape[1], right_half_flipped.shape[1]
                            )
                            if min_width > 0:
                                left_half = left_half[:, :min_width]
                                right_half_flipped = right_half_flipped[:, :min_width]
                                symmetry = (
                                    1.0
                                    - np.mean(np.abs(left_half - right_half_flipped))
                                    / 255.0
                                )
                            else:
                                symmetry = 0.5
                        else:
                            symmetry = 0.5

                        # Combined score
                        if variance > 200 and symmetry > 0.6:
                            # YCrCb validation for better skin detection
                            ycrcb_score = self._validate_skin_ycrcb(window_img)

                            confidence = (
                                skin_ratio * 0.3 + symmetry * 0.3 + ycrcb_score * 0.4
                            )

                            if confidence > self.confidence_threshold:
                                face_candidates.append(
                                    (x, y, window_w, window_h, confidence)
                                )

        # Apply NMS to candidates
        faces = self._non_maximum_suppression(face_candidates)

        # Convert to BoundingBox objects and scale back to original coordinates
        bounding_boxes = []
        for x, y, w, h, conf in faces[:5]:  # Limit faces
            bounding_boxes.append(
                BoundingBox(
                    x=int(x * scale_factor),
                    y=int(y * scale_factor),
                    width=int(w * scale_factor),
                    height=int(h * scale_factor),
                    confidence=conf,
                )
            )

        return bounding_boxes

    def _preprocess_for_model(self, image: Image.Image) -> np.ndarray:
        """Preprocess image for BlazeFace model."""
        # Resize to model input size
        resized = image.resize(
            (self.input_size, self.input_size), Image.Resampling.LANCZOS
        )

        # Convert to RGB if needed
        if resized.mode != "RGB":
            resized = resized.convert("RGB")

        # Convert to array
        img_array = np.array(resized).astype(np.float32)

        # Normalize to [-1, 1] (BlazeFace normalization)
        img_array = (img_array - 127.5) / 127.5

        # Transpose to CHW format
        img_array = np.transpose(img_array, (2, 0, 1))

        # Add batch dimension
        img_array = np.expand_dims(img_array, axis=0)

        return img_array

    def _generate_anchors(self) -> np.ndarray:
        """Generate anchor boxes for BlazeFace."""
        anchors = []

        layer_id = 0
        for stride, anchor_count in zip(
            self.config["strides"], self.config["anchor_counts"]
        ):
            feature_map_size = self.input_size // stride

            for y in range(feature_map_size):
                for x in range(feature_map_size):
                    for anchor_id in range(anchor_count):
                        # Calculate anchor center
                        cx = (x + 0.5) / feature_map_size
                        cy = (y + 0.5) / feature_map_size

                        # Calculate anchor size
                        if layer_id == 0:
                            # First layer has smaller anchors
                            scale = self.config["min_scale"]
                        else:
                            # Interpolate scale
                            scale = self.config["min_scale"] + (
                                self.config["max_scale"] - self.config["min_scale"]
                            ) * (anchor_id / (anchor_count - 1))

                        anchors.append([cx, cy, scale, scale])

            layer_id += 1

        return np.array(anchors, dtype=np.float32)

    def _decode_detections(
        self, raw_outputs: np.ndarray
    ) -> List[Tuple[float, float, float, float, float]]:
        """Decode raw model outputs to bounding boxes.

        Args:
            raw_outputs: Shape [num_anchors, 5] with [score, dcx, dcy, dw, dh]

        Returns:
            List of (x, y, w, h, confidence) tuples in normalized coordinates
        """
        detections = []

        for i, anchor in enumerate(self.anchors):
            score = 1.0 / (1.0 + np.exp(-raw_outputs[i, 0]))  # Sigmoid

            if score > self.confidence_threshold:
                # Decode box offsets
                dcx, dcy, dw, dh = raw_outputs[i, 1:5]

                # Apply anchor-based decoding
                cx = anchor[0] + dcx * 0.1 * anchor[2]
                cy = anchor[1] + dcy * 0.1 * anchor[3]
                w = anchor[2] * np.exp(dw * 0.2)
                h = anchor[3] * np.exp(dh * 0.2)

                # Convert center to top-left
                x = cx - w / 2
                y = cy - h / 2

                # Clip to [0, 1]
                x = max(0, min(1, x))
                y = max(0, min(1, y))
                w = min(w, 1 - x)
                h = min(h, 1 - y)

                detections.append((x, y, w, h, score))

        return detections

    def _non_maximum_suppression(
        self, detections: List[Tuple[float, float, float, float, float]]
    ) -> List[Tuple[float, float, float, float, float]]:
        """Apply Non-Maximum Suppression to remove duplicate detections."""
        if not detections:
            return []

        # Sort by confidence
        detections = sorted(detections, key=lambda x: x[4], reverse=True)

        keep = []
        merged_indices = set()

        for i, detection in enumerate(detections):
            if i in merged_indices:
                continue

            # Find all overlapping detections
            overlapping = [detection]
            overlapping_indices = {i}

            for j, other in enumerate(detections[i + 1 :], i + 1):
                if j in merged_indices:
                    continue

                iou = self._calculate_iou(detection[:4], other[:4])

                # Also check center distance for grouping nearby faces
                c1x = detection[0] + detection[2] / 2
                c1y = detection[1] + detection[3] / 2
                c2x = other[0] + other[2] / 2
                c2y = other[1] + other[3] / 2

                center_dist = ((c2x - c1x) ** 2 + (c2y - c1y) ** 2) ** 0.5
                max_size = max(detection[2], detection[3], other[2], other[3])

                # Group if overlapping OR centers are close
                if iou > 0.1 or center_dist < max_size * 2.0:
                    overlapping.append(other)
                    overlapping_indices.add(j)

            # Merge overlapping detections into one
            if len(overlapping) > 1:
                # Calculate weighted average position based on confidence
                total_conf = sum(d[4] for d in overlapping)
                avg_x = sum(d[0] * d[4] for d in overlapping) / total_conf
                avg_y = sum(d[1] * d[4] for d in overlapping) / total_conf
                avg_w = sum(d[2] * d[4] for d in overlapping) / total_conf
                avg_h = sum(d[3] * d[4] for d in overlapping) / total_conf
                max_conf = max(d[4] for d in overlapping)

                keep.append((avg_x, avg_y, avg_w, avg_h, max_conf))
                merged_indices.update(overlapping_indices)
            else:
                keep.append(detection)
                merged_indices.add(i)

        return keep

    def _calculate_iou(
        self,
        box1: Tuple[float, float, float, float],
        box2: Tuple[float, float, float, float],
    ) -> float:
        """Calculate Intersection over Union between two boxes."""
        x1, y1, w1, h1 = box1
        x2, y2, w2, h2 = box2

        # Calculate intersection
        xi1 = max(x1, x2)
        yi1 = max(y1, y2)
        xi2 = min(x1 + w1, x2 + w2)
        yi2 = min(y1 + h1, y2 + h2)

        if xi2 <= xi1 or yi2 <= yi1:
            return 0.0

        intersection = (xi2 - xi1) * (yi2 - yi1)

        # Calculate union
        area1 = w1 * h1
        area2 = w2 * h2
        union = area1 + area2 - intersection

        return intersection / union if union > 0 else 0.0

    def _detect_skin_regions(self, img_array: np.ndarray) -> np.ndarray:
        """Detect skin-colored regions (simple HSV-based approach)."""
        # Convert RGB to HSV
        img_normalized = img_array.astype(np.float32) / 255.0

        # Manual RGB to HSV conversion
        r, g, b = (
            img_normalized[:, :, 0],
            img_normalized[:, :, 1],
            img_normalized[:, :, 2],
        )

        max_rgb = np.maximum(np.maximum(r, g), b)
        min_rgb = np.minimum(np.minimum(r, g), b)
        diff = max_rgb - min_rgb

        # Hue calculation
        hue = np.zeros_like(max_rgb)

        # Red is max
        mask = (max_rgb == r) & (diff > 0)
        hue[mask] = ((g[mask] - b[mask]) / diff[mask]) % 6

        # Green is max
        mask = (max_rgb == g) & (diff > 0)
        hue[mask] = (b[mask] - r[mask]) / diff[mask] + 2

        # Blue is max
        mask = (max_rgb == b) & (diff > 0)
        hue[mask] = (r[mask] - g[mask]) / diff[mask] + 4

        hue = hue * 60  # Convert to degrees

        # Saturation
        with np.errstate(divide="ignore", invalid="ignore"):
            saturation = np.where(max_rgb > 0, diff / max_rgb, 0)
            saturation = np.nan_to_num(saturation, nan=0.0)

        # Value
        value = max_rgb

        # Skin detection thresholds (in HSV)
        # Hue: 0-20 or 340-360 (reddish)
        # Saturation: 0.1-0.6
        # Value: 0.3-0.9

        skin_mask = (
            ((hue >= 0) & (hue <= 20) | (hue >= 340) & (hue <= 360))
            & (saturation >= 0.1)
            & (saturation <= 0.6)
            & (value >= 0.3)
            & (value <= 0.9)
        )

        # Also include yellowish skin tones
        skin_mask |= (
            (hue >= 20)
            & (hue <= 40)
            & (saturation >= 0.1)
            & (saturation <= 0.4)
            & (value >= 0.4)
            & (value <= 0.9)
        )

        return skin_mask.astype(np.uint8)

    def _validate_skin_ycrcb(self, img_patch: np.ndarray) -> float:
        """Validate skin using YCrCb color space (more robust)."""
        # Convert RGB to YCrCb
        # Y = 0.299*R + 0.587*G + 0.114*B
        # Cr = (R-Y)*0.713 + 128
        # Cb = (B-Y)*0.564 + 128

        r = img_patch[:, :, 0].astype(np.float32)
        g = img_patch[:, :, 1].astype(np.float32)
        b = img_patch[:, :, 2].astype(np.float32)

        y = 0.299 * r + 0.587 * g + 0.114 * b
        cr = (r - y) * 0.713 + 128
        cb = (b - y) * 0.564 + 128

        # Skin detection in YCrCb
        # Typical skin values: Cr in [133, 173], Cb in [77, 127]
        skin_cr = (cr >= 133) & (cr <= 173)
        skin_cb = (cb >= 77) & (cb <= 127)
        skin_ycrcb = skin_cr & skin_cb

        # Calculate ratio of skin pixels
        skin_ratio = np.sum(skin_ycrcb) / skin_ycrcb.size

        return float(skin_ratio)

    def _calculate_importance_scores(
        self, faces: List[BoundingBox], image_size: Tuple[int, int]
    ) -> List[BoundingBox]:
        """Calculate importance score for each face based on size and position."""
        img_width, img_height = image_size
        img_area = img_width * img_height

        for face in faces:
            # Size-based importance (larger faces more important)
            face_area = face.width * face.height
            size_score = min(1.0, (face_area / img_area) * 10)

            # Position-based importance (center faces more important)
            face_center_x = face.x + face.width / 2
            face_center_y = face.y + face.height / 2

            # Distance from image center
            center_dist_x = abs(face_center_x - img_width / 2) / (img_width / 2)
            center_dist_y = abs(face_center_y - img_height / 2) / (img_height / 2)
            center_dist = (center_dist_x + center_dist_y) / 2

            position_score = 1.0 - (center_dist * 0.5)

            # Combine scores (weighted average)
            importance = (size_score * 0.7 + position_score * 0.3) * face.confidence

            # Store as additional attribute (not part of base model)
            face.confidence = min(1.0, importance)

        # Sort by importance
        faces.sort(key=lambda f: f.confidence, reverse=True)

        return faces

    def _clear_sensitive_data(self) -> None:
        """Clear any sensitive data from memory for privacy."""
        # Clear any temporary arrays or data that might contain face info
        # This is called after each detection to ensure privacy

        # Clear any cached detection results
        if hasattr(self, "_temp_detections"):
            if isinstance(self._temp_detections, (bytearray, np.ndarray)):
                if isinstance(self._temp_detections, np.ndarray):
                    # Clear numpy array
                    self._temp_detections.fill(0)
                else:
                    # Use secure clear for bytearray
                    from app.core.security.memory import secure_clear

                    secure_clear(self._temp_detections)
            delattr(self, "_temp_detections")

        # Clear any cached face features (landmarks, etc)
        if hasattr(self, "_face_features"):
            delattr(self, "_face_features")

        # Force garbage collection to clear any remaining references
        import gc

        gc.collect()
