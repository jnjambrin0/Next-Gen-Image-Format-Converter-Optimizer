"""Unit tests for face detection functionality."""

import io
from unittest.mock import MagicMock, Mock, patch

import numpy as np
import pytest
from PIL import Image

from app.core.intelligence.face_detector import FaceDetector
from app.models.conversion import BoundingBox


class TestFaceDetector:
    """Test suite for FaceDetector class."""

    @pytest.fixture
    def face_detector(self):
        """Create a FaceDetector instance for testing."""
        return FaceDetector(model_session=None, input_size=128)

    @pytest.fixture
    def mock_model_session(self):
        """Create a mock ONNX model session."""
        mock = Mock()

        # Mock inputs
        mock_input = Mock()
        mock_input.name = "input"
        mock.get_inputs.return_value = [mock_input]

        # Mock run method
        # Return BlazeFace-style output [num_anchors, 17]
        # We only use first 5 values [score, dcx, dcy, dw, dh]
        num_anchors = 896  # For 128x128 input
        outputs = np.zeros((1, num_anchors, 17), dtype=np.float32)

        # Add a few high-confidence detections
        outputs[0, 100, 0] = 5.0  # High logit score (sigmoid ~0.99)
        outputs[0, 100, 1:5] = [0.1, 0.1, 0.0, 0.0]  # Small offset from anchor

        outputs[0, 200, 0] = 4.0  # Another face
        outputs[0, 200, 1:5] = [-0.1, -0.1, 0.1, 0.1]

        mock.run.return_value = [outputs]

        return mock

    @pytest.fixture
    def portrait_image(self):
        """Create a portrait-like test image."""
        # Create image with face-like region
        img = Image.new("RGB", (400, 400), color="white")
        pixels = img.load()

        # Add a face-like oval in center
        center_x, center_y = 200, 200
        for y in range(150, 250):
            for x in range(150, 250):
                # Create oval shape
                dx = x - center_x
                dy = y - center_y
                if (dx * dx / 50**2 + dy * dy / 70**2) < 1:
                    # Skin-like color
                    pixels[x, y] = (220, 180, 160)

        return img

    @pytest.fixture
    def multi_face_image(self):
        """Create image with multiple face regions."""
        img = Image.new("RGB", (600, 400), color="white")
        pixels = img.load()

        # Add multiple face-like regions
        face_positions = [(150, 200), (450, 200)]

        for center_x, center_y in face_positions:
            for y in range(center_y - 50, center_y + 50):
                for x in range(center_x - 40, center_x + 40):
                    if 0 <= x < 600 and 0 <= y < 400:
                        dx = x - center_x
                        dy = y - center_y
                        if (dx * dx / 40**2 + dy * dy / 50**2) < 1:
                            pixels[x, y] = (210, 170, 150)

        return img

    def test_detector_initialization(self, face_detector):
        """Test detector initializes correctly."""
        assert face_detector.input_size == 128
        assert face_detector.confidence_threshold == 0.5
        assert face_detector.nms_threshold == 0.3
        assert face_detector.model_session is None
        assert len(face_detector.anchors) > 0

    def test_generate_anchors(self, face_detector):
        """Test anchor generation for BlazeFace."""
        anchors = face_detector._generate_anchors()

        assert isinstance(anchors, np.ndarray)
        assert anchors.shape[1] == 4  # cx, cy, w, h
        assert len(anchors) == 896  # Expected for 128x128 input

        # Check anchor values are normalized [0, 1]
        assert np.all(anchors >= 0)
        assert np.all(anchors <= 1)

    def test_detect_with_heuristics_portrait(self, face_detector, portrait_image):
        """Test heuristic face detection on portrait image."""
        faces = face_detector.detect(portrait_image)

        assert isinstance(faces, list)
        assert len(faces) > 0

        # Check first face
        first_face = faces[0]
        assert isinstance(first_face, BoundingBox)
        assert first_face.x >= 0
        assert first_face.y >= 0
        assert first_face.width > 20
        assert first_face.height > 20
        assert 0 <= first_face.confidence <= 1.0

    def test_detect_with_heuristics_blank(self, face_detector):
        """Test heuristic face detection on blank image."""
        blank_img = Image.new("RGB", (300, 300), color="white")
        faces = face_detector.detect(blank_img)

        assert isinstance(faces, list)
        assert len(faces) == 0  # No faces in blank image

    def test_detect_with_model(self, mock_model_session, portrait_image):
        """Test ML-based face detection."""
        detector = FaceDetector(model_session=mock_model_session, input_size=128)
        faces = detector.detect(portrait_image)

        assert isinstance(faces, list)
        assert len(faces) > 0

        # Verify model was called
        mock_model_session.run.assert_called_once()

    def test_preprocess_for_model(self, face_detector):
        """Test image preprocessing for model."""
        # Create test image
        test_img = Image.new("RGB", (640, 480), color="blue")

        # Preprocess
        preprocessed = face_detector._preprocess_for_model(test_img)

        # Check output
        assert isinstance(preprocessed, np.ndarray)
        assert preprocessed.shape == (1, 3, 128, 128)  # Batch, channels, H, W
        assert -1.0 <= preprocessed.min() <= preprocessed.max() <= 1.0

    def test_decode_detections(self, face_detector):
        """Test decoding of raw model outputs."""
        # Create mock outputs
        raw_outputs = np.zeros((896, 5), dtype=np.float32)

        # Add high-confidence detection
        raw_outputs[100, 0] = 3.0  # Logit score
        raw_outputs[100, 1:5] = [0.05, 0.05, 0.1, 0.1]  # Offsets

        # Decode
        detections = face_detector._decode_detections(raw_outputs)

        assert len(detections) > 0
        x, y, w, h, conf = detections[0]
        assert 0 <= x <= 1
        assert 0 <= y <= 1
        assert 0 < w <= 1
        assert 0 < h <= 1
        assert 0.5 < conf <= 1.0

    def test_non_maximum_suppression(self, face_detector):
        """Test NMS to remove duplicate detections."""
        # Create overlapping detections
        detections = [
            (0.1, 0.1, 0.2, 0.2, 0.9),  # High confidence
            (0.12, 0.12, 0.2, 0.2, 0.8),  # Overlaps first
            (0.5, 0.5, 0.2, 0.2, 0.85),  # Separate face
        ]

        # Apply NMS
        filtered = face_detector._non_maximum_suppression(detections)

        assert len(filtered) == 2  # Should remove overlapping detection
        assert filtered[0][4] == 0.9  # Highest confidence kept
        assert filtered[1][4] == 0.85  # Separate face kept

    def test_calculate_iou(self, face_detector):
        """Test Intersection over Union calculation."""
        # Identical boxes
        box1 = (0.1, 0.1, 0.2, 0.2)
        box2 = (0.1, 0.1, 0.2, 0.2)
        iou = face_detector._calculate_iou(box1, box2)
        assert abs(iou - 1.0) < 0.001

        # Non-overlapping boxes
        box1 = (0.0, 0.0, 0.2, 0.2)
        box2 = (0.5, 0.5, 0.2, 0.2)
        iou = face_detector._calculate_iou(box1, box2)
        assert iou == 0.0

        # Partial overlap
        box1 = (0.0, 0.0, 0.3, 0.3)
        box2 = (0.2, 0.2, 0.3, 0.3)
        iou = face_detector._calculate_iou(box1, box2)
        assert 0 < iou < 1

    def test_detect_skin_regions(self, face_detector, portrait_image):
        """Test skin color detection."""
        img_array = np.array(portrait_image)
        skin_mask = face_detector._detect_skin_regions(img_array)

        assert isinstance(skin_mask, np.ndarray)
        assert skin_mask.shape == img_array.shape[:2]
        assert skin_mask.dtype == np.uint8

        # Should detect some skin pixels
        assert np.sum(skin_mask) > 0

    def test_calculate_importance_scores(self, face_detector):
        """Test face importance score calculation."""
        # Create faces with different sizes and positions
        faces = [
            BoundingBox(
                x=150, y=150, width=100, height=120, confidence=0.8
            ),  # Center, large
            BoundingBox(
                x=10, y=10, width=50, height=60, confidence=0.7
            ),  # Corner, small
        ]

        # Calculate importance
        scored_faces = face_detector._calculate_importance_scores(faces, (400, 400))

        # Center, larger face should have higher importance
        assert scored_faces[0].confidence > scored_faces[1].confidence

    def test_multi_face_detection(self, face_detector, multi_face_image):
        """Test detection of multiple faces."""
        faces = face_detector.detect(multi_face_image)

        assert isinstance(faces, list)
        assert len(faces) >= 2  # Should detect multiple faces

        # Check faces are in different locations
        if len(faces) >= 2:
            face1, face2 = faces[0], faces[1]
            distance = abs(face1.x - face2.x) + abs(face1.y - face2.y)
            assert distance > 100  # Faces should be separated

    def test_face_limit(self, face_detector):
        """Test that face detection is limited to reasonable number."""
        # Create mock with many detections
        mock_detections = [(0.1 * i, 0.1 * i, 0.05, 0.05, 0.6) for i in range(20)]

        with patch.object(
            face_detector, "_non_maximum_suppression", return_value=mock_detections
        ):
            with patch.object(
                face_detector, "_detect_with_heuristics", return_value=[]
            ):
                faces = face_detector.detect(Image.new("RGB", (100, 100)))

                # Should be limited
                assert len(faces) <= 10

    def test_privacy_preservation(self, face_detector):
        """Test that only bounding boxes are returned (no identity info)."""
        faces = face_detector.detect(Image.new("RGB", (200, 200)))

        # Check that results only contain location info
        for face in faces:
            assert hasattr(face, "x")
            assert hasattr(face, "y")
            assert hasattr(face, "width")
            assert hasattr(face, "height")
            assert hasattr(face, "confidence")
            # Should not have any identity-related attributes
            assert not hasattr(face, "landmarks")
            assert not hasattr(face, "features")
            assert not hasattr(face, "identity")

    def test_detection_error_handling(self, face_detector):
        """Test error handling in detection."""
        # Mock an error during detection
        with patch.object(
            face_detector,
            "_detect_with_heuristics",
            side_effect=Exception("Test error"),
        ):
            faces = face_detector.detect(Image.new("RGB", (100, 100)))

            # Should return empty list on error
            assert faces == []

    def test_clear_sensitive_data(self, face_detector):
        """Test that sensitive data clearing method exists."""
        # Should not raise error
        face_detector._clear_sensitive_data()

        # In real implementation, would verify memory clearing
        assert True
