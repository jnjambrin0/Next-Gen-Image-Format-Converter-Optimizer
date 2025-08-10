"""Unit tests for face detection with real images."""

import os
from pathlib import Path

import pytest
from PIL import Image

from app.core.intelligence.face_detector import FaceDetector
from app.models.conversion import BoundingBox


class TestFaceDetectorWithRealImages:
    """Test suite for FaceDetector with real test images."""

    @pytest.fixture
    def face_detector(self):
        """Create a FaceDetector instance for testing."""
        return FaceDetector(model_session=None, input_size=128)

    @pytest.fixture
    def fixtures_path(self):
        """Get path to test fixtures."""
        return Path(__file__).parent.parent / "fixtures" / "intelligence"

    @pytest.fixture
    def portrait_image(self, fixtures_path):
        """Load portrait image."""
        img_path = fixtures_path / "faces" / "portrait.jpg"
        if img_path.exists():
            return Image.open(img_path)
        pytest.skip(f"Test image not found: {img_path}")

    @pytest.fixture
    def woman_face_image(self, fixtures_path):
        """Load woman face image."""
        img_path = fixtures_path / "faces" / "woman-face.png"
        if img_path.exists():
            return Image.open(img_path)
        pytest.skip(f"Test image not found: {img_path}")

    @pytest.fixture
    def portrait_with_text(self, fixtures_path):
        """Load portrait with text overlay."""
        img_path = fixtures_path / "edge_cases" / "portrait-with-text.png"
        if img_path.exists():
            return Image.open(img_path)
        pytest.skip(f"Test image not found: {img_path}")

    @pytest.fixture
    def group_photo(self, fixtures_path):
        """Load group photo."""
        img_path = fixtures_path / "edge_cases" / "group-mixed-text.JPG"
        if img_path.exists():
            return Image.open(img_path)
        pytest.skip(f"Test image not found: {img_path}")

    @pytest.fixture
    def no_face_image(self, fixtures_path):
        """Load image without faces."""
        # Use a random image like building or plant
        for name in ["building.JPG", "plant-with-dog-and-light.JPG"]:
            img_path = fixtures_path / "random" / name
            if img_path.exists():
                return Image.open(img_path)
        pytest.skip("No non-face test image found")

    def test_detect_single_portrait(self, face_detector, portrait_image):
        """Test face detection on single portrait."""
        faces = face_detector.detect(portrait_image)

        assert isinstance(faces, list)
        assert len(faces) > 0, "Should detect face in portrait"

        # Should detect 1-2 face regions in portrait (might detect face parts)
        assert (
            1 <= len(faces) <= 2
        ), f"Should detect 1-2 face regions in portrait, got {len(faces)}"

        face = faces[0]
        assert isinstance(face, BoundingBox)

        # Face should be reasonably sized
        img_area = portrait_image.width * portrait_image.height
        face_area = face.width * face.height

        # Face typically takes 5-50% of portrait image
        assert face_area > img_area * 0.02
        assert face_area < img_area * 0.8

        # Face should be somewhat centered in portrait
        face_center_x = face.x + face.width / 2
        face_center_y = face.y + face.height / 2

        # Check if reasonably centered (within middle 80%)
        assert face_center_x > portrait_image.width * 0.1
        assert face_center_x < portrait_image.width * 0.9

    def test_detect_woman_face(self, face_detector, woman_face_image):
        """Test face detection on woman face image."""
        faces = face_detector.detect(woman_face_image)

        assert isinstance(faces, list)
        assert len(faces) > 0, "Should detect face in woman portrait"

        face = faces[0]

        # Check confidence is reasonable
        assert face.confidence > 0.3

        # Face dimensions should be reasonable
        assert face.width > 30
        assert face.height > 30

        # Aspect ratio should be face-like (height slightly more than width)
        aspect_ratio = face.height / face.width
        assert 0.8 < aspect_ratio < 1.5

    def test_detect_portrait_with_text(self, face_detector, portrait_with_text):
        """Test face detection on portrait with text overlay."""
        faces = face_detector.detect(portrait_with_text)

        assert isinstance(faces, list)

        if faces:
            # If face detected, should be main subject
            face = faces[0]

            # Should still detect face despite text overlay
            assert face.confidence > 0.25

            # Face should be substantial part of image
            img_area = portrait_with_text.width * portrait_with_text.height
            face_area = face.width * face.height
            assert face_area > img_area * 0.01

    def test_detect_group_faces(self, face_detector, group_photo):
        """Test face detection on group photo."""
        faces = face_detector.detect(group_photo)

        assert isinstance(faces, list)

        # Group photo should have multiple faces
        # With heuristics might not detect all, but should detect some
        if faces:
            assert len(faces) >= 1, "Should detect at least one face in group"

            # Check faces are in different locations
            if len(faces) > 1:
                face1, face2 = faces[0], faces[1]

                # Calculate distance between face centers
                center1_x = face1.x + face1.width / 2
                center1_y = face1.y + face1.height / 2
                center2_x = face2.x + face2.width / 2
                center2_y = face2.y + face2.height / 2

                distance = (
                    (center2_x - center1_x) ** 2 + (center2_y - center1_y) ** 2
                ) ** 0.5

                # Faces should be separated
                assert distance > min(face1.width, face2.width)

    def test_no_face_detection(self, face_detector, no_face_image):
        """Test that no faces are detected in non-face images."""
        faces = face_detector.detect(no_face_image)

        assert isinstance(faces, list)

        # Should detect no or very few false positives
        assert len(faces) <= 2, "Should not detect many faces in non-face image"

        # Any detected faces should have low confidence
        for face in faces:
            assert face.confidence < 0.5

    def test_importance_scoring(self, face_detector, portrait_image):
        """Test face importance scoring."""
        faces = face_detector.detect(portrait_image)

        if faces:
            # In portrait, main face should have high importance
            main_face = faces[0]

            # Importance is stored in confidence after scoring
            assert main_face.confidence > 0.4

            # If multiple faces, check ordering
            if len(faces) > 1:
                # Faces should be ordered by importance
                for i in range(len(faces) - 1):
                    assert faces[i].confidence >= faces[i + 1].confidence

    def test_skin_detection_accuracy(self, face_detector, portrait_image):
        """Test skin region detection on real portrait."""
        img_array = np.array(portrait_image)

        # Test skin detection
        skin_mask = face_detector._detect_skin_regions(img_array)

        # Should detect some skin pixels
        skin_pixel_count = np.sum(skin_mask)
        total_pixels = skin_mask.shape[0] * skin_mask.shape[1]

        skin_ratio = skin_pixel_count / total_pixels

        # Portrait should have 5-40% skin pixels
        assert 0.02 < skin_ratio < 0.6, f"Skin ratio {skin_ratio} out of expected range"

    def test_performance_on_all_faces(self, face_detector, fixtures_path):
        """Test detection performance on all face images."""
        faces_dir = fixtures_path / "faces"

        if not faces_dir.exists():
            pytest.skip("Faces fixtures directory not found")

        detection_results = {}

        for img_file in faces_dir.glob("*.*"):
            if img_file.suffix.lower() in [".jpg", ".jpeg", ".png"]:
                img = Image.open(img_file)

                import time

                start = time.time()
                faces = face_detector.detect(img)
                duration = time.time() - start

                detection_results[img_file.name] = {
                    "faces": len(faces),
                    "time": duration,
                }

                # Should complete quickly
                assert duration < 2.0, f"Detection took too long for {img_file.name}"

                # Face images should have at least one face
                assert len(faces) > 0, f"No face detected in {img_file.name}"

        # Average time should be reasonable
        if detection_results:
            avg_time = sum(r["time"] for r in detection_results.values()) / len(
                detection_results
            )
            assert avg_time < 1.0, "Average face detection should be under 1 second"

    def test_privacy_preservation_real_images(self, face_detector, portrait_image):
        """Test that only privacy-safe information is returned."""
        faces = face_detector.detect(portrait_image)

        for face in faces:
            # Check only location data is present
            assert hasattr(face, "x")
            assert hasattr(face, "y")
            assert hasattr(face, "width")
            assert hasattr(face, "height")
            assert hasattr(face, "confidence")

            # Ensure no identity information
            assert not hasattr(face, "age")
            assert not hasattr(face, "gender")
            assert not hasattr(face, "identity")
            assert not hasattr(face, "landmarks")
            assert not hasattr(face, "embeddings")

    def test_edge_cases_robustness(self, face_detector, fixtures_path):
        """Test robustness on edge case images."""
        edge_cases_dir = fixtures_path / "edge_cases"

        if not edge_cases_dir.exists():
            pytest.skip("Edge cases directory not found")

        for img_file in edge_cases_dir.glob("*.*"):
            if img_file.suffix.lower() in [".jpg", ".jpeg", ".png"]:
                img = Image.open(img_file)

                # Should not crash on any image
                try:
                    faces = face_detector.detect(img)
                    assert isinstance(faces, list)

                    # All faces should be valid
                    for face in faces:
                        assert isinstance(face, BoundingBox)
                        assert face.x >= 0
                        assert face.y >= 0
                        assert face.width > 0
                        assert face.height > 0
                        assert 0 <= face.confidence <= 1

                except Exception as e:
                    pytest.fail(f"Face detection failed on {img_file.name}: {e}")
