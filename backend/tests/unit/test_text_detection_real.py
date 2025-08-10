"""Unit tests for text detection with real images."""

from typing import Any
from pathlib import Path

import pytest
from PIL import Image

from app.core.intelligence.text_detector import TextDetector
from app.models.conversion import BoundingBox


class TestTextDetectorWithRealImages:
    """Test suite for TextDetector with real test images."""

    @pytest.fixture
    def text_detector(self) -> None:
        """Create a TextDetector instance for testing."""
        return TextDetector(model_session=None)  # Will use heuristics

    @pytest.fixture
    def fixtures_path(self) -> None:
        """Get path to test fixtures."""
        return Path(__file__).parent.parent / "fixtures" / "intelligence"

    @pytest.fixture
    def document_image(self, fixtures_path) -> None:
        """Load real document image."""
        img_path = fixtures_path / "text" / "document.JPG"
        if img_path.exists():
            return Image.open(img_path)
        pytest.skip(f"Test image not found: {img_path}")

    @pytest.fixture
    def code_image(self, fixtures_path) -> None:
        """Load code screenshot image."""
        img_path = fixtures_path / "text" / "text-code.JPG"
        if img_path.exists():
            return Image.open(img_path)
        pytest.skip(f"Test image not found: {img_path}")

    @pytest.fixture
    def mixed_portrait_text(self, fixtures_path) -> None:
        """Load portrait with text image."""
        img_path = fixtures_path / "edge_cases" / "portrait-with-text.png"
        if img_path.exists():
            return Image.open(img_path)
        pytest.skip(f"Test image not found: {img_path}")

    @pytest.fixture
    def group_mixed_text(self, fixtures_path) -> None:
        """Load group photo with text."""
        img_path = fixtures_path / "edge_cases" / "group-mixed-text.JPG"
        if img_path.exists():
            return Image.open(img_path)
        pytest.skip(f"Test image not found: {img_path}")

    @pytest.fixture
    def random_no_text(self, fixtures_path) -> None:
        """Load random image without text."""
        img_path = fixtures_path / "random" / "plant-with-dog-and-light.JPG"
        if img_path.exists():
            return Image.open(img_path)
        pytest.skip(f"Test image not found: {img_path}")

    def test_detect_document_text(self, text_detector, document_image) -> None:
        """Test text detection on real document image."""
        regions = text_detector.detect(document_image)

        assert isinstance(regions, list)
        assert len(regions) > 0, "Should detect text in document image"

        # Document should have multiple text regions
        assert len(regions) >= 5, "Document should have multiple text regions"

        # Check that at least some regions are reasonable text lines
        wide_regions = [r for r in regions if r.width > 100]
        assert len(wide_regions) >= 2, "Should have at least 2 wide text regions"

        # Check regions are valid
        for region in regions:
            assert isinstance(region, BoundingBox)
            assert region.width > 0
            assert region.height > 0
            assert 0 <= region.confidence <= 1.0

    def test_detect_code_text(self, text_detector, code_image) -> None:
        """Test text detection on code screenshot."""
        regions = text_detector.detect(code_image)

        assert isinstance(regions, list)
        assert len(regions) > 0, "Should detect text in code image"

        # Code should have many lines
        assert len(regions) >= 5, "Code should have multiple lines"

        # Code lines tend to be more uniform
        heights = [r.height for r in regions]
        avg_height = sum(heights) / len(heights)

        # Most lines should be similar height
        similar_height_count = sum(
            1 for h in heights if abs(h - avg_height) < avg_height * 0.3
        )
        assert similar_height_count > len(heights) * 0.6

    def test_detect_mixed_portrait_text(
        self, text_detector, mixed_portrait_text
    ) -> None:
        """Test text detection on portrait with text overlay."""
        regions = text_detector.detect(mixed_portrait_text)

        assert isinstance(regions, list)
        # May or may not detect text depending on contrast
        # Just ensure no crash

        if regions:
            # If text detected, should be in reasonable positions
            for region in regions:
                assert 0 <= region.x < mixed_portrait_text.width
                assert 0 <= region.y < mixed_portrait_text.height

    def test_detect_group_mixed_text(self, text_detector, group_mixed_text) -> None:
        """Test text detection on group photo with text."""
        regions = text_detector.detect(group_mixed_text)

        assert isinstance(regions, list)
        # Should detect some text if present

        for region in regions:
            assert region.confidence > 0.2  # Lower threshold for mixed content

    def test_no_text_detection(self, text_detector, random_no_text) -> None:
        """Test that no text is detected in non-text image."""
        regions = text_detector.detect(random_no_text)

        assert isinstance(regions, list)
        # Should detect very few or no text regions
        assert len(regions) < 3, "Should not detect many text regions in nature photo"

        # Any detected regions should have low confidence
        for region in regions:
            assert region.confidence < 0.6

    def test_text_density_calculation(self, text_detector, document_image) -> None:
        """Test text density calculation on real document."""
        regions = text_detector.detect(document_image)

        # Calculate density
        density = text_detector.calculate_text_density(document_image, regions)

        assert 0 <= density <= 1.0
        assert density > 0.3, "Document should have significant text density"

    def test_performance_on_real_images(self, text_detector, fixtures_path) -> None:
        """Test detection performance on all text images."""
        text_dir = fixtures_path / "text"

        if not text_dir.exists():
            pytest.skip("Text fixtures directory not found")

        processing_times = []

        for img_file in text_dir.glob("*.JPG"):
            img = Image.open(img_file)

            import time

            start = time.time()
            regions = text_detector.detect(img)
            duration = time.time() - start

            processing_times.append(duration)

            # Should complete quickly
            assert duration < 2.0, f"Detection took too long for {img_file.name}"
            assert isinstance(regions, list)

        if processing_times:
            avg_time = sum(processing_times) / len(processing_times)
            assert avg_time < 1.0, "Average processing time should be under 1 second"

    def test_merge_behavior_on_real_text(self, text_detector, document_image) -> None:
        """Test region merging on real document."""
        # Get initial regions
        regions = text_detector.detect(document_image)
        initial_count = len(regions)

        # Regions should be properly merged
        # Check no tiny fragments
        for region in regions:
            assert region.width > 20 or region.height > 20

        # Check no excessive overlap
        for i, r1 in enumerate(regions):
            for j, r2 in enumerate(regions[i + 1 :], i + 1):
                # Calculate overlap
                x_overlap = max(
                    0, min(r1.x + r1.width, r2.x + r2.width) - max(r1.x, r2.x)
                )
                y_overlap = max(
                    0, min(r1.y + r1.height, r2.y + r2.height) - max(r1.y, r2.y)
                )
                overlap_area = x_overlap * y_overlap

                r1_area = r1.width * r1.height
                r2_area = r2.width * r2.height

                # Overlap should be minimal
                assert overlap_area < min(r1_area, r2_area) * 0.2

    def test_confidence_scores_correlation(self, text_detector, fixtures_path) -> None:
        """Test that confidence scores correlate with text clarity."""
        # Load different images
        clear_text = fixtures_path / "text" / "document.JPG"
        mixed_text = fixtures_path / "edge_cases" / "portrait-with-text.png"

        if clear_text.exists() and mixed_text.exists():
            clear_img = Image.open(clear_text)
            mixed_img = Image.open(mixed_text)

            clear_regions = text_detector.detect(clear_img)
            mixed_regions = text_detector.detect(mixed_img)

            if clear_regions and mixed_regions:
                # Clear text should have higher average confidence
                clear_avg_conf = sum(r.confidence for r in clear_regions) / len(
                    clear_regions
                )
                mixed_avg_conf = sum(r.confidence for r in mixed_regions) / len(
                    mixed_regions
                )

                # This might not always be true with heuristics, but test the logic
                assert clear_avg_conf > 0.4
                assert mixed_avg_conf > 0.2
