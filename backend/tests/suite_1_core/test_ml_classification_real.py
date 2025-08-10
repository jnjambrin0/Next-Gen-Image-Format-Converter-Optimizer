"""
Ultra-realistic ML classification tests using ONNX Runtime.
Tests content detection with real-world images and edge cases.
"""

import pytest
import asyncio
import numpy as np
from PIL import Image, ImageDraw, ImageFont
import io
from typing import Dict, List, Tuple
import time

from app.services.intelligence_service import intelligence_service
from app.core.intelligence.classifiers import ContentType


class TestMLClassificationRealistic:
    """Test ML-based content classification with realistic scenarios."""

    @pytest.fixture(autouse=True)
    def setup(self, realistic_image_generator):
        """Setup test environment."""
        self.image_generator = realistic_image_generator
        self.classification_results = []

    def create_photo_with_faces(self) -> bytes:
        """Create a realistic photo with face-like features."""
        img = Image.new("RGB", (1920, 1080))
        draw = ImageDraw.Draw(img)

        # Background gradient (sky)
        for y in range(1080):
            color = (
                135 + int(y * 50 / 1080),  # Blue gradient
                206 - int(y * 50 / 1080),  #
                235 - int(y * 35 / 1080),
            )
            draw.rectangle([(0, y), (1920, y + 1)], fill=color)

        # Add face-like features (simplified but realistic proportions)
        face_positions = [(400, 300), (1000, 350), (700, 500)]
        for x, y in face_positions:
            # Face oval
            draw.ellipse([x - 80, y - 100, x + 80, y + 100], fill=(255, 220, 177))
            # Eyes
            draw.ellipse([x - 30, y - 30, x - 10, y - 10], fill=(50, 50, 50))
            draw.ellipse([x + 10, y - 30, x + 30, y - 10], fill=(50, 50, 50))
            # Mouth
            draw.arc(
                [x - 30, y + 20, x + 30, y + 60],
                start=0,
                end=180,
                fill=(200, 100, 100),
                width=3,
            )

        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=95)
        return buffer.getvalue()

    def create_screenshot_with_ui(self) -> bytes:
        """Create a realistic screenshot with UI elements."""
        img = Image.new("RGB", (1440, 900), color=(245, 245, 247))
        draw = ImageDraw.Draw(img)

        # Menu bar
        draw.rectangle([(0, 0), (1440, 30)], fill=(232, 232, 232))

        # Window chrome
        draw.rectangle([(100, 50), (1340, 850)], outline=(200, 200, 200), width=1)
        draw.rectangle([(100, 50), (1340, 80)], fill=(250, 250, 250))

        # Buttons (red, yellow, green)
        draw.ellipse([110, 58, 122, 70], fill=(255, 95, 86))
        draw.ellipse([130, 58, 142, 70], fill=(255, 189, 46))
        draw.ellipse([150, 58, 162, 70], fill=(40, 201, 55))

        # Content area with text-like lines
        y_pos = 120
        for _ in range(20):
            line_width = np.random.randint(200, 1000)
            draw.rectangle(
                [(150, y_pos), (150 + line_width, y_pos + 12)], fill=(100, 100, 100)
            )
            y_pos += 30

        # Sidebar
        draw.rectangle([(100, 80), (300, 850)], fill=(248, 248, 248))

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def create_document_with_text(self) -> bytes:
        """Create a realistic document with text patterns."""
        img = Image.new("RGB", (2480, 3508), color=(255, 255, 255))  # A4 at 300 DPI
        draw = ImageDraw.Draw(img)

        # Title
        draw.rectangle([(300, 200), (2180, 280)], fill=(20, 20, 20))

        # Paragraphs
        y_pos = 400
        for paragraph in range(8):
            # Paragraph with varying line lengths
            for line in range(np.random.randint(3, 8)):
                line_width = (
                    np.random.randint(1600, 2000)
                    if line < 5
                    else np.random.randint(800, 1500)
                )
                # Simulate text with small rectangles
                x_pos = 300
                while x_pos < 300 + line_width:
                    word_width = np.random.randint(30, 150)
                    draw.rectangle(
                        [(x_pos, y_pos), (x_pos + word_width, y_pos + 24)],
                        fill=(30, 30, 30),
                    )
                    x_pos += word_width + 15  # Space between words
                y_pos += 40
            y_pos += 60  # Paragraph spacing

        # Footer
        draw.line([(300, 3300), (2180, 3300)], fill=(150, 150, 150), width=2)
        draw.rectangle([(1100, 3350), (1380, 3380)], fill=(100, 100, 100))

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def create_illustration_with_vectors(self) -> bytes:
        """Create a vector-style illustration."""
        img = Image.new("RGBA", (1000, 1000), color=(255, 255, 255, 0))
        draw = ImageDraw.Draw(img)

        # Geometric shapes with flat colors
        shapes = [
            ("circle", (200, 200, 100), (255, 100, 100, 200)),
            ("circle", (700, 300, 150), (100, 255, 100, 200)),
            ("rect", (400, 500, 200, 300), (100, 100, 255, 200)),
            ("triangle", [(300, 700), (500, 600), (400, 900)], (255, 255, 100, 200)),
        ]

        for shape_type, coords, color in shapes:
            if shape_type == "circle":
                x, y, r = coords
                draw.ellipse([x - r, y - r, x + r, y + r], fill=color)
            elif shape_type == "rect":
                x, y, w, h = coords
                draw.rectangle([x, y, x + w, y + h], fill=color)
            elif shape_type == "triangle":
                draw.polygon(coords, fill=color)

        # Add some lines for artistic effect
        for _ in range(10):
            x1, y1 = np.random.randint(0, 1000, 2)
            x2, y2 = np.random.randint(0, 1000, 2)
            draw.line([(x1, y1), (x2, y2)], fill=(50, 50, 50, 100), width=2)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    @pytest.mark.ml
    @pytest.mark.critical
    async def test_classify_photo_with_faces(self):
        """Test classification of photos with face detection."""
        # Create realistic photo with faces
        photo_data = self.create_photo_with_faces()

        # Classify
        result = await intelligence_service.classify_content(photo_data)

        # Validate classification
        assert result is not None, "Classification returned None"
        assert (
            result.content_type == ContentType.PHOTOGRAPH
        ), f"Expected PHOTOGRAPH, got {result.content_type}"
        assert result.confidence > 0.7, f"Low confidence: {result.confidence}"

        # Check face detection
        assert result.face_regions is not None, "No face detection performed"
        assert len(result.face_regions) > 0, "No faces detected in photo with faces"

        # Validate face regions are reasonable
        for face in result.face_regions:
            assert face.width > 50, "Face region too small"
            assert face.height > 50, "Face region too small"
            assert face.confidence > 0.5, f"Low face confidence: {face.confidence}"

    @pytest.mark.ml
    async def test_classify_screenshot(self):
        """Test classification of UI screenshots."""
        screenshot_data = self.create_screenshot_with_ui()

        result = await intelligence_service.classify_content(screenshot_data)

        assert (
            result.content_type == ContentType.SCREENSHOT
        ), f"Expected SCREENSHOT, got {result.content_type}"
        assert (
            result.confidence > 0.75
        ), f"Low confidence for clear screenshot: {result.confidence}"

        # Screenshots should not detect faces
        assert result.face_regions is None or len(result.face_regions) == 0

        # Check UI element detection hints
        assert result.optimization_hints is not None
        assert result.optimization_hints.get(
            "can_reduce_colors", False
        ), "Screenshot should allow color reduction"

    @pytest.mark.ml
    async def test_classify_document(self):
        """Test classification of document scans."""
        document_data = self.create_document_with_text()

        result = await intelligence_service.classify_content(document_data)

        assert (
            result.content_type == ContentType.DOCUMENT
        ), f"Expected DOCUMENT, got {result.content_type}"
        assert (
            result.confidence > 0.8
        ), f"Low confidence for clear document: {result.confidence}"

        # Documents might have text regions detected
        if result.text_regions:
            assert len(result.text_regions) > 0, "Document should have text regions"
            for text_region in result.text_regions:
                assert text_region.width > 100, "Text region too small"

    @pytest.mark.ml
    async def test_classify_illustration(self):
        """Test classification of vector illustrations."""
        illustration_data = self.create_illustration_with_vectors()

        result = await intelligence_service.classify_content(illustration_data)

        assert (
            result.content_type == ContentType.ILLUSTRATION
        ), f"Expected ILLUSTRATION, got {result.content_type}"
        assert result.confidence > 0.6, f"Low confidence: {result.confidence}"

        # Check optimization hints for illustrations
        assert result.optimization_hints is not None
        suggested_formats = result.optimization_hints.get("suggested_formats", [])
        assert (
            "webp" in suggested_formats or "png" in suggested_formats
        ), "Should suggest efficient formats"

    @pytest.mark.ml
    @pytest.mark.slow
    async def test_classification_batch_performance(self):
        """Test classification performance with batch of images."""
        # Create diverse test set
        test_images = [
            ("photo1", self.create_photo_with_faces()),
            ("photo2", self.image_generator(content_type="photo")),
            ("screenshot1", self.create_screenshot_with_ui()),
            ("screenshot2", self.image_generator(content_type="screenshot")),
            ("document1", self.create_document_with_text()),
            ("document2", self.image_generator(content_type="document")),
            ("illustration1", self.create_illustration_with_vectors()),
            ("illustration2", self.image_generator(content_type="illustration")),
        ]

        # Measure batch classification time
        start_time = time.perf_counter()

        tasks = [
            intelligence_service.classify_content(img_data)
            for _, img_data in test_images
        ]

        results = await asyncio.gather(*tasks)

        total_time = time.perf_counter() - start_time
        avg_time = total_time / len(test_images)

        # Performance assertions
        assert avg_time < 0.5, f"Classification too slow: {avg_time:.3f}s average"
        assert all(r is not None for r in results), "Some classifications failed"

        # Accuracy check
        correct = 0
        for (name, _), result in zip(test_images, results):
            expected_type = name.split("1")[0].split("2")[0]  # Extract type from name
            if (
                expected_type == "photo"
                and result.content_type == ContentType.PHOTOGRAPH
            ):
                correct += 1
            elif (
                expected_type == "screenshot"
                and result.content_type == ContentType.SCREENSHOT
            ):
                correct += 1
            elif (
                expected_type == "document"
                and result.content_type == ContentType.DOCUMENT
            ):
                correct += 1
            elif (
                expected_type == "illustration"
                and result.content_type == ContentType.ILLUSTRATION
            ):
                correct += 1

        accuracy = correct / len(test_images)
        assert accuracy >= 0.75, f"Low classification accuracy: {accuracy:.2%}"

    @pytest.mark.ml
    async def test_edge_case_ambiguous_content(self):
        """Test classification of ambiguous content (photo of document, screenshot of photo, etc.)."""
        # Create photo of a document (ambiguous case)
        img = Image.new("RGB", (2000, 1500), color=(200, 200, 200))
        draw = ImageDraw.Draw(img)

        # Add perspective transform to simulate photographed document
        # Document area
        doc_coords = [(400, 300), (1600, 250), (1650, 1200), (350, 1250)]
        draw.polygon(doc_coords, fill=(255, 255, 255))

        # Add text-like patterns on document
        for y in range(400, 1100, 40):
            for x in range(500, 1500, 200):
                draw.rectangle(
                    [(x, y), (x + np.random.randint(50, 150), y + 20)],
                    fill=(50, 50, 50),
                )

        # Add photo artifacts (shadows, lighting)
        for i in range(50):
            x, y = np.random.randint(0, 2000), np.random.randint(0, 1500)
            radius = np.random.randint(100, 300)
            opacity = np.random.randint(10, 30)
            overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
            overlay_draw = ImageDraw.Draw(overlay)
            overlay_draw.ellipse(
                [x - radius, y - radius, x + radius, y + radius],
                fill=(0, 0, 0, opacity),
            )
            img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")

        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        ambiguous_data = buffer.getvalue()

        # Classify ambiguous content
        result = await intelligence_service.classify_content(ambiguous_data)

        # Should classify as either photo or document with moderate confidence
        assert result.content_type in [ContentType.PHOTOGRAPH, ContentType.DOCUMENT]
        assert (
            0.4 < result.confidence < 0.8
        ), "Confidence should be moderate for ambiguous content"

        # Check if text regions are detected
        if result.content_type == ContentType.DOCUMENT:
            assert result.text_regions is not None

    @pytest.mark.ml
    @pytest.mark.performance
    async def test_classification_memory_stability(self, memory_monitor):
        """Test memory stability during repeated classifications."""
        memory_monitor.start()

        # Create test image once
        test_image = self.create_photo_with_faces()

        # Classify same image 50 times
        for i in range(50):
            result = await intelligence_service.classify_content(test_image)
            assert result is not None

            # Sample memory every 10 classifications
            if i % 10 == 0:
                memory_monitor.sample()

        # Check memory stability
        memory_monitor.assert_stable(max_growth_mb=30)

    @pytest.mark.ml
    async def test_classification_with_corrupted_model_fallback(self):
        """Test graceful fallback when ML model fails."""
        # Create a valid image
        test_image = self.image_generator(content_type="photo")

        # Temporarily corrupt the model path or simulate failure
        original_classify = intelligence_service.engine.classify_content

        async def failing_classify(*args, **kwargs):
            raise RuntimeError("Model loading failed")

        intelligence_service.engine.classify_content = failing_classify

        try:
            # Should fallback to basic classification
            result = await intelligence_service.classify_content(test_image)

            # Should still return a result, just with lower confidence
            assert result is not None
            assert result.content_type is not None
            assert result.confidence < 0.5, "Fallback should have low confidence"

        finally:
            # Restore original method
            intelligence_service.engine.classify_content = original_classify
