"""
Core integration tests for IntelligenceEngine.
Tests ML model integration and content classification.
"""

import asyncio
import io
from typing import Optional

import numpy as np
import pytest
from PIL import Image

from app.core.intelligence.engine import IntelligenceEngine
from app.models.intelligence import ContentClassification, ContentType


@pytest.fixture
async def intelligence_engine():
    """Create IntelligenceEngine instance."""
    engine = IntelligenceEngine()
    await engine.initialize()
    yield engine
    await engine.cleanup() if hasattr(engine, "cleanup") else None


@pytest.fixture
def create_test_image():
    """Factory to create test images of different types."""

    def _create(content_type: str, size: tuple = (200, 200)) -> bytes:
        if content_type == "photo":
            # Create a realistic photo-like image with gradients
            img = Image.new("RGB", size)
            pixels = img.load()
            for i in range(size[0]):
                for j in range(size[1]):
                    # Create gradient for photo-like appearance
                    r = int(255 * (i / size[0]))
                    g = int(255 * (j / size[1]))
                    b = int(255 * ((i + j) / (size[0] + size[1])))
                    pixels[i, j] = (r, g, b)

        elif content_type == "screenshot":
            # Create UI-like image with rectangles
            img = Image.new("RGB", size, color="white")
            from PIL import ImageDraw

            draw = ImageDraw.Draw(img)
            # Add UI elements
            draw.rectangle([10, 10, 190, 30], fill="blue")  # Title bar
            draw.rectangle([10, 40, 90, 190], fill="lightgray")  # Sidebar
            draw.rectangle(
                [100, 40, 190, 190], fill="white", outline="black"
            )  # Content

        elif content_type == "document":
            # Create document-like image with text lines
            img = Image.new("RGB", size, color="white")
            from PIL import ImageDraw

            draw = ImageDraw.Draw(img)
            # Add text-like lines
            for y in range(20, 180, 15):
                draw.rectangle([20, y, 180, y + 2], fill="black")

        else:  # illustration
            # Create illustration with shapes
            img = Image.new("RGB", size, color="white")
            from PIL import ImageDraw

            draw = ImageDraw.Draw(img)
            draw.ellipse([50, 50, 150, 150], fill="red", outline="black")
            draw.polygon([(100, 20), (140, 100), (60, 100)], fill="yellow")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    return _create


class TestIntelligenceEngineCore:
    """Test core intelligence engine functionality."""

    @pytest.mark.asyncio
    async def test_engine_initialization(self, intelligence_engine):
        """Test engine initializes properly."""
        assert intelligence_engine is not None
        assert intelligence_engine.initialized is True
        assert intelligence_engine.enable_ml is True

    @pytest.mark.asyncio
    async def test_classify_photo_content(self, intelligence_engine, create_test_image):
        """Test classification of photo content."""
        photo_data = create_test_image("photo")

        classification = await intelligence_engine.classify_content(photo_data)

        assert isinstance(classification, ContentClassification)
        assert classification.content_type in [
            ContentType.PHOTO,
            ContentType.ILLUSTRATION,
        ]
        assert 0 <= classification.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_classify_screenshot_content(
        self, intelligence_engine, create_test_image
    ):
        """Test classification of screenshot content."""
        screenshot_data = create_test_image("screenshot")

        classification = await intelligence_engine.classify_content(screenshot_data)

        assert isinstance(classification, ContentClassification)
        # Screenshots might be classified as screenshots or documents
        assert classification.content_type in [
            ContentType.SCREENSHOT,
            ContentType.DOCUMENT,
        ]

    @pytest.mark.asyncio
    async def test_classify_document_content(
        self, intelligence_engine, create_test_image
    ):
        """Test classification of document content."""
        document_data = create_test_image("document")

        classification = await intelligence_engine.classify_content(document_data)

        assert isinstance(classification, ContentClassification)
        assert classification.content_type in [
            ContentType.DOCUMENT,
            ContentType.SCREENSHOT,
        ]

    @pytest.mark.asyncio
    async def test_classify_illustration_content(
        self, intelligence_engine, create_test_image
    ):
        """Test classification of illustration content."""
        illustration_data = create_test_image("illustration")

        classification = await intelligence_engine.classify_content(illustration_data)

        assert isinstance(classification, ContentClassification)
        assert classification.content_type in [
            ContentType.ILLUSTRATION,
            ContentType.PHOTO,
        ]

    @pytest.mark.asyncio
    async def test_face_detection(self, intelligence_engine):
        """Test face detection capability."""
        # Create image with face-like features
        img = Image.new("RGB", (200, 200), color="white")
        from PIL import ImageDraw

        draw = ImageDraw.Draw(img)

        # Draw simple face
        draw.ellipse([70, 50, 130, 110], fill="peach", outline="black")  # Face
        draw.ellipse([80, 65, 90, 75], fill="black")  # Left eye
        draw.ellipse([110, 65, 120, 75], fill="black")  # Right eye
        draw.arc([85, 85, 115, 100], 0, 180, fill="black")  # Smile

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        face_data = buffer.getvalue()

        classification = await intelligence_engine.classify_content(face_data)

        assert isinstance(classification, ContentClassification)
        # Check if faces detected (if face detection is enabled)
        if hasattr(classification, "face_regions"):
            assert isinstance(classification.face_regions, list)

    @pytest.mark.asyncio
    async def test_text_detection(self, intelligence_engine):
        """Test text detection capability."""
        # Create image with text
        img = Image.new("RGB", (200, 200), color="white")
        from PIL import ImageDraw, ImageFont

        draw = ImageDraw.Draw(img)

        # Add text
        try:
            # Try to use a font, fallback to default if not available
            font = ImageFont.truetype("Arial.ttf", 20)
        except:
            font = ImageFont.load_default()

        draw.text((50, 50), "Test Text", fill="black", font=font)
        draw.text((50, 100), "More Text", fill="black", font=font)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        text_data = buffer.getvalue()

        classification = await intelligence_engine.classify_content(text_data)

        assert isinstance(classification, ContentClassification)
        # Should classify as document due to text
        assert classification.content_type in [
            ContentType.DOCUMENT,
            ContentType.SCREENSHOT,
        ]

        # Check if text regions detected (if text detection is enabled)
        if hasattr(classification, "text_regions"):
            assert isinstance(classification.text_regions, list)

    @pytest.mark.asyncio
    async def test_concurrent_classifications(
        self, intelligence_engine, create_test_image
    ):
        """Test concurrent classification requests."""
        images = [
            create_test_image("photo"),
            create_test_image("screenshot"),
            create_test_image("document"),
            create_test_image("illustration"),
        ]

        tasks = [intelligence_engine.classify_content(img) for img in images]

        results = await asyncio.gather(*tasks)

        assert len(results) == 4
        assert all(isinstance(r, ContentClassification) for r in results)
        # Each should have a valid content type
        assert all(r.content_type in ContentType for r in results)

    @pytest.mark.asyncio
    async def test_caching_mechanism(self, intelligence_engine, create_test_image):
        """Test that caching improves performance."""
        import time

        photo_data = create_test_image("photo")

        # First classification (not cached)
        start = time.time()
        result1 = await intelligence_engine.classify_content(photo_data)
        first_time = time.time() - start

        # Second classification (should be cached)
        start = time.time()
        result2 = await intelligence_engine.classify_content(photo_data)
        second_time = time.time() - start

        assert result1.content_type == result2.content_type
        assert result1.confidence == result2.confidence
        # Cached should be faster (at least 2x)
        assert second_time < first_time / 2

    @pytest.mark.asyncio
    async def test_invalid_image_handling(self, intelligence_engine):
        """Test handling of invalid image data."""
        invalid_data = b"not an image"

        with pytest.raises(Exception):
            await intelligence_engine.classify_content(invalid_data)

    @pytest.mark.asyncio
    async def test_empty_image_handling(self, intelligence_engine):
        """Test handling of empty image data."""
        empty_data = b""

        with pytest.raises(Exception):
            await intelligence_engine.classify_content(empty_data)

    @pytest.mark.asyncio
    async def test_huge_image_handling(self, intelligence_engine):
        """Test handling of very large images."""
        # Create a huge image (5000x5000)
        huge_img = Image.new("RGB", (5000, 5000), color="blue")
        buffer = io.BytesIO()
        huge_img.save(buffer, format="JPEG", quality=95)
        huge_data = buffer.getvalue()

        # Should handle large images (might downsample)
        classification = await intelligence_engine.classify_content(huge_data)

        assert isinstance(classification, ContentClassification)
        assert classification.content_type in ContentType

    @pytest.mark.asyncio
    async def test_optimization_recommendations(
        self, intelligence_engine, create_test_image
    ):
        """Test optimization recommendations based on content."""
        photo_data = create_test_image("photo")

        classification = await intelligence_engine.classify_content(photo_data)
        recommendations = await intelligence_engine.get_optimization_recommendations(
            classification
        )

        assert isinstance(recommendations, dict)
        assert "format" in recommendations
        assert "quality" in recommendations

        # Photos should recommend lossy formats
        if classification.content_type == ContentType.PHOTO:
            assert recommendations["format"] in ["jpeg", "webp", "avif"]
            assert recommendations["quality"] <= 90

    @pytest.mark.asyncio
    async def test_ml_model_fallback(self, intelligence_engine):
        """Test fallback when ML model is unavailable."""
        # Disable ML temporarily
        original_enable_ml = intelligence_engine.enable_ml
        intelligence_engine.enable_ml = False

        photo_data = create_test_image("photo")

        # Should still work with heuristics
        classification = await intelligence_engine.classify_content(photo_data)

        assert isinstance(classification, ContentClassification)
        assert classification.content_type in ContentType
        assert classification.confidence <= 0.5  # Lower confidence without ML

        # Restore ML
        intelligence_engine.enable_ml = original_enable_ml

    @pytest.mark.asyncio
    async def test_memory_usage(self, intelligence_engine, create_test_image):
        """Test that memory usage is reasonable."""
        import gc
        import os

        import psutil

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Process many images
        for _ in range(50):
            img_data = create_test_image("photo", size=(500, 500))
            await intelligence_engine.classify_content(img_data)

        gc.collect()

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        # Should not leak memory (< 100MB increase for 50 images)
        assert memory_increase < 100, f"Possible memory leak: {memory_increase}MB"
