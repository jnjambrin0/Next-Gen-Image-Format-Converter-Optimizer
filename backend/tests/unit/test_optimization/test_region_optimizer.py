"""Unit tests for the RegionOptimizer."""

from typing import Any
import io
from unittest.mock import AsyncMock, MagicMock

import pytest
from PIL import Image

from app.core.optimization.region_optimizer import Region, RegionOptimizer, RegionType
from app.core.security.errors_simplified import SecurityError
from app.models.conversion import BoundingBox, ContentClassification


class TestRegionOptimizer:
    """Test cases for RegionOptimizer."""

    @pytest.fixture
    def mock_intelligence_engine(self) -> None:
        """Create a mock intelligence engine."""
        engine = MagicMock()

        # Mock content classification with faces and text
        classification = ContentClassification(
            primary_type="photo",
            confidence=0.95,
            processing_time_ms=100,
            has_faces=True,
            face_regions=[BoundingBox(x=20, y=20, width=30, height=40, confidence=0.9)],
            has_text=True,
            text_regions=[
                BoundingBox(x=60, y=10, width=30, height=20, confidence=0.85)
            ],
        )

        engine.classify_content = AsyncMock(return_value=classification)
        return engine

    @pytest.fixture
    def optimizer(self, mock_intelligence_engine) -> None:
        """Create a RegionOptimizer instance."""
        return RegionOptimizer(
            intelligence_engine=mock_intelligence_engine,
            quality_factors={
                RegionType.FACE: 1.0,
                RegionType.TEXT: 0.95,
                RegionType.FOREGROUND: 0.85,
                RegionType.BACKGROUND: 0.7,
            },
        )

    @pytest.fixture
    def test_image(self) -> None:
        """Create a test image."""
        img = Image.new("RGB", (200, 200), color="white")
        # Add some colored regions
        pixels = img.load()
        # Face region (red)
        for x in range(20, 50):
            for y in range(20, 60):
                pixels[x, y] = (255, 0, 0)
        # Text region (blue)
        for x in range(60, 90):
            for y in range(10, 30):
                pixels[x, y] = (0, 0, 255)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    @pytest.fixture
    def mock_conversion_func(self) -> None:
        """Create a mock conversion function."""

        async def conversion_func(image_data, output_format, quality=85, **kwargs):
            # Just return the input data for testing
            return image_data

        return conversion_func

    @pytest.mark.asyncio
    async def test_optimize_regions_basic(
        self, optimizer, test_image, mock_conversion_func
    ):
        """Test basic region optimization."""
        result = await optimizer.optimize_regions(
            test_image,
            "jpeg",
            base_quality=80,
            detect_faces=True,
            detect_text=True,
            detect_foreground=True,
            conversion_func=mock_conversion_func,
        )

        assert len(result) > 0
        # Should have detected regions
        assert optimizer.intelligence_engine.classify_content.called

    @pytest.mark.asyncio
    async def test_region_detection(self, optimizer, test_image):
        """Test region detection."""
        img = Image.open(io.BytesIO(test_image))

        regions = await optimizer._detect_regions(
            test_image, img, detect_faces=True, detect_text=True, detect_foreground=True
        )

        # Should detect face, text, and foreground/background regions
        region_types = {r.type for r in regions}
        assert RegionType.FACE in region_types
        assert RegionType.TEXT in region_types
        assert RegionType.FOREGROUND in region_types
        assert RegionType.BACKGROUND in region_types

    @pytest.mark.asyncio
    async def test_small_image_handling(self, optimizer, mock_conversion_func):
        """Test handling of images too small for region optimization."""
        # Create a tiny image
        small_img = Image.new("RGB", (40, 40), color="red")
        buffer = io.BytesIO()
        small_img.save(buffer, format="PNG")
        small_data = buffer.getvalue()

        result = await optimizer.optimize_regions(
            small_data, "jpeg", base_quality=80, conversion_func=mock_conversion_func
        )

        # Should return without region optimization
        assert result == small_data

    def test_merge_overlapping_regions(self, optimizer) -> None:
        """Test merging of overlapping regions."""
        regions = [
            Region(RegionType.FACE, (10, 10, 50, 50), 0.9, 1.0),
            Region(
                RegionType.TEXT, (20, 20, 60, 60), 0.8, 0.95
            ),  # 44% overlap with face
            Region(RegionType.BACKGROUND, (100, 100, 150, 150), 0.7, 0.7),
        ]

        merged = optimizer._merge_overlapping_regions(regions)

        # Face should take priority over text (they overlap >30%)
        assert len(merged) == 2  # Face and background
        assert merged[0].type == RegionType.FACE
        assert merged[1].type == RegionType.BACKGROUND

    def test_calculate_overlap(self, optimizer) -> None:
        """Test overlap calculation."""
        # No overlap
        overlap = optimizer._calculate_overlap((0, 0, 10, 10), (20, 20, 30, 30))
        assert overlap == 0.0

        # Complete overlap
        overlap = optimizer._calculate_overlap((0, 0, 10, 10), (0, 0, 10, 10))
        assert overlap == 1.0

        # Partial overlap
        overlap = optimizer._calculate_overlap((0, 0, 10, 10), (5, 5, 15, 15))
        assert 0 < overlap < 1

    def test_create_quality_map(self, optimizer) -> None:
        """Test quality map creation."""
        regions = [
            Region(RegionType.FACE, (10, 10, 30, 30), 0.9, 1.0),
            Region(RegionType.BACKGROUND, (0, 0, 100, 100), 0.7, 0.7),
        ]

        quality_map = optimizer._create_quality_map((100, 100), regions, 80)

        # Face region should have higher quality
        face_quality = quality_map[15, 15]
        bg_quality = quality_map[50, 50]
        assert face_quality > bg_quality

    @pytest.mark.asyncio
    async def test_input_validation(self, optimizer, mock_conversion_func):
        """Test input validation."""
        # Invalid input type
        with pytest.raises(SecurityError) as exc_info:
            await optimizer.optimize_regions(
                "not bytes", "jpeg", 80, conversion_func=mock_conversion_func
            )
        assert "invalid_input_type" in str(exc_info.value)

        # Empty input
        with pytest.raises(SecurityError) as exc_info:
            await optimizer.optimize_regions(
                b"", "jpeg", 80, conversion_func=mock_conversion_func
            )
        assert "empty_input" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_no_intelligence_engine(self, test_image, mock_conversion_func):
        """Test behavior without intelligence engine."""
        optimizer = RegionOptimizer(intelligence_engine=None)

        result = await optimizer.optimize_regions(
            test_image, "jpeg", base_quality=80, conversion_func=mock_conversion_func
        )

        # Should return without region optimization
        assert result == test_image

    def test_visualize_regions(self, optimizer) -> None:
        """Test region visualization."""
        # Create test image
        img = Image.new("RGB", (100, 100), color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        image_data = buffer.getvalue()

        regions = [
            Region(RegionType.FACE, (10, 10, 30, 30), 0.9, 1.0),
            Region(RegionType.TEXT, (50, 50, 80, 80), 0.85, 0.95),
        ]

        visualization = optimizer.visualize_regions(image_data, regions)

        # Should return valid image data
        assert len(visualization) > 0
        # Verify it's a valid image
        img = Image.open(io.BytesIO(visualization))
        assert img.format == "PNG"

    @pytest.mark.asyncio
    async def test_quality_factors_application(self, optimizer, test_image):
        """Test that quality factors are applied correctly."""
        img = Image.open(io.BytesIO(test_image))

        regions = [
            Region(
                RegionType.FACE,
                (10, 10, 30, 30),
                0.9,
                optimizer.quality_factors[RegionType.FACE],
            ),
            Region(
                RegionType.TEXT,
                (50, 50, 80, 80),
                0.85,
                optimizer.quality_factors[RegionType.TEXT],
            ),
            Region(
                RegionType.BACKGROUND,
                (0, 0, 200, 200),
                0.7,
                optimizer.quality_factors[RegionType.BACKGROUND],
            ),
        ]

        quality_map = optimizer._create_quality_map(img.size, regions, 80)

        # Check that quality factors are applied
        face_quality = quality_map[15, 15]
        text_quality = quality_map[65, 65]
        bg_quality = quality_map[150, 150]

        assert face_quality == 80 * 1.0  # Base quality * face factor
        assert text_quality == 80 * 0.95
        assert bg_quality == 80 * 0.7
