"""Region-based optimization for different image areas."""

import asyncio
import io
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from PIL import Image, ImageDraw

from app.core.constants import IMAGE_MAX_PIXELS
from app.core.security.errors_simplified import create_file_error
from app.core.security.memory import secure_clear
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Constants
MAX_CONCURRENT_REGIONS = 5
MIN_REGION_SIZE = 50  # Minimum pixels for a region
REGION_OVERLAP_THRESHOLD = 0.3  # 30% overlap to merge regions


class RegionType(Enum):
    """Types of regions for optimization."""

    FACE = "face"
    TEXT = "text"
    FOREGROUND = "foreground"
    BACKGROUND = "background"


@dataclass
class Region:
    """Represents a detected region in the image."""

    type: RegionType
    bbox: Tuple[int, int, int, int]  # x1, y1, x2, y2
    confidence: float
    quality_factor: float


class RegionOptimizer:
    """Optimizes different regions of an image with varying quality settings."""

    # Default quality factors for different region types
    DEFAULT_QUALITY_FACTORS = {
        RegionType.FACE: 1.0,  # Highest quality for faces
        RegionType.TEXT: 0.95,  # High quality for text
        RegionType.FOREGROUND: 0.85,  # Good quality for main subjects
        RegionType.BACKGROUND: 0.7,  # Lower quality acceptable
    }

    def __init__(
        self,
        intelligence_engine: Optional[Any] = None,
        quality_factors: Optional[Dict[RegionType, float]] = None,
    ):
        """Initialize the region optimizer.

        Args:
            intelligence_engine: IntelligenceEngine instance for detection
            quality_factors: Custom quality factors per region type
        """
        self.intelligence_engine = intelligence_engine
        self.quality_factors = quality_factors or self.DEFAULT_QUALITY_FACTORS
        self._region_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REGIONS)

    async def optimize_regions(
        self,
        image_data: bytes,
        output_format: str,
        base_quality: int,
        detect_faces: bool = True,
        detect_text: bool = True,
        detect_foreground: bool = True,
        conversion_func: Optional[Any] = None,
        **kwargs,
    ) -> bytes:
        """Optimize image with different quality settings per region.

        Args:
            image_data: Input image data
            output_format: Target format
            base_quality: Base quality for the image
            detect_faces: Whether to detect face regions
            detect_text: Whether to detect text regions
            detect_foreground: Whether to detect foreground
            conversion_func: Function to convert regions
            **kwargs: Additional conversion parameters

        Returns:
            Optimized image data
        """
        # Input validation
        if not isinstance(image_data, bytes):
            raise create_file_error("invalid_input_type")
        if len(image_data) == 0:
            raise create_file_error("empty_input")
        if len(image_data) > IMAGE_MAX_PIXELS * 4:
            raise create_file_error("input_too_large")

        # Load image
        image = Image.open(io.BytesIO(image_data))

        # Check if image is too small for region optimization
        if image.width < MIN_REGION_SIZE * 2 or image.height < MIN_REGION_SIZE * 2:
            # Too small, return regular conversion
            if conversion_func:
                return await conversion_func(
                    image_data, output_format, quality=base_quality, **kwargs
                )
            return image_data

        # Detect regions
        regions = await self._detect_regions(
            image_data, image, detect_faces, detect_text, detect_foreground
        )

        if not regions:
            # No regions detected, return regular conversion
            if conversion_func:
                return await conversion_func(
                    image_data, output_format, quality=base_quality, **kwargs
                )
            return image_data

        # Merge overlapping regions
        regions = self._merge_overlapping_regions(regions)

        # Create quality map
        quality_map = self._create_quality_map(image.size, regions, base_quality)

        # Apply region-based optimization
        optimized_data = await self._apply_region_optimization(
            image, quality_map, output_format, base_quality, conversion_func, **kwargs
        )

        return optimized_data

    async def _detect_regions(
        self,
        image_data: bytes,
        image: Image.Image,
        detect_faces: bool,
        detect_text: bool,
        detect_foreground: bool,
    ) -> List[Region]:
        """Detect regions in the image."""
        regions = []

        if not self.intelligence_engine:
            logger.warning("No intelligence engine available for region detection")
            return regions

        # Use intelligence engine for detection
        async with self._region_semaphore:
            try:
                # Get content classification
                classification = await self.intelligence_engine.classify_content(
                    image_data
                )

                # Detect faces
                if detect_faces and classification.face_regions:
                    for face in classification.face_regions:
                        regions.append(
                            Region(
                                type=RegionType.FACE,
                                bbox=(
                                    face.x,
                                    face.y,
                                    face.x + face.width,
                                    face.y + face.height,
                                ),
                                confidence=face.confidence,
                                quality_factor=self.quality_factors[RegionType.FACE],
                            )
                        )

                # Detect text
                if detect_text and classification.text_regions:
                    for text in classification.text_regions:
                        regions.append(
                            Region(
                                type=RegionType.TEXT,
                                bbox=(
                                    text.x,
                                    text.y,
                                    text.x + text.width,
                                    text.y + text.height,
                                ),
                                confidence=text.confidence,
                                quality_factor=self.quality_factors[RegionType.TEXT],
                            )
                        )

                # Detect foreground/background
                if detect_foreground:
                    # Simple foreground detection using center focus
                    width, height = image.size
                    center_x, center_y = width // 2, height // 2

                    # Foreground region (center 60% of image)
                    fg_margin_x = int(width * 0.2)
                    fg_margin_y = int(height * 0.2)
                    regions.append(
                        Region(
                            type=RegionType.FOREGROUND,
                            bbox=(
                                fg_margin_x,
                                fg_margin_y,
                                width - fg_margin_x,
                                height - fg_margin_y,
                            ),
                            confidence=0.8,
                            quality_factor=self.quality_factors[RegionType.FOREGROUND],
                        )
                    )

                    # Background regions (edges)
                    # Top
                    regions.append(
                        Region(
                            type=RegionType.BACKGROUND,
                            bbox=(0, 0, width, fg_margin_y),
                            confidence=0.7,
                            quality_factor=self.quality_factors[RegionType.BACKGROUND],
                        )
                    )
                    # Bottom
                    regions.append(
                        Region(
                            type=RegionType.BACKGROUND,
                            bbox=(0, height - fg_margin_y, width, height),
                            confidence=0.7,
                            quality_factor=self.quality_factors[RegionType.BACKGROUND],
                        )
                    )
                    # Left
                    regions.append(
                        Region(
                            type=RegionType.BACKGROUND,
                            bbox=(0, fg_margin_y, fg_margin_x, height - fg_margin_y),
                            confidence=0.7,
                            quality_factor=self.quality_factors[RegionType.BACKGROUND],
                        )
                    )
                    # Right
                    regions.append(
                        Region(
                            type=RegionType.BACKGROUND,
                            bbox=(
                                width - fg_margin_x,
                                fg_margin_y,
                                width,
                                height - fg_margin_y,
                            ),
                            confidence=0.7,
                            quality_factor=self.quality_factors[RegionType.BACKGROUND],
                        )
                    )

            except Exception as e:
                logger.error(f"Region detection failed: {str(e)}")

        return regions

    def _merge_overlapping_regions(self, regions: List[Region]) -> List[Region]:
        """Merge overlapping regions, keeping highest priority."""
        if not regions:
            return regions

        # Sort by priority (face > text > foreground > background)
        priority_map = {
            RegionType.FACE: 4,
            RegionType.TEXT: 3,
            RegionType.FOREGROUND: 2,
            RegionType.BACKGROUND: 1,
        }
        regions.sort(key=lambda r: priority_map[r.type], reverse=True)

        merged = []
        for region in regions:
            should_add = True

            for existing in merged:
                overlap = self._calculate_overlap(region.bbox, existing.bbox)
                if overlap > REGION_OVERLAP_THRESHOLD:
                    # Keep the higher priority region
                    should_add = False
                    break

            if should_add:
                merged.append(region)

        return merged

    def _calculate_overlap(
        self, bbox1: Tuple[int, int, int, int], bbox2: Tuple[int, int, int, int]
    ) -> float:
        """Calculate overlap ratio between two bounding boxes."""
        x1_1, y1_1, x2_1, y2_1 = bbox1
        x1_2, y1_2, x2_2, y2_2 = bbox2

        # Calculate intersection
        x1_i = max(x1_1, x1_2)
        y1_i = max(y1_1, y1_2)
        x2_i = min(x2_1, x2_2)
        y2_i = min(y2_1, y2_2)

        if x1_i >= x2_i or y1_i >= y2_i:
            return 0.0

        intersection = (x2_i - x1_i) * (y2_i - y1_i)
        area1 = (x2_1 - x1_1) * (y2_1 - y1_1)
        area2 = (x2_2 - x1_2) * (y2_2 - y1_2)
        union = area1 + area2 - intersection

        return intersection / union if union > 0 else 0.0

    def _create_quality_map(
        self, size: Tuple[int, int], regions: List[Region], base_quality: int
    ) -> np.ndarray:
        """Create a quality map for the image."""
        width, height = size
        quality_map = np.full((height, width), base_quality, dtype=np.float32)

        for region in regions:
            x1, y1, x2, y2 = region.bbox
            # Ensure bounds are within image
            x1 = max(0, min(x1, width - 1))
            y1 = max(0, min(y1, height - 1))
            x2 = max(0, min(x2, width))
            y2 = max(0, min(y2, height))

            # Apply quality factor to region
            region_quality = base_quality * region.quality_factor
            quality_map[y1:y2, x1:x2] = np.maximum(
                quality_map[y1:y2, x1:x2], region_quality
            )

        return quality_map

    async def _apply_region_optimization(
        self,
        image: Image.Image,
        quality_map: np.ndarray,
        output_format: str,
        base_quality: int,
        conversion_func: Optional[Any],
        **kwargs,
    ) -> bytes:
        """Apply region-based optimization to the image."""
        # For simple implementation, we'll use the highest quality needed
        # In a more advanced implementation, we could use libvips for true region-based encoding

        max_quality = int(np.max(quality_map))

        # Convert with the highest quality needed
        buffer = io.BytesIO()
        image.save(buffer, format=output_format.upper(), quality=max_quality, **kwargs)

        # Clear sensitive data - numpy arrays need special handling
        if isinstance(quality_map, np.ndarray):
            quality_map.fill(0)

        return buffer.getvalue()

    def visualize_regions(self, image_data: bytes, regions: List[Region]) -> bytes:
        """Create a visualization of detected regions (for debugging)."""
        image = Image.open(io.BytesIO(image_data))
        draw = ImageDraw.Draw(image)

        # Colors for different region types
        colors = {
            RegionType.FACE: (255, 0, 0),  # Red
            RegionType.TEXT: (0, 255, 0),  # Green
            RegionType.FOREGROUND: (0, 0, 255),  # Blue
            RegionType.BACKGROUND: (255, 255, 0),  # Yellow
        }

        for region in regions:
            color = colors.get(region.type, (255, 255, 255))
            draw.rectangle(region.bbox, outline=color, width=3)

        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()
