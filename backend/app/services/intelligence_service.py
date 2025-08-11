"""Intelligence service for ML-based image analysis."""

import asyncio
import logging
from typing import Any, Dict, Optional

from app.core.intelligence import IntelligenceEngine
from app.models.conversion import ContentClassification, ContentType

logger = logging.getLogger(__name__)


class IntelligenceService:
    """Service layer for intelligence engine operations."""

    def __init__(self):
        """Initialize the intelligence service."""
        self.engine: Optional[IntelligenceEngine] = None
        self.stats_collector = None  # Will be injected at startup
        self._initialized = False
        self._lock = asyncio.Lock()

    async def initialize(self, models_dir: Optional[str] = None) -> None:
        """Initialize the intelligence engine.

        Args:
            models_dir: Directory containing ML models
        """
        async with self._lock:
            if self._initialized:
                return

            try:
                self.engine = IntelligenceEngine(
                    models_dir=models_dir,
                    fallback_mode=True,  # Always allow fallback
                    enable_caching=True,
                )
                self._initialized = True
                logger.info("Intelligence service initialized successfully")

                # Track initialization in stats if available
                if self.stats_collector:
                    await self.stats_collector.track_event(
                        "intelligence_initialized",
                        {"model_loaded": self.engine.model_loaded},
                    )

            except Exception as e:
                logger.error(f"Failed to initialize intelligence service: {e}")
                # Create engine in fallback mode
                self.engine = IntelligenceEngine(
                    models_dir=models_dir, fallback_mode=True, enable_caching=True
                )
                self._initialized = True

    async def analyze_image(
        self, image_data: bytes, debug: bool = False
    ) -> ContentClassification:
        """Analyze image content using ML models.

        Args:
            image_data: Raw image bytes
            debug: Include debug information

        Returns:
            ContentClassification with detected content type and metadata
        """
        if not self._initialized:
            await self.initialize()

        if not self.engine:
            raise RuntimeError("Intelligence engine not initialized")

        try:
            # Track analysis start
            if self.stats_collector:
                await self.stats_collector.increment_counter("intelligence_analyses")

            # Run classification
            result = await self.engine.classify_content(image_data, debug=debug)

            # Track results
            if self.stats_collector:
                await self.stats_collector.track_event(
                    "intelligence_analysis",
                    {
                        "content_type": result.primary_type.value,
                        "confidence": result.confidence,
                        "processing_time_ms": result.processing_time_ms,
                        "has_text": result.has_text,
                        "has_faces": result.has_faces,
                        "mixed_content": result.mixed_content,
                    },
                )

                # Track timing
                await self.stats_collector.record_timing(
                    "intelligence_analysis_time", result.processing_time_ms
                )

            return result

        except Exception as e:
            logger.error(f"Image analysis failed: {e}")

            # Track failure
            if self.stats_collector:
                await self.stats_collector.increment_counter("intelligence_failures")

            # Return fallback result
            return ContentClassification(
                primary_type=ContentType.PHOTO,
                confidence=0.0,
                processing_time_ms=0.0,
                has_text=False,
                has_faces=False,
            )

    async def get_optimization_recommendations(
        self, content_type: ContentType, target_format: str
    ) -> Dict[str, Any]:
        """Get optimization recommendations based on content type.

        Args:
            content_type: Detected content type
            target_format: Target output format

        Returns:
            Dictionary of recommended settings
        """
        if not self._initialized:
            await self.initialize()

        if not self.engine:
            raise RuntimeError("Intelligence engine not initialized")

        try:
            recommendations = self.engine.recommend_settings(
                content_type, target_format
            )

            # Track recommendation request
            if self.stats_collector:
                await self.stats_collector.track_event(
                    "intelligence_recommendation",
                    {
                        "content_type": content_type.value,
                        "target_format": target_format,
                    },
                )

            return recommendations

        except Exception as e:
            logger.error(f"Failed to get recommendations: {e}")
            # Return default recommendations
            return {
                "quality": 85,
                "optimization_preset": "balanced",
                "strip_metadata": True,
            }

    async def clear_cache(self) -> None:
        """Clear the classification cache."""
        if self.engine:
            self.engine.clear_cache()
            logger.info("Intelligence cache cleared")

            # Track cache clear
            if self.stats_collector:
                await self.stats_collector.track_event("intelligence_cache_cleared", {})

    async def get_status(self) -> Dict[str, Any]:
        """Get intelligence service status.

        Returns:
            Dictionary with service status information
        """
        status = {
            "initialized": self._initialized,
            "model_loaded": False,
            "fallback_mode": True,
            "cache_enabled": True,
            "cache_size": 0,
        }

        if self.engine:
            status.update(
                {
                    "model_loaded": self.engine.model_loaded,
                    "fallback_mode": self.engine.fallback_mode,
                    "cache_enabled": self.engine.enable_caching,
                    "cache_size": len(self.engine._cache),
                }
            )

        return status

    async def shutdown(self) -> None:
        """Shutdown the intelligence service."""
        if self.engine:
            # Clear cache
            self.engine.clear_cache()

            # Track shutdown
            if self.stats_collector:
                await self.stats_collector.track_event("intelligence_shutdown", {})

            # Clear engine reference
            self.engine = None
            self._initialized = False

            logger.info("Intelligence service shut down")


# Create singleton instance
intelligence_service = IntelligenceService()
