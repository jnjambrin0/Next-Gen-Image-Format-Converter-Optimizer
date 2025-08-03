"""Service for format recommendations."""

import time
from typing import List, Optional, Dict, Any
import asyncio
import os
import copy

from app.models.conversion import ContentType, OutputFormat, InputFormat
from app.models.recommendation import (
    RecommendationRequest,
    RecommendationResponse,
    FormatRecommendation,
    UseCaseType,
)
from app.core.intelligence.recommendation_engine import RecommendationEngine
from app.core.intelligence.format_analyzer import FormatAnalyzer
from app.core.intelligence.user_preferences import UserPreferenceTracker
from app.utils.logging import get_logger
from app.core.security.errors_simplified import create_file_error, create_verification_error, create_rate_limit_error

logger = get_logger(__name__)


class RecommendationService:
    """Service for generating intelligent format recommendations."""
    
    def __init__(self, preference_db_path: Optional[str] = None):
        """Initialize recommendation service.
        
        Args:
            preference_db_path: Path to preference database
        """
        # CRITICAL: Ensure database directory exists (CLAUDE.md pattern #5)
        db_path = preference_db_path or "./data/user_preferences.db"
        db_dir = os.path.dirname(db_path)
        os.makedirs(db_dir, exist_ok=True)
        
        self.preference_tracker = UserPreferenceTracker(
            db_path=db_path
        )
        self.format_analyzer = FormatAnalyzer()
        
        # Initialize engine with preference callback
        self.recommendation_engine = RecommendationEngine(
            preference_callback=self._get_preference_callback()
        )
        
        # Cache for recommendations
        self._recommendation_cache = {}
        self._cache_ttl = 300  # 5 minutes
        
        logger.info("Recommendation service initialized")
        
    def _get_preference_callback(self):
        """Create preference callback for recommendation engine."""
        async def callback(content_type, format_option, use_case):
            return await self.preference_tracker.get_preference_score(
                content_type, format_option, use_case
            )
        return callback
        
    async def get_recommendations(
        self,
        request: RecommendationRequest,
        override_format: Optional[OutputFormat] = None
    ) -> RecommendationResponse:
        """Get format recommendations for the given request.
        
        Args:
            request: Recommendation request
            override_format: Optional format override
            
        Returns:
            Recommendation response with top formats
        """
        start_time = time.time()
        
        # Validate request
        if request.original_size_kb <= 0:
            raise create_file_error("invalid_size", "Original size must be positive")
            
        if not request.content_classification:
            raise create_verification_error("missing_classification", "Content classification required")
            
        # Check cache
        cache_key = self._create_cache_key(request)
        if cache_key in self._recommendation_cache:
            cached_response, cache_time = self._recommendation_cache[cache_key]
            if time.time() - cache_time < self._cache_ttl:
                logger.debug("Returning cached recommendations")
                # CRITICAL: Deep copy to prevent cache poisoning (CLAUDE.md security pattern)
                return copy.deepcopy(cached_response)
                
        try:
            # Generate recommendations
            if override_format:
                # User override - create single recommendation
                recommendations = [await self._create_override_recommendation(
                    override_format, request
                )]
            else:
                # Normal recommendation flow
                recommendations = await self.recommendation_engine.generate_recommendations(
                    request, max_recommendations=3
                )
                
            # Create comparison matrix
            comparison_matrix = self._create_comparison_matrix(
                recommendations, request
            )
            
            # Build response
            processing_time_ms = (time.time() - start_time) * 1000
            response = RecommendationResponse(
                recommendations=recommendations,
                comparison_matrix=comparison_matrix,
                content_type=request.content_classification.primary_type.value,
                use_case=request.use_case.value if request.use_case else None,
                processing_time_ms=processing_time_ms
            )
            
            # Cache response
            self._recommendation_cache[cache_key] = (response, time.time())
            
            # Limit cache size
            if len(self._recommendation_cache) > 100:
                # Remove oldest entries
                sorted_keys = sorted(
                    self._recommendation_cache.keys(),
                    key=lambda k: self._recommendation_cache[k][1]
                )
                for key in sorted_keys[:20]:
                    del self._recommendation_cache[key]
                    
            # Privacy-aware logging
            logger.info(f"Generated recommendations in {processing_time_ms:.1f}ms")
            
            return response
            
        except (ValueError, KeyError) as e:
            logger.error("Invalid request data for recommendations")
            raise create_file_error("invalid_input", "Invalid recommendation request data")
        except asyncio.TimeoutError:
            logger.error("Recommendation generation timed out")
            raise create_rate_limit_error("timeout", "Recommendation generation timed out")
        except Exception as e:
            logger.error("Unexpected error generating recommendations")
            raise create_file_error("processing_failed", "Failed to generate recommendations")
            
    async def _create_override_recommendation(
        self,
        format_enum: OutputFormat,
        request: RecommendationRequest
    ) -> FormatRecommendation:
        """Create recommendation for user override format."""
        # Get format characteristics
        from app.core.intelligence.recommendation_engine import RecommendationEngine
        characteristics = RecommendationEngine.FORMAT_CHARACTERISTICS.get(format_enum)
        
        # Analyze trade-offs
        compatibility = self.format_analyzer.analyze_format_compatibility(
            request.original_format,
            format_enum
        )
        
        # Create recommendation with override notice
        reasons = ["User-selected format"]
        if compatibility.conversion_notes:
            reasons.extend(compatibility.conversion_notes[:2])
            
        # Estimate size
        compression_ratio = self.format_analyzer.estimate_compression_ratio(
            request.original_format,
            format_enum,
            request.content_classification.primary_type
        )
        estimated_size = int(request.original_size_kb * compression_ratio)
        
        # Get quality score
        quality_score = self.format_analyzer.predict_quality_score(
            format_enum,
            request.content_classification.primary_type
        )
        
        return FormatRecommendation(
            format=format_enum,
            score=1.0,  # User override gets max score
            reasons=reasons,
            estimated_size_kb=estimated_size,
            quality_score=quality_score,
            compatibility_score=compatibility.compatibility_score,
            features=self.format_analyzer.get_format_features(format_enum),
            trade_offs=self.recommendation_engine._analyze_trade_offs(
                format_enum, request
            ),
            pros=["User preference"],
            cons=[]
        )
        
    def _create_comparison_matrix(
        self,
        recommendations: List[FormatRecommendation],
        request: RecommendationRequest
    ) -> Dict[str, Dict[str, Any]]:
        """Create detailed comparison matrix for recommendations."""
        matrix = {}
        
        # Get formats for comparison
        formats = [rec.format for rec in recommendations]
        
        # Create metrics for each format
        metrics = self.format_analyzer.create_comparison_metrics(
            formats,
            request.content_classification.primary_type,
            request.original_size_kb
        )
        
        # Build comparison structure
        for rec in recommendations:
            format_key = rec.format.value
            matrix[format_key] = {
                "score": rec.score,
                "estimated_size_kb": rec.estimated_size_kb,
                "quality_score": rec.quality_score,
                "compatibility_score": rec.compatibility_score,
                "metrics": [m.dict() for m in metrics.get(format_key, [])],
                "features": rec.features,
                "pros": rec.pros,
                "cons": rec.cons
            }
            
        return matrix
        
    def _create_cache_key(self, request: RecommendationRequest) -> str:
        """Create cache key for recommendation request."""
        key_parts = [
            request.content_classification.primary_type.value,
            request.original_format.value,
            str(request.original_size_kb),
            request.use_case.value if request.use_case else "none",
            request.prioritize or "none",
            ",".join(f.value for f in (request.exclude_formats or []))
        ]
        return "|".join(key_parts)
        
    async def record_user_choice(
        self,
        content_type: ContentType,
        chosen_format: OutputFormat,
        use_case: Optional[UseCaseType] = None,
        was_override: bool = False
    ) -> None:
        """Record user's format choice for learning.
        
        Args:
            content_type: Type of content
            chosen_format: Format chosen by user
            use_case: Optional use case context
            was_override: Whether this was an override of recommendations
        """
        try:
            await self.preference_tracker.record_preference(
                content_type,
                chosen_format,
                use_case
            )
            
            # Log override separately for analysis
            if was_override:
                logger.info("User format override recorded")
                
        except Exception:
            logger.error("Failed to record user choice")
            
    async def get_user_preferences(
        self,
        content_type: ContentType,
        use_case: Optional[UseCaseType] = None
    ) -> List[Dict[str, Any]]:
        """Get user's format preferences.
        
        Args:
            content_type: Type of content
            use_case: Optional use case context
            
        Returns:
            List of format preferences
        """
        try:
            preferences = await self.preference_tracker.get_format_preferences(
                content_type, use_case
            )
            
            return [
                {
                    "format": pref.chosen_format.value,
                    "score_adjustment": pref.score_adjustment,
                    "last_used": pref.timestamp
                }
                for pref in preferences
            ]
            
        except Exception:
            logger.error("Failed to get user preferences")
            return []
            
    async def reset_preferences(
        self,
        content_type: Optional[ContentType] = None,
        format_option: Optional[OutputFormat] = None
    ) -> int:
        """Reset user preferences.
        
        Args:
            content_type: Optional content type to reset
            format_option: Optional format to reset
            
        Returns:
            Number of preferences reset
        """
        try:
            count = await self.preference_tracker.reset_preferences(
                content_type, format_option
            )
            
            # Clear recommendation cache as preferences changed
            self._recommendation_cache.clear()
            
            logger.info(f"Reset {count} user preferences")
            
            return count
            
        except Exception:
            logger.error("Failed to reset preferences")
            return 0
            
    async def get_format_details(
        self,
        format_enum: OutputFormat,
        content_type: ContentType
    ) -> Dict[str, Any]:
        """Get detailed information about a format.
        
        Args:
            format_enum: Output format
            content_type: Content type context
            
        Returns:
            Dictionary of format details
        """
        from app.core.intelligence.recommendation_engine import RecommendationEngine
        
        characteristics = RecommendationEngine.FORMAT_CHARACTERISTICS.get(format_enum)
        features = self.format_analyzer.get_format_features(format_enum)
        
        # Get content-specific score
        content_score = RecommendationEngine.CONTENT_SCORES.get(
            content_type, {}
        ).get(format_enum, 0.5)
        
        return {
            "format": format_enum.value,
            "characteristics": characteristics.dict() if characteristics else None,
            "features": features,
            "content_suitability": content_score,
            "description": self._get_format_description(format_enum),
            "best_for": self._get_best_use_cases(format_enum)
        }
        
    def _get_format_description(self, format_enum: OutputFormat) -> str:
        """Get human-readable format description."""
        descriptions = {
            OutputFormat.WEBP: "Modern format by Google with excellent compression and wide support",
            OutputFormat.AVIF: "Next-generation format with best-in-class compression and HDR support",
            OutputFormat.JPEGXL: "Advanced format with lossless JPEG recompression and progressive decoding",
            OutputFormat.HEIF: "Apple's format for photos with good compression and device support",
            OutputFormat.PNG: "Lossless format perfect for graphics, screenshots, and images with transparency",
            OutputFormat.JPEG: "Universal format with excellent compatibility but lossy compression",
            OutputFormat.WEBP2: "Experimental next version of WebP with improved compression",
            OutputFormat.JPEG2000: "Advanced JPEG variant with better quality but limited support"
        }
        return descriptions.get(format_enum, "Image format")
        
    def _get_best_use_cases(self, format_enum: OutputFormat) -> List[str]:
        """Get best use cases for format."""
        use_cases = {
            OutputFormat.WEBP: ["Web images", "General purpose", "E-commerce"],
            OutputFormat.AVIF: ["Photography", "Web galleries", "HDR content"],
            OutputFormat.JPEGXL: ["Professional photography", "Archival", "Print"],
            OutputFormat.HEIF: ["Mobile photos", "iOS apps", "Photo storage"],
            OutputFormat.PNG: ["Logos", "Screenshots", "Graphics with transparency"],
            OutputFormat.JPEG: ["Web photos", "Email attachments", "Universal sharing"],
            OutputFormat.WEBP2: ["Experimental use", "Future web content"],
            OutputFormat.JPEG2000: ["Medical imaging", "Digital cinema", "GIS"]
        }
        return use_cases.get(format_enum, ["General use"])
        
    def clear_cache(self) -> None:
        """Clear recommendation cache."""
        self._recommendation_cache.clear()
        logger.info("Recommendation cache cleared")


# Singleton instance - initialized in main.py to avoid circular imports (CLAUDE.md pattern #6)
recommendation_service: Optional[RecommendationService] = None