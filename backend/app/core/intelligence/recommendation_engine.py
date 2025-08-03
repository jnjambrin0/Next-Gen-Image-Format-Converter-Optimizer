"""Format recommendation engine for intelligent format selection."""

import asyncio
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import time

from app.models.conversion import ContentType, OutputFormat, InputFormat
from app.models.recommendation import (
    FormatRecommendation,
    RecommendationRequest,
    UseCaseType,
    FormatCharacteristics,
    TradeOffAnalysis,
)
from app.utils.logging import get_logger
from app.core.constants import SUPPORTED_OUTPUT_FORMATS

logger = get_logger(__name__)


class RecommendationEngine:
    """Engine for generating intelligent format recommendations."""
    
    # Weight distribution for scoring
    CONTENT_WEIGHT = 0.4
    USE_CASE_WEIGHT = 0.3
    COMPATIBILITY_WEIGHT = 0.2
    PREFERENCE_WEIGHT = 0.1
    
    # Cache configuration
    CACHE_TTL_SECONDS = 300  # 5 minutes
    MAX_CACHE_SIZE = 1000
    CACHE_CLEANUP_SIZE = 100
    
    # Performance requirements
    MAX_RECOMMENDATION_TIME_MS = 200
    
    # Concurrency protection (CLAUDE.md security requirements)
    MAX_CONCURRENT_RECOMMENDATIONS = 10
    _semaphore = None  # Will be initialized in __init__
    
    # Format characteristics database
    FORMAT_CHARACTERISTICS: Dict[OutputFormat, FormatCharacteristics] = {
        OutputFormat.WEBP: FormatCharacteristics(
            compression_efficiency=0.9,
            browser_support=0.85,
            quality_preservation=0.85,
            features={
                "transparency": True,
                "animation": True,
                "hdr": False,
                "lossless": True,
                "progressive": True
            },
            processing_speed=0.9,
            future_proof=0.8
        ),
        OutputFormat.AVIF: FormatCharacteristics(
            compression_efficiency=0.95,
            browser_support=0.65,
            quality_preservation=0.9,
            features={
                "transparency": True,
                "animation": True,
                "hdr": True,
                "lossless": True,
                "progressive": False
            },
            processing_speed=0.6,
            future_proof=0.9
        ),
        OutputFormat.JPEGXL: FormatCharacteristics(
            compression_efficiency=0.93,
            browser_support=0.3,
            quality_preservation=0.95,
            features={
                "transparency": True,
                "animation": True,
                "hdr": True,
                "lossless": True,
                "progressive": True
            },
            processing_speed=0.7,
            future_proof=0.95
        ),
        OutputFormat.HEIF: FormatCharacteristics(
            compression_efficiency=0.9,
            browser_support=0.5,
            quality_preservation=0.88,
            features={
                "transparency": True,
                "animation": True,
                "hdr": True,
                "lossless": False,
                "progressive": False
            },
            processing_speed=0.7,
            future_proof=0.7
        ),
        OutputFormat.PNG: FormatCharacteristics(
            compression_efficiency=0.5,
            browser_support=1.0,
            quality_preservation=1.0,
            features={
                "transparency": True,
                "animation": False,
                "hdr": False,
                "lossless": True,
                "progressive": True
            },
            processing_speed=0.8,
            future_proof=0.9
        ),
        OutputFormat.JPEG: FormatCharacteristics(
            compression_efficiency=0.75,
            browser_support=1.0,
            quality_preservation=0.75,
            features={
                "transparency": False,
                "animation": False,
                "hdr": False,
                "lossless": False,
                "progressive": True
            },
            processing_speed=0.95,
            future_proof=0.8
        ),
        OutputFormat.WEBP2: FormatCharacteristics(
            compression_efficiency=0.96,
            browser_support=0.1,
            quality_preservation=0.92,
            features={
                "transparency": True,
                "animation": True,
                "hdr": True,
                "lossless": True,
                "progressive": True
            },
            processing_speed=0.5,
            future_proof=0.6
        ),
        OutputFormat.JPEG2000: FormatCharacteristics(
            compression_efficiency=0.85,
            browser_support=0.2,
            quality_preservation=0.9,
            features={
                "transparency": True,
                "animation": False,
                "hdr": False,
                "lossless": True,
                "progressive": True
            },
            processing_speed=0.6,
            future_proof=0.5
        )
    }
    
    # Content type scoring matrix
    CONTENT_SCORES: Dict[ContentType, Dict[OutputFormat, float]] = {
        ContentType.PHOTO: {
            OutputFormat.AVIF: 0.95,
            OutputFormat.WEBP: 0.85,
            OutputFormat.HEIF: 0.85,
            OutputFormat.JPEG: 0.8,
            OutputFormat.JPEGXL: 0.9,
            OutputFormat.PNG: 0.3,
            OutputFormat.WEBP2: 0.9,
            OutputFormat.JPEG2000: 0.75
        },
        ContentType.ILLUSTRATION: {
            OutputFormat.PNG: 0.9,
            OutputFormat.WEBP: 0.95,
            OutputFormat.AVIF: 0.85,
            OutputFormat.JPEGXL: 0.88,
            OutputFormat.JPEG: 0.5,
            OutputFormat.HEIF: 0.7,
            OutputFormat.WEBP2: 0.92,
            OutputFormat.JPEG2000: 0.7
        },
        ContentType.SCREENSHOT: {
            OutputFormat.PNG: 0.95,
            OutputFormat.WEBP: 0.9,
            OutputFormat.AVIF: 0.8,
            OutputFormat.JPEGXL: 0.85,
            OutputFormat.JPEG: 0.6,
            OutputFormat.HEIF: 0.7,
            OutputFormat.WEBP2: 0.88,
            OutputFormat.JPEG2000: 0.75
        },
        ContentType.DOCUMENT: {
            OutputFormat.PNG: 0.95,
            OutputFormat.WEBP: 0.85,
            OutputFormat.JPEG: 0.7,
            OutputFormat.AVIF: 0.75,
            OutputFormat.JPEGXL: 0.9,
            OutputFormat.HEIF: 0.6,
            OutputFormat.WEBP2: 0.8,
            OutputFormat.JPEG2000: 0.85
        }
    }
    
    # Use case scoring matrix
    USE_CASE_SCORES: Dict[UseCaseType, Dict[str, float]] = {
        UseCaseType.WEB: {
            "compression": 0.9,
            "browser_support": 0.95,
            "quality": 0.7,
            "features": 0.6,
            "speed": 0.8
        },
        UseCaseType.PRINT: {
            "compression": 0.3,
            "browser_support": 0.1,
            "quality": 0.95,
            "features": 0.8,
            "speed": 0.4
        },
        UseCaseType.ARCHIVE: {
            "compression": 0.5,
            "browser_support": 0.2,
            "quality": 0.9,
            "features": 0.9,
            "speed": 0.3,
            "future_proof": 0.95
        }
    }
    
    def __init__(self, preference_callback=None):
        """Initialize recommendation engine.
        
        Args:
            preference_callback: Optional callback to get user preferences
        """
        self.preference_callback = preference_callback
        self._format_cache = {}
        self._score_cache = {}  # Cache for format scores
        self._cache_ttl = self.CACHE_TTL_SECONDS
        self._cache_timestamps = {}
        
        # Initialize semaphore for concurrency protection
        if RecommendationEngine._semaphore is None:
            RecommendationEngine._semaphore = asyncio.Semaphore(
                self.MAX_CONCURRENT_RECOMMENDATIONS
            )
        
    async def generate_recommendations(
        self,
        request: RecommendationRequest,
        max_recommendations: int = 3
    ) -> List[FormatRecommendation]:
        """Generate format recommendations based on content and use case.
        
        Args:
            request: Recommendation request with content classification
            max_recommendations: Maximum number of recommendations to return
            
        Returns:
            List of format recommendations sorted by score
        """
        # CRITICAL: Input validation (CLAUDE.md security requirements)
        from app.core.security.errors_simplified import create_file_error
        
        if not isinstance(request, RecommendationRequest):
            raise create_file_error("invalid_input_type", "Invalid recommendation request type")
        
        if request.original_size_kb <= 0:
            raise create_file_error("invalid_input", "Invalid original size")
            
        if request.original_size_kb > 100 * 1024:  # 100MB limit
            raise create_file_error("input_too_large", "Input size exceeds 100MB limit")
            
        if not request.content_classification:
            raise create_file_error("invalid_input", "Content classification required")
        
        # Use semaphore for concurrency protection
        async with self._semaphore:
            start_time = time.time()
            
            # Get available formats
            available_formats = self._get_available_formats(request)
            
            # Score each format - use parallel execution for performance
            format_scores = {}
            scoring_tasks = []
            
            for format_enum in available_formats:
                # Check cache first
                cache_key = self._create_score_cache_key(format_enum, request)
                cached_score = self._get_cached_score(cache_key)
                
                if cached_score is not None:
                    format_scores[format_enum] = cached_score
                else:
                    # Add to tasks for parallel scoring
                    scoring_tasks.append((format_enum, self._calculate_format_score(format_enum, request)))
            
            # Execute scoring tasks in parallel
            if scoring_tasks:
                results = await asyncio.gather(*[task[1] for task in scoring_tasks])
                for i, (format_enum, _) in enumerate(scoring_tasks):
                    score = results[i]
                    format_scores[format_enum] = score
                    # Cache the score
                    cache_key = self._create_score_cache_key(format_enum, request)
                    self._cache_score(cache_key, score)
                
            # Sort by score
            sorted_formats = sorted(
                format_scores.items(),
                key=lambda x: x[1],
                reverse=True
            )[:max_recommendations]
            
            # Generate detailed recommendations
            recommendations = []
            for format_enum, score in sorted_formats:
                recommendation = await self._create_recommendation(
                    format_enum,
                    score,
                    request
                )
                recommendations.append(recommendation)
            
            # Privacy-aware logging
            processing_time_ms = (time.time() - start_time) * 1000
            logger.info(f"Generated format recommendations in {processing_time_ms:.1f}ms")
            
            return recommendations
    
    def _get_available_formats(self, request: RecommendationRequest) -> List[OutputFormat]:
        """Get list of available formats excluding user exclusions."""
        available = []
        
        # Map string values to enum
        for format_str in SUPPORTED_OUTPUT_FORMATS:
            try:
                format_enum = OutputFormat(format_str)
                # Skip optimized variants and excluded formats
                if (format_enum not in [
                    OutputFormat.PNG_OPTIMIZED,
                    OutputFormat.JPEG_OPTIMIZED,
                    OutputFormat.JPG_OPTIMIZED,
                    OutputFormat.JPG,  # Use JPEG instead
                    OutputFormat.JXL,  # Use JPEGXL instead
                    OutputFormat.JPEG_XL,  # Use JPEGXL instead
                    OutputFormat.JP2,  # Use JPEG2000 instead
                ] and format_enum not in (request.exclude_formats or [])):
                    available.append(format_enum)
            except ValueError:
                continue
                
        return available
    
    async def _calculate_format_score(
        self,
        format_enum: OutputFormat,
        request: RecommendationRequest
    ) -> float:
        """Calculate overall score for a format.
        
        Args:
            format_enum: Output format to score
            request: Recommendation request
            
        Returns:
            Overall score (0-1)
        """
        # Content-based score
        content_score = self._get_content_score(
            format_enum,
            request.content_classification.primary_type
        )
        
        # Use case score
        use_case_score = self._get_use_case_score(
            format_enum,
            request.use_case,
            request.prioritize
        )
        
        # Source compatibility score
        compatibility_score = self._get_compatibility_score(
            format_enum,
            request.original_format
        )
        
        # User preference score
        preference_score = await self._get_preference_score(
            format_enum,
            request.content_classification.primary_type,
            request.use_case
        )
        
        # Calculate weighted score
        total_score = (
            content_score * self.CONTENT_WEIGHT +
            use_case_score * self.USE_CASE_WEIGHT +
            compatibility_score * self.COMPATIBILITY_WEIGHT +
            preference_score * self.PREFERENCE_WEIGHT
        )
        
        return min(1.0, max(0.0, total_score))
    
    def _get_content_score(
        self,
        format_enum: OutputFormat,
        content_type: ContentType
    ) -> float:
        """Get content-based score for format."""
        return self.CONTENT_SCORES.get(content_type, {}).get(format_enum, 0.5)
    
    def _get_use_case_score(
        self,
        format_enum: OutputFormat,
        use_case: Optional[UseCaseType],
        prioritize: Optional[str]
    ) -> float:
        """Calculate use case score for format."""
        if not use_case:
            # Default balanced scoring
            use_case = UseCaseType.WEB
            
        characteristics = self.FORMAT_CHARACTERISTICS.get(format_enum)
        if not characteristics:
            return 0.5
            
        weights = self.USE_CASE_SCORES.get(use_case, {})
        
        # Adjust weights based on priority
        if prioritize:
            if prioritize == "size":
                weights["compression"] = min(1.0, weights.get("compression", 0.5) * 1.5)
            elif prioritize == "quality":
                weights["quality"] = min(1.0, weights.get("quality", 0.5) * 1.5)
            elif prioritize == "compatibility":
                weights["browser_support"] = min(1.0, weights.get("browser_support", 0.5) * 1.5)
                
        # Calculate weighted score
        score = 0.0
        total_weight = 0.0
        
        if "compression" in weights:
            score += characteristics.compression_efficiency * weights["compression"]
            total_weight += weights["compression"]
            
        if "browser_support" in weights:
            score += characteristics.browser_support * weights["browser_support"]
            total_weight += weights["browser_support"]
            
        if "quality" in weights:
            score += characteristics.quality_preservation * weights["quality"]
            total_weight += weights["quality"]
            
        if "speed" in weights:
            score += characteristics.processing_speed * weights["speed"]
            total_weight += weights["speed"]
            
        if "future_proof" in weights:
            score += characteristics.future_proof * weights.get("future_proof", 0.5)
            total_weight += weights.get("future_proof", 0.5)
            
        return score / total_weight if total_weight > 0 else 0.5
    
    def _get_compatibility_score(
        self,
        output_format: OutputFormat,
        input_format: InputFormat
    ) -> float:
        """Calculate format compatibility score."""
        # High compatibility for same format family
        if output_format.value.lower() == input_format.value.lower():
            return 1.0
            
        # JPEG variants
        if (input_format in [InputFormat.JPEG, InputFormat.JPG] and
            output_format in [OutputFormat.JPEG, OutputFormat.WEBP, OutputFormat.AVIF]):
            return 0.9
            
        # PNG to lossless formats
        if (input_format == InputFormat.PNG and
            output_format in [OutputFormat.PNG, OutputFormat.WEBP, OutputFormat.AVIF]):
            return 0.95
            
        # Modern format compatibility
        modern_formats = [OutputFormat.WEBP, OutputFormat.AVIF, OutputFormat.JPEGXL]
        if output_format in modern_formats:
            return 0.8
            
        # Default compatibility
        return 0.7
    
    async def _get_preference_score(
        self,
        format_enum: OutputFormat,
        content_type: ContentType,
        use_case: Optional[UseCaseType]
    ) -> float:
        """Get user preference score for format."""
        if not self.preference_callback:
            return 0.5  # Neutral score
            
        try:
            preference = await self.preference_callback(
                content_type,
                format_enum,
                use_case
            )
            return 0.5 + preference  # preference is -0.5 to 0.5
        except Exception:
            logger.warning("Failed to get preference score")
            return 0.5
    
    async def _create_recommendation(
        self,
        format_enum: OutputFormat,
        score: float,
        request: RecommendationRequest
    ) -> FormatRecommendation:
        """Create detailed format recommendation."""
        characteristics = self.FORMAT_CHARACTERISTICS.get(format_enum)
        
        # Generate trade-off analysis
        trade_offs = self._analyze_trade_offs(
            format_enum,
            request
        )
        
        # Generate reasons
        reasons = self._generate_reasons(
            format_enum,
            request,
            characteristics
        )
        
        # Generate pros and cons
        pros, cons = self._generate_pros_cons(
            format_enum,
            request,
            characteristics
        )
        
        # Estimate output size
        estimated_size = self._estimate_output_size(
            format_enum,
            request.original_size_kb,
            request.content_classification.primary_type
        )
        
        return FormatRecommendation(
            format=format_enum,
            score=score,
            reasons=reasons,
            estimated_size_kb=estimated_size,
            quality_score=characteristics.quality_preservation if characteristics else 0.7,
            compatibility_score=characteristics.browser_support if characteristics else 0.5,
            features=characteristics.features if characteristics else {},
            trade_offs=trade_offs,
            pros=pros,
            cons=cons
        )
    
    def _analyze_trade_offs(
        self,
        format_enum: OutputFormat,
        request: RecommendationRequest
    ) -> TradeOffAnalysis:
        """Analyze trade-offs for format selection."""
        characteristics = self.FORMAT_CHARACTERISTICS.get(format_enum)
        if not characteristics:
            # Default trade-offs
            return TradeOffAnalysis(
                size_reduction=0.5,
                quality_score=0.7,
                compatibility_score=0.5,
                feature_score=0.5,
                performance_score=0.5
            )
            
        # Calculate size reduction based on format efficiency
        size_reduction = characteristics.compression_efficiency
        
        # Adjust for content type
        content_type = request.content_classification.primary_type
        if content_type == ContentType.PHOTO and format_enum in [OutputFormat.PNG]:
            size_reduction *= 0.5  # PNG is inefficient for photos
        elif content_type == ContentType.DOCUMENT and format_enum in [OutputFormat.JPEG]:
            size_reduction *= 0.8  # JPEG artifacts bad for text
            
        # Feature score based on required features
        feature_score = 0.7  # Base score
        if request.content_classification.has_text and not characteristics.features.get("lossless"):
            feature_score *= 0.8
        if characteristics.features.get("transparency") and content_type == ContentType.ILLUSTRATION:
            feature_score *= 1.2
            
        return TradeOffAnalysis(
            size_reduction=min(1.0, size_reduction),
            quality_score=characteristics.quality_preservation,
            compatibility_score=characteristics.browser_support,
            feature_score=min(1.0, feature_score),
            performance_score=characteristics.processing_speed
        )
    
    def _generate_reasons(
        self,
        format_enum: OutputFormat,
        request: RecommendationRequest,
        characteristics: Optional[FormatCharacteristics]
    ) -> List[str]:
        """Generate human-readable reasons for recommendation."""
        reasons = []
        content_type = request.content_classification.primary_type
        
        # Content-specific reasons
        content_score = self._get_content_score(format_enum, content_type)
        if content_score >= 0.9:
            if content_type == ContentType.PHOTO:
                reasons.append(f"Excellent for photographs with {int(content_score * 100)}% suitability")
            elif content_type == ContentType.ILLUSTRATION:
                reasons.append(f"Perfect for illustrations and graphics")
            elif content_type == ContentType.SCREENSHOT:
                reasons.append(f"Optimized for screenshots with sharp text")
            elif content_type == ContentType.DOCUMENT:
                reasons.append(f"Ideal for document images with text clarity")
                
        # Use case reasons
        if request.use_case:
            if request.use_case == UseCaseType.WEB and characteristics and characteristics.browser_support >= 0.8:
                reasons.append(f"Wide browser support ({int(characteristics.browser_support * 100)}%)")
            elif request.use_case == UseCaseType.PRINT and characteristics and characteristics.quality_preservation >= 0.9:
                reasons.append("High quality preservation for print reproduction")
            elif request.use_case == UseCaseType.ARCHIVE and characteristics and characteristics.future_proof >= 0.8:
                reasons.append("Future-proof format for long-term archival")
                
        # Compression efficiency
        if characteristics and characteristics.compression_efficiency >= 0.9:
            reasons.append(f"Superior compression (~{int((1 - characteristics.compression_efficiency) * 100 + 30)}% smaller files)")
            
        # Special features
        if characteristics and characteristics.features:
            if characteristics.features.get("hdr"):
                reasons.append("Supports HDR for enhanced dynamic range")
            if characteristics.features.get("transparency") and content_type == ContentType.ILLUSTRATION:
                reasons.append("Preserves transparency for logos and graphics")
                
        return reasons[:4]  # Limit to 4 most relevant reasons
    
    def _generate_pros_cons(
        self,
        format_enum: OutputFormat,
        request: RecommendationRequest,
        characteristics: Optional[FormatCharacteristics]
    ) -> Tuple[List[str], List[str]]:
        """Generate pros and cons for format."""
        pros = []
        cons = []
        
        if not characteristics:
            return ["Modern format"], ["Limited tool support"]
            
        # Pros
        if characteristics.compression_efficiency >= 0.85:
            pros.append("Excellent file size reduction")
        if characteristics.browser_support >= 0.8:
            pros.append("Widely supported across browsers")
        if characteristics.quality_preservation >= 0.9:
            pros.append("Minimal quality loss")
        if characteristics.processing_speed >= 0.8:
            pros.append("Fast encoding/decoding")
        if characteristics.features.get("lossless"):
            pros.append("Lossless compression available")
        if characteristics.features.get("progressive"):
            pros.append("Progressive loading support")
            
        # Cons
        if characteristics.browser_support < 0.7:
            cons.append("Limited browser compatibility")
        if characteristics.processing_speed < 0.6:
            cons.append("Slower processing times")
        if not characteristics.features.get("transparency") and request.content_classification.primary_type == ContentType.ILLUSTRATION:
            cons.append("No transparency support")
        if format_enum in [OutputFormat.JPEG] and request.content_classification.has_text:
            cons.append("May introduce artifacts around text")
        if format_enum in [OutputFormat.JPEGXL, OutputFormat.WEBP2]:
            cons.append("Newer format with limited adoption")
            
        return pros[:3], cons[:2]  # Limit pros/cons
    
    def _estimate_output_size(
        self,
        format_enum: OutputFormat,
        original_size_kb: int,
        content_type: ContentType
    ) -> int:
        """Estimate output file size based on format and content."""
        characteristics = self.FORMAT_CHARACTERISTICS.get(format_enum)
        if not characteristics:
            return int(original_size_kb * 0.7)  # Default 30% reduction
            
        # Base estimation on compression efficiency
        base_ratio = 1.0 - characteristics.compression_efficiency * 0.7
        
        # Adjust for content type
        if content_type == ContentType.PHOTO:
            if format_enum in [OutputFormat.PNG]:
                base_ratio *= 2.0  # PNG inefficient for photos
            elif format_enum in [OutputFormat.AVIF, OutputFormat.WEBP]:
                base_ratio *= 0.8  # Extra efficient for photos
        elif content_type == ContentType.DOCUMENT:
            if format_enum in [OutputFormat.PNG]:
                base_ratio *= 0.6  # PNG good for documents
            elif format_enum in [OutputFormat.JPEG]:
                base_ratio *= 1.2  # JPEG less efficient for text
                
        estimated_size = int(original_size_kb * base_ratio)
        return max(1, estimated_size)  # At least 1 KB
    
    def _create_score_cache_key(self, format_enum: OutputFormat, request: RecommendationRequest) -> str:
        """Create cache key for format scoring."""
        key_parts = [
            format_enum.value,
            request.content_classification.primary_type.value,
            request.use_case.value if request.use_case else "none",
            request.prioritize or "none",
            request.original_format.value
        ]
        return "|".join(key_parts)
    
    def _get_cached_score(self, cache_key: str) -> Optional[float]:
        """Get cached score if available and not expired."""
        if cache_key not in self._score_cache:
            return None
            
        timestamp = self._cache_timestamps.get(cache_key, 0)
        if time.time() - timestamp > self._cache_ttl:
            # Expired
            del self._score_cache[cache_key]
            del self._cache_timestamps[cache_key]
            return None
            
        return self._score_cache[cache_key]
    
    def _cache_score(self, cache_key: str, score: float) -> None:
        """Cache a format score."""
        self._score_cache[cache_key] = score
        self._cache_timestamps[cache_key] = time.time()
        
        # Limit cache size
        if len(self._score_cache) > self.MAX_CACHE_SIZE:
            # Remove oldest entries
            sorted_keys = sorted(
                self._cache_timestamps.keys(),
                key=lambda k: self._cache_timestamps[k]
            )
            for key in sorted_keys[:self.CACHE_CLEANUP_SIZE]:
                del self._score_cache[key]
                del self._cache_timestamps[key]