"""Unit tests for recommendation engine."""

import pytest
from unittest.mock import Mock, AsyncMock

from app.models.conversion import ContentType, OutputFormat, InputFormat, ContentClassification
from app.models.recommendation import (
    RecommendationRequest,
    UseCaseType,
    FormatRecommendation,
)
from app.core.intelligence.recommendation_engine import RecommendationEngine


class TestRecommendationEngine:
    """Test cases for RecommendationEngine."""
    
    @pytest.fixture
    def engine(self):
        """Create recommendation engine instance."""
        return RecommendationEngine()
        
    @pytest.fixture
    def sample_classification(self):
        """Create sample content classification."""
        return ContentClassification(
            primary_type=ContentType.PHOTO,
            confidence=0.9,
            processing_time_ms=50.0,
            has_text=False,
            has_faces=True
        )
        
    @pytest.fixture
    def sample_request(self, sample_classification):
        """Create sample recommendation request."""
        return RecommendationRequest(
            content_classification=sample_classification,
            use_case=UseCaseType.WEB,
            original_format=InputFormat.JPEG,
            original_size_kb=500,
            prioritize="size"
        )
        
    def test_format_characteristics_defined(self, engine):
        """Test that format characteristics are properly defined."""
        assert len(RecommendationEngine.FORMAT_CHARACTERISTICS) >= 6
        
        # Check WebP characteristics
        webp = RecommendationEngine.FORMAT_CHARACTERISTICS[OutputFormat.WEBP]
        assert webp.compression_efficiency == 0.9
        assert webp.browser_support == 0.85
        assert webp.features["transparency"] is True
        assert webp.features["animation"] is True
        
    def test_content_scores_defined(self, engine):
        """Test that content scores are properly defined."""
        assert len(RecommendationEngine.CONTENT_SCORES) == 4
        
        # Check photo scores
        photo_scores = RecommendationEngine.CONTENT_SCORES[ContentType.PHOTO]
        assert photo_scores[OutputFormat.AVIF] > photo_scores[OutputFormat.PNG]
        assert photo_scores[OutputFormat.JPEG] > 0.5
        
    @pytest.mark.asyncio
    async def test_generate_recommendations_basic(self, engine, sample_request):
        """Test basic recommendation generation."""
        recommendations = await engine.generate_recommendations(sample_request)
        
        assert len(recommendations) <= 3
        assert all(isinstance(r, FormatRecommendation) for r in recommendations)
        assert recommendations[0].score >= recommendations[-1].score  # Sorted by score
        
    @pytest.mark.asyncio
    async def test_generate_recommendations_photo_web(self, engine, sample_request):
        """Test recommendations for web photos."""
        recommendations = await engine.generate_recommendations(sample_request)
        
        # For web photos, WebP or AVIF should be top choices
        top_formats = [r.format for r in recommendations[:2]]
        assert any(f in [OutputFormat.WEBP, OutputFormat.AVIF] for f in top_formats)
        
        # Check reasons
        top_rec = recommendations[0]
        assert len(top_rec.reasons) > 0
        assert any("compression" in r.lower() or "browser" in r.lower() for r in top_rec.reasons)
        
    @pytest.mark.asyncio
    async def test_generate_recommendations_document_archive(self, engine):
        """Test recommendations for archival documents."""
        classification = ContentClassification(
            primary_type=ContentType.DOCUMENT,
            confidence=0.95,
            processing_time_ms=45.0,
            has_text=True,
            has_faces=False
        )
        
        request = RecommendationRequest(
            content_classification=classification,
            use_case=UseCaseType.ARCHIVE,
            original_format=InputFormat.PNG,
            original_size_kb=1000,
            prioritize="quality"
        )
        
        recommendations = await engine.generate_recommendations(request)
        
        # PNG should be highly rated for document archival
        formats = [r.format for r in recommendations]
        assert OutputFormat.PNG in formats
        
        # Find PNG recommendation
        png_rec = next(r for r in recommendations if r.format == OutputFormat.PNG)
        assert png_rec.quality_score >= 0.95  # Perfect quality
        
    def test_content_score_calculation(self, engine):
        """Test content-based scoring."""
        # Photo content
        score = engine._get_content_score(OutputFormat.AVIF, ContentType.PHOTO)
        assert score == 0.95
        
        # Document content
        score = engine._get_content_score(OutputFormat.PNG, ContentType.DOCUMENT)
        assert score == 0.95
        
        # Illustration content
        score = engine._get_content_score(OutputFormat.WEBP, ContentType.ILLUSTRATION)
        assert score == 0.95
        
    def test_use_case_score_calculation(self, engine):
        """Test use case scoring."""
        # Web use case with high browser support format
        score = engine._get_use_case_score(
            OutputFormat.JPEG,
            UseCaseType.WEB,
            None
        )
        assert score > 0.8  # JPEG has perfect browser support
        
        # Archive use case with future-proof format
        score = engine._get_use_case_score(
            OutputFormat.JPEGXL,
            UseCaseType.ARCHIVE,
            None
        )
        assert score > 0.7  # JPEG XL is future-proof
        
    def test_use_case_score_with_priority(self, engine):
        """Test use case scoring with user priority."""
        # Size priority
        score_size = engine._get_use_case_score(
            OutputFormat.AVIF,
            UseCaseType.WEB,
            "size"
        )
        
        # Quality priority
        score_quality = engine._get_use_case_score(
            OutputFormat.AVIF,
            UseCaseType.WEB,
            "quality"
        )
        
        # Different priorities should yield different scores
        assert score_size != score_quality
        
    def test_compatibility_score_calculation(self, engine):
        """Test format compatibility scoring."""
        # Same format
        score = engine._get_compatibility_score(
            OutputFormat.JPEG,
            InputFormat.JPEG
        )
        assert score == 1.0
        
        # Compatible formats
        score = engine._get_compatibility_score(
            OutputFormat.WEBP,
            InputFormat.JPEG
        )
        assert score >= 0.8
        
        # Less compatible
        score = engine._get_compatibility_score(
            OutputFormat.JPEG,
            InputFormat.PNG
        )
        assert score < 0.9
        
    @pytest.mark.asyncio
    async def test_preference_score_integration(self):
        """Test preference score callback integration."""
        # Mock preference callback
        async def mock_preference(content_type, format_option, use_case):
            if format_option == OutputFormat.WEBP:
                return 0.3  # User prefers WebP
            return 0.0
            
        engine = RecommendationEngine(preference_callback=mock_preference)
        
        classification = ContentClassification(
            primary_type=ContentType.PHOTO,
            confidence=0.9,
            processing_time_ms=50.0,
            has_text=False,
            has_faces=False
        )
        
        request = RecommendationRequest(
            content_classification=classification,
            use_case=UseCaseType.WEB,
            original_format=InputFormat.JPEG,
            original_size_kb=500
        )
        
        # Calculate scores
        webp_score = await engine._calculate_format_score(OutputFormat.WEBP, request)
        jpeg_score = await engine._calculate_format_score(OutputFormat.JPEG, request)
        
        # WebP should have higher score due to preference
        assert webp_score > jpeg_score
        
    def test_trade_off_analysis(self, engine, sample_request):
        """Test trade-off analysis generation."""
        trade_offs = engine._analyze_trade_offs(OutputFormat.AVIF, sample_request)
        
        assert 0 <= trade_offs.size_reduction <= 1
        assert 0 <= trade_offs.quality_score <= 1
        assert 0 <= trade_offs.compatibility_score <= 1
        assert 0 <= trade_offs.feature_score <= 1
        assert 0 <= trade_offs.performance_score <= 1
        
    def test_reason_generation(self, engine, sample_request):
        """Test human-readable reason generation."""
        characteristics = RecommendationEngine.FORMAT_CHARACTERISTICS[OutputFormat.AVIF]
        reasons = engine._generate_reasons(
            OutputFormat.AVIF,
            sample_request,
            characteristics
        )
        
        assert isinstance(reasons, list)
        assert len(reasons) > 0
        assert all(isinstance(r, str) and len(r) > 0 for r in reasons)
        
    def test_pros_cons_generation(self, engine, sample_request):
        """Test pros and cons generation."""
        characteristics = RecommendationEngine.FORMAT_CHARACTERISTICS[OutputFormat.WEBP]
        pros, cons = engine._generate_pros_cons(
            OutputFormat.WEBP,
            sample_request,
            characteristics
        )
        
        assert isinstance(pros, list)
        assert isinstance(cons, list)
        assert len(pros) > 0
        assert all(isinstance(p, str) for p in pros)
        assert all(isinstance(c, str) for c in cons)
        
    def test_size_estimation(self, engine):
        """Test output size estimation."""
        # Photo to AVIF (should be smaller)
        size = engine._estimate_output_size(
            OutputFormat.AVIF,
            1000,  # 1MB original
            ContentType.PHOTO
        )
        assert size < 500  # Should be less than 50%
        
        # Photo to PNG (should be larger)
        size = engine._estimate_output_size(
            OutputFormat.PNG,
            1000,
            ContentType.PHOTO
        )
        assert size > 800  # PNG inefficient for photos
        
    @pytest.mark.asyncio
    async def test_exclude_formats(self, engine, sample_request):
        """Test format exclusion."""
        # Exclude WebP and AVIF
        sample_request.exclude_formats = [OutputFormat.WEBP, OutputFormat.AVIF]
        
        recommendations = await engine.generate_recommendations(sample_request)
        
        formats = [r.format for r in recommendations]
        assert OutputFormat.WEBP not in formats
        assert OutputFormat.AVIF not in formats
        
    @pytest.mark.asyncio
    async def test_recommendation_completeness(self, engine, sample_request):
        """Test that recommendations have all required fields."""
        recommendations = await engine.generate_recommendations(sample_request)
        
        for rec in recommendations:
            assert rec.format in OutputFormat
            assert 0 <= rec.score <= 1
            assert len(rec.reasons) > 0
            assert rec.estimated_size_kb > 0
            assert 0 <= rec.quality_score <= 1
            assert 0 <= rec.compatibility_score <= 1
            assert isinstance(rec.features, dict)
            assert rec.trade_offs is not None
            assert isinstance(rec.pros, list)
            assert isinstance(rec.cons, list)
            
    def test_available_formats_filtering(self, engine):
        """Test filtering of available formats."""
        request = Mock()
        request.exclude_formats = [OutputFormat.WEBP]
        
        formats = engine._get_available_formats(request)
        
        # Should exclude optimized variants and WebP
        assert OutputFormat.PNG_OPTIMIZED not in formats
        assert OutputFormat.JPEG_OPTIMIZED not in formats
        assert OutputFormat.WEBP not in formats
        
        # Should include regular formats
        assert OutputFormat.PNG in formats
        assert OutputFormat.JPEG in formats
        assert OutputFormat.AVIF in formats