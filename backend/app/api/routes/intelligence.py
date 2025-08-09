"""API routes for image intelligence and analysis."""

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, Body, File, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse

from app.core.constants import MAX_FILE_SIZE
from app.models.conversion import (
    ContentClassification,
    ContentType,
    InputFormat,
    OutputFormat,
)
from app.models.recommendation import RecommendationRequest, UseCaseType
from app.services.intelligence_service import intelligence_service
from app.services.recommendation_service import recommendation_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/intelligence", tags=["intelligence"])


@router.post("/analyze")
async def analyze_image(
    file: UploadFile = File(..., description="Image file to analyze"),
    debug: bool = Query(False, description="Include debug information"),
) -> JSONResponse:
    """Analyze image content and detect type using ML models.

    This endpoint performs intelligent content detection to identify:
    - Content type (photo, screenshot, document, illustration)
    - Confidence score
    - Text regions (if any)
    - Face regions (if any)
    - Processing time
    - Additional metadata

    Args:
        file: Image file to analyze
        debug: Include detailed debug information

    Returns:
        JSON response with classification results
    """
    try:
        # Validate file size
        contents = await file.read()
        if len(contents) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File size exceeds maximum allowed size of {MAX_FILE_SIZE / 1024 / 1024:.1f}MB",
            )

        # Validate file is an image
        if not file.content_type or not file.content_type.startswith("image/"):
            raise HTTPException(status_code=400, detail="File must be an image")

        # Analyze image
        classification = await intelligence_service.analyze_image(contents, debug=debug)

        # Prepare response
        response_data = {
            "content_type": classification.primary_type.value,
            "confidence": classification.confidence,
            "processing_time_ms": classification.processing_time_ms,
            "has_text": classification.has_text,
            "has_faces": classification.has_faces,
        }

        # Add optional fields if available
        if classification.secondary_types:
            response_data["secondary_types"] = [
                {"type": t.value, "confidence": c}
                for t, c in classification.secondary_types
            ]

        if classification.complexity_score is not None:
            response_data["complexity_score"] = classification.complexity_score

        if classification.dominant_colors:
            response_data["dominant_colors"] = classification.dominant_colors

        # Add debug information if requested
        if debug:
            response_data["debug_info"] = {
                "mixed_content": classification.mixed_content,
                "text_coverage": classification.text_coverage,
                "text_regions": [
                    {
                        "x": r.x,
                        "y": r.y,
                        "width": r.width,
                        "height": r.height,
                        "confidence": r.confidence,
                    }
                    for r in (classification.text_regions or [])
                ],
                "face_regions": [
                    {
                        "x": r.x,
                        "y": r.y,
                        "width": r.width,
                        "height": r.height,
                        "confidence": r.confidence,
                    }
                    for r in (classification.face_regions or [])
                ],
            }

        return JSONResponse(content=response_data, status_code=200)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Image analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze image")


@router.get("/recommendations/{content_type}/{target_format}")
async def get_optimization_recommendations(
    content_type: ContentType, target_format: str
) -> JSONResponse:
    """Get optimization recommendations for a specific content type and format.

    Args:
        content_type: Detected content type
        target_format: Target output format

    Returns:
        JSON response with recommended settings
    """
    try:
        recommendations = await intelligence_service.get_optimization_recommendations(
            content_type, target_format
        )

        return JSONResponse(content=recommendations, status_code=200)

    except Exception as e:
        logger.error(f"Failed to get recommendations: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to get optimization recommendations"
        )


@router.get("/status")
async def get_intelligence_status() -> JSONResponse:
    """Get intelligence service status.

    Returns:
        JSON response with service status
    """
    try:
        status = await intelligence_service.get_status()

        return JSONResponse(content=status, status_code=200)

    except Exception as e:
        logger.error(f"Failed to get intelligence status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get service status")


@router.post("/cache/clear")
async def clear_intelligence_cache() -> JSONResponse:
    """Clear the intelligence service cache.

    Returns:
        JSON response confirming cache cleared
    """
    try:
        await intelligence_service.clear_cache()

        return JSONResponse(
            content={"message": "Intelligence cache cleared successfully"},
            status_code=200,
        )

    except Exception as e:
        logger.error(f"Failed to clear intelligence cache: {e}")
        raise HTTPException(status_code=500, detail="Failed to clear cache")


@router.post("/recommend")
async def get_format_recommendations(
    content_classification: ContentClassification = Body(
        ..., description="Content classification from analysis"
    ),
    original_format: InputFormat = Body(..., description="Original image format"),
    original_size_kb: int = Body(
        ..., gt=0, le=102400, description="Original file size in KB (max 100MB)"
    ),
    use_case: Optional[UseCaseType] = Body(None, description="Intended use case"),
    prioritize: Optional[str] = Body(
        None,
        regex="^(size|quality|compatibility)$",
        description="What to prioritize: size/quality/compatibility",
    ),
    exclude_formats: Optional[List[OutputFormat]] = Body(
        None, description="Formats to exclude"
    ),
    override_format: Optional[OutputFormat] = Body(
        None, description="User override format choice"
    ),
) -> JSONResponse:
    """Get intelligent format recommendations based on content and use case.

    This endpoint provides:
    - Top 3 format recommendations with scores
    - Detailed reasons for each recommendation
    - Size and quality predictions
    - Trade-off analysis
    - Format comparison matrix

    Args:
        content_classification: Classification result from /analyze endpoint
        original_format: Format of the source image
        original_size_kb: Size of the source image in KB
        use_case: Optional[Any] use case (web/print/archive)
        prioritize: Optional[Any] priority (size/quality/compatibility)
        exclude_formats: Optional[Any] list of formats to exclude
        override_format: Optional[Any] user-selected format override

    Returns:
        JSON response with format recommendations
    """
    try:
        # Create recommendation request
        request = RecommendationRequest(
            content_classification=content_classification,
            use_case=use_case,
            original_format=original_format,
            original_size_kb=original_size_kb,
            prioritize=prioritize,
            exclude_formats=exclude_formats or [],
        )

        # Get recommendations
        response = await recommendation_service.get_recommendations(
            request, override_format=override_format
        )

        # Convert to dict for JSON response
        response_data = {
            "recommendations": [
                {
                    "format": rec.format.value,
                    "score": rec.score,
                    "reasons": rec.reasons,
                    "estimated_size_kb": rec.estimated_size_kb,
                    "quality_score": rec.quality_score,
                    "compatibility_score": rec.compatibility_score,
                    "features": rec.features,
                    "trade_offs": rec.trade_offs.dict(),
                    "pros": rec.pros,
                    "cons": rec.cons,
                }
                for rec in response.recommendations
            ],
            "comparison_matrix": response.comparison_matrix,
            "content_type": response.content_type,
            "use_case": response.use_case,
            "processing_time_ms": response.processing_time_ms,
        }

        return JSONResponse(content=response_data, status_code=200)

    except Exception as e:
        logger.error(f"Failed to generate recommendations: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to generate format recommendations"
        )


@router.post("/preferences/record")
async def record_format_preference(
    content_type: ContentType = Body(..., description="Content type"),
    chosen_format: OutputFormat = Body(..., description="Format chosen by user"),
    use_case: Optional[UseCaseType] = Body(None, description="Use case context"),
    was_override: bool = Body(False, description="Whether this was an override"),
) -> JSONResponse:
    """Record user's format choice for learning.

    Args:
        content_type: Type of content
        chosen_format: Format chosen by user
        use_case: Optional[Any] use case context
        was_override: Whether user overrode recommendations

    Returns:
        JSON response confirming preference recorded
    """
    try:
        await recommendation_service.record_user_choice(
            content_type, chosen_format, use_case, was_override
        )

        return JSONResponse(
            content={"message": "Preference recorded successfully"}, status_code=200
        )

    except Exception as e:
        logger.error(f"Failed to record preference: {e}")
        raise HTTPException(status_code=500, detail="Failed to record preference")


@router.get("/preferences/{content_type}")
async def get_format_preferences(
    content_type: ContentType,
    use_case: Optional[UseCaseType] = Query(
        None, description="Optional use case filter"
    ),
) -> JSONResponse:
    """Get user's format preferences for content type.

    Args:
        content_type: Type of content
        use_case: Optional[Any] use case filter

    Returns:
        JSON response with format preferences
    """
    try:
        preferences = await recommendation_service.get_user_preferences(
            content_type, use_case
        )

        return JSONResponse(
            content={
                "content_type": content_type.value,
                "use_case": use_case.value if use_case else None,
                "preferences": preferences,
            },
            status_code=200,
        )

    except Exception as e:
        logger.error(f"Failed to get preferences: {e}")
        raise HTTPException(status_code=500, detail="Failed to get preferences")


@router.post("/preferences/reset")
async def reset_format_preferences(
    content_type: Optional[ContentType] = Body(
        None, description="Content type to reset"
    ),
    format_option: Optional[OutputFormat] = Body(None, description="Format to reset"),
) -> JSONResponse:
    """Reset user format preferences.

    Args:
        content_type: Optional[Any] content type to reset (all if None)
        format_option: Optional[Any] format to reset (all if None)

    Returns:
        JSON response with reset count
    """
    try:
        count = await recommendation_service.reset_preferences(
            content_type, format_option
        )

        return JSONResponse(
            content={"message": f"Reset {count} preferences", "count": count},
            status_code=200,
        )

    except Exception as e:
        logger.error(f"Failed to reset preferences: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset preferences")


@router.get("/formats/{format}/details")
async def get_format_details(
    format: OutputFormat,
    content_type: ContentType = Query(..., description="Content type for context"),
) -> JSONResponse:
    """Get detailed information about a specific format.

    Args:
        format: Output format to get details for
        content_type: Content type for suitability context

    Returns:
        JSON response with format details
    """
    try:
        details = await recommendation_service.get_format_details(format, content_type)

        return JSONResponse(content=details, status_code=200)

    except Exception as e:
        logger.error(f"Failed to get format details: {e}")
        raise HTTPException(status_code=500, detail="Failed to get format details")
