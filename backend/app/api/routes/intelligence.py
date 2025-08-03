"""API routes for image intelligence and analysis."""

from fastapi import APIRouter, File, UploadFile, Query, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional
import logging

from app.services.intelligence_service import intelligence_service
from app.models.conversion import ContentType, ContentClassification
from app.core.constants import MAX_FILE_SIZE

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
                detail=f"File size exceeds maximum allowed size of {MAX_FILE_SIZE / 1024 / 1024:.1f}MB"
            )
        
        # Validate file is an image
        if not file.content_type or not file.content_type.startswith("image/"):
            raise HTTPException(
                status_code=400,
                detail="File must be an image"
            )
        
        # Analyze image
        classification = await intelligence_service.analyze_image(
            contents,
            debug=debug
        )
        
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
                        "confidence": r.confidence
                    }
                    for r in (classification.text_regions or [])
                ],
                "face_regions": [
                    {
                        "x": r.x,
                        "y": r.y,
                        "width": r.width,
                        "height": r.height,
                        "confidence": r.confidence
                    }
                    for r in (classification.face_regions or [])
                ]
            }
        
        return JSONResponse(
            content=response_data,
            status_code=200
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Image analysis failed: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to analyze image"
        )


@router.get("/recommendations/{content_type}/{target_format}")
async def get_optimization_recommendations(
    content_type: ContentType,
    target_format: str
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
            content_type,
            target_format
        )
        
        return JSONResponse(
            content=recommendations,
            status_code=200
        )
        
    except Exception as e:
        logger.error(f"Failed to get recommendations: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get optimization recommendations"
        )


@router.get("/status")
async def get_intelligence_status() -> JSONResponse:
    """Get intelligence service status.
    
    Returns:
        JSON response with service status
    """
    try:
        status = await intelligence_service.get_status()
        
        return JSONResponse(
            content=status,
            status_code=200
        )
        
    except Exception as e:
        logger.error(f"Failed to get intelligence status: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get service status"
        )


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
            status_code=200
        )
        
    except Exception as e:
        logger.error(f"Failed to clear intelligence cache: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to clear cache"
        )