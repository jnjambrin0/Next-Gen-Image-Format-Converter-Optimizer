"""Format detection and analysis API endpoints."""

import asyncio
from typing import Optional
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from fastapi.responses import JSONResponse
import structlog

from app.models.responses import (
    FormatDetectionResponse,
    FormatRecommendationResponse,
    FormatCompatibilityResponse,
    FormatCompatibilityMatrix,
    FormatRecommendation,
    ErrorResponse,
)
from app.services.format_detection_service import format_detection_service
from app.services.recommendation_service import recommendation_service
from app.services.intelligence_service import intelligence_service
from app.config import settings
from app.core.exceptions import ValidationError, SecurityError
from app.api.utils.validation import (
    validate_uploaded_file,
    secure_memory_clear,
    SemaphoreContextManager,
    validate_content_type,
)
from app.core.constants import FORMAT_TO_MIME_TYPE, SUPPORTED_INPUT_FORMATS, SUPPORTED_OUTPUT_FORMATS

logger = structlog.get_logger()

router = APIRouter(prefix="/detection", tags=["detection"])

# Semaphore for concurrent request limiting
detection_semaphore = asyncio.Semaphore(settings.max_concurrent_conversions)


@router.post(
    "/detect-format",
    response_model=FormatDetectionResponse,
    responses={
        200: {"model": FormatDetectionResponse, "description": "Format detected successfully"},
        400: {"model": ErrorResponse, "description": "Bad Request"},
        413: {"model": ErrorResponse, "description": "Payload Too Large"},
        422: {"model": ErrorResponse, "description": "Validation Error"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
        503: {"model": ErrorResponse, "description": "Service Unavailable"},
    },
    summary="Detect image format from uploaded file",
    description="""
    Detect the actual image format from file content, regardless of file extension.
    
    This endpoint uses advanced format detection techniques including:
    - Magic byte analysis
    - Content structure validation
    - Format-specific header parsing
    
    The detection is more reliable than relying on file extensions, which can be misleading.
    
    **Parameters:**
    - **file**: Image file to analyze (multipart/form-data)
    
    **Returns:**
    - Detected format with confidence score
    - Original file extension (if any)
    - MIME type information
    - Additional format-specific details
    """,
)
async def detect_format(
    request: Request,
    file: UploadFile = File(..., description="Image file to analyze"),
):
    """Detect the format of an uploaded image file."""
    # Validate content type
    if not validate_content_type(file):
        raise HTTPException(
            status_code=415,
            detail={
                "error_code": "DET415",
                "message": "Unsupported media type. Please upload a valid image file.",
                "correlation_id": request.state.correlation_id,
            },
        )
    
    contents = None
    async with SemaphoreContextManager(
        detection_semaphore, 0.01, "DET503", "Detection service", request
    ):
        try:
            # Validate and read file
            contents, file_size = await validate_uploaded_file(
                file, request, error_prefix="DET"
            )

            # Extract file extension if available
            file_extension = None
            if file.filename:
                file_extension = Path(file.filename).suffix.lower().lstrip(".")

            # Perform format detection
            detected_format, confidence = await format_detection_service.detect_format(contents)

            if not detected_format:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error_code": "DET422",
                        "message": "Unable to detect image format. The file may be corrupted or in an unsupported format.",
                        "correlation_id": request.state.correlation_id,
                    },
                )

            # Get additional format details
            format_details = {}
            try:
                # Import PIL here to avoid import errors and improve startup time
                from PIL import Image
                from io import BytesIO
                
                # Try to get more detailed format information
                with Image.open(BytesIO(contents)) as img:
                    format_details = {
                        "dimensions": {"width": img.width, "height": img.height},
                        "mode": img.mode,
                        "has_transparency": img.mode in ("RGBA", "LA", "P") and "transparency" in img.info,
                        "animated": getattr(img, "is_animated", False),
                    }
                    
                    # Add format-specific details
                    if img.format:
                        format_details["pil_format"] = img.format
                        
            except Exception as e:
                logger.warning(
                    "Failed to extract detailed format information",
                    error=str(e),
                    correlation_id=request.state.correlation_id,
                )

            # Determine MIME type from centralized constants
            mime_type = FORMAT_TO_MIME_TYPE.get(detected_format.lower())

            logger.info(
                "Format detection completed",
                detected_format=detected_format,
                confidence=confidence,
                file_extension=file_extension,
                file_size=file_size,
                correlation_id=request.state.correlation_id,
            )

            return FormatDetectionResponse(
                detected_format=detected_format,
                confidence=confidence,
                file_extension=file_extension,
                mime_type=mime_type,
                format_details=format_details,
            )

        except HTTPException:
            # Re-raise HTTP exceptions
            raise

        except Exception as e:
            logger.exception(
                "Unexpected error during format detection",
                error=str(e),
                correlation_id=request.state.correlation_id,
            )
            raise HTTPException(
                status_code=500,
                detail={
                    "error_code": "DET500",
                    "message": "An unexpected error occurred during format detection",
                    "correlation_id": request.state.correlation_id,
                },
            )

        finally:
            # Clear sensitive data from memory using secure pattern
            secure_memory_clear(contents)


@router.post(
    "/recommend-format",
    response_model=FormatRecommendationResponse,
    responses={
        200: {"model": FormatRecommendationResponse, "description": "Recommendations generated successfully"},
        400: {"model": ErrorResponse, "description": "Bad Request"},
        413: {"model": ErrorResponse, "description": "Payload Too Large"},
        422: {"model": ErrorResponse, "description": "Validation Error"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
        503: {"model": ErrorResponse, "description": "Service Unavailable"},
    },
    summary="Get format recommendations based on image content",
    description="""
    Analyze an image and provide intelligent format recommendations based on:
    - Content type detection (photo, illustration, screenshot, document)
    - Image characteristics (transparency, animation, dimensions)
    - Compression efficiency predictions
    - Quality preservation analysis
    
    The recommendations are ranked by score and include detailed reasoning.
    
    **Parameters:**
    - **file**: Image file to analyze (multipart/form-data)
    
    **Returns:**
    - Input format and content type
    - Ranked list of recommended output formats
    - Reasoning and estimated impact for each recommendation
    """,
)
async def recommend_format(
    request: Request,
    file: UploadFile = File(..., description="Image file to analyze for recommendations"),
):
    """Get format recommendations based on image content analysis."""
    # Validate content type
    if not validate_content_type(file):
        raise HTTPException(
            status_code=415,
            detail={
                "error_code": "REC415",
                "message": "Unsupported media type. Please upload a valid image file.",
                "correlation_id": request.state.correlation_id,
            },
        )
    
    contents = None
    async with SemaphoreContextManager(
        detection_semaphore, 0.01, "REC503", "Recommendation service", request
    ):
        try:
            # Validate and read file
            contents, file_size = await validate_uploaded_file(
                file, request, error_prefix="REC"
            )

            # Detect input format first
            detected_format, confidence = await format_detection_service.detect_format(contents)

            if not detected_format:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error_code": "REC422",
                        "message": "Unable to detect input format for analysis",
                        "correlation_id": request.state.correlation_id,
                    },
                )

            # Perform content analysis using intelligence engine
            try:
                classification = await intelligence_service.classify_content(contents)
                content_type = classification.content_type
            except Exception as e:
                logger.warning(
                    "Content classification failed, using fallback",
                    error=str(e),
                    correlation_id=request.state.correlation_id,
                )
                content_type = "photo"  # Default fallback

            # Get recommendations from recommendation service
            recommendations_data = await recommendation_service.get_recommendations(
                contents, detected_format, content_type
            )

            # Convert to response format
            recommendations = []
            for rec in recommendations_data.get("recommendations", []):
                reasons = rec.get("reasons", [])
                
                # Determine quality impact
                quality_score = rec.get("quality_score", 0.8)
                if quality_score >= 0.9:
                    quality_impact = "Excellent - Near lossless quality"
                elif quality_score >= 0.8:
                    quality_impact = "Very Good - Minimal quality loss"
                elif quality_score >= 0.7:
                    quality_impact = "Good - Acceptable quality trade-off"
                elif quality_score >= 0.6:
                    quality_impact = "Fair - Noticeable quality reduction"  
                else:
                    quality_impact = "Poor - Significant quality loss"

                recommendations.append(
                    FormatRecommendation(
                        format=rec["format"],
                        score=rec["score"],
                        reasons=reasons,
                        estimated_compression=rec.get("estimated_compression"),
                        quality_impact=quality_impact,
                    )
                )

            logger.info(
                "Format recommendations completed",
                input_format=detected_format,
                content_type=content_type,
                num_recommendations=len(recommendations),
                correlation_id=request.state.correlation_id,
            )

            return FormatRecommendationResponse(
                input_format=detected_format,
                content_type=content_type,
                recommendations=recommendations,
                analysis_details={
                    "file_size": file_size,
                    "detection_confidence": confidence,
                    "analysis_version": "1.0",
                },
            )

        except HTTPException:
            # Re-raise HTTP exceptions
            raise

        except Exception as e:
            logger.exception(
                "Unexpected error during format recommendation",
                error=str(e),
                correlation_id=request.state.correlation_id,
            )
            raise HTTPException(
                status_code=500,
                detail={
                    "error_code": "REC500",
                    "message": "An unexpected error occurred during format recommendation",
                    "correlation_id": request.state.correlation_id,
                },
            )

        finally:
            # Clear sensitive data from memory using secure pattern
            secure_memory_clear(contents)


@router.get(
    "/formats/compatibility",
    response_model=FormatCompatibilityResponse,
    responses={
        200: {"model": FormatCompatibilityResponse, "description": "Compatibility matrix retrieved"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Get format compatibility matrix",
    description="""
    Returns a comprehensive matrix showing which input formats can be converted to which output formats.
    
    This endpoint provides:
    - Complete compatibility matrix for all supported formats
    - List of all supported input and output formats
    - Known limitations or restrictions for specific format pairs
    
    This information is useful for:
    - Building format selection UIs
    - Validating conversion requests
    - Understanding format capabilities
    """,
)
async def get_format_compatibility(request: Request):
    """Get the format compatibility matrix."""
    try:
        # Use centralized format constants
        supported_input_formats = list(SUPPORTED_INPUT_FORMATS)
        
        # Filter output formats to only include main formats, not optimized variants
        supported_output_formats = [
            fmt for fmt in SUPPORTED_OUTPUT_FORMATS 
            if not fmt.endswith('_optimized') and fmt not in ['jpg', 'tif', 'jpegxl', 'jpeg_xl', 'jpeg2000']
        ]

        # Build compatibility matrix
        compatibility_matrix = []
        
        for input_format in supported_input_formats:
            limitations = []
            compatible_outputs = supported_output_formats.copy()
            
            # Add format-specific limitations
            if input_format == "gif":
                limitations.append("Animation support varies by output format")
                limitations.append("WebP and AVIF preserve animation, others use first frame")
            
            if input_format in ["heif", "heic"]:
                limitations.append("Requires compatible system codecs")
                
            if input_format == "tiff":
                limitations.append("Multi-page TIFF uses first page only")
            
            compatibility_matrix.append(
                FormatCompatibilityMatrix(
                    input_format=input_format,
                    output_formats=compatible_outputs,
                    limitations=limitations if limitations else None,
                )
            )

        logger.info(
            "Format compatibility matrix requested",
            correlation_id=request.state.correlation_id,
        )

        return FormatCompatibilityResponse(
            compatibility_matrix=compatibility_matrix,
            supported_input_formats=supported_input_formats,
            supported_output_formats=supported_output_formats,
        )

    except Exception as e:
        logger.exception(
            "Error retrieving format compatibility matrix",
            error=str(e),
            correlation_id=request.state.correlation_id,
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error_code": "COMP500",
                "message": "An unexpected error occurred while retrieving compatibility information",
                "correlation_id": request.state.correlation_id,
            },
        )