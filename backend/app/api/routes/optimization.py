"""API routes for advanced optimization features."""

import asyncio
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, File, UploadFile, Form, HTTPException, BackgroundTasks
from fastapi.responses import Response, StreamingResponse
from sse_starlette.sse import EventSourceResponse

from app.models.optimization import (
    OptimizationRequest,
    OptimizationResponse,
    OptimizationProgressUpdate,
    OptimizationMode
)
from app.core.optimization.encoding_options import ChromaSubsampling
from app.services.optimization_service import optimization_service
from app.services.format_detection_service import format_detection_service
from app.core.security.errors_simplified import SecurityErrorHandler
from app.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/optimize")

# Global timeout for optimization operations (30 seconds)
OPTIMIZATION_TIMEOUT_SECONDS = 30

# Progress tracking for SSE
optimization_progress = {}


@router.post("/advanced", response_model=OptimizationResponse)
async def optimize_advanced(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Image file to optimize"),
    output_format: str = Form(..., description="Target output format"),
    optimization_mode: str = Form("balanced", description="Optimization mode"),
    multi_pass: bool = Form(False, description="Enable multi-pass optimization"),
    target_size_kb: Optional[int] = Form(None, description="Target size in KB"),
    region_optimization: bool = Form(False, description="Enable region optimization"),
    perceptual_metrics: bool = Form(True, description="Calculate quality metrics"),
    chroma_subsampling: Optional[str] = Form(None, description="Chroma subsampling mode"),
    progressive: Optional[bool] = Form(None, description="Progressive encoding"),
    lossless: Optional[bool] = Form(None, description="Lossless compression"),
    alpha_quality: Optional[int] = Form(None, description="Alpha channel quality"),
    min_quality: int = Form(40, description="Minimum quality"),
    max_quality: int = Form(95, description="Maximum quality"),
    base_quality: int = Form(85, description="Base quality")
):
    """Perform advanced optimization on an uploaded image.
    
    This endpoint provides fine-grained control over image optimization with
    features like multi-pass optimization, region-based quality, and advanced
    encoding options.
    """
    try:
        # Read file data
        file_data = await file.read()
        
        # Detect format
        detected_format, _ = await format_detection_service.detect_format(file_data)
        if not detected_format:
            raise HTTPException(status_code=400, detail="Unsupported or corrupted file format")
        
        # Parse optimization mode
        try:
            mode = OptimizationMode(optimization_mode)
        except ValueError:
            mode = OptimizationMode.BALANCED
            
        # Parse chroma subsampling
        chroma = None
        if chroma_subsampling:
            try:
                chroma = ChromaSubsampling(chroma_subsampling)
            except ValueError:
                chroma = ChromaSubsampling.AUTO
        
        # Create request model
        request = OptimizationRequest(
            output_format=output_format,
            optimization_mode=mode,
            multi_pass=multi_pass,
            target_size_kb=target_size_kb,
            region_optimization=region_optimization,
            perceptual_metrics=perceptual_metrics,
            chroma_subsampling=chroma,
            progressive=progressive,
            lossless=lossless,
            alpha_quality=alpha_quality,
            min_quality=min_quality,
            max_quality=max_quality,
            base_quality=base_quality
        )
        
        # Perform optimization with timeout
        try:
            response = await asyncio.wait_for(
                optimization_service.optimize_image(
                    file_data,
                    request,
                    detected_format
                ),
                timeout=OPTIMIZATION_TIMEOUT_SECONDS
            )
            
            return response
            
        except asyncio.TimeoutError:
            logger.warning(f"Optimization timeout after {OPTIMIZATION_TIMEOUT_SECONDS}s")
            raise HTTPException(
                status_code=504,
                detail=f"Optimization timeout after {OPTIMIZATION_TIMEOUT_SECONDS} seconds"
            )
        
    except Exception as e:
        if isinstance(e, HTTPException):
            raise  # Re-raise HTTP exceptions as-is
        error_info = SecurityErrorHandler.handle_error(e)
        raise HTTPException(
            status_code=500,
            detail=error_info.get("message", "Internal server error")
        )


@router.post("/advanced/download")
async def optimize_advanced_download(
    file: UploadFile = File(..., description="Image file to optimize"),
    output_format: str = Form(..., description="Target output format"),
    optimization_mode: str = Form("balanced", description="Optimization mode"),
    multi_pass: bool = Form(False, description="Enable multi-pass optimization"),
    target_size_kb: Optional[int] = Form(None, description="Target size in KB"),
    region_optimization: bool = Form(False, description="Enable region optimization"),
    lossless: Optional[bool] = Form(None, description="Lossless compression"),
    base_quality: int = Form(85, description="Base quality")
):
    """Optimize and directly download the result.
    
    Similar to /advanced but returns the optimized image directly for download.
    """
    try:
        # Read file data
        file_data = await file.read()
        
        # Detect format
        detected_format, _ = await format_detection_service.detect_format(file_data)
        if not detected_format:
            raise HTTPException(status_code=400, detail="Unsupported or corrupted file format")
        
        # Parse optimization mode
        try:
            mode = OptimizationMode(optimization_mode)
        except ValueError:
            mode = OptimizationMode.BALANCED
        
        # Create simplified request
        request = OptimizationRequest(
            output_format=output_format,
            optimization_mode=mode,
            multi_pass=multi_pass,
            target_size_kb=target_size_kb,
            region_optimization=region_optimization,
            perceptual_metrics=False,  # Skip metrics for download
            lossless=lossless,
            base_quality=base_quality
        )
        
        # Get conversion service
        from app.services.conversion_service import conversion_service
        
        # Set conversion service if not already set
        if optimization_service.conversion_func is None:
            optimization_service.set_conversion_service(conversion_service)
        
        # Perform optimization and get data with timeout
        try:
            response, optimized_data = await asyncio.wait_for(
                optimization_service.optimize_and_get_data(
                    file_data,
                    request,
                    detected_format
                ),
                timeout=OPTIMIZATION_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            logger.warning(f"Optimization timeout after {OPTIMIZATION_TIMEOUT_SECONDS}s")
            raise HTTPException(
                status_code=504,
                detail=f"Optimization timeout after {OPTIMIZATION_TIMEOUT_SECONDS} seconds"
            )
        
        if not response.success or not optimized_data:
            raise HTTPException(status_code=500, detail=response.error_message or "Optimization failed")
        
        # Return optimized image
        return Response(
            content=optimized_data,
            media_type=f"image/{output_format.lower()}",
            headers={
                "Content-Disposition": f"attachment; filename=optimized.{output_format.lower()}"
            }
        )
        
    except Exception as e:
        if isinstance(e, HTTPException):
            raise  # Re-raise HTTP exceptions as-is
        error_info = SecurityErrorHandler.handle_error(e)
        raise HTTPException(
            status_code=500,
            detail=error_info.get("message", "Internal server error")
        )


@router.get("/progress/{conversion_id}")
async def optimization_progress_stream(conversion_id: UUID):
    """Stream optimization progress updates via Server-Sent Events.
    
    Connect to this endpoint to receive real-time updates during
    multi-pass optimization.
    """
    async def event_generator():
        """Generate SSE events for optimization progress."""
        while True:
            # Check if optimization is in progress
            if str(conversion_id) in optimization_progress:
                update = optimization_progress[str(conversion_id)]
                yield {
                    "event": "progress",
                    "data": update.json()
                }
                
                # Remove if completed
                if update.status in ["completed", "failed"]:
                    del optimization_progress[str(conversion_id)]
                    break
                    
            await asyncio.sleep(0.5)
    
    return EventSourceResponse(event_generator())


@router.post("/analyze")
async def analyze_optimization_potential(
    file: UploadFile = File(..., description="Image file to analyze"),
    output_format: str = Form(..., description="Target output format")
):
    """Analyze optimization potential for an image.
    
    Returns analysis of potential optimizations including alpha channel usage,
    compression estimates, and format-specific recommendations.
    """
    try:
        # Read file data
        file_data = await file.read()
        
        # Analyze optimization potential with timeout
        try:
            analysis = await asyncio.wait_for(
                optimization_service.analyze_optimization_potential(
                    file_data,
                    output_format
                ),
                timeout=OPTIMIZATION_TIMEOUT_SECONDS
            )
            
            return analysis
            
        except asyncio.TimeoutError:
            logger.warning(f"Analysis timeout after {OPTIMIZATION_TIMEOUT_SECONDS}s")
            raise HTTPException(
                status_code=504,
                detail=f"Analysis timeout after {OPTIMIZATION_TIMEOUT_SECONDS} seconds"
            )
        
    except Exception as e:
        if isinstance(e, HTTPException):
            raise  # Re-raise HTTP exceptions as-is
        error_info = SecurityErrorHandler.handle_error(e)
        raise HTTPException(
            status_code=500,
            detail=error_info.get("message", "Internal server error")
        )


@router.get("/capabilities/{format}")
async def get_format_capabilities(format: str):
    """Get optimization capabilities for a specific format.
    
    Returns detailed information about what optimization features
    are available for the specified image format.
    """
    format = format.lower()
    
    # Get encoding capabilities
    encoding_caps = optimization_service.encoding_options.get_format_capabilities(format)
    if not encoding_caps:
        raise HTTPException(status_code=404, detail=f"Format '{format}' not supported")
    
    # Get lossless capabilities
    lossless_caps = optimization_service.lossless_compressor.get_format_capabilities(format)
    
    return {
        "format": format,
        "encoding_options": encoding_caps,
        "lossless_compression": lossless_caps,
        "supports_alpha": encoding_caps.get("alpha", False),
        "supports_progressive": encoding_caps.get("progressive", False),
        "supports_lossless": lossless_caps.get("native", False),
        "supports_chroma_subsampling": encoding_caps.get("chroma_subsampling", False)
    }