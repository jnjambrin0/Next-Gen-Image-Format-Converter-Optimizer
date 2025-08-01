"""Conversion API endpoints."""

import asyncio
from typing import Optional
from pathlib import Path
import os

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Response, Request
from fastapi.responses import StreamingResponse
import structlog

from app.core.exceptions import (
    ConversionError,
    InvalidImageError,
    UnsupportedFormatError,
    ConversionFailedError,
)
from app.models.conversion import OutputFormat, ConversionSettings
from app.models.requests import ConversionApiRequest
from app.models.responses import ConversionApiResponse, ErrorResponse
from app.services.conversion_service import ConversionService
from app.config import settings

logger = structlog.get_logger()

router = APIRouter()

# Initialize conversion service
conversion_service = ConversionService()

# Semaphore for concurrent request limiting
conversion_semaphore = asyncio.Semaphore(settings.max_concurrent_conversions)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal attacks.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove any path separators (both Unix and Windows)
    # Split by both forward and backslashes and take the last part
    for sep in ['/', '\\']:
        parts = filename.split(sep)
        filename = parts[-1]
    
    # Remove any null bytes
    filename = filename.replace('\x00', '')
    
    # Remove any non-printable characters
    filename = ''.join(char for char in filename if char.isprintable())
    
    # Remove any remaining path traversal sequences
    filename = filename.replace('..', '')
    
    # Ensure filename is not empty after sanitization
    if not filename or filename == '.':
        filename = 'unnamed'
    
    # Add extension if missing
    if '.' not in filename:
        filename = filename + '.bin'
    
    # Limit length
    max_length = 255
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        # Preserve extension but truncate name
        filename = name[:max_length - len(ext)] + ext
    
    return filename


@router.post(
    "/convert",
    response_model=None,
    responses={
        200: {
            "description": "Converted image binary data",
            "content": {
                "image/webp": {},
                "image/avif": {},
                "image/jpeg": {},
                "image/png": {},
            },
        },
        400: {"model": ErrorResponse, "description": "Bad Request"},
        413: {"model": ErrorResponse, "description": "Payload Too Large"},
        415: {"model": ErrorResponse, "description": "Unsupported Media Type"},
        422: {"model": ErrorResponse, "description": "Validation Error"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
        503: {"model": ErrorResponse, "description": "Service Unavailable"},
    },
    summary="Convert an image to a different format",
    description="""
    Convert an uploaded image to a different format with optional quality and metadata settings.
    
    - **file**: The image file to convert (multipart/form-data)
    - **output_format**: Target format (webp, avif, etc.)
    - **quality**: Optional quality setting (1-100, default: 85)
    - **strip_metadata**: Remove EXIF and other metadata (default: true)
    - **preserve_metadata**: Preserve non-GPS metadata (overrides strip_metadata, default: false)
    - **preserve_gps**: Preserve GPS location data (only if preserve_metadata is true, default: false)
    
    By default, all metadata including GPS data is removed for privacy. 
    To keep metadata but remove GPS, set preserve_metadata=true and preserve_gps=false.
    """,
)
async def convert_image(
    request: Request,
    file: UploadFile = File(..., description="Image file to convert"),
    output_format: OutputFormat = Form(..., description="Target image format"),
    quality: Optional[int] = Form(
        85, ge=1, le=100, description="Output quality (1-100)"
    ),
    strip_metadata: Optional[bool] = Form(
        True, description="Remove EXIF and other metadata (default: true)"
    ),
    preserve_metadata: Optional[bool] = Form(
        False, description="Preserve non-GPS metadata (overrides strip_metadata)"
    ),
    preserve_gps: Optional[bool] = Form(
        False, description="Preserve GPS location data (only if preserve_metadata is true)"
    ),
):
    """Convert an image to a different format."""
    # Try to acquire semaphore without blocking using timeout
    try:
        await asyncio.wait_for(conversion_semaphore.acquire(), timeout=0.01)
    except asyncio.TimeoutError:
        logger.warning("Conversion service at capacity")
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "CONV251",
                "message": "Service temporarily unavailable due to high load",
                "correlation_id": request.state.correlation_id,
            },
        )

    try:
        # Log conversion request
        logger.info(
            "Conversion request received",
            filename=file.filename,
            content_type=file.content_type,
            output_format=output_format,
            quality=quality,
            correlation_id=request.state.correlation_id,
        )

        # Validate file size
        file_size = 0
        contents = await file.read()
        file_size = len(contents)

        if file_size == 0:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error_code": "CONV201",
                        "message": "Empty file uploaded",
                        "correlation_id": request.state.correlation_id,
                    },
                )

        if file_size > settings.max_file_size:
                raise HTTPException(
                    status_code=413,
                    detail={
                        "error_code": "CONV202",
                        "message": f"File size exceeds maximum allowed size of {settings.max_file_size / 1024 / 1024}MB",
                        "correlation_id": request.state.correlation_id,
                        "details": {
                            "file_size": file_size,
                            "max_size": settings.max_file_size,
                        },
                    },
                )

        # Extract file format from filename
        if not file.filename:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error_code": "CONV203",
                        "message": "Filename is required",
                        "correlation_id": request.state.correlation_id,
                    },
                )

        # Sanitize filename to prevent path traversal
        safe_filename = sanitize_filename(file.filename)
        file_ext = Path(safe_filename).suffix.lower().lstrip(".")
        if not file_ext:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error_code": "CONV204",
                        "message": "Cannot determine file format from filename",
                        "correlation_id": request.state.correlation_id,
                    },
                )

        # Create conversion request
        conversion_request = ConversionApiRequest(
                filename=safe_filename,
                input_format=file_ext,
                output_format=output_format,
                settings=ConversionSettings(
                    quality=quality,
                    strip_metadata=strip_metadata,
                    preserve_metadata=preserve_metadata,
                    preserve_gps=preserve_gps,
                    optimize=True,
                ),
            )

        # Perform conversion
        result, output_data = await conversion_service.convert(
                contents, conversion_request
            )

        if not output_data:
                raise HTTPException(
                    status_code=500,
                    detail={
                        "error_code": "CONV299",
                        "message": "Conversion failed to produce output",
                        "correlation_id": request.state.correlation_id,
                    },
                )

        # Determine content type
        content_type_map = {
                "webp": "image/webp",
                "avif": "image/avif",
                "jpeg": "image/jpeg",
                "jpg": "image/jpeg",
                "png": "image/png",
                "heif": "image/heif",
                "jpegxl": "image/jxl",
                "jxl": "image/jxl",
                "webp2": "image/webp2",
                "jp2": "image/jp2",
            }
        content_type = content_type_map.get(
                output_format.lower(), "application/octet-stream"
            )

        # Generate output filename
        base_name = Path(safe_filename).stem
        output_filename = f"{base_name}.{output_format.lower()}"

        # Log successful conversion
        logger.info(
                "Conversion completed",
                input_size=file_size,
                output_size=len(output_data),
                compression_ratio=round(len(output_data) / file_size, 3),
                processing_time=result.processing_time,
                metadata_removed=result.metadata_removed,
                correlation_id=request.state.correlation_id,
            )

        # Return binary response
        return Response(
                content=output_data,
                media_type=content_type,
                headers={
                    "Content-Disposition": f'attachment; filename="{output_filename}"',
                    "X-Conversion-Id": result.id,
                    "X-Processing-Time": str(result.processing_time),
                    "X-Compression-Ratio": str(result.compression_ratio),
                    "X-Metadata-Removed": str(result.metadata_removed),
                },
            )

    except asyncio.TimeoutError:
            logger.error(
                "Conversion timeout",
                filename=file.filename,
                correlation_id=request.state.correlation_id,
            )
            raise HTTPException(
                status_code=500,
                detail={
                    "error_code": "CONV250",
                    "message": f"Conversion timed out after {settings.conversion_timeout} seconds",
                    "correlation_id": request.state.correlation_id,
                },
            )

    except InvalidImageError as e:
            logger.error(
                "Invalid image error",
                error=str(e),
                correlation_id=request.state.correlation_id,
            )
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "CONV210",
                    "message": str(e),
                    "correlation_id": request.state.correlation_id,
                },
            )

    except UnsupportedFormatError as e:
            logger.error(
                "Unsupported format error",
                error=str(e),
                correlation_id=request.state.correlation_id,
            )
            raise HTTPException(
                status_code=415,
                detail={
                    "error_code": "CONV211",
                    "message": str(e),
                    "correlation_id": request.state.correlation_id,
                },
            )

    except ConversionFailedError as e:
            logger.error(
                "Conversion failed",
                error=str(e),
                correlation_id=request.state.correlation_id,
            )
            raise HTTPException(
                status_code=500,
                detail={
                    "error_code": "CONV299",
                    "message": str(e),
                    "correlation_id": request.state.correlation_id,
                },
            )

    except HTTPException:
        # Re-raise HTTP exceptions
        raise

    except Exception as e:
        logger.exception(
            "Unexpected error during conversion",
            error=str(e),
            correlation_id=request.state.correlation_id,
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error_code": "CONV299",
                "message": "An unexpected error occurred during conversion",
                "correlation_id": request.state.correlation_id,
            },
        )
    finally:
        # Always release the semaphore
        conversion_semaphore.release()
        
        # Clear sensitive data from memory
        try:
            # Clear file contents from memory
            if 'contents' in locals():
                del contents
            # Clear output data from memory
            if 'output_data' in locals():
                del output_data
        except Exception as e:
            logger.warning("Failed to clear memory", error=str(e))

