"""Conversion API endpoints."""

import asyncio
import os
from pathlib import Path
from typing import Optional

import structlog
from fastapi import APIRouter, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import StreamingResponse

from app.api.utils.error_handling import EndpointErrorHandler
from app.api.utils.validation import secure_memory_clear, validate_content_type
from app.config import settings
from app.core.constants import FORMAT_TO_CONTENT_TYPE
from app.core.exceptions import (
    ConversionError,
    ConversionFailedError,
    InvalidImageError,
    UnsupportedFormatError,
)
from app.models.conversion import ConversionSettings, OptimizationSettings, OutputFormat
from app.models.requests import ConversionApiRequest
from app.models.responses import ConversionApiResponse, ErrorResponse
from app.services.conversion_service import conversion_service

logger = structlog.get_logger()

router = APIRouter()

# Semaphore for concurrent request limiting
conversion_semaphore = asyncio.Semaphore(settings.max_concurrent_conversions)

# Error handler for this endpoint
error_handler = EndpointErrorHandler("conversion", "convert_image")


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
    for sep in ["/", "\\"]:
        parts = filename.split(sep)
        filename = parts[-1]

    # Remove any null bytes
    filename = filename.replace("\x00", "")

    # Remove any non-printable characters
    filename = "".join(char for char in filename if char.isprintable())

    # Remove any remaining path traversal sequences
    filename = filename.replace("..", "")

    # Ensure filename is not empty after sanitization
    if not filename or filename == ".":
        filename = "unnamed"

    # Add extension if missing
    if "." not in filename:
        filename = filename + ".bin"

    # Limit length
    max_length = 255
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        # Preserve extension but truncate name
        filename = name[: max_length - len(ext)] + ext

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
    Convert an uploaded image to a different format with comprehensive optimization and metadata control.
    
    ## Request Parameters
    
    ### Required
    - **file**: Image file to convert (multipart/form-data)
      - Supported formats: JPEG, PNG, WebP, GIF, BMP, TIFF, HEIF/HEIC, AVIF
      - Max size: 100MB per file
      - Content-based format detection (ignores file extension)
    - **output_format**: Target format (webp, avif, jpeg, png, heif, jxl, webp2)
    
    ### Optional Settings
    - **quality**: Quality setting (1-100, default: 85)
      - Higher values = better quality, larger file size
      - Ignored for lossless formats (PNG)
    - **strip_metadata**: Remove EXIF and other metadata (default: true)
      - Recommended for privacy and smaller file sizes
    - **preserve_metadata**: Keep non-GPS metadata (overrides strip_metadata, default: false)
      - Preserves camera settings, creation date, etc.
    - **preserve_gps**: Keep GPS location data (requires preserve_metadata=true, default: false)
      - ⚠️ GPS data can reveal location information
    - **preset_id**: UUID of conversion preset to apply
      - Preset settings override individual parameters
      - Use `/api/v1/presets` to list available presets
    
    ## Response
    
    ### Success (200)
    - Binary image data in requested format
    - Enhanced response headers with conversion metadata:
      - `X-Conversion-Id`: Unique conversion identifier
      - `X-Processing-Time`: Time taken in seconds
      - `X-Compression-Ratio`: Output/input size ratio
      - `X-Input-Format`: Detected input format
      - `X-Output-Format`: Actual output format used
      - `X-Input-Size`: Original file size in bytes
      - `X-Output-Size`: Converted file size in bytes
      - `X-Quality-Used`: Quality setting applied
      - `X-Metadata-Removed`: Whether metadata was stripped
    
    ### Error Responses
    - **400**: Invalid request (empty file, missing filename, unknown format)
    - **413**: File too large (exceeds size limits)
    - **415**: Unsupported file format
    - **422**: Invalid image data or corrupted file
    - **503**: Service temporarily unavailable (too many concurrent requests)
    
    ## Privacy & Security
    - All processing happens locally (no data sent to external services)
    - Metadata (including GPS) removed by default
    - Files processed in sandboxed environment
    - Memory securely cleared after conversion
    
    ## Performance
    - Concurrent request limiting prevents overload
    - Automatic format detection more reliable than file extensions
    - Optimized for files up to 50MB (larger files may be slower)
    
    ## Examples
    
    ### Basic Conversion
    ```bash
    curl -X POST "/api/v1/convert" \\
         -F "file=@photo.jpg" \\
         -F "output_format=webp" \\
         -F "quality=90"
    ```
    
    ### Using Presets
    ```bash
    curl -X POST "/api/v1/convert" \\
         -F "file=@photo.jpg" \\
         -F "output_format=webp" \\
         -F "preset_id=550e8400-e29b-41d4-a716-446655440000"
    ```
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
        False,
        description="Preserve GPS location data (only if preserve_metadata is true)",
    ),
    preset_id: Optional[str] = Form(None, description="UUID of preset to apply"),
):
    """Convert an image to a different format."""
    # Try to acquire semaphore without blocking using timeout
    try:
        await asyncio.wait_for(conversion_semaphore.acquire(), timeout=0.01)
    except asyncio.TimeoutError:
        raise error_handler.service_unavailable_error(
            "Service temporarily unavailable due to high load", request, retry_after=60
        )

    try:
        # Validate content type
        if not validate_content_type(file):
            raise error_handler.unsupported_media_type_error(
                "Unsupported file type. Please upload an image file (JPEG, PNG, WebP, GIF, BMP, TIFF, HEIF/HEIC, or AVIF).",
                request,
            )

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
            raise error_handler.validation_error(
                "The uploaded file is empty. Please select a valid image file to convert.",
                request,
            )

        if file_size > settings.max_file_size:
            raise error_handler.payload_too_large_error(
                f"File size exceeds maximum allowed size of {settings.max_file_size / 1024 / 1024}MB",
                request,
                details={
                    "file_size": file_size,
                    "max_size": settings.max_file_size,
                },
            )

        # Extract file format from filename
        if not file.filename:
            raise error_handler.validation_error(
                "A filename is required. Please ensure your file has a valid name before uploading.",
                request,
            )

        # Sanitize filename to prevent path traversal
        safe_filename = sanitize_filename(file.filename)
        file_ext = Path(safe_filename).suffix.lower().lstrip(".")

        # Try to detect format from content (more reliable than extension)
        detected_format = None
        try:
            from app.services.format_detection_service import format_detection_service

            detected_format, confident = await format_detection_service.detect_format(
                contents
            )
            logger.info(
                "Format detected from content",
                detected_format=detected_format,
                file_extension=file_ext,
                confident=confident,
                correlation_id=request.state.correlation_id,
            )
        except Exception as e:
            logger.warning(
                "Format detection failed, falling back to extension",
                error=str(e),
                file_extension=file_ext,
                correlation_id=request.state.correlation_id,
            )

        # Use detected format if available, otherwise fall back to extension
        input_format = detected_format or file_ext

        if not input_format:
            raise error_handler.validation_error(
                "Unable to determine the image format. The file may be corrupted or in an unsupported format. Supported formats: JPEG, PNG, WebP, GIF, BMP, TIFF, HEIF/HEIC, AVIF.",
                request,
            )

        # Create conversion request
        conversion_request = ConversionApiRequest(
            filename=safe_filename,
            input_format=input_format,
            output_format=output_format,
            settings=ConversionSettings(
                quality=quality,
                strip_metadata=strip_metadata,
                preserve_metadata=preserve_metadata,
                preserve_gps=preserve_gps,
                optimize=True,
            ),
            preset_id=preset_id,
        )

        # Perform conversion
        result, output_data = await conversion_service.convert(
            contents, conversion_request
        )

        if not output_data:
            raise error_handler.internal_server_error(
                "The conversion process completed but did not produce any output. This may indicate an issue with the selected output format or image content. Please try a different output format.",
                request,
            )

        # Determine content type - use actual output format from result
        # Use the actual output format from the conversion result
        actual_output_format = (
            result.output_format.lower()
            if hasattr(result.output_format, "lower")
            else str(result.output_format).lower()
        )
        content_type = FORMAT_TO_CONTENT_TYPE.get(
            actual_output_format, "application/octet-stream"
        )

        # Generate output filename with actual format
        base_name = Path(safe_filename).stem
        output_filename = f"{base_name}.{actual_output_format}"

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

        # Return binary response with enhanced headers
        return Response(
            content=output_data,
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{output_filename}"',
                "X-Conversion-Id": result.id,
                "X-Processing-Time": str(result.processing_time),
                "X-Compression-Ratio": str(result.compression_ratio),
                "X-Metadata-Removed": str(result.metadata_removed),
                "X-Input-Format": input_format,
                "X-Output-Format": actual_output_format,
                "X-Input-Size": str(file_size),
                "X-Output-Size": str(len(output_data)),
                "X-Quality-Used": str(quality),
                "X-API-Version": "v1",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    except asyncio.TimeoutError:
        logger.error(
            "Conversion timeout",
            filename=file.filename,
            correlation_id=request.state.correlation_id,
        )
        raise error_handler.internal_server_error(
            f"Conversion timed out after {settings.conversion_timeout} seconds", request
        )

    except InvalidImageError as e:
        logger.error(
            "Invalid image error",
            error=str(e),
            correlation_id=request.state.correlation_id,
        )
        raise error_handler.unprocessable_entity_error(str(e), request)

    except UnsupportedFormatError as e:
        logger.error(
            "Unsupported format error",
            error=str(e),
            correlation_id=request.state.correlation_id,
        )
        raise error_handler.unsupported_media_type_error(str(e), request)

    except ConversionFailedError as e:
        logger.error(
            "Conversion failed",
            error=str(e),
            correlation_id=request.state.correlation_id,
        )
        raise error_handler.internal_server_error(str(e), request)

    except HTTPException:
        # Re-raise HTTP exceptions
        raise

    except Exception as e:
        logger.exception(
            "Unexpected error during conversion",
            error=str(e),
            correlation_id=request.state.correlation_id,
        )
        raise error_handler.internal_server_error(
            "An unexpected error occurred during image conversion. Please verify your image file is valid and try again. If the problem persists, try converting to a different format.",
            request,
        )
    finally:
        # Always release the semaphore
        conversion_semaphore.release()

        # Clear sensitive data from memory
        secure_memory_clear(contents if "contents" in locals() else None)
        secure_memory_clear(output_data if "output_data" in locals() else None)
