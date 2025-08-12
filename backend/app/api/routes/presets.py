"""API routes for preset management with enhanced search and versioning."""

from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, Request, Response

from app.api.utils.error_handling import EndpointErrorHandler
from app.core.exceptions import SecurityError, ValidationError
from app.models.responses import ErrorResponse
from app.models.schemas import (
    PresetBase,
    PresetCreate,
    PresetExport,
    PresetImport,
    PresetListResponse,
    PresetResponse,
    PresetUpdate,
)
from app.services.preset_service import preset_service
from app.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/presets", tags=["presets"])

# Error handlers for preset endpoints
preset_list_error_handler = EndpointErrorHandler("preset", "list_presets")
preset_get_error_handler = EndpointErrorHandler("preset", "get_preset")
preset_create_error_handler = EndpointErrorHandler("preset", "create_preset")
preset_update_error_handler = EndpointErrorHandler("preset", "update_preset")
preset_delete_error_handler = EndpointErrorHandler("preset", "delete_preset")
preset_import_error_handler = EndpointErrorHandler("preset", "import_presets")
preset_export_error_handler = EndpointErrorHandler("preset", "export_preset")
preset_search_error_handler = EndpointErrorHandler("preset", "search_presets")


@router.get(
    "",
    response_model=PresetListResponse,
    responses={
        200: {
            "model": PresetListResponse,
            "description": "Presets retrieved successfully",
        },
        400: {"model": ErrorResponse, "description": "Bad Request"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="List presets with advanced filtering and pagination",
    description="""
    List all available presets with support for:
    - Search by name, description, or format
    - Filtering by format, builtin status, or usage count
    - Pagination with limit/offset
    - Sorting by name, created date, or usage
    
    **Parameters:**
    - **include_builtin**: Include built-in system presets
    - **search**: Search term for name/description (case-insensitive)
    - **format_filter**: Filter by output format
    - **sort_by**: Sort field (name, created_at, usage_count)
    - **sort_order**: Sort direction (asc, desc)
    - **limit**: Maximum presets to return
    - **offset**: Number of presets to skip
    
    **Returns:**
    - List of matching presets with pagination metadata
    """,
)
async def list_presets(
    request: Request,
    include_builtin: bool = Query(True, description="Include built-in presets"),
    search: Optional[str] = Query(None, description="Search term for name/description"),
    format_filter: Optional[str] = Query(None, description="Filter by output format"),
    sort_by: Optional[str] = Query(
        "name", description="Sort field (name, created_at, usage_count)"
    ),
    sort_order: Optional[str] = Query("asc", description="Sort direction (asc, desc)"),
    limit: Optional[int] = Query(
        None, ge=1, le=100, description="Maximum presets to return"
    ),
    offset: Optional[int] = Query(0, ge=0, description="Number of presets to skip"),
) -> PresetListResponse:
    """List all available presets with advanced filtering and pagination."""
    try:
        # Validate sort parameters
        valid_sort_fields = ["name", "created_at", "usage_count", "updated_at"]
        if sort_by not in valid_sort_fields:
            raise preset_list_error_handler.validation_error(
                "Invalid sort field",
                request,
                details={"provided_field": sort_by, "valid_fields": valid_sort_fields},
            )

        valid_sort_orders = ["asc", "desc"]
        if sort_order not in valid_sort_orders:
            raise preset_list_error_handler.validation_error(
                "Invalid sort order",
                request,
                details={
                    "provided_order": sort_order,
                    "valid_orders": valid_sort_orders,
                },
            )

        # Validate format filter if provided
        if format_filter:
            valid_formats = [
                "webp",
                "avif",
                "jpeg",
                "png",
                "jxl",
                "heif",
                "jpeg_optimized",
                "png_optimized",
                "webp2",
            ]
            if format_filter not in valid_formats:
                raise preset_list_error_handler.validation_error(
                    "Invalid format filter",
                    request,
                    details={
                        "provided_format": format_filter,
                        "valid_formats": valid_formats,
                    },
                )

        # Build filter parameters
        filter_params = {
            "include_builtin": include_builtin,
            "search": search,
            "format_filter": format_filter,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "limit": limit,
            "offset": offset,
        }

        # Get filtered and paginated presets
        result = await preset_service.list_presets_advanced(**filter_params)

        logger.info(
            "Presets listed",
            total_presets=result.get("total", 0),
            returned_presets=len(result.get("presets", [])),
            search_term=search,
            format_filter=format_filter,
            correlation_id=request.state.correlation_id,
        )

        # Create response with metadata
        response = PresetListResponse(
            presets=result.get("presets", []),
            total=result.get("total", 0),
            offset=offset,
            limit=limit,
            has_more=result.get("has_more", False),
        )

        # Add pagination headers
        if limit or offset:
            request.state.response_headers = {
                "X-Total-Presets": str(result.get("total", 0)),
                "X-Returned-Presets": str(len(result.get("presets", []))),
                "X-Offset": str(offset),
                "X-Has-More": str(result.get("has_more", False)).lower(),
            }
            if limit:
                request.state.response_headers["X-Limit"] = str(limit)

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error listing presets: {e}")
        raise preset_list_error_handler.internal_server_error(
            "Failed to retrieve presets", request
        )


@router.get(
    "/{preset_id}",
    response_model=PresetResponse,
    responses={
        200: {"model": PresetResponse, "description": "Preset retrieved successfully"},
        404: {"model": ErrorResponse, "description": "Preset not found"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Get preset by ID with version information",
    description="""
    Retrieve a specific preset by its UUID with detailed version information.
    
    **Parameters:**
    - **preset_id**: UUID of the preset to retrieve
    - **include_usage**: Include usage statistics
    - **version**: Specific version to retrieve (defaults to latest)
    
    **Returns:**
    - Complete preset details including settings, metadata, and version info
    """,
)
async def get_preset(
    preset_id: str,
    request: Request,
    include_usage: bool = Query(False, description="Include usage statistics"),
    version: Optional[str] = Query(None, description="Specific version to retrieve"),
) -> PresetResponse:
    """Get a specific preset by ID with enhanced details."""
    try:
        # Get preset with optional version and usage info
        preset = await preset_service.get_preset_detailed(
            preset_id, include_usage=include_usage, version=version
        )

        if not preset:
            raise preset_get_error_handler.not_found_error(
                "Preset not found",
                request,
                details={"preset_id": preset_id, "version": version},
            )

        logger.info(
            "Preset retrieved",
            preset_id=preset_id,
            preset_name=preset.name,
            version=version,
            correlation_id=request.state.correlation_id,
        )

        return preset

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error getting preset: {e}")
        raise preset_get_error_handler.internal_server_error(
            "Failed to retrieve preset", request
        )


@router.get(
    "/search/advanced",
    response_model=PresetListResponse,
    responses={
        200: {
            "model": PresetListResponse,
            "description": "Search results retrieved successfully",
        },
        400: {"model": ErrorResponse, "description": "Bad Request"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Advanced preset search with fuzzy matching",
    description="""
    Perform advanced search across presets with fuzzy matching and ranking.
    
    This endpoint provides:
    - Fuzzy text matching across name, description, and tags
    - Search ranking based on relevance score
    - Multiple filter combinations
    - Format-specific search
    - Usage-based recommendations
    
    **Search Features:**
    - Text search in name, description, and tags
    - Fuzzy matching for typos and partial matches
    - Format-specific filtering
    - Quality range filtering
    - Optimization mode filtering
    - Usage count thresholds
    
    **Parameters:**
    - **q**: Main search query (fuzzy matched)
    - **formats**: Comma-separated list of formats to include
    - **min_quality**: Minimum quality setting
    - **max_quality**: Maximum quality setting
    - **optimization_modes**: Comma-separated optimization modes
    - **min_usage**: Minimum usage count threshold
    - **include_builtin**: Include built-in system presets
    - **limit**: Maximum results to return
    - **offset**: Number of results to skip
    
    **Returns:**
    - Ranked search results with relevance scores
    """,
)
async def search_presets_advanced(
    request: Request,
    q: str = Query(..., min_length=1, description="Search query"),
    formats: Optional[str] = Query(
        None, description="Comma-separated formats to include"
    ),
    min_quality: Optional[int] = Query(
        None, ge=1, le=100, description="Minimum quality setting"
    ),
    max_quality: Optional[int] = Query(
        None, ge=1, le=100, description="Maximum quality setting"
    ),
    optimization_modes: Optional[str] = Query(
        None, description="Comma-separated optimization modes"
    ),
    min_usage: Optional[int] = Query(None, ge=0, description="Minimum usage count"),
    include_builtin: bool = Query(True, description="Include built-in presets"),
    limit: Optional[int] = Query(
        20, ge=1, le=100, description="Maximum results to return"
    ),
    offset: Optional[int] = Query(0, ge=0, description="Number of results to skip"),
) -> PresetListResponse:
    """Advanced preset search with fuzzy matching and ranking."""
    try:
        # Validate quality range
        if (
            min_quality is not None
            and max_quality is not None
            and min_quality > max_quality
        ):
            raise preset_search_error_handler.validation_error(
                "Minimum quality cannot be greater than maximum quality",
                request,
                details={"min_quality": min_quality, "max_quality": max_quality},
            )

        # Parse comma-separated lists
        format_list = None
        if formats:
            format_list = [f.strip().lower() for f in formats.split(",") if f.strip()]
            valid_formats = [
                "webp",
                "avif",
                "jpeg",
                "png",
                "jxl",
                "heif",
                "jpeg_optimized",
                "png_optimized",
                "webp2",
            ]
            invalid_formats = [f for f in format_list if f not in valid_formats]
            if invalid_formats:
                raise preset_search_error_handler.validation_error(
                    "Invalid formats specified",
                    request,
                    details={
                        "invalid_formats": invalid_formats,
                        "valid_formats": valid_formats,
                    },
                )

        optimization_mode_list = None
        if optimization_modes:
            optimization_mode_list = [
                m.strip().lower() for m in optimization_modes.split(",") if m.strip()
            ]
            valid_modes = ["size", "quality", "balanced", "lossless"]
            invalid_modes = [m for m in optimization_mode_list if m not in valid_modes]
            if invalid_modes:
                raise preset_search_error_handler.validation_error(
                    "Invalid optimization modes specified",
                    request,
                    details={
                        "invalid_modes": invalid_modes,
                        "valid_modes": valid_modes,
                    },
                )

        # Build search parameters
        search_params = {
            "query": q,
            "formats": format_list,
            "min_quality": min_quality,
            "max_quality": max_quality,
            "optimization_modes": optimization_mode_list,
            "min_usage": min_usage,
            "include_builtin": include_builtin,
            "limit": limit,
            "offset": offset,
        }

        # Perform advanced search
        result = await preset_service.search_presets_advanced(**search_params)

        logger.info(
            "Advanced preset search completed",
            query=q,
            total_results=result.get("total", 0),
            returned_results=len(result.get("presets", [])),
            formats=format_list,
            correlation_id=request.state.correlation_id,
        )

        # Create response with search metadata
        response = PresetListResponse(
            presets=result.get("presets", []),
            total=result.get("total", 0),
            offset=offset,
            limit=limit,
            has_more=result.get("has_more", False),
            search_query=q,
            search_metadata={
                "execution_time_ms": result.get("execution_time_ms", 0),
                "max_relevance_score": result.get("max_relevance_score", 0.0),
                "filters_applied": {
                    "formats": format_list,
                    "quality_range": (
                        [min_quality, max_quality]
                        if min_quality or max_quality
                        else None
                    ),
                    "optimization_modes": optimization_mode_list,
                    "min_usage": min_usage,
                },
            },
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error in advanced search: {e}")
        raise preset_search_error_handler.internal_server_error(
            "Failed to perform advanced search", request
        )


@router.post(
    "",
    response_model=PresetResponse,
    status_code=201,
    responses={
        201: {"model": PresetResponse, "description": "Preset created successfully"},
        400: {"model": ErrorResponse, "description": "Bad Request"},
        409: {"model": ErrorResponse, "description": "Preset name already exists"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Create new preset with validation and versioning",
    description="""
    Create a new conversion preset with comprehensive validation.
    
    **Features:**
    - Automatic version tracking (starts at v1.0)
    - Name uniqueness validation
    - Settings format validation
    - Quality parameter validation
    - Format compatibility checking
    
    **Validation Rules:**
    - Name: 3-50 characters, alphanumeric and spaces
    - Description: Optional, max 200 characters
    - Quality: 1-100 for lossy formats, ignored for lossless
    - Format: Must be supported output format
    - Optimization mode: size, quality, balanced, or lossless
    
    **Parameters:**
    - **preset_data**: Complete preset configuration
    
    **Returns:**
    - Created preset with generated UUID and version info
    """,
)
async def create_preset(preset_data: PresetCreate, request: Request) -> PresetResponse:
    """Create a new preset with enhanced validation."""
    try:
        # Enhanced validation before creation
        if len(preset_data.name.strip()) < 3:
            raise preset_create_error_handler.validation_error(
                "Preset name must be at least 3 characters long",
                request,
                details={
                    "provided_length": len(preset_data.name.strip()),
                    "min_length": 3,
                },
            )

        # Validate format is supported
        valid_formats = [
            "webp",
            "avif",
            "jpeg",
            "png",
            "jxl",
            "heif",
            "jpeg_optimized",
            "png_optimized",
            "webp2",
        ]
        if preset_data.settings.output_format not in valid_formats:
            raise preset_create_error_handler.validation_error(
                "Unsupported output format",
                request,
                details={
                    "provided_format": preset_data.settings.output_format,
                    "valid_formats": valid_formats,
                },
            )

        # Create preset with version tracking
        preset = await preset_service.create_preset(preset_data)

        logger.info(
            "Preset created",
            preset_id=preset.id,
            preset_name=preset.name,
            output_format=preset_data.settings.output_format,
            correlation_id=request.state.correlation_id,
        )

        return preset

    except ValidationError as e:
        raise preset_create_error_handler.validation_error(str(e), request)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error creating preset: {e}")
        raise preset_create_error_handler.internal_server_error(
            "Failed to create preset", request
        )


@router.put(
    "/{preset_id}",
    response_model=PresetResponse,
    responses={
        200: {"model": PresetResponse, "description": "Preset updated successfully"},
        400: {"model": ErrorResponse, "description": "Bad Request"},
        403: {"model": ErrorResponse, "description": "Cannot modify built-in preset"},
        404: {"model": ErrorResponse, "description": "Preset not found"},
        409: {"model": ErrorResponse, "description": "Name conflict"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Update preset with version tracking",
    description="""
    Update an existing user preset with automatic version increment.
    
    **Version Management:**
    - Automatically increments version number
    - Preserves version history
    - Tracks modification timestamp
    - Records change summary
    
    **Restrictions:**
    - Cannot modify built-in system presets
    - Cannot change preset ID or creation date
    - Name must remain unique among user presets
    
    **Parameters:**
    - **preset_id**: UUID of preset to update
    - **update_data**: Fields to update (partial update supported)
    - **version_note**: Optional change description
    
    **Returns:**
    - Updated preset with new version information
    """,
)
async def update_preset(
    preset_id: str,
    update_data: PresetUpdate,
    request: Request,
    version_note: Optional[str] = Query(
        None, description="Optional change description"
    ),
) -> PresetResponse:
    """Update an existing preset with version tracking."""
    try:
        # Validate preset exists and is user-modifiable
        existing_preset = await preset_service.get_preset(preset_id)
        if not existing_preset:
            raise preset_update_error_handler.not_found_error(
                "Preset not found", request, details={"preset_id": preset_id}
            )

        # Enhanced update with version tracking
        preset = await preset_service.update_preset_versioned(
            preset_id, update_data, version_note=version_note
        )

        if not preset:
            raise preset_update_error_handler.not_found_error(
                "Preset not found or no changes applied",
                request,
                details={"preset_id": preset_id},
            )

        logger.info(
            "Preset updated",
            preset_id=preset_id,
            preset_name=preset.name,
            new_version=getattr(preset, "version", "unknown"),
            version_note=version_note,
            correlation_id=request.state.correlation_id,
        )

        return preset

    except SecurityError as e:
        raise preset_update_error_handler.forbidden_error(
            str(e),
            request,
            details={"preset_id": preset_id, "reason": "builtin_preset"},
        )
    except ValidationError as e:
        raise preset_update_error_handler.validation_error(str(e), request)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error updating preset: {e}")
        raise preset_update_error_handler.internal_server_error(
            "Failed to update preset", request
        )


@router.delete(
    "/{preset_id}",
    status_code=204,
    responses={
        204: {"description": "Preset deleted successfully"},
        403: {"model": ErrorResponse, "description": "Cannot delete built-in preset"},
        404: {"model": ErrorResponse, "description": "Preset not found"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Delete user preset with safety checks",
    description="""
    Delete a user-created preset with comprehensive safety validation.
    
    **Safety Features:**
    - Cannot delete built-in system presets
    - Validates preset ownership
    - Cleans up related data (usage stats, version history)
    - Atomic operation with rollback on failure
    
    **Parameters:**
    - **preset_id**: UUID of preset to delete
    - **force**: Override safety checks (requires admin)
    
    **Returns:**
    - 204 No Content on successful deletion
    """,
)
async def delete_preset(
    preset_id: str,
    request: Request,
    force: bool = Query(False, description="Force deletion (admin only)"),
) -> Response:
    """Delete a preset with enhanced safety checks."""
    try:
        # Check if preset exists and get details for logging
        existing_preset = await preset_service.get_preset(preset_id)
        if not existing_preset:
            raise preset_delete_error_handler.not_found_error(
                "Preset not found", request, details={"preset_id": preset_id}
            )

        # Perform safe deletion
        deleted = await preset_service.delete_preset_safe(preset_id, force=force)

        if not deleted:
            raise preset_delete_error_handler.not_found_error(
                "Preset not found or already deleted",
                request,
                details={"preset_id": preset_id},
            )

        logger.info(
            "Preset deleted",
            preset_id=preset_id,
            preset_name=existing_preset.name,
            force=force,
            correlation_id=request.state.correlation_id,
        )

        return Response(status_code=204)

    except SecurityError as e:
        raise preset_delete_error_handler.forbidden_error(
            str(e),
            request,
            details={"preset_id": preset_id, "reason": "builtin_preset"},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error deleting preset: {e}")
        raise preset_delete_error_handler.internal_server_error(
            "Failed to delete preset", request
        )


@router.get(
    "/{preset_id}/versions",
    response_model=List[dict],
    responses={
        200: {"description": "Version history retrieved successfully"},
        404: {"model": ErrorResponse, "description": "Preset not found"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Get preset version history",
    description="""
    Retrieve complete version history for a preset.
    
    **Features:**
    - Complete version timeline
    - Change summaries and timestamps
    - Version comparison metadata
    - Usage statistics per version
    
    **Parameters:**
    - **preset_id**: UUID of preset
    - **limit**: Maximum versions to return
    - **include_content**: Include full preset content for each version
    
    **Returns:**
    - Chronological list of all preset versions
    """,
)
async def get_preset_versions(
    preset_id: str,
    request: Request,
    limit: Optional[int] = Query(
        None, ge=1, le=50, description="Maximum versions to return"
    ),
    include_content: bool = Query(
        False, description="Include full content for each version"
    ),
) -> List[dict]:
    """Get version history for a preset."""
    try:
        # Validate preset exists
        preset = await preset_service.get_preset(preset_id)
        if not preset:
            raise preset_get_error_handler.not_found_error(
                "Preset not found", request, details={"preset_id": preset_id}
            )

        # Get version history
        versions = await preset_service.get_preset_versions(
            preset_id, limit=limit, include_content=include_content
        )

        logger.info(
            "Preset versions retrieved",
            preset_id=preset_id,
            version_count=len(versions),
            include_content=include_content,
            correlation_id=request.state.correlation_id,
        )

        return versions

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error getting preset versions: {e}")
        raise preset_get_error_handler.internal_server_error(
            "Failed to retrieve preset versions", request
        )


@router.post(
    "/{preset_id}/versions/{version}/restore",
    response_model=PresetResponse,
    responses={
        200: {"model": PresetResponse, "description": "Version restored successfully"},
        400: {"model": ErrorResponse, "description": "Invalid version"},
        403: {"model": ErrorResponse, "description": "Cannot restore built-in preset"},
        404: {"model": ErrorResponse, "description": "Preset or version not found"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Restore preset to previous version",
    description="""
    Restore a preset to a previous version, creating a new version entry.
    
    **Process:**
    - Validates version exists in history
    - Creates new version with restored content
    - Preserves complete version chain
    - Updates modification timestamp
    
    **Parameters:**
    - **preset_id**: UUID of preset
    - **version**: Version identifier to restore to
    - **restore_note**: Optional note about the restoration
    
    **Returns:**
    - Updated preset with restored content as new version
    """,
)
async def restore_preset_version(
    preset_id: str,
    version: str,
    request: Request,
    restore_note: Optional[str] = Query(None, description="Optional restoration note"),
) -> PresetResponse:
    """Restore a preset to a previous version."""
    try:
        # Restore to previous version
        preset = await preset_service.restore_preset_version(
            preset_id, version, restore_note=restore_note
        )

        if not preset:
            raise preset_update_error_handler.not_found_error(
                "Preset or version not found",
                request,
                details={"preset_id": preset_id, "version": version},
            )

        logger.info(
            "Preset version restored",
            preset_id=preset_id,
            restored_from_version=version,
            new_version=getattr(preset, "version", "unknown"),
            restore_note=restore_note,
            correlation_id=request.state.correlation_id,
        )

        return preset

    except SecurityError as e:
        raise preset_update_error_handler.forbidden_error(
            str(e),
            request,
            details={"preset_id": preset_id, "reason": "builtin_preset"},
        )
    except ValidationError as e:
        raise preset_update_error_handler.validation_error(str(e), request)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error restoring preset version: {e}")
        raise preset_update_error_handler.internal_server_error(
            "Failed to restore preset version", request
        )


@router.post(
    "/import",
    response_model=List[PresetResponse],
    status_code=201,
    responses={
        201: {
            "model": List[PresetResponse],
            "description": "Presets imported successfully",
        },
        400: {"model": ErrorResponse, "description": "Invalid import data"},
        409: {"model": ErrorResponse, "description": "Name conflicts detected"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Import presets with conflict resolution",
    description="""
    Import multiple presets from JSON with advanced conflict handling.
    
    **Features:**
    - Batch import with atomic transactions
    - Name conflict detection and resolution
    - Format validation for all presets
    - Partial import support (skip conflicts)
    - Import summary with success/failure counts
    
    **Conflict Resolution:**
    - **skip**: Skip conflicting presets (default)
    - **overwrite**: Replace existing presets
    - **rename**: Auto-rename with suffix
    
    **Parameters:**
    - **import_data**: JSON containing preset array
    - **conflict_strategy**: How to handle name conflicts
    - **validate_settings**: Perform deep validation
    
    **Returns:**
    - List of successfully imported presets
    """,
)
async def import_presets(
    import_data: PresetImport,
    request: Request,
    conflict_strategy: str = Query("skip", description="Conflict resolution strategy"),
    validate_settings: bool = Query(True, description="Perform deep validation"),
) -> List[PresetResponse]:
    """Import presets with enhanced conflict resolution."""
    try:
        # Validate conflict strategy
        valid_strategies = ["skip", "overwrite", "rename"]
        if conflict_strategy not in valid_strategies:
            raise preset_import_error_handler.validation_error(
                "Invalid conflict resolution strategy",
                request,
                details={
                    "provided_strategy": conflict_strategy,
                    "valid_strategies": valid_strategies,
                },
            )

        # Enhanced import with conflict resolution
        result = await preset_service.import_presets_enhanced(
            import_data,
            conflict_strategy=conflict_strategy,
            validate_settings=validate_settings,
        )

        imported_presets = result.get("imported", [])
        skipped_count = result.get("skipped", 0)

        logger.info(
            "Presets imported",
            imported_count=len(imported_presets),
            skipped_count=skipped_count,
            conflict_strategy=conflict_strategy,
            correlation_id=request.state.correlation_id,
        )

        # Add import summary to response headers
        request.state.response_headers = {
            "X-Imported-Count": str(len(imported_presets)),
            "X-Skipped-Count": str(skipped_count),
            "X-Conflict-Strategy": conflict_strategy,
        }

        return imported_presets

    except ValidationError as e:
        raise preset_import_error_handler.validation_error(str(e), request)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error importing presets: {e}")
        raise preset_import_error_handler.internal_server_error(
            "Failed to import presets", request
        )


@router.get(
    "/{preset_id}/export",
    response_model=PresetExport,
    responses={
        200: {"model": PresetExport, "description": "Preset exported successfully"},
        404: {"model": ErrorResponse, "description": "Preset not found"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Export preset with version information",
    description="""
    Export a preset as portable JSON with complete metadata.
    
    **Export Features:**
    - Complete preset configuration
    - Version information and history
    - Usage statistics (optional)
    - Import compatibility metadata
    - Validation checksums
    
    **Parameters:**
    - **preset_id**: UUID of preset to export
    - **include_history**: Include version history
    - **include_usage**: Include usage statistics
    - **format_version**: Export format version
    
    **Returns:**
    - Complete preset export package
    """,
)
async def export_preset(
    preset_id: str,
    request: Request,
    include_history: bool = Query(False, description="Include version history"),
    include_usage: bool = Query(False, description="Include usage statistics"),
    format_version: str = Query("1.0", description="Export format version"),
) -> PresetExport:
    """Export a preset with enhanced metadata."""
    try:
        # Enhanced export with additional metadata
        export = await preset_service.export_preset_enhanced(
            preset_id,
            include_history=include_history,
            include_usage=include_usage,
            format_version=format_version,
        )

        if not export:
            raise preset_export_error_handler.not_found_error(
                "Preset not found", request, details={"preset_id": preset_id}
            )

        logger.info(
            "Preset exported",
            preset_id=preset_id,
            include_history=include_history,
            include_usage=include_usage,
            format_version=format_version,
            correlation_id=request.state.correlation_id,
        )

        return export

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error exporting preset: {e}")
        raise preset_export_error_handler.internal_server_error(
            "Failed to export preset", request
        )


@router.get(
    "/export/all",
    response_model=List[PresetBase],
    responses={
        200: {
            "model": List[PresetBase],
            "description": "All presets exported successfully",
        },
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    summary="Export all user presets with filtering",
    description="""
    Export all user presets (excluding built-in) with filtering options.
    
    **Features:**
    - Excludes built-in system presets
    - Optional format filtering
    - Batch export optimization
    - Export validation and checksums
    - Compressed output support
    
    **Parameters:**
    - **format_filter**: Only export presets for specific format
    - **include_unused**: Include presets with zero usage
    - **export_format**: Output format (json, yaml)
    
    **Returns:**
    - Complete export package for all user presets
    """,
)
async def export_all_presets(
    request: Request,
    format_filter: Optional[str] = Query(None, description="Filter by output format"),
    include_unused: bool = Query(True, description="Include unused presets"),
    export_format: str = Query("json", description="Export format"),
) -> List[PresetBase]:
    """Export all user presets with filtering."""
    try:
        # Validate parameters
        if format_filter:
            valid_formats = [
                "webp",
                "avif",
                "jpeg",
                "png",
                "jxl",
                "heif",
                "jpeg_optimized",
                "png_optimized",
                "webp2",
            ]
            if format_filter not in valid_formats:
                raise preset_export_error_handler.validation_error(
                    "Invalid format filter",
                    request,
                    details={
                        "provided_format": format_filter,
                        "valid_formats": valid_formats,
                    },
                )

        valid_export_formats = ["json", "yaml"]
        if export_format not in valid_export_formats:
            raise preset_export_error_handler.validation_error(
                "Invalid export format",
                request,
                details={
                    "provided_format": export_format,
                    "valid_formats": valid_export_formats,
                },
            )

        # Enhanced export with filtering
        presets = await preset_service.export_all_presets_filtered(
            format_filter=format_filter,
            include_unused=include_unused,
            export_format=export_format,
        )

        logger.info(
            "All presets exported",
            preset_count=len(presets),
            format_filter=format_filter,
            include_unused=include_unused,
            export_format=export_format,
            correlation_id=request.state.correlation_id,
        )

        # Add export metadata to headers
        request.state.response_headers = {
            "X-Export-Count": str(len(presets)),
            "X-Export-Format": export_format,
            "X-Format-Filter": format_filter or "none",
        }

        return presets

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error exporting all presets: {e}")
        raise preset_export_error_handler.internal_server_error(
            "Failed to export presets", request
        )
