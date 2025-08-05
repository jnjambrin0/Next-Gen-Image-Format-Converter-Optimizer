"""API routes for preset management."""

from typing import List
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.schemas import (
    PresetCreate,
    PresetUpdate,
    PresetResponse,
    PresetImport,
    PresetExport,
    PresetListResponse,
    PresetBase
)
from app.services.preset_service import preset_service
from app.core.exceptions import ValidationError, SecurityError

router = APIRouter(prefix="/presets")


@router.get("", response_model=PresetListResponse)
async def list_presets(include_builtin: bool = True) -> PresetListResponse:
    """List all available presets.
    
    Args:
        include_builtin: Whether to include built-in presets
        
    Returns:
        List of all presets
    """
    presets = await preset_service.list_presets(include_builtin=include_builtin)
    return PresetListResponse(
        presets=presets,
        total=len(presets)
    )


@router.get("/{preset_id}", response_model=PresetResponse)
async def get_preset(preset_id: str) -> PresetResponse:
    """Get a specific preset by ID.
    
    Args:
        preset_id: Preset UUID
        
    Returns:
        Preset details
        
    Raises:
        HTTPException: If preset not found
    """
    preset = await preset_service.get_preset(preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail="Preset not found")
    return preset


@router.post("", response_model=PresetResponse, status_code=201)
async def create_preset(preset_data: PresetCreate) -> PresetResponse:
    """Create a new preset.
    
    Args:
        preset_data: Preset creation data
        
    Returns:
        Created preset
        
    Raises:
        HTTPException: If preset name already exists
    """
    try:
        preset = await preset_service.create_preset(preset_data)
        return preset
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{preset_id}", response_model=PresetResponse)
async def update_preset(preset_id: str, update_data: PresetUpdate) -> PresetResponse:
    """Update an existing preset.
    
    Args:
        preset_id: Preset UUID
        update_data: Update data
        
    Returns:
        Updated preset
        
    Raises:
        HTTPException: If preset not found, is built-in, or name conflicts
    """
    try:
        preset = await preset_service.update_preset(preset_id, update_data)
        if not preset:
            raise HTTPException(status_code=404, detail="Preset not found")
        return preset
    except SecurityError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{preset_id}", status_code=204)
async def delete_preset(preset_id: str) -> Response:
    """Delete a preset.
    
    Args:
        preset_id: Preset UUID
        
    Returns:
        Empty response on success
        
    Raises:
        HTTPException: If preset not found or is built-in
    """
    try:
        deleted = await preset_service.delete_preset(preset_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Preset not found")
        return Response(status_code=204)
    except SecurityError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.post("/import", response_model=List[PresetResponse], status_code=201)
async def import_presets(import_data: PresetImport) -> List[PresetResponse]:
    """Import presets from JSON.
    
    Args:
        import_data: Import data containing presets
        
    Returns:
        List of imported presets
        
    Raises:
        HTTPException: If any preset names conflict
    """
    try:
        imported = await preset_service.import_presets(import_data)
        return imported
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{preset_id}/export", response_model=PresetExport)
async def export_preset(preset_id: str) -> PresetExport:
    """Export a preset as JSON.
    
    Args:
        preset_id: Preset UUID
        
    Returns:
        Export data
        
    Raises:
        HTTPException: If preset not found
    """
    export = await preset_service.export_preset(preset_id)
    if not export:
        raise HTTPException(status_code=404, detail="Preset not found")
    return export


@router.get("/export/all", response_model=List[PresetBase])
async def export_all_presets() -> List[PresetBase]:
    """Export all user presets (excluding built-in).
    
    Returns:
        List of all user presets for export
    """
    presets = await preset_service.export_all_presets()
    return presets