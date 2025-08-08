"""Service for managing user presets."""

import json
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy import create_engine, select, and_
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError

from app.models.database import Base, UserPreset
from app.models.schemas import (
    PresetCreate,
    PresetUpdate,
    PresetResponse,
    PresetSettings,
    PresetImport,
    PresetExport,
    PresetBase
)
from app.core.exceptions import ValidationError, SecurityError


class PresetService:
    """Service for managing conversion presets."""
    
    def __init__(self, db_path: str = "./data/presets.db"):
        """Initialize preset service.
        
        Args:
            db_path: Path to SQLite database
        """
        self.engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self._initialized = False
    
    async def initialize(self):
        """Initialize service and create built-in presets if needed."""
        if self._initialized:
            return
        
        await self._ensure_builtin_presets()
        self._initialized = True
    
    async def _ensure_builtin_presets(self):
        """Create built-in presets if they don't exist."""
        builtin_presets = [
            {
                "name": "Web Optimized",
                "description": "Optimized for web use - smaller file size with good quality",
                "settings": {
                    "output_format": "webp",
                    "quality": 85,
                    "optimization_mode": "file_size",
                    "preserve_metadata": False
                }
            },
            {
                "name": "Print Quality",
                "description": "High quality for printing - preserves all image data",
                "settings": {
                    "output_format": "png",
                    "quality": 100,
                    "optimization_mode": "quality",
                    "preserve_metadata": True
                }
            },
            {
                "name": "Archive",
                "description": "Lossless compression for long-term storage",
                "settings": {
                    "output_format": "webp",
                    "quality": 100,
                    "optimization_mode": "balanced",
                    "preserve_metadata": True,
                    "advanced_settings": {"lossless": True}
                }
            }
        ]
        
        with self.SessionLocal() as session:
            for preset_data in builtin_presets:
                # Check if preset already exists
                existing = session.query(UserPreset).filter_by(
                    name=preset_data["name"],
                    is_builtin=True
                ).first()
                
                if not existing:
                    preset = UserPreset(
                        id=str(uuid.uuid4()),
                        name=preset_data["name"],
                        description=preset_data["description"],
                        settings=json.dumps(preset_data["settings"]),
                        is_builtin=True
                    )
                    session.add(preset)
            
            session.commit()
    
    async def create_preset(self, preset_data: PresetCreate) -> PresetResponse:
        """Create a new preset.
        
        Args:
            preset_data: Preset creation data
            
        Returns:
            Created preset
            
        Raises:
            APIError: If preset name already exists
        """
        with self.SessionLocal() as session:
            # Check for duplicate name
            existing = session.query(UserPreset).filter_by(name=preset_data.name).first()
            if existing:
                raise ValidationError(
                    f"Preset with name '{preset_data.name}' already exists"
                )
            
            # Create new preset
            preset = UserPreset(
                id=str(uuid.uuid4()),
                name=preset_data.name,
                description=preset_data.description,
                settings=json.dumps(preset_data.settings.model_dump()),
                is_builtin=False
            )
            
            session.add(preset)
            session.commit()
            session.refresh(preset)
            
            return self._preset_to_response(preset)
    
    async def get_preset(self, preset_id: str) -> Optional[PresetResponse]:
        """Get a preset by ID.
        
        Args:
            preset_id: Preset UUID
            
        Returns:
            Preset if found, None otherwise
        """
        with self.SessionLocal() as session:
            preset = session.query(UserPreset).filter_by(id=preset_id).first()
            if preset:
                return self._preset_to_response(preset)
            return None
    
    async def list_presets(self, include_builtin: bool = True) -> List[PresetResponse]:
        """List all presets.
        
        Args:
            include_builtin: Whether to include built-in presets
            
        Returns:
            List of presets
        """
        with self.SessionLocal() as session:
            query = session.query(UserPreset)
            
            if not include_builtin:
                query = query.filter_by(is_builtin=False)
            
            # Order by built-in first, then by name
            query = query.order_by(UserPreset.is_builtin.desc(), UserPreset.name)
            
            presets = query.all()
            return [self._preset_to_response(preset) for preset in presets]
    
    async def list_presets_advanced(
        self,
        include_builtin: bool = True,
        search: Optional[str] = None,
        format_filter: Optional[str] = None,
        sort_by: str = "name",
        sort_order: str = "asc",
        limit: Optional[int] = None,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List presets with advanced filtering, search, and pagination.
        
        Args:
            include_builtin: Whether to include built-in presets
            search: Search term for name/description
            format_filter: Filter by output format in settings
            sort_by: Field to sort by (name, created_at, updated_at, usage_count)
            sort_order: Sort direction (asc, desc)
            limit: Maximum number of presets to return
            offset: Number of presets to skip
            
        Returns:
            Dictionary with presets and pagination metadata
        """
        with self.SessionLocal() as session:
            query = session.query(UserPreset)
            
            # Filter by built-in status
            if not include_builtin:
                query = query.filter_by(is_builtin=False)
            
            # Search in name and description
            if search:
                search_term = f"%{search}%"
                from sqlalchemy import or_
                query = query.filter(
                    or_(
                        UserPreset.name.ilike(search_term),
                        UserPreset.description.ilike(search_term)
                    )
                )
            
            # Filter by output format in JSON settings
            if format_filter:
                # Use JSON extraction for SQLite
                # SQLite stores JSON as text, so we use LIKE pattern matching
                format_pattern = f'%"output_format": "{format_filter}"%'
                query = query.filter(UserPreset.settings.like(format_pattern))
            
            # Get total count before pagination
            total_count = query.count()
            
            # Apply sorting
            if sort_by == "name":
                if sort_order == "desc":
                    query = query.order_by(UserPreset.name.desc())
                else:
                    query = query.order_by(UserPreset.name)
            elif sort_by == "created_at":
                if sort_order == "desc":
                    query = query.order_by(UserPreset.created_at.desc())
                else:
                    query = query.order_by(UserPreset.created_at)
            elif sort_by == "updated_at":
                if sort_order == "desc":
                    query = query.order_by(UserPreset.updated_at.desc())
                else:
                    query = query.order_by(UserPreset.updated_at)
            elif sort_by == "usage_count":
                # For now, sort by name as usage_count is not tracked
                # This maintains API compatibility
                if sort_order == "desc":
                    query = query.order_by(UserPreset.name.desc())
                else:
                    query = query.order_by(UserPreset.name)
            
            # Apply pagination
            if limit:
                query = query.limit(limit)
            query = query.offset(offset)
            
            # Execute query
            presets = query.all()
            preset_responses = [self._preset_to_response(preset) for preset in presets]
            
            # Calculate pagination metadata
            page_size = limit if limit else total_count
            current_page = (offset // page_size) + 1 if page_size > 0 else 1
            total_pages = (total_count + page_size - 1) // page_size if page_size > 0 else 1
            
            return {
                "presets": preset_responses,
                "total": total_count,
                "page": current_page,
                "page_size": page_size,
                "total_pages": total_pages,
                "has_next": (offset + page_size) < total_count if limit else False,
                "has_previous": offset > 0
            }
    
    async def update_preset(self, preset_id: str, update_data: PresetUpdate) -> Optional[PresetResponse]:
        """Update an existing preset.
        
        Args:
            preset_id: Preset UUID
            update_data: Update data
            
        Returns:
            Updated preset if found, None otherwise
            
        Raises:
            APIError: If trying to update built-in preset or duplicate name
        """
        with self.SessionLocal() as session:
            preset = session.query(UserPreset).filter_by(id=preset_id).first()
            
            if not preset:
                return None
            
            if preset.is_builtin:
                raise SecurityError(
                    "Cannot modify built-in presets"
                )
            
            # Check for duplicate name if name is being changed
            if update_data.name and update_data.name != preset.name:
                existing = session.query(UserPreset).filter_by(name=update_data.name).first()
                if existing:
                    raise ValidationError(
                        f"Preset with name '{update_data.name}' already exists"
                    )
                preset.name = update_data.name
            
            if update_data.description is not None:
                preset.description = update_data.description
            
            if update_data.settings:
                preset.settings = json.dumps(update_data.settings.model_dump())
            
            preset.updated_at = datetime.utcnow()
            
            session.commit()
            session.refresh(preset)
            
            return self._preset_to_response(preset)
    
    async def delete_preset(self, preset_id: str) -> bool:
        """Delete a preset.
        
        Args:
            preset_id: Preset UUID
            
        Returns:
            True if deleted, False if not found
            
        Raises:
            APIError: If trying to delete built-in preset
        """
        with self.SessionLocal() as session:
            preset = session.query(UserPreset).filter_by(id=preset_id).first()
            
            if not preset:
                return False
            
            if preset.is_builtin:
                raise SecurityError(
                    "Cannot delete built-in presets"
                )
            
            session.delete(preset)
            session.commit()
            
            return True
    
    async def import_presets(self, import_data: PresetImport) -> List[PresetResponse]:
        """Import presets from JSON.
        
        Args:
            import_data: Import data containing presets
            
        Returns:
            List of imported presets
            
        Raises:
            APIError: If any preset names conflict
        """
        imported_presets = []
        
        with self.SessionLocal() as session:
            # Check for name conflicts
            for preset_data in import_data.presets:
                existing = session.query(UserPreset).filter_by(name=preset_data.name).first()
                if existing:
                    raise ValidationError(
                        f"Preset with name '{preset_data.name}' already exists"
                    )
            
            # Import all presets
            for preset_data in import_data.presets:
                preset = UserPreset(
                    id=str(uuid.uuid4()),
                    name=preset_data.name,
                    description=preset_data.description,
                    settings=json.dumps(preset_data.settings.model_dump()),
                    is_builtin=False
                )
                session.add(preset)
                imported_presets.append(preset)
            
            session.commit()
            
            # Convert to response models
            return [self._preset_to_response(preset) for preset in imported_presets]
    
    async def export_preset(self, preset_id: str) -> Optional[PresetExport]:
        """Export a preset as JSON.
        
        Args:
            preset_id: Preset UUID
            
        Returns:
            Export data if preset found, None otherwise
        """
        preset_response = await self.get_preset(preset_id)
        if preset_response:
            return PresetExport(preset=preset_response)
        return None
    
    async def export_all_presets(self) -> List[PresetBase]:
        """Export all user presets (excluding built-in).
        
        Returns:
            List of preset data for export
        """
        presets = await self.list_presets(include_builtin=False)
        return [
            PresetBase(
                name=preset.name,
                description=preset.description,
                settings=preset.settings
            )
            for preset in presets
        ]
    
    def _preset_to_response(self, preset: UserPreset) -> PresetResponse:
        """Convert database model to response model.
        
        Args:
            preset: Database preset model
            
        Returns:
            Response model
        """
        settings_dict = json.loads(preset.settings)
        settings = PresetSettings(**settings_dict)
        
        return PresetResponse(
            id=preset.id,
            name=preset.name,
            description=preset.description,
            settings=settings,
            is_builtin=preset.is_builtin,
            created_at=preset.created_at,
            updated_at=preset.updated_at
        )


# Create singleton instance
import os
preset_service = PresetService(db_path=os.environ.get("PRESET_DB_PATH", "./data/presets.db"))