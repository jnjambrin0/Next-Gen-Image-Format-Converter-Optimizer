"""Unit tests for preset service."""

import pytest
import pytest_asyncio
import os
import tempfile
import json
from datetime import datetime

from app.services.preset_service import PresetService
from app.models.schemas import (
    PresetCreate,
    PresetUpdate,
    PresetSettings,
    PresetImport,
    PresetBase
)
from app.core.exceptions import ValidationError, SecurityError


@pytest_asyncio.fixture
async def preset_service():
    """Create a preset service with temporary database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_presets.db")
        service = PresetService(db_path=db_path)
        await service.initialize()
        yield service


@pytest.fixture
def sample_preset_data():
    """Sample preset creation data."""
    return PresetCreate(
        name="Test Preset",
        description="A test preset",
        settings=PresetSettings(
            output_format="webp",
            quality=85,
            optimization_mode="balanced",
            preserve_metadata=False
        )
    )


class TestPresetService:
    """Test PresetService functionality."""
    
    @pytest.mark.asyncio
    async def test_initialize_builtin_presets(self, preset_service):
        """Test that built-in presets are created on initialization."""
        presets = await preset_service.list_presets(include_builtin=True)
        
        # Should have 3 built-in presets
        builtin_presets = [p for p in presets if p.is_builtin]
        assert len(builtin_presets) == 3
        
        # Check preset names
        builtin_names = {p.name for p in builtin_presets}
        assert builtin_names == {"Web Optimized", "Print Quality", "Archive"}
        
        # Verify Web Optimized preset
        web_preset = next(p for p in builtin_presets if p.name == "Web Optimized")
        assert web_preset.settings.output_format == "webp"
        assert web_preset.settings.quality == 85
        assert web_preset.settings.optimization_mode == "file_size"
        assert not web_preset.settings.preserve_metadata
        
        # Verify Print Quality preset
        print_preset = next(p for p in builtin_presets if p.name == "Print Quality")
        assert print_preset.settings.output_format == "png"
        assert print_preset.settings.quality == 100
        assert print_preset.settings.optimization_mode == "quality"
        assert print_preset.settings.preserve_metadata
        
        # Verify Archive preset
        archive_preset = next(p for p in builtin_presets if p.name == "Archive")
        assert archive_preset.settings.output_format == "webp"
        assert archive_preset.settings.quality == 100
        assert archive_preset.settings.optimization_mode == "balanced"
        assert archive_preset.settings.preserve_metadata
        assert archive_preset.settings.advanced_settings == {"lossless": True}
    
    @pytest.mark.asyncio
    async def test_create_preset(self, preset_service, sample_preset_data):
        """Test creating a new preset."""
        preset = await preset_service.create_preset(sample_preset_data)
        
        assert preset.name == sample_preset_data.name
        assert preset.description == sample_preset_data.description
        assert preset.settings.output_format == sample_preset_data.settings.output_format
        assert preset.settings.quality == sample_preset_data.settings.quality
        assert not preset.is_builtin
        assert preset.id is not None
        assert isinstance(preset.created_at, datetime)
        assert isinstance(preset.updated_at, datetime)
    
    @pytest.mark.asyncio
    async def test_create_preset_duplicate_name(self, preset_service, sample_preset_data):
        """Test creating preset with duplicate name raises error."""
        # Create first preset
        await preset_service.create_preset(sample_preset_data)
        
        # Try to create with same name
        with pytest.raises(ValidationError) as exc_info:
            await preset_service.create_preset(sample_preset_data)
        
        assert "already exists" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_get_preset(self, preset_service, sample_preset_data):
        """Test getting a preset by ID."""
        created = await preset_service.create_preset(sample_preset_data)
        
        preset = await preset_service.get_preset(created.id)
        assert preset is not None
        assert preset.id == created.id
        assert preset.name == created.name
        
        # Test non-existent preset
        preset = await preset_service.get_preset("non-existent-id")
        assert preset is None
    
    @pytest.mark.asyncio
    async def test_list_presets(self, preset_service, sample_preset_data):
        """Test listing presets."""
        # Initially should have 3 built-in presets
        presets = await preset_service.list_presets()
        assert len(presets) == 3
        
        # Create custom preset
        await preset_service.create_preset(sample_preset_data)
        
        # Should now have 4 presets
        presets = await preset_service.list_presets()
        assert len(presets) == 4
        
        # Test excluding built-in
        custom_presets = await preset_service.list_presets(include_builtin=False)
        assert len(custom_presets) == 1
        assert custom_presets[0].name == sample_preset_data.name
    
    @pytest.mark.asyncio
    async def test_update_preset(self, preset_service, sample_preset_data):
        """Test updating a preset."""
        created = await preset_service.create_preset(sample_preset_data)
        
        # Update preset
        update_data = PresetUpdate(
            name="Updated Preset",
            description="Updated description",
            settings=PresetSettings(
                output_format="jpeg",
                quality=90
            )
        )
        
        updated = await preset_service.update_preset(created.id, update_data)
        assert updated is not None
        assert updated.name == "Updated Preset"
        assert updated.description == "Updated description"
        assert updated.settings.output_format == "jpeg"
        assert updated.settings.quality == 90
        assert updated.updated_at > created.updated_at
    
    @pytest.mark.asyncio
    async def test_update_preset_partial(self, preset_service, sample_preset_data):
        """Test partial update of preset."""
        created = await preset_service.create_preset(sample_preset_data)
        
        # Update only name
        update_data = PresetUpdate(name="New Name Only")
        updated = await preset_service.update_preset(created.id, update_data)
        
        assert updated.name == "New Name Only"
        assert updated.description == created.description  # Unchanged
        assert updated.settings.output_format == created.settings.output_format  # Unchanged
    
    @pytest.mark.asyncio
    async def test_update_builtin_preset(self, preset_service):
        """Test that built-in presets cannot be updated."""
        presets = await preset_service.list_presets()
        builtin = next(p for p in presets if p.is_builtin)
        
        update_data = PresetUpdate(name="Cannot Update")
        
        with pytest.raises(SecurityError) as exc_info:
            await preset_service.update_preset(builtin.id, update_data)
        
        assert "Cannot modify built-in presets" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_update_preset_duplicate_name(self, preset_service):
        """Test updating preset to duplicate name raises error."""
        # Create two presets
        preset1 = await preset_service.create_preset(
            PresetCreate(
                name="Preset 1",
                settings=PresetSettings(output_format="webp")
            )
        )
        preset2 = await preset_service.create_preset(
            PresetCreate(
                name="Preset 2",
                settings=PresetSettings(output_format="jpeg")
            )
        )
        
        # Try to update preset2 with preset1's name
        update_data = PresetUpdate(name="Preset 1")
        
        with pytest.raises(ValidationError) as exc_info:
            await preset_service.update_preset(preset2.id, update_data)
        
        assert "already exists" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_delete_preset(self, preset_service, sample_preset_data):
        """Test deleting a preset."""
        created = await preset_service.create_preset(sample_preset_data)
        
        # Delete preset
        deleted = await preset_service.delete_preset(created.id)
        assert deleted is True
        
        # Verify it's gone
        preset = await preset_service.get_preset(created.id)
        assert preset is None
        
        # Try to delete non-existent
        deleted = await preset_service.delete_preset("non-existent")
        assert deleted is False
    
    @pytest.mark.asyncio
    async def test_delete_builtin_preset(self, preset_service):
        """Test that built-in presets cannot be deleted."""
        presets = await preset_service.list_presets()
        builtin = next(p for p in presets if p.is_builtin)
        
        with pytest.raises(SecurityError) as exc_info:
            await preset_service.delete_preset(builtin.id)
        
        assert "Cannot delete built-in presets" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_import_presets(self, preset_service):
        """Test importing presets."""
        import_data = PresetImport(
            presets=[
                PresetBase(
                    name="Imported 1",
                    description="First import",
                    settings=PresetSettings(output_format="webp", quality=80)
                ),
                PresetBase(
                    name="Imported 2",
                    description="Second import",
                    settings=PresetSettings(output_format="jpeg", quality=90)
                )
            ]
        )
        
        imported = await preset_service.import_presets(import_data)
        assert len(imported) == 2
        assert imported[0].name == "Imported 1"
        assert imported[1].name == "Imported 2"
        assert all(not p.is_builtin for p in imported)
        
        # Verify they were saved
        all_presets = await preset_service.list_presets(include_builtin=False)
        assert len(all_presets) == 2
    
    @pytest.mark.asyncio
    async def test_import_presets_duplicate_name(self, preset_service, sample_preset_data):
        """Test importing presets with duplicate names fails."""
        # Create existing preset
        await preset_service.create_preset(sample_preset_data)
        
        # Try to import with same name
        import_data = PresetImport(
            presets=[
                PresetBase(
                    name=sample_preset_data.name,  # Duplicate!
                    settings=PresetSettings(output_format="jpeg")
                )
            ]
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await preset_service.import_presets(import_data)
        
        assert "already exists" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_export_preset(self, preset_service, sample_preset_data):
        """Test exporting a single preset."""
        created = await preset_service.create_preset(sample_preset_data)
        
        export = await preset_service.export_preset(created.id)
        assert export is not None
        assert export.preset.id == created.id
        assert export.preset.name == created.name
        assert export.export_version == "1.0"
        assert isinstance(export.exported_at, datetime)
        
        # Test non-existent preset
        export = await preset_service.export_preset("non-existent")
        assert export is None
    
    @pytest.mark.asyncio
    async def test_export_all_presets(self, preset_service):
        """Test exporting all user presets."""
        # Create some presets
        for i in range(3):
            await preset_service.create_preset(
                PresetCreate(
                    name=f"Export Test {i}",
                    settings=PresetSettings(output_format="webp", quality=80+i)
                )
            )
        
        exported = await preset_service.export_all_presets()
        assert len(exported) == 3  # Only user presets, not built-in
        assert all(isinstance(p, PresetBase) for p in exported)
        assert all(p.name.startswith("Export Test") for p in exported)