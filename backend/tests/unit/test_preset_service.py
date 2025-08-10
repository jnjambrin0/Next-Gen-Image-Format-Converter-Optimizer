"""Unit tests for preset service."""

import os
import tempfile
from datetime import datetime
from typing import Any

import pytest
import pytest_asyncio

from app.core.exceptions import SecurityError, ValidationError
from app.models.schemas import (PresetBase, PresetCreate, PresetImport,
                                PresetSettings, PresetUpdate)
from app.services.preset_service import PresetService


@pytest_asyncio.fixture
async def preset_service():
    """Create a preset service with temporary database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_presets.db")
        service = PresetService(db_path=db_path)
        await service.initialize()
        yield service


@pytest.fixture
def sample_preset_data() -> None:
    """Sample preset creation data."""
    return PresetCreate(
        name="Test Preset",
        description="A test preset",
        settings=PresetSettings(
            output_format="webp",
            quality=85,
            optimization_mode="balanced",
            preserve_metadata=False,
        ),
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
        assert (
            preset.settings.output_format == sample_preset_data.settings.output_format
        )
        assert preset.settings.quality == sample_preset_data.settings.quality
        assert not preset.is_builtin
        assert preset.id is not None
        assert isinstance(preset.created_at, datetime)
        assert isinstance(preset.updated_at, datetime)

    @pytest.mark.asyncio
    async def test_create_preset_duplicate_name(
        self, preset_service, sample_preset_data
    ):
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
            settings=PresetSettings(output_format="jpeg", quality=90),
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
        assert (
            updated.settings.output_format == created.settings.output_format
        )  # Unchanged

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
            PresetCreate(name="Preset 1", settings=PresetSettings(output_format="webp"))
        )
        preset2 = await preset_service.create_preset(
            PresetCreate(name="Preset 2", settings=PresetSettings(output_format="jpeg"))
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
                    settings=PresetSettings(output_format="webp", quality=80),
                ),
                PresetBase(
                    name="Imported 2",
                    description="Second import",
                    settings=PresetSettings(output_format="jpeg", quality=90),
                ),
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
    async def test_import_presets_duplicate_name(
        self, preset_service, sample_preset_data
    ):
        """Test importing presets with duplicate names fails."""
        # Create existing preset
        await preset_service.create_preset(sample_preset_data)

        # Try to import with same name
        import_data = PresetImport(
            presets=[
                PresetBase(
                    name=sample_preset_data.name,  # Duplicate!
                    settings=PresetSettings(output_format="jpeg"),
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
                    settings=PresetSettings(output_format="webp", quality=80 + i),
                )
            )

        exported = await preset_service.export_all_presets()
        assert len(exported) == 3  # Only user presets, not built-in
        assert all(isinstance(p, PresetBase) for p in exported)
        assert all(p.name.startswith("Export Test") for p in exported)


class TestListPresetsAdvanced:
    """Test suite for list_presets_advanced method."""

    @pytest.mark.asyncio
    async def test_list_all_with_pagination_metadata(self, preset_service):
        """Test listing all presets returns correct metadata."""
        result = await preset_service.list_presets_advanced()

        assert "presets" in result
        assert "total" in result
        assert "page" in result
        assert "page_size" in result
        assert "total_pages" in result
        assert "has_next" in result
        assert "has_previous" in result

        # Should have 3 built-in presets
        assert result["total"] == 3
        assert len(result["presets"]) == 3
        assert result["page"] == 1
        assert result["has_next"] is False
        assert result["has_previous"] is False

    @pytest.mark.asyncio
    async def test_search_functionality(self, preset_service):
        """Test search in name and description."""
        # Create a preset with specific search terms
        await preset_service.create_preset(
            PresetCreate(
                name="Custom Photo Preset",
                description="Special preset for photo processing",
                settings=PresetSettings(output_format="jpeg", quality=95),
            )
        )

        # Search for "photo"
        result = await preset_service.list_presets_advanced(search="photo")

        assert result["total"] == 1
        assert len(result["presets"]) == 1
        assert (
            "photo" in result["presets"][0].name.lower()
            or "photo" in result["presets"][0].description.lower()
        )

        # Search for "web" should find "Web Optimized"
        result = await preset_service.list_presets_advanced(search="web")

        assert result["total"] >= 1
        found_web = any(
            "web" in p.name.lower() or "web" in p.description.lower()
            for p in result["presets"]
        )
        assert found_web

    @pytest.mark.asyncio
    async def test_format_filter(self, preset_service):
        """Test filtering by output format."""
        # Create presets with different formats
        await preset_service.create_preset(
            PresetCreate(
                name="AVIF Test",
                settings=PresetSettings(output_format="avif", quality=85),
            )
        )
        await preset_service.create_preset(
            PresetCreate(
                name="Another AVIF",
                settings=PresetSettings(output_format="avif", quality=90),
            )
        )

        # Filter by AVIF format
        result = await preset_service.list_presets_advanced(format_filter="avif")

        assert result["total"] == 2
        assert all(p.settings.output_format == "avif" for p in result["presets"])

        # Filter by WebP format (from built-in presets)
        result = await preset_service.list_presets_advanced(format_filter="webp")

        assert result["total"] >= 2  # At least 2 built-in presets use webp

    @pytest.mark.asyncio
    async def test_exclude_builtin(self, preset_service):
        """Test excluding built-in presets."""
        # Create custom presets
        for i in range(2):
            await preset_service.create_preset(
                PresetCreate(
                    name=f"Custom {i}",
                    settings=PresetSettings(output_format="jpeg", quality=85),
                )
            )

        # Get only custom presets
        result = await preset_service.list_presets_advanced(include_builtin=False)

        assert result["total"] == 2
        assert all(not p.is_builtin for p in result["presets"])

    @pytest.mark.asyncio
    async def test_sorting_by_name(self, preset_service):
        """Test sorting by name ascending and descending."""
        # Create presets with specific names
        await preset_service.create_preset(
            PresetCreate(name="Alpha", settings=PresetSettings(output_format="jpeg"))
        )
        await preset_service.create_preset(
            PresetCreate(name="Zeta", settings=PresetSettings(output_format="jpeg"))
        )

        # Sort ascending
        result = await preset_service.list_presets_advanced(
            include_builtin=False, sort_by="name", sort_order="asc"
        )

        names = [p.name for p in result["presets"]]
        assert names == sorted(names)

        # Sort descending
        result = await preset_service.list_presets_advanced(
            include_builtin=False, sort_by="name", sort_order="desc"
        )

        names = [p.name for p in result["presets"]]
        assert names == sorted(names, reverse=True)

    @pytest.mark.asyncio
    async def test_sorting_by_created_at(self, preset_service):
        """Test sorting by creation date."""
        # Sort by created_at works with existing presets created in other tests
        # Simply verify the sort functionality works without timing dependencies

        # Create a couple of presets
        await preset_service.create_preset(
            PresetCreate(
                name="SortTest1", settings=PresetSettings(output_format="jpeg")
            )
        )
        await preset_service.create_preset(
            PresetCreate(
                name="SortTest2", settings=PresetSettings(output_format="jpeg")
            )
        )

        # Sort by created_at ascending
        result = await preset_service.list_presets_advanced(
            include_builtin=False, sort_by="created_at", sort_order="asc"
        )

        # Verify we got results and they have created_at timestamps
        assert len(result["presets"]) >= 2
        for i in range(len(result["presets"]) - 1):
            # Each preset's created_at should be <= the next one
            assert (
                result["presets"][i].created_at <= result["presets"][i + 1].created_at
            )

        # Sort by created_at descending
        result = await preset_service.list_presets_advanced(
            include_builtin=False, sort_by="created_at", sort_order="desc"
        )

        # Verify descending order
        assert len(result["presets"]) >= 2
        for i in range(len(result["presets"]) - 1):
            # Each preset's created_at should be >= the next one
            assert (
                result["presets"][i].created_at >= result["presets"][i + 1].created_at
            )

    @pytest.mark.asyncio
    async def test_pagination_with_limit(self, preset_service):
        """Test pagination with limit and offset."""
        # Create 5 custom presets
        for i in range(5):
            await preset_service.create_preset(
                PresetCreate(
                    name=f"Page Test {i}",
                    settings=PresetSettings(output_format="jpeg", quality=80),
                )
            )

        # Get first page (2 items)
        result = await preset_service.list_presets_advanced(
            include_builtin=False, limit=2, offset=0
        )

        assert result["total"] == 5
        assert len(result["presets"]) == 2
        assert result["page"] == 1
        assert result["page_size"] == 2
        assert result["total_pages"] == 3
        assert result["has_next"] is True
        assert result["has_previous"] is False

        # Get second page
        result = await preset_service.list_presets_advanced(
            include_builtin=False, limit=2, offset=2
        )

        assert len(result["presets"]) == 2
        assert result["page"] == 2
        assert result["has_next"] is True
        assert result["has_previous"] is True

        # Get last page
        result = await preset_service.list_presets_advanced(
            include_builtin=False, limit=2, offset=4
        )

        assert len(result["presets"]) == 1
        assert result["page"] == 3
        assert result["has_next"] is False
        assert result["has_previous"] is True

    @pytest.mark.asyncio
    async def test_combined_filters(self, preset_service):
        """Test combining multiple filters."""
        # Create diverse presets
        await preset_service.create_preset(
            PresetCreate(
                name="WebP Ultra",
                description="Ultra quality WebP",
                settings=PresetSettings(output_format="webp", quality=100),
            )
        )
        await preset_service.create_preset(
            PresetCreate(
                name="JPEG Basic",
                description="Basic JPEG conversion",
                settings=PresetSettings(output_format="jpeg", quality=75),
            )
        )
        await preset_service.create_preset(
            PresetCreate(
                name="WebP Standard",
                description="Standard WebP preset",
                settings=PresetSettings(output_format="webp", quality=85),
            )
        )

        # Search for "webp" with format filter and sorting
        result = await preset_service.list_presets_advanced(
            include_builtin=False,
            search="webp",
            format_filter="webp",
            sort_by="name",
            sort_order="desc",
            limit=10,
        )

        # Should find both custom WebP presets
        assert result["total"] == 2
        assert all(
            "webp" in p.name.lower() or "webp" in p.description.lower()
            for p in result["presets"]
        )
        assert all(p.settings.output_format == "webp" for p in result["presets"])

        # Names should be in descending order
        names = [p.name for p in result["presets"]]
        assert names == sorted(names, reverse=True)

    @pytest.mark.asyncio
    async def test_no_results(self, preset_service):
        """Test when no presets match the filters."""
        # Search for non-existent term
        result = await preset_service.list_presets_advanced(search="nonexistentterm123")

        assert result["total"] == 0
        assert len(result["presets"]) == 0
        assert result["has_next"] is False
        assert result["has_previous"] is False

    @pytest.mark.asyncio
    async def test_usage_count_sorting_fallback(self, preset_service):
        """Test that usage_count sorting falls back to name sorting."""
        # Create presets
        await preset_service.create_preset(
            PresetCreate(name="Beta", settings=PresetSettings(output_format="jpeg"))
        )
        await preset_service.create_preset(
            PresetCreate(name="Alpha", settings=PresetSettings(output_format="jpeg"))
        )

        # Sort by usage_count (should fallback to name)
        result = await preset_service.list_presets_advanced(
            include_builtin=False, sort_by="usage_count", sort_order="asc"
        )

        # Should be sorted by name since usage_count isn't tracked
        names = [p.name for p in result["presets"]]
        assert names == ["Alpha", "Beta"]
