"""Unit tests for preset data models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from app.models.schemas import (
    PresetBase,
    PresetCreate,
    PresetExport,
    PresetImport,
    PresetListResponse,
    PresetResponse,
    PresetSettings,
    PresetUpdate,
)


class TestPresetSettings:
    """Test PresetSettings model validation."""

    def test_valid_preset_settings(self):
        """Test creating valid preset settings."""
        settings = PresetSettings(
            output_format="webp",
            quality=85,
            optimization_mode="balanced",
            preserve_metadata=False,
        )
        assert settings.output_format == "webp"
        assert settings.quality == 85
        assert settings.optimization_mode == "balanced"
        assert settings.preserve_metadata is False

    def test_invalid_output_format(self):
        """Test invalid output format raises error."""
        with pytest.raises(ValidationError) as exc_info:
            PresetSettings(output_format="invalid_format", quality=85)
        assert "Unsupported output format" in str(exc_info.value)

    def test_quality_bounds(self):
        """Test quality value bounds."""
        # Valid range
        settings = PresetSettings(output_format="jpeg", quality=1)
        assert settings.quality == 1

        settings = PresetSettings(output_format="jpeg", quality=100)
        assert settings.quality == 100

        # Invalid - too low
        with pytest.raises(ValidationError):
            PresetSettings(output_format="jpeg", quality=0)

        # Invalid - too high
        with pytest.raises(ValidationError):
            PresetSettings(output_format="jpeg", quality=101)

    def test_invalid_optimization_mode(self):
        """Test invalid optimization mode raises error."""
        with pytest.raises(ValidationError) as exc_info:
            PresetSettings(output_format="webp", optimization_mode="invalid_mode")
        assert "Invalid optimization mode" in str(exc_info.value)

    def test_optional_fields(self):
        """Test optional fields in settings."""
        settings = PresetSettings(
            output_format="png",
            resize_options={"width": 800, "height": 600},
            advanced_settings={"compression_level": 9},
        )
        assert settings.resize_options == {"width": 800, "height": 600}
        assert settings.advanced_settings == {"compression_level": 9}


class TestPresetBase:
    """Test PresetBase model validation."""

    def test_valid_preset_base(self):
        """Test creating valid preset base."""
        preset = PresetBase(
            name="Web Optimized",
            description="Optimized for web use",
            settings=PresetSettings(output_format="webp", quality=85),
        )
        assert preset.name == "Web Optimized"
        assert preset.description == "Optimized for web use"
        assert preset.settings.output_format == "webp"

    def test_name_validation(self):
        """Test preset name validation."""
        # Valid names
        valid_names = [
            "Web Optimized",
            "Print-Quality",
            "Archive_Format",
            "My Preset 123",
        ]
        for name in valid_names:
            preset = PresetBase(
                name=name, settings=PresetSettings(output_format="webp")
            )
            assert preset.name == name.strip()

        # Invalid names
        invalid_names = [
            "Web@Optimized",  # Special chars
            "Print!Quality",
            "Archive#Format",
            "My$Preset",
        ]
        for name in invalid_names:
            with pytest.raises(ValidationError):
                PresetBase(name=name, settings=PresetSettings(output_format="webp"))

    def test_name_length_limits(self):
        """Test name length validation."""
        # Minimum length
        with pytest.raises(ValidationError):
            PresetBase(name="", settings=PresetSettings(output_format="webp"))

        # Maximum length
        long_name = "a" * 100
        preset = PresetBase(
            name=long_name, settings=PresetSettings(output_format="webp")
        )
        assert len(preset.name) == 100

        # Too long
        with pytest.raises(ValidationError):
            PresetBase(name="a" * 101, settings=PresetSettings(output_format="webp"))

    def test_description_length_limit(self):
        """Test description length validation."""
        long_desc = "a" * 500
        preset = PresetBase(
            name="Test",
            description=long_desc,
            settings=PresetSettings(output_format="webp"),
        )
        assert len(preset.description) == 500

        # Too long
        with pytest.raises(ValidationError):
            PresetBase(
                name="Test",
                description="a" * 501,
                settings=PresetSettings(output_format="webp"),
            )


class TestPresetUpdate:
    """Test PresetUpdate model validation."""

    def test_partial_update(self):
        """Test partial updates are allowed."""
        # Update only name
        update = PresetUpdate(name="New Name")
        assert update.name == "New Name"
        assert update.description is None
        assert update.settings is None

        # Update only settings
        update = PresetUpdate(settings=PresetSettings(output_format="jpeg", quality=90))
        assert update.name is None
        assert update.settings.output_format == "jpeg"

    def test_empty_update(self):
        """Test empty update is valid."""
        update = PresetUpdate()
        assert update.name is None
        assert update.description is None
        assert update.settings is None


class TestPresetResponse:
    """Test PresetResponse model."""

    def test_preset_response(self):
        """Test creating preset response."""
        now = datetime.utcnow()
        response = PresetResponse(
            id="12345",
            name="Test Preset",
            settings=PresetSettings(output_format="png"),
            is_builtin=True,
            created_at=now,
            updated_at=now,
        )
        assert response.id == "12345"
        assert response.is_builtin is True
        assert response.created_at == now


class TestPresetImport:
    """Test PresetImport model validation."""

    def test_valid_import(self):
        """Test valid preset import."""
        import_data = PresetImport(
            presets=[
                PresetBase(
                    name="Preset 1", settings=PresetSettings(output_format="webp")
                ),
                PresetBase(
                    name="Preset 2", settings=PresetSettings(output_format="jpeg")
                ),
            ]
        )
        assert len(import_data.presets) == 2

    def test_empty_import(self):
        """Test empty import raises error."""
        with pytest.raises(ValidationError) as exc_info:
            PresetImport(presets=[])
        assert "At least one preset must be provided" in str(exc_info.value)

    def test_too_many_presets(self):
        """Test import limit."""
        presets = [
            PresetBase(
                name=f"Preset {i}", settings=PresetSettings(output_format="webp")
            )
            for i in range(51)
        ]
        with pytest.raises(ValidationError) as exc_info:
            PresetImport(presets=presets)
        assert "Cannot import more than 50 presets" in str(exc_info.value)

    def test_duplicate_names(self):
        """Test duplicate names in import."""
        with pytest.raises(ValidationError) as exc_info:
            PresetImport(
                presets=[
                    PresetBase(
                        name="Duplicate", settings=PresetSettings(output_format="webp")
                    ),
                    PresetBase(
                        name="Duplicate", settings=PresetSettings(output_format="jpeg")
                    ),
                ]
            )
        assert "Duplicate preset names" in str(exc_info.value)


class TestPresetExport:
    """Test PresetExport model."""

    def test_preset_export(self):
        """Test creating preset export."""
        now = datetime.utcnow()
        preset_response = PresetResponse(
            id="12345",
            name="Test",
            settings=PresetSettings(output_format="webp"),
            is_builtin=False,
            created_at=now,
            updated_at=now,
        )

        export = PresetExport(preset=preset_response)
        assert export.preset.id == "12345"
        assert export.export_version == "1.0"
        assert isinstance(export.exported_at, datetime)
