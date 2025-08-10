"""Unit tests for format alias system."""

import pytest
from unittest.mock import Mock, patch

from app.core.conversion.manager import ConversionManager
from app.core.conversion.formats.base import BaseFormatHandler
from app.core.constants import FORMAT_ALIASES, CANONICAL_FORMATS
from app.core.exceptions import UnsupportedFormatError


class MockHandler(BaseFormatHandler):
    """Mock format handler for testing."""

    def __init__(self, format_name: str):
        super().__init__()
        self.format_name = format_name
        self.supported_formats = [format_name]

    def can_handle(self, format_name: str) -> bool:
        return format_name.lower() in self.supported_formats

    def validate_image(self, image_data: bytes) -> bool:
        return True

    def load_image(self, image_data: bytes):
        return Mock()

    def save_image(self, image, output_buffer, settings):
        output_buffer.write(b"mock output")


class TestFormatAliases:
    """Test suite for format alias functionality."""

    def test_format_aliases_defined(self):
        """Test that format aliases are properly defined."""
        assert "jpg" in FORMAT_ALIASES
        assert FORMAT_ALIASES["jpg"] == "jpeg"

        assert "jpeg_optimized" in FORMAT_ALIASES
        assert FORMAT_ALIASES["jpeg_optimized"] == "jpeg_opt"

        assert "jpegxl" in FORMAT_ALIASES
        assert FORMAT_ALIASES["jpegxl"] == "jxl"

        assert "tif" in FORMAT_ALIASES
        assert FORMAT_ALIASES["tif"] == "tiff"

    def test_canonical_formats_defined(self):
        """Test that canonical formats are properly defined."""
        assert "jpeg" in CANONICAL_FORMATS
        assert "png" in CANONICAL_FORMATS
        assert "jxl" in CANONICAL_FORMATS
        assert "jpeg_opt" in CANONICAL_FORMATS

        # Aliases should not be in canonical formats
        assert "jpg" not in CANONICAL_FORMATS
        assert "jpegxl" not in CANONICAL_FORMATS

    def test_resolve_format_name(self):
        """Test format name resolution."""
        manager = ConversionManager()

        # Test alias resolution
        assert manager._resolve_format_name("jpg") == "jpeg"
        assert manager._resolve_format_name("jpeg_optimized") == "jpeg_opt"
        assert manager._resolve_format_name("jpegxl") == "jxl"

        # Test canonical names pass through
        assert manager._resolve_format_name("jpeg") == "jpeg"
        assert manager._resolve_format_name("png") == "png"

        # Test unknown formats pass through
        assert manager._resolve_format_name("unknown") == "unknown"

    def test_register_handler_with_alias(self):
        """Test handler registration with aliases."""
        manager = ConversionManager()
        manager.format_handlers.clear()
        manager.available_formats.clear()

        # Register handler with aliased name
        handler_class = lambda: MockHandler("jpeg")
        manager.register_handler("jpg", handler_class)

        # Should be registered under both names
        assert "jpg" in manager.format_handlers
        assert "jpeg" in manager.format_handlers
        assert "jpg" in manager.available_formats
        assert "jpeg" in manager.available_formats

    def test_get_format_with_fallback_alias(self):
        """Test format fallback with aliases."""
        manager = ConversionManager()
        manager.format_handlers.clear()
        manager.available_formats.clear()

        # Register JPEG handler
        manager.register_handler("jpeg", lambda: MockHandler("jpeg"))

        # Request by alias should work
        format_to_use, is_fallback = manager.get_format_with_fallback("jpg")
        assert format_to_use == "jpeg"
        assert is_fallback is False

        # Request optimized JPEG should fallback
        format_to_use, is_fallback = manager.get_format_with_fallback("jpeg_optimized")
        assert format_to_use == "jpeg"
        assert is_fallback is True

    def test_format_fallback_chains(self):
        """Test that fallback chains use canonical names."""
        manager = ConversionManager()

        # Check fallback definitions
        assert "jxl" in manager.format_fallbacks
        assert "jpeg_opt" in manager.format_fallbacks
        assert "png_opt" in manager.format_fallbacks

        # Aliases should not be in fallback definitions
        assert "jpegxl" not in manager.format_fallbacks
        assert "jpeg_optimized" not in manager.format_fallbacks

    def test_is_format_available_with_alias(self):
        """Test format availability check with aliases."""
        manager = ConversionManager()
        manager.format_handlers.clear()
        manager.available_formats.clear()

        # Register PNG handler
        manager.register_handler("png", lambda: MockHandler("png"))

        # Direct format available
        assert manager.is_format_available("png") is True

        # Format with fallback available
        assert manager.is_format_available("png_optimized") is True
        assert manager.is_format_available("png_opt") is True

    def test_handler_initialization_consolidation(self):
        """Test that handler initialization is consolidated."""
        # This is more of an integration test
        manager = ConversionManager()

        # JPEG variants should all use same handler
        if "jpeg" in manager.format_handlers and "jpg" in manager.format_handlers:
            assert manager.format_handlers["jpeg"] == manager.format_handlers["jpg"]

        # TIFF variants should use same handler
        if "tiff" in manager.format_handlers and "tif" in manager.format_handlers:
            assert manager.format_handlers["tiff"] == manager.format_handlers["tif"]

    def test_all_aliases_have_canonical(self):
        """Test that all aliases map to valid canonical formats."""
        for alias, canonical in FORMAT_ALIASES.items():
            # Skip if it's a special case (optimized variants)
            if canonical.endswith("_opt"):
                continue
            assert (
                canonical in CANONICAL_FORMATS
            ), f"Alias {alias} maps to {canonical} which is not canonical"

    def test_no_circular_aliases(self):
        """Test that there are no circular alias definitions."""
        for alias, canonical in FORMAT_ALIASES.items():
            # Canonical should not itself be an alias
            assert (
                canonical not in FORMAT_ALIASES
            ), f"Circular alias: {alias} -> {canonical}"

    def test_format_case_insensitive(self):
        """Test that format resolution is case-insensitive."""
        manager = ConversionManager()

        assert manager._resolve_format_name("JPG") == "jpeg"
        assert manager._resolve_format_name("JPEG_OPTIMIZED") == "jpeg_opt"
        assert manager._resolve_format_name("JpegXL") == "jxl"
