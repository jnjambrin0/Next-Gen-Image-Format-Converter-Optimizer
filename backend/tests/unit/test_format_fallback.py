"""Unit tests for format fallback system."""

import pytest
from unittest.mock import Mock, patch
from typing import Set

# Import fixtures
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.conversion.manager import ConversionManager
from app.core.conversion.formats.base import BaseFormatHandler
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


class TestFormatFallback:
    """Test suite for format fallback functionality."""

    @pytest.fixture
    def conversion_manager(self):
        """Create a conversion manager with mock handlers."""
        manager = ConversionManager()
        # Clear default handlers
        manager.format_handlers.clear()
        manager.available_formats.clear()
        return manager

    def test_direct_format_available(self, conversion_manager):
        """Test when requested format is directly available."""
        # Register handler
        conversion_manager.register_handler("webp", lambda: MockHandler("webp"))

        # Request format that's available
        format_to_use, is_fallback = conversion_manager.get_format_with_fallback("webp")

        assert format_to_use == "webp"
        assert is_fallback is False

    def test_fallback_to_first_available(self, conversion_manager):
        """Test fallback to first available format in chain."""
        # Register only PNG handler
        conversion_manager.register_handler("png", lambda: MockHandler("png"))

        # Request WebP2 which should fallback to PNG
        format_to_use, is_fallback = conversion_manager.get_format_with_fallback(
            "webp2"
        )

        assert format_to_use == "png"
        assert is_fallback is True

    def test_fallback_chain_order(self, conversion_manager):
        """Test that fallback follows the defined chain order."""
        # WebP2 fallback chain is ["webp", "png"]
        # Register both, should pick webp first
        conversion_manager.register_handler("png", lambda: MockHandler("png"))
        conversion_manager.register_handler("webp", lambda: MockHandler("webp"))

        format_to_use, is_fallback = conversion_manager.get_format_with_fallback(
            "webp2"
        )

        assert format_to_use == "webp"
        assert is_fallback is True

    def test_no_fallback_available(self, conversion_manager):
        """Test when no fallback is available."""
        # Don't register any handlers

        with pytest.raises(UnsupportedFormatError) as exc_info:
            conversion_manager.get_format_with_fallback("webp2")

        assert "webp2" in str(exc_info.value)
        assert "no fallback found" in str(exc_info.value)

    def test_format_without_fallback_definition(self, conversion_manager):
        """Test format that has no fallback defined."""
        # Request a format not in fallback mapping
        with pytest.raises(UnsupportedFormatError) as exc_info:
            conversion_manager.get_format_with_fallback("unknown_format")

        assert "unknown_format" in str(exc_info.value)

    def test_is_format_available_direct(self, conversion_manager):
        """Test is_format_available for directly available format."""
        conversion_manager.register_handler("jpeg", lambda: MockHandler("jpeg"))

        assert conversion_manager.is_format_available("jpeg") is True
        assert conversion_manager.is_format_available("png") is False

    def test_is_format_available_via_fallback(self, conversion_manager):
        """Test is_format_available for format available via fallback."""
        # Register PNG which is a fallback for jpeg_xl
        conversion_manager.register_handler("png", lambda: MockHandler("png"))

        assert conversion_manager.is_format_available("jpeg_xl") is True
        assert (
            conversion_manager.is_format_available("webp2") is True
        )  # png is a fallback for webp2

        # Test format with no fallback available
        assert conversion_manager.is_format_available("unknown_format") is False

    def test_get_available_formats_includes_fallbacks(self, conversion_manager):
        """Test that get_available_formats includes formats with working fallbacks."""
        # Register some handlers
        conversion_manager.register_handler("jpeg", lambda: MockHandler("jpeg"))
        conversion_manager.register_handler("png", lambda: MockHandler("png"))
        conversion_manager.register_handler("webp", lambda: MockHandler("webp"))

        available = conversion_manager.get_available_formats()

        # Should include direct formats
        assert "jpeg" in available
        assert "png" in available
        assert "webp" in available

        # Should include formats that have working fallbacks
        assert "jpeg_xl" in available  # Falls back to webp or png
        assert "webp2" in available  # Falls back to webp
        assert "jpeg_optimized" in available  # Falls back to jpeg

        # Should be sorted
        assert available == sorted(available)

    def test_optimized_format_fallback(self, conversion_manager):
        """Test optimized format fallback to regular format."""
        # Register regular JPEG handler
        conversion_manager.register_handler("jpeg", lambda: MockHandler("jpeg"))

        # Request optimized JPEG
        format_to_use, is_fallback = conversion_manager.get_format_with_fallback(
            "jpeg_optimized"
        )

        assert format_to_use == "jpeg"
        assert is_fallback is True

    def test_case_insensitive_format_lookup(self, conversion_manager):
        """Test that format lookup is case-insensitive."""
        conversion_manager.register_handler("JPEG", lambda: MockHandler("jpeg"))

        # Various case combinations
        assert conversion_manager.is_format_available("jpeg") is True
        assert conversion_manager.is_format_available("JPEG") is True
        assert conversion_manager.is_format_available("Jpeg") is True

    def test_fallback_mapping_completeness(self, conversion_manager):
        """Test that all fallback formats are valid."""
        # Verify all formats in fallback chains are recognized format names
        all_formats = set()
        for fallbacks in conversion_manager.format_fallbacks.values():
            all_formats.update(fallbacks)

        # These should all be valid format names
        expected_formats = {"webp", "png", "jpeg", "jpg"}
        assert all_formats.issubset(expected_formats)

    @pytest.mark.parametrize(
        "format_name,expected_fallbacks",
        [
            ("webp2", ["webp", "png"]),
            ("jpeg_xl", ["webp", "png"]),
            ("jpeg_optimized", ["jpeg", "jpg"]),
            ("png_optimized", ["png"]),
            ("heif", ["jpeg", "png"]),
            ("avif", ["webp", "png"]),
            ("jp2", ["jpeg", "png"]),
        ],
    )
    def test_specific_fallback_chains(
        self, conversion_manager, format_name, expected_fallbacks
    ):
        """Test specific fallback chains are correctly defined."""
        assert conversion_manager.format_fallbacks[format_name] == expected_fallbacks
