"""Unit tests for metadata functionality without sandboxing."""

from typing import Any
import io

import pytest
from PIL import Image

from app.core.security.metadata import MetadataStripper


class TestMetadataUnit:
    """Unit tests for metadata stripping."""

    @pytest.fixture
    def metadata_stripper(self) -> None:
        """Create metadata stripper instance."""
        return MetadataStripper()

    def test_simple_jpeg_metadata_removal(self, metadata_stripper) -> None:
        """Test basic JPEG metadata removal synchronously."""
        # Create a simple JPEG
        img = Image.new("RGB", (100, 100), color="red")

        # Save with basic info
        output = io.BytesIO()
        img.save(output, format="JPEG", quality=90)
        output.seek(0)
        original_data = output.read()

        # Synchronous wrapper for testing
        import asyncio

        # Strip metadata
        loop = asyncio.new_event_loop()
        stripped_data, summary = loop.run_until_complete(
            metadata_stripper.analyze_and_strip_metadata(
                original_data, "JPEG", preserve_metadata=False, preserve_gps=False
            )
        )

        # Basic checks
        assert len(stripped_data) > 0
        assert isinstance(summary, dict)
        assert "metadata_removed" in summary

    def test_metadata_detection(self, metadata_stripper) -> None:
        """Test metadata detection functionality."""
        # Create image with no metadata
        img = Image.new("RGB", (50, 50), color="blue")
        output = io.BytesIO()
        img.save(output, format="PNG")
        output.seek(0)

        # Get metadata info
        info = metadata_stripper.get_metadata_info(output.read(), "PNG")

        assert info["format"] == "PNG"
        assert info["has_exif"] is False
        assert info["has_gps"] is False

    def test_supported_formats(self, metadata_stripper) -> None:
        """Test that all supported formats can be processed."""
        formats_to_test = ["JPEG", "PNG", "BMP", "WEBP"]

        for format_name in formats_to_test:
            # Create test image
            mode = "RGBA" if format_name == "PNG" else "RGB"
            img = Image.new(mode, (50, 50), color="green")
            output = io.BytesIO()

            # Handle JPEG vs JPG
            save_format = "JPEG" if format_name == "JPG" else format_name
            img.save(output, format=save_format)
            output.seek(0)
            image_data = output.read()

            # Process with metadata stripper
            import asyncio

            loop = asyncio.new_event_loop()
            stripped_data, summary = loop.run_until_complete(
                metadata_stripper.analyze_and_strip_metadata(
                    image_data, format_name, preserve_metadata=False, preserve_gps=False
                )
            )

            # Verify we got valid data back
            assert len(stripped_data) > 0

            # Verify we can load the stripped image
            stripped_img = Image.open(io.BytesIO(stripped_data))
            assert stripped_img is not None
