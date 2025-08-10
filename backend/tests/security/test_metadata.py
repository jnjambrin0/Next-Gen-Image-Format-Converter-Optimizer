"""Tests for metadata stripping functionality."""

import asyncio
import io
from pathlib import Path

import piexif
import pytest
from PIL import Image
from PIL.ExifTags import TAGS

from app.core.security.engine import SecurityEngine
from app.core.security.metadata import MetadataStripper


class TestMetadataStripper:
    """Test metadata stripping functionality."""

    @pytest.fixture
    def metadata_stripper(self):
        """Create metadata stripper instance."""
        return MetadataStripper()

    @pytest.fixture
    def security_engine(self):
        """Create security engine instance."""
        return SecurityEngine()

    @pytest.fixture
    def sample_image_with_exif(self):
        """Create a sample JPEG image with EXIF data."""
        # Create a simple image
        img = Image.new("RGB", (100, 100), color="red")

        # Create EXIF data with GPS info
        zeroth_ifd = {
            piexif.ImageIFD.Make: b"Test Camera",
            piexif.ImageIFD.Model: b"Test Model",
            piexif.ImageIFD.Software: b"Test Software",
            piexif.ImageIFD.DateTime: b"2024:01:01 12:00:00",
            piexif.ImageIFD.Artist: b"Test Artist",
        }

        exif_ifd = {
            piexif.ExifIFD.DateTimeOriginal: b"2024:01:01 12:00:00",
            piexif.ExifIFD.UserComment: b"Test Comment",
        }

        gps_ifd = {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((37, 1), (46, 1), (30, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: ((122, 1), (25, 1), (0, 1)),
            piexif.GPSIFD.GPSAltitude: (10, 1),
        }

        # Create thumbnail
        thumbnail = Image.new("RGB", (20, 20), color="blue")
        thumbnail_bytes = io.BytesIO()
        thumbnail.save(thumbnail_bytes, format="JPEG")

        exif_dict = {
            "0th": zeroth_ifd,
            "Exif": exif_ifd,
            "GPS": gps_ifd,
            "1st": {},
            "thumbnail": thumbnail_bytes.getvalue(),
        }

        exif_bytes = piexif.dump(exif_dict)

        # Save image with EXIF
        output = io.BytesIO()
        img.save(output, format="JPEG", exif=exif_bytes)
        output.seek(0)

        return output.read()

    @pytest.fixture
    def sample_png_with_metadata(self):
        """Create a sample PNG image with metadata."""
        img = Image.new("RGBA", (100, 100), color="green")

        # Add text metadata
        from PIL import PngImagePlugin

        pnginfo = PngImagePlugin.PngInfo()
        pnginfo.add_text("Author", "Test Author")
        pnginfo.add_text("Description", "Test Description")
        pnginfo.add_text("Software", "Test Software")

        output = io.BytesIO()
        img.save(output, format="PNG", pnginfo=pnginfo)
        output.seek(0)

        return output.read()

    @pytest.mark.asyncio
    async def test_strip_all_metadata_from_jpeg(
        self, metadata_stripper, sample_image_with_exif
    ):
        """Test complete metadata removal from JPEG."""
        # Strip metadata
        stripped_data, summary = await metadata_stripper.analyze_and_strip_metadata(
            sample_image_with_exif, "JPEG", preserve_metadata=False, preserve_gps=False
        )

        # Verify metadata was detected
        assert summary["had_exif"] is True
        assert summary["had_gps"] is True
        assert summary["had_thumbnail"] is True

        # Verify metadata was removed
        assert summary["gps_removed"] is True
        assert "all_exif" in summary["metadata_removed"]

        # Load stripped image and verify no EXIF
        stripped_img = Image.open(io.BytesIO(stripped_data))
        assert not hasattr(stripped_img, "_getexif") or stripped_img._getexif() is None

    @pytest.mark.asyncio
    async def test_preserve_metadata_but_remove_gps(
        self, metadata_stripper, sample_image_with_exif
    ):
        """Test preserving metadata while removing GPS."""
        # Strip only GPS
        stripped_data, summary = await metadata_stripper.analyze_and_strip_metadata(
            sample_image_with_exif, "JPEG", preserve_metadata=True, preserve_gps=False
        )

        # Verify GPS was removed
        assert summary["gps_removed"] is True
        assert "GPS" in summary["metadata_removed"]
        assert "basic_exif" in summary["metadata_preserved"]

        # Load stripped image
        stripped_img = Image.open(io.BytesIO(stripped_data))

        # Verify EXIF exists but no GPS
        if hasattr(stripped_img, "_getexif") and stripped_img._getexif():
            exif = stripped_img._getexif()
            # GPS IFD tag (34853) should not be present
            assert 34853 not in exif

    @pytest.mark.asyncio
    async def test_preserve_all_metadata(
        self, metadata_stripper, sample_image_with_exif
    ):
        """Test preserving all metadata including GPS."""
        # Preserve everything
        stripped_data, summary = await metadata_stripper.analyze_and_strip_metadata(
            sample_image_with_exif, "JPEG", preserve_metadata=True, preserve_gps=True
        )

        # Verify nothing was removed
        assert summary["gps_removed"] is False
        assert "all" in summary["metadata_preserved"]
        assert len(summary["metadata_removed"]) == 0

        # Data should be unchanged
        assert stripped_data == sample_image_with_exif

    @pytest.mark.asyncio
    async def test_strip_png_metadata(
        self, metadata_stripper, sample_png_with_metadata
    ):
        """Test metadata removal from PNG."""
        # Strip metadata
        stripped_data, summary = await metadata_stripper.analyze_and_strip_metadata(
            sample_png_with_metadata, "PNG", preserve_metadata=False, preserve_gps=False
        )

        # Verify metadata was removed
        assert len(summary["metadata_removed"]) > 0

        # Load stripped image
        stripped_img = Image.open(io.BytesIO(stripped_data))

        # PNG text chunks should be gone
        assert "Author" not in stripped_img.info
        assert "Description" not in stripped_img.info

    @pytest.mark.asyncio
    async def test_security_engine_integration(
        self, security_engine, sample_image_with_exif
    ):
        """Test metadata stripping through SecurityEngine."""
        # Strip metadata using SecurityEngine
        stripped_data, summary = await security_engine.strip_metadata(
            sample_image_with_exif, "JPEG", preserve_metadata=False, preserve_gps=False
        )

        # Verify it worked
        assert summary["had_exif"] is True
        assert summary["gps_removed"] is True
        assert len(stripped_data) < len(sample_image_with_exif)  # Should be smaller

    @pytest.mark.asyncio
    async def test_handle_image_without_metadata(self, metadata_stripper):
        """Test handling images that have no metadata."""
        # Create image without metadata
        img = Image.new("RGB", (50, 50), color="blue")
        output = io.BytesIO()
        img.save(output, format="JPEG")
        output.seek(0)
        image_data = output.read()

        # Try to strip metadata
        stripped_data, summary = await metadata_stripper.analyze_and_strip_metadata(
            image_data, "JPEG", preserve_metadata=False, preserve_gps=False
        )

        # Verify no metadata was found
        assert summary["had_exif"] is False
        assert summary["had_gps"] is False
        assert summary["gps_removed"] is False

    @pytest.mark.asyncio
    async def test_sensitive_exif_tag_removal(self, metadata_stripper):
        """Test removal of sensitive EXIF tags while preserving others."""
        # Create image with various EXIF tags
        img = Image.new("RGB", (100, 100), color="yellow")

        zeroth_ifd = {
            piexif.ImageIFD.Make: b"Camera Brand",  # Sensitive
            piexif.ImageIFD.Model: b"Camera Model",  # Sensitive
            piexif.ImageIFD.Orientation: 1,  # Not sensitive
            piexif.ImageIFD.XResolution: (72, 1),  # Not sensitive
            piexif.ImageIFD.YResolution: (72, 1),  # Not sensitive
            piexif.ImageIFD.Artist: b"John Doe",  # Sensitive
            piexif.ImageIFD.Copyright: b"Copyright 2024",  # Sensitive
        }

        exif_dict = {"0th": zeroth_ifd}
        exif_bytes = piexif.dump(exif_dict)

        output = io.BytesIO()
        img.save(output, format="JPEG", exif=exif_bytes)
        output.seek(0)
        image_data = output.read()

        # Strip with preserve_metadata=True (should remove sensitive tags)
        stripped_data, summary = await metadata_stripper.analyze_and_strip_metadata(
            image_data, "JPEG", preserve_metadata=True, preserve_gps=False
        )

        # Verify sensitive tags were removed
        assert any("Make" in item for item in summary["metadata_removed"])
        assert any("Model" in item for item in summary["metadata_removed"])
        assert any("Artist" in item for item in summary["metadata_removed"])
        assert "basic_exif" in summary["metadata_preserved"]

    @pytest.mark.asyncio
    async def test_error_handling(self, metadata_stripper):
        """Test error handling with corrupted data."""
        # Provide invalid image data
        invalid_data = b"This is not an image"

        # Should return original data on error
        stripped_data, summary = await metadata_stripper.analyze_and_strip_metadata(
            invalid_data, "JPEG", preserve_metadata=False, preserve_gps=False
        )

        # Should return original data
        assert stripped_data == invalid_data

    @pytest.mark.asyncio
    async def test_metadata_info_extraction(
        self, metadata_stripper, sample_image_with_exif
    ):
        """Test metadata info extraction for logging."""
        info = metadata_stripper.get_metadata_info(sample_image_with_exif, "JPEG")

        assert info["format"] == "JPEG"
        assert info["has_exif"] is True
        assert info["has_gps"] is True
        assert info["exif_tags_count"] > 0

    @pytest.mark.asyncio
    async def test_different_image_formats(self, metadata_stripper):
        """Test metadata stripping for different formats."""
        formats_to_test = [
            ("JPEG", "RGB"),
            ("PNG", "RGBA"),
            ("BMP", "RGB"),
            ("TIFF", "RGB"),
            ("WEBP", "RGB"),
        ]

        for format_name, mode in formats_to_test:
            # Create test image
            img = Image.new(mode, (50, 50), color="red")
            output = io.BytesIO()

            # Add some metadata if format supports it
            if format_name == "JPEG":
                exif_dict = {"0th": {piexif.ImageIFD.Make: b"Test"}}
                exif_bytes = piexif.dump(exif_dict)
                img.save(output, format=format_name, exif=exif_bytes)
            else:
                img.save(output, format=format_name)

            output.seek(0)
            image_data = output.read()

            # Strip metadata
            stripped_data, summary = await metadata_stripper.analyze_and_strip_metadata(
                image_data, format_name, preserve_metadata=False, preserve_gps=False
            )

            # Verify we got valid image data back
            assert len(stripped_data) > 0

            # Verify we can load the stripped image
            stripped_img = Image.open(io.BytesIO(stripped_data))
            assert stripped_img.format == format_name
