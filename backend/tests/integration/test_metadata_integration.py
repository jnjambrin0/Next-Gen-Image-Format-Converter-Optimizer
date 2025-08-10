"""Integration tests for metadata stripping in the conversion pipeline."""

import asyncio
import io
from pathlib import Path

import piexif
import pytest
from PIL import Image

from app.core.conversion.manager import ConversionManager
from app.core.security.engine import SecurityEngine
from app.models.conversion import ConversionRequest, ConversionSettings, OutputFormat


class TestMetadataIntegration:
    """Test metadata handling in the full conversion pipeline."""

    @pytest.fixture
    def conversion_manager(self):
        """Create conversion manager instance."""
        return ConversionManager()

    @pytest.fixture
    def jpeg_with_metadata(self):
        """Create JPEG with comprehensive metadata."""
        img = Image.new("RGB", (200, 200), color="blue")

        # Create rich EXIF data
        zeroth_ifd = {
            piexif.ImageIFD.Make: b"Canon",
            piexif.ImageIFD.Model: b"EOS 5D Mark IV",
            piexif.ImageIFD.Software: b"Adobe Photoshop",
            piexif.ImageIFD.DateTime: b"2024:01:15 10:30:00",
            piexif.ImageIFD.Artist: b"John Photographer",
            piexif.ImageIFD.Copyright: b"Copyright 2024",
        }

        exif_ifd = {
            piexif.ExifIFD.DateTimeOriginal: b"2024:01:15 10:30:00",
            piexif.ExifIFD.UserComment: b"Beautiful sunset photo",
            piexif.ExifIFD.CameraOwnerName: b"John Doe",
            piexif.ExifIFD.BodySerialNumber: b"1234567890",
        }

        gps_ifd = {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((40, 1), (42, 1), (51, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: ((74, 1), (0, 1), (23, 1)),
            piexif.GPSIFD.GPSAltitude: (30, 1),
            piexif.GPSIFD.GPSDateStamp: b"2024:01:15",
        }

        # Add thumbnail
        thumbnail = Image.new("RGB", (40, 40), color="red")
        thumb_bytes = io.BytesIO()
        thumbnail.save(thumb_bytes, format="JPEG")

        exif_dict = {
            "0th": zeroth_ifd,
            "Exif": exif_ifd,
            "GPS": gps_ifd,
            "1st": {},
            "thumbnail": thumb_bytes.getvalue(),
        }

        exif_bytes = piexif.dump(exif_dict)

        output = io.BytesIO()
        img.save(output, format="JPEG", exif=exif_bytes, quality=95)
        output.seek(0)

        return output.read()

    @pytest.mark.asyncio
    async def test_default_metadata_stripping(
        self, conversion_manager, jpeg_with_metadata
    ):
        """Test that metadata is stripped by default."""
        # Create conversion request with default settings
        request = ConversionRequest(output_format=OutputFormat.PNG)

        # Convert
        result = await conversion_manager.convert_image(
            jpeg_with_metadata, "jpeg", request
        )

        # Verify metadata was removed
        assert result.metadata_removed is True
        assert "metadata_summary" in result.quality_settings

        # Check the output doesn't have EXIF
        output_data = result._output_data
        output_img = Image.open(io.BytesIO(output_data))

        # PNG shouldn't have EXIF after stripping
        assert "exif" not in output_img.info

    @pytest.mark.asyncio
    async def test_preserve_metadata_no_gps(
        self, conversion_manager, jpeg_with_metadata
    ):
        """Test preserving metadata while removing GPS."""
        # Create request to preserve metadata but not GPS
        request = ConversionRequest(
            output_format=OutputFormat.JPEG,
            settings=ConversionSettings(
                strip_metadata=False,
                preserve_metadata=True,
                preserve_gps=False,
                quality=90,
            ),
        )

        # Convert
        result = await conversion_manager.convert_image(
            jpeg_with_metadata, "jpeg", request
        )

        # Verify GPS was removed but other metadata preserved
        assert result.metadata_removed is True  # Some metadata was removed (GPS)
        summary = result.quality_settings.get("metadata_summary", {})
        assert summary.get("gps_removed") is True
        assert "basic_exif" in summary.get("metadata_preserved", [])

        # Verify output has EXIF but no GPS
        output_data = result._output_data
        output_img = Image.open(io.BytesIO(output_data))

        if hasattr(output_img, "_getexif") and output_img._getexif():
            exif = output_img._getexif()
            # GPS IFD should not be present
            assert piexif.ImageIFD.GPSInfo not in exif

    @pytest.mark.asyncio
    async def test_preserve_all_metadata(self, conversion_manager, jpeg_with_metadata):
        """Test preserving all metadata including GPS."""
        # Create request to preserve everything
        request = ConversionRequest(
            output_format=OutputFormat.JPEG,
            settings=ConversionSettings(
                strip_metadata=False,
                preserve_metadata=True,
                preserve_gps=True,
                quality=90,
            ),
        )

        # Convert
        result = await conversion_manager.convert_image(
            jpeg_with_metadata, "jpeg", request
        )

        # Verify nothing was removed
        assert result.metadata_removed is False
        summary = result.quality_settings.get("metadata_summary", {})
        assert summary.get("gps_removed") is False
        assert "all" in summary.get("metadata_preserved", [])

    @pytest.mark.asyncio
    async def test_strip_metadata_explicit(
        self, conversion_manager, jpeg_with_metadata
    ):
        """Test explicit metadata stripping with strip_metadata=True."""
        # Create request with explicit strip_metadata
        request = ConversionRequest(
            output_format=OutputFormat.WEBP,
            settings=ConversionSettings(
                strip_metadata=True,
                preserve_metadata=False,  # Should be ignored when strip_metadata=True
                quality=85,
            ),
        )

        # Convert
        result = await conversion_manager.convert_image(
            jpeg_with_metadata, "jpeg", request
        )

        # Verify metadata was removed
        assert result.metadata_removed is True
        summary = result.quality_settings.get("metadata_summary", {})
        assert len(summary.get("metadata_removed", [])) > 0

    @pytest.mark.asyncio
    async def test_format_conversion_metadata_handling(
        self, conversion_manager, jpeg_with_metadata
    ):
        """Test metadata handling across different format conversions."""
        formats_to_test = [
            (OutputFormat.PNG, ConversionSettings(strip_metadata=True)),
            (OutputFormat.WEBP, ConversionSettings(strip_metadata=True)),
            (
                OutputFormat.JPEG,
                ConversionSettings(preserve_metadata=True, preserve_gps=False),
            ),
        ]

        for output_format, settings in formats_to_test:
            request = ConversionRequest(output_format=output_format, settings=settings)

            result = await conversion_manager.convert_image(
                jpeg_with_metadata, "jpeg", request
            )

            # All should complete successfully
            assert result.status.value == "completed"

            # Check metadata handling based on settings
            if settings.strip_metadata and not settings.preserve_metadata:
                assert result.metadata_removed is True
            elif settings.preserve_metadata and not settings.preserve_gps:
                # GPS should be removed
                summary = result.quality_settings.get("metadata_summary", {})
                assert summary.get("gps_removed") is True

    @pytest.mark.asyncio
    async def test_image_without_metadata(self, conversion_manager):
        """Test handling images that have no metadata."""
        # Create simple image without metadata
        img = Image.new("RGB", (100, 100), color="green")
        output = io.BytesIO()
        img.save(output, format="JPEG", quality=90)
        output.seek(0)
        image_data = output.read()

        # Convert with metadata stripping
        request = ConversionRequest(
            output_format=OutputFormat.PNG,
            settings=ConversionSettings(strip_metadata=True),
        )

        result = await conversion_manager.convert_image(image_data, "jpeg", request)

        # Should complete successfully
        assert result.status.value == "completed"

        # No metadata should have been removed
        summary = result.quality_settings.get("metadata_summary", {})
        assert summary.get("had_exif") is False
        assert summary.get("had_gps") is False

    @pytest.mark.asyncio
    async def test_batch_conversion_metadata(self, conversion_manager):
        """Test metadata handling in batch conversions."""
        # Create multiple images with different metadata
        images = []

        # Image 1: With GPS
        img1 = Image.new("RGB", (50, 50), color="red")
        gps_dict = {
            "GPS": {
                piexif.GPSIFD.GPSLatitudeRef: b"N",
                piexif.GPSIFD.GPSLatitude: ((37, 1), (0, 1), (0, 1)),
            }
        }
        exif1 = piexif.dump(gps_dict)
        output1 = io.BytesIO()
        img1.save(output1, format="JPEG", exif=exif1)
        output1.seek(0)
        images.append(("image1.jpg", output1.read()))

        # Image 2: Without metadata
        img2 = Image.new("RGB", (50, 50), color="green")
        output2 = io.BytesIO()
        img2.save(output2, format="JPEG")
        output2.seek(0)
        images.append(("image2.jpg", output2.read()))

        # Convert both with metadata stripping
        request = ConversionRequest(
            output_format=OutputFormat.PNG,
            settings=ConversionSettings(strip_metadata=True),
        )

        results = []
        for name, data in images:
            result = await conversion_manager.convert_image(data, "jpeg", request)
            results.append(result)

        # First image should have metadata removed
        assert results[0].metadata_removed is True
        summary1 = results[0].quality_settings.get("metadata_summary", {})
        assert summary1.get("had_gps") is True
        assert summary1.get("gps_removed") is True

        # Second image had no metadata
        summary2 = results[1].quality_settings.get("metadata_summary", {})
        assert summary2.get("had_exif") is False

    @pytest.mark.asyncio
    async def test_metadata_error_recovery(self, conversion_manager):
        """Test that conversion continues even if metadata stripping fails."""
        # Create a valid image
        img = Image.new("RGB", (100, 100), color="purple")
        output = io.BytesIO()
        img.save(output, format="JPEG")
        output.seek(0)
        image_data = output.read()

        # Request conversion with metadata stripping
        request = ConversionRequest(
            output_format=OutputFormat.PNG,
            settings=ConversionSettings(strip_metadata=True),
        )

        # Even if metadata stripping has issues, conversion should succeed
        result = await conversion_manager.convert_image(image_data, "jpeg", request)

        assert result.status.value == "completed"
        assert result.output_size > 0
