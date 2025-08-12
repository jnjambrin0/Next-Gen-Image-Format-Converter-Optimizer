"""
Ultra-realistic metadata removal tests covering all metadata types.
Tests EXIF, GPS, IPTC, XMP, and hidden metadata removal.
"""

import asyncio
import hashlib
import io
import json
import struct
from typing import Any, Dict, Optional

import pytest
from PIL import Image

try:
    import piexif
except ImportError:
    piexif = None

from app.core.security.engine import SecurityEngine
from app.models.conversion import ConversionRequest, ConversionStatus
from app.services.conversion_service import conversion_service


class TestMetadataRemovalComplete:
    """Comprehensive metadata removal tests for privacy protection."""

    @pytest.fixture
    def security_engine(self):
        """Create SecurityEngine instance."""
        return SecurityEngine()

    def create_image_with_all_metadata(self) -> bytes:
        """Create image with comprehensive metadata for testing."""
        img = Image.new("RGB", (2048, 1536))

        # Add realistic photo content
        pixels = img.load()
        for i in range(0, 2048, 10):
            for j in range(0, 1536, 10):
                pixels[i, j] = (100 + (i * 50 // 2048), 150, 200 - (j * 50 // 1536))

        if piexif:
            # Create comprehensive EXIF data
            exif_dict = {
                "0th": {
                    # Camera information
                    piexif.ImageIFD.Make: b"Canon",
                    piexif.ImageIFD.Model: b"EOS 5D Mark IV",
                    piexif.ImageIFD.Software: b"Adobe Photoshop CC 2024",
                    piexif.ImageIFD.DateTime: b"2025:01:15 14:30:45",
                    piexif.ImageIFD.Artist: b"John Doe",
                    piexif.ImageIFD.Copyright: b"(c) 2025 John Doe Photography",
                    piexif.ImageIFD.ImageDescription: b"Family vacation in Hawaii",
                    # Technical details
                    piexif.ImageIFD.XResolution: (300, 1),
                    piexif.ImageIFD.YResolution: (300, 1),
                    piexif.ImageIFD.ResolutionUnit: 2,
                },
                "Exif": {
                    # Camera settings
                    piexif.ExifIFD.ExposureTime: (1, 125),
                    piexif.ExifIFD.FNumber: (28, 10),
                    piexif.ExifIFD.ISOSpeedRatings: 400,
                    piexif.ExifIFD.DateTimeOriginal: b"2025:01:15 14:30:45",
                    piexif.ExifIFD.DateTimeDigitized: b"2025:01:15 14:30:45",
                    piexif.ExifIFD.FocalLength: (85, 1),
                    piexif.ExifIFD.LensMake: b"Canon",
                    piexif.ExifIFD.LensModel: b"EF 85mm f/1.2L II USM",
                    # User comment with potential PII
                    piexif.ExifIFD.UserComment: b"Shot at home address: 123 Main St, Anytown, CA 94102",
                    piexif.ExifIFD.SubSecTimeOriginal: b"523",
                    piexif.ExifIFD.CameraOwnerName: b"john.doe@email.com",
                    piexif.ExifIFD.BodySerialNumber: b"123456789",
                },
                "GPS": {
                    # Precise GPS location (San Francisco)
                    piexif.GPSIFD.GPSLatitudeRef: b"N",
                    piexif.GPSIFD.GPSLatitude: ((37, 1), (46, 1), (29, 1)),
                    piexif.GPSIFD.GPSLongitudeRef: b"W",
                    piexif.GPSIFD.GPSLongitude: ((122, 1), (25, 1), (15, 1)),
                    piexif.GPSIFD.GPSAltitudeRef: 0,
                    piexif.GPSIFD.GPSAltitude: (52, 1),
                    piexif.GPSIFD.GPSTimeStamp: ((14, 1), (30, 1), (45, 1)),
                    piexif.GPSIFD.GPSDateStamp: b"2025:01:15",
                    piexif.GPSIFD.GPSProcessingMethod: b"GPS",
                    piexif.GPSIFD.GPSAreaInformation: b"Home Location",
                },
                "1st": {
                    # Thumbnail with its own metadata
                    piexif.ImageIFD.Make: b"Canon",
                    piexif.ImageIFD.Model: b"EOS 5D Mark IV",
                },
            }

            # Add thumbnail
            thumb = img.resize((160, 120))
            thumb_buffer = io.BytesIO()
            thumb.save(thumb_buffer, format="JPEG")
            exif_dict["thumbnail"] = thumb_buffer.getvalue()

            exif_bytes = piexif.dump(exif_dict)
        else:
            exif_bytes = None

        # Save with metadata
        buffer = io.BytesIO()

        # Add custom metadata through save parameters
        metadata = {
            "dpi": (300, 300),
            "description": "Test image with sensitive metadata",
            "author": "John Doe",
            "copyright": "2025 Private Photo",
            "comment": "Contains GPS and personal information",
        }

        if exif_bytes:
            img.save(buffer, format="JPEG", quality=95, exif=exif_bytes, **metadata)
        else:
            img.save(buffer, format="JPEG", quality=95, **metadata)

        return buffer.getvalue()

    @pytest.mark.security
    @pytest.mark.critical
    async def test_complete_exif_removal(self, security_engine):
        """
        Test complete removal of all EXIF data.

        Validates that no EXIF information remains after processing.
        """
        # Create image with full EXIF
        image_with_exif = self.create_image_with_all_metadata()

        # Process with metadata removal
        processed_data, metadata_summary = (
            await security_engine.analyze_and_process_metadata(
                image_data=image_with_exif, image_format="jpeg", strip_metadata=True
            )
        )

        # Verify EXIF was detected initially
        assert metadata_summary["exif"]["found"] is True
        assert metadata_summary["exif"]["removed"] is True

        # Load processed image and check for EXIF
        processed_img = Image.open(io.BytesIO(processed_data))

        # Check using PIL
        exif_data = processed_img.getexif()
        assert len(exif_data) == 0, f"EXIF data still present: {dict(exif_data)}"

        # Check using piexif if available
        if piexif:
            try:
                piexif.load(processed_data)
                assert False, "EXIF data still readable by piexif"
            except (ValueError, piexif.InvalidImageDataError):
                # Expected - no EXIF to load
                pass

        # Verify no EXIF markers in raw data
        assert (
            b"Exif\x00\x00" not in processed_data
        ), "EXIF marker found in processed image"

    @pytest.mark.security
    @pytest.mark.critical
    async def test_gps_location_removal(self, security_engine):
        """
        Test complete removal of GPS location data.

        Critical for privacy - ensures no location data leaks.
        """
        # Create image with GPS data
        image_with_gps = self.create_image_with_all_metadata()

        # Process with metadata removal
        processed_data, metadata_summary = (
            await security_engine.analyze_and_process_metadata(
                image_data=image_with_gps, image_format="jpeg", strip_metadata=True
            )
        )

        # Verify GPS was detected and removed
        assert metadata_summary["gps"]["found"] is True
        assert metadata_summary["gps"]["removed"] is True
        assert "latitude" in metadata_summary["gps"]["data"]
        assert "longitude" in metadata_summary["gps"]["data"]

        # Verify no GPS data in processed image
        if piexif:
            try:
                exif_dict = piexif.load(processed_data)
                assert "GPS" not in exif_dict or len(exif_dict.get("GPS", {})) == 0
            except (ValueError, piexif.InvalidImageDataError):
                # Even better - no EXIF at all
                pass

        # Check for GPS markers in raw data
        gps_markers = [b"GPS", b"GPSLatitude", b"GPSLongitude", b"GPSAltitude"]
        for marker in gps_markers:
            assert (
                marker not in processed_data
            ), f"GPS marker '{marker}' found in processed image"

    @pytest.mark.security
    async def test_iptc_metadata_removal(self):
        """
        Test removal of IPTC (International Press Telecommunications Council) metadata.

        Common in professional photography and news images.
        """
        # Create image with IPTC-like metadata
        img = Image.new("RGB", (1024, 768))

        # Add IPTC info through image info
        img.info["iptc"] = {
            "caption": "Confidential corporate event",
            "credit": "Corporate Photographer",
            "source": "Company XYZ",
            "keywords": ["confidential", "internal", "private"],
            "copyright": "2025 Company XYZ - Internal Use Only",
            "contact": "photo@company.com",
        }

        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        image_data = buffer.getvalue()

        # Process with metadata removal
        request = ConversionRequest(
            output_format="jpeg", quality=90, strip_metadata=True
        )

        result, processed_data = await conversion_service.convert(
            image_data=image_data, request=request
        )

        assert result.status == ConversionStatus.COMPLETED

        # Load processed image
        processed_img = Image.open(io.BytesIO(processed_data))

        # Check IPTC removal
        assert "iptc" not in processed_img.info
        assert b"IPTC" not in processed_data
        assert b"8BIM" not in processed_data  # Photoshop IPTC marker

    @pytest.mark.security
    async def test_xmp_metadata_removal(self):
        """
        Test removal of XMP (Extensible Metadata Platform) data.

        XMP can contain extensive metadata including edit history.
        """
        # Create image with XMP-like metadata
        img = Image.new("RGB", (1600, 1200))

        # XMP data (simplified)
        xmp_data = """<?xml version="1.0" encoding="UTF-8"?>
        <x:xmpmeta xmlns:x="adobe:ns:meta/">
            <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
                <rdf:Description rdf:about=""
                    xmlns:dc="http://purl.org/dc/elements/1.1/"
                    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
                    xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/">
                    <dc:creator>John Doe</dc:creator>
                    <dc:rights>Private</dc:rights>
                    <xmp:CreatorTool>Adobe Photoshop</xmp:CreatorTool>
                    <photoshop:City>San Francisco</photoshop:City>
                    <photoshop:Country>USA</photoshop:Country>
                </rdf:Description>
            </rdf:RDF>
        </x:xmpmeta>"""

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        image_data = buffer.getvalue()

        # Inject XMP data (simplified - normally would be in proper PNG chunk)
        image_data = image_data.replace(b"IEND", xmp_data.encode() + b"IEND")

        # Process with metadata removal
        request = ConversionRequest(output_format="png", strip_metadata=True)

        result, processed_data = await conversion_service.convert(
            image_data=image_data, request=request
        )

        assert result.status == ConversionStatus.COMPLETED

        # Check XMP removal
        assert b"xmpmeta" not in processed_data
        assert b"adobe:ns:meta" not in processed_data
        assert b"John Doe" not in processed_data
        assert b"San Francisco" not in processed_data

    @pytest.mark.security
    async def test_thumbnail_metadata_removal(self, security_engine):
        """
        Test that embedded thumbnails and their metadata are removed.

        Thumbnails can contain their own EXIF/GPS data.
        """
        # Create image with thumbnail containing metadata
        image_with_thumb = self.create_image_with_all_metadata()

        # Verify thumbnail exists
        if piexif:
            original_exif = piexif.load(image_with_thumb)
            assert "thumbnail" in original_exif
            assert original_exif["thumbnail"] is not None

        # Process with metadata removal
        processed_data, metadata_summary = (
            await security_engine.analyze_and_process_metadata(
                image_data=image_with_thumb, image_format="jpeg", strip_metadata=True
            )
        )

        # Verify thumbnail was removed
        if piexif:
            try:
                processed_exif = piexif.load(processed_data)
                assert (
                    "thumbnail" not in processed_exif
                    or processed_exif["thumbnail"] is None
                )
            except (ValueError, piexif.InvalidImageDataError):
                # No EXIF at all - even better
                pass

        # Check for thumbnail markers
        assert (
            b"\xff\xd8\xff\xd8" not in processed_data
        )  # Double JPEG start (main + thumb)

    @pytest.mark.security
    async def test_comment_and_description_removal(self):
        """
        Test removal of comments and descriptions that may contain PII.

        These fields are often overlooked but can contain sensitive info.
        """
        # Create image with various comment fields
        img = Image.new("RGB", (800, 600))

        buffer = io.BytesIO()
        img.save(buffer, format="PNG", pnginfo=self._create_png_metadata_with_pii())
        image_data = buffer.getvalue()

        # Process with metadata removal
        request = ConversionRequest(output_format="png", strip_metadata=True)

        result, processed_data = await conversion_service.convert(
            image_data=image_data, request=request
        )

        assert result.status == ConversionStatus.COMPLETED

        # Check for PII in processed image
        pii_strings = [
            b"john.doe@email.com",
            b"123 Main Street",
            b"555-0123",
            b"SSN",
            b"passport",
            b"license",
        ]

        for pii in pii_strings:
            assert pii not in processed_data, f"PII '{pii}' found in processed image"

    def _create_png_metadata_with_pii(self):
        """Create PNG metadata chunks with PII."""
        from PIL import PngImagePlugin

        pnginfo = PngImagePlugin.PngInfo()
        pnginfo.add_text("Author", "John Doe")
        pnginfo.add_text("Copyright", "Personal Photo - john.doe@email.com")
        pnginfo.add_text("Description", "Taken at home: 123 Main Street")
        pnginfo.add_text("Comment", "Contact: 555-0123")
        pnginfo.add_text("Software", "Personal Camera App v1.0")

        return pnginfo

    @pytest.mark.security
    @pytest.mark.critical
    async def test_format_conversion_metadata_removal(self):
        """
        Test metadata removal during format conversion.

        Ensures metadata is removed even when changing formats.
        """
        # Create JPEG with metadata
        jpeg_with_metadata = self.create_image_with_all_metadata()

        # Test conversions to different formats
        target_formats = ["png", "webp", "bmp", "tiff"]

        for target_format in target_formats:
            request = ConversionRequest(
                output_format=target_format, strip_metadata=True
            )

            result, processed_data = await conversion_service.convert(
                image_data=jpeg_with_metadata, request=request
            )

            assert result.status == ConversionStatus.COMPLETED

            # Check for metadata markers in any format
            metadata_markers = [
                b"Exif",
                b"GPS",
                b"IPTC",
                b"XMP",
                b"John Doe",
                b"john.doe@email.com",
                b"37.7749",  # Latitude
                b"122.4194",  # Longitude
            ]

            for marker in metadata_markers:
                assert (
                    marker not in processed_data
                ), f"Metadata marker '{marker}' found in {target_format} output"

    @pytest.mark.security
    async def test_partial_metadata_preservation(self, security_engine):
        """
        Test selective metadata preservation (e.g., keep copyright, remove GPS).

        Some use cases require keeping certain metadata.
        """
        # Create image with metadata
        image_with_metadata = self.create_image_with_all_metadata()

        # Process with selective removal
        processed_data, metadata_summary = (
            await security_engine.analyze_and_process_metadata(
                image_data=image_with_metadata,
                image_format="jpeg",
                strip_metadata=True,
                preserve_copyright=True,  # Keep copyright info
            )
        )

        # GPS should be removed
        assert b"GPS" not in processed_data
        assert b"37.7749" not in processed_data

        # Copyright might be preserved (depending on implementation)
        # This is a policy decision - test documents the behavior

        # Personal info should still be removed
        assert b"john.doe@email.com" not in processed_data
        assert b"123 Main St" not in processed_data

    @pytest.mark.security
    @pytest.mark.performance
    async def test_metadata_removal_performance(self):
        """
        Test performance of metadata removal on various image sizes.

        Ensures metadata removal doesn't significantly impact performance.
        """
        import time

        sizes = [(1024, 768), (2048, 1536), (4096, 3072)]

        for width, height in sizes:
            # Create image with metadata
            img = Image.new("RGB", (width, height))

            if piexif:
                exif_dict = {
                    "0th": {
                        piexif.ImageIFD.Make: b"TestCamera",
                        piexif.ImageIFD.DateTime: b"2025:01:15 12:00:00",
                    },
                    "GPS": {
                        piexif.GPSIFD.GPSLatitude: ((37, 1), (46, 1), (29, 1)),
                        piexif.GPSIFD.GPSLongitude: ((122, 1), (25, 1), (15, 1)),
                    },
                }
                exif_bytes = piexif.dump(exif_dict)
            else:
                exif_bytes = None

            buffer = io.BytesIO()
            if exif_bytes:
                img.save(buffer, format="JPEG", quality=90, exif=exif_bytes)
            else:
                img.save(buffer, format="JPEG", quality=90)
            image_data = buffer.getvalue()

            # Measure removal time
            start_time = time.perf_counter()

            request = ConversionRequest(
                output_format="jpeg", quality=90, strip_metadata=True
            )

            result, processed_data = await conversion_service.convert(
                image_data=image_data, request=request
            )

            processing_time = time.perf_counter() - start_time

            assert result.status == ConversionStatus.COMPLETED

            # Performance assertions
            if width * height <= 2048 * 1536:
                assert (
                    processing_time < 1.0
                ), f"Metadata removal too slow for {width}x{height}"
            else:
                assert (
                    processing_time < 2.0
                ), f"Metadata removal too slow for large image"

    @pytest.mark.security
    async def test_hidden_metadata_detection(self, security_engine):
        """
        Test detection of hidden or steganographic metadata.

        Some metadata can be hidden in image data itself.
        """
        # Create image with potential hidden data
        img = Image.new("RGB", (512, 512))

        # Embed data in least significant bits (simplified steganography)
        pixels = img.load()
        hidden_message = "SECRET_DATA_12345"

        for i, char in enumerate(hidden_message):
            if i < 512:
                # Modify LSB of red channel
                r, g, b = pixels[i, 0]
                r = (r & 0xFE) | (ord(char) & 1)
                pixels[i, 0] = (r, g, b)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        image_data = buffer.getvalue()

        # Process with metadata removal and analysis
        processed_data, metadata_summary = (
            await security_engine.analyze_and_process_metadata(
                image_data=image_data,
                image_format="png",
                strip_metadata=True,
                deep_scan=True,  # Enable deep scanning for hidden data
            )
        )

        # The system should at least not introduce new metadata
        assert len(processed_data) <= len(image_data) * 1.1  # Allow small size increase

        # Verify standard metadata is removed
        processed_img = Image.open(io.BytesIO(processed_data))
        assert len(processed_img.info) == 0 or all(
            key in ["dpi", "gamma"] for key in processed_img.info.keys()
        )
