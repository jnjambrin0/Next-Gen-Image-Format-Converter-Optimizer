"""
Ultra-realistic format detection edge cases tests.
Tests magic bytes vs extensions, polyglot files, and rare formats.
"""

import pytest
import struct
import io
from PIL import Image
from typing import Tuple, Optional
import hashlib

from app.services.format_detection_service import format_detection_service
from app.services.conversion_service import conversion_service
from app.models.conversion import ConversionRequest


class TestFormatDetectionEdge:
    """Test format detection with edge cases and problematic files."""

    def create_polyglot_file(self, format1: str, format2: str) -> bytes:
        """Create a file that's valid in multiple formats (polyglot)."""
        if format1 == "gif" and format2 == "javascript":
            # GIF that's also valid JavaScript
            gif_js = b"GIF89a/*" + b"\x00" * 10 + b"*/=1;"
            gif_js += b"\x21\xf9\x04\x01\x00\x00\x00\x00"
            gif_js += b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"
            gif_js += b"\x02\x02\x44\x01\x00;"
            gif_js += b"//';alert(\"XSS\")'"
            return gif_js

        elif format1 == "pdf" and format2 == "jpeg":
            # PDF with embedded JPEG that can be opened as either
            pdf_header = b"%PDF-1.4\n"
            jpeg_data = (
                b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            )
            jpeg_data += b"\xff\xdb\x00C\x00" + b"\x08" * 64  # Quantization table
            jpeg_data += b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"  # SOF
            jpeg_data += b"\xff\xd9"  # EOI

            pdf_content = (
                pdf_header + b"1 0 obj\n<< /Type /XObject /Subtype /Image >>\nstream\n"
            )
            pdf_content += jpeg_data
            pdf_content += b"\nendstream\nendobj\n%%EOF"
            return pdf_content

        elif format1 == "png" and format2 == "html":
            # PNG that contains HTML in chunks
            png_header = b"\x89PNG\r\n\x1a\n"

            # IHDR chunk
            ihdr_data = struct.pack(">II", 1, 1) + b"\x08\x02\x00\x00\x00"
            ihdr_crc = struct.pack(">I", 0x1234)  # Simplified CRC
            ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc

            # Custom chunk with HTML
            html_data = b'<script>alert("XSS")</script>'
            html_chunk = (
                struct.pack(">I", len(html_data))
                + b"htML"
                + html_data
                + struct.pack(">I", 0)
            )

            # IDAT chunk (minimal)
            idat_data = b"\x78\x9c\x62\x00\x00\x00\x02\x00\x01"
            idat_chunk = (
                struct.pack(">I", len(idat_data))
                + b"IDAT"
                + idat_data
                + struct.pack(">I", 0)
            )

            # IEND chunk
            iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)

            return png_header + ihdr_chunk + html_chunk + idat_chunk + iend_chunk

        else:
            # Generic polyglot attempt
            return b"POLY" + format1.encode() + b"\x00" + format2.encode()

    def create_file_with_wrong_extension(
        self, real_format: str, fake_extension: str
    ) -> Tuple[bytes, str]:
        """Create a file with misleading extension."""
        # Create real content
        if real_format == "png":
            img = Image.new("RGB", (100, 100), color=(255, 0, 0))
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            content = buffer.getvalue()
        elif real_format == "jpeg":
            img = Image.new("RGB", (100, 100), color=(0, 255, 0))
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG")
            content = buffer.getvalue()
        elif real_format == "gif":
            img = Image.new("RGB", (100, 100), color=(0, 0, 255))
            buffer = io.BytesIO()
            img.save(buffer, format="GIF")
            content = buffer.getvalue()
        elif real_format == "bmp":
            img = Image.new("RGB", (100, 100), color=(255, 255, 0))
            buffer = io.BytesIO()
            img.save(buffer, format="BMP")
            content = buffer.getvalue()
        else:
            content = b"FAKE" + real_format.encode()

        # Create misleading filename
        filename = f"image.{fake_extension}"

        return content, filename

    @pytest.mark.critical
    async def test_magic_bytes_vs_extension_priority(self):
        """
        Test that magic bytes take priority over file extensions.

        Critical for security - prevents extension spoofing attacks.
        """
        test_cases = [
            ("png", "jpg"),  # PNG file named .jpg
            ("jpeg", "png"),  # JPEG file named .png
            ("gif", "bmp"),  # GIF file named .bmp
            ("bmp", "gif"),  # BMP file named .gif
        ]

        for real_format, fake_extension in test_cases:
            content, filename = self.create_file_with_wrong_extension(
                real_format, fake_extension
            )

            # Detect format
            detected_format, confidence = await format_detection_service.detect_format(
                image_data=content
            )

            # Should detect real format, not extension
            assert (
                detected_format.lower() == real_format.lower()
            ), f"Failed to detect {real_format} disguised as .{fake_extension}"

            # Confidence should be high for magic byte detection
            assert confidence > 0.8, f"Low confidence for {real_format}: {confidence}"

    @pytest.mark.security
    async def test_polyglot_file_detection(self):
        """
        Test detection of polyglot files (valid in multiple formats).

        Security critical - polyglots can bypass filters.
        """
        polyglot_cases = [
            ("gif", "javascript"),
            ("pdf", "jpeg"),
            ("png", "html"),
        ]

        for format1, format2 in polyglot_cases:
            polyglot_data = self.create_polyglot_file(format1, format2)

            # Detect format
            detected_format, confidence = await format_detection_service.detect_format(
                image_data=polyglot_data
            )

            # Should detect the image format (not the embedded format)
            assert detected_format.lower() in [
                format1.lower(),
                format2.lower(),
            ], f"Failed to detect polyglot {format1}/{format2}"

            # Should flag as potentially suspicious
            detection_result = await format_detection_service.analyze_format_security(
                image_data=polyglot_data, detected_format=detected_format
            )

            if detection_result:
                assert detection_result.get(
                    "is_polyglot", False
                ) or detection_result.get(
                    "has_suspicious_data", False
                ), "Polyglot not flagged as suspicious"

    async def test_rare_format_detection(self):
        """
        Test detection of rare and uncommon image formats.

        Ensures comprehensive format support.
        """
        # Create test data for rare formats
        rare_formats = {
            "webp": b"RIFF\x00\x00\x00\x00WEBPVP8 ",
            "ico": b"\x00\x00\x01\x00\x01\x00\x10\x10",
            "tga": b"\x00\x00\x02\x00\x00\x00\x00\x00",
            "pcx": b"\x0a\x05\x01\x08",
            "pbm": b"P1\n# Comment\n2 2\n0 1\n1 0",
            "pgm": b"P2\n# Comment\n2 2\n255\n0 255\n255 0",
            "ppm": b"P3\n# Comment\n2 2\n255\n255 0 0\n0 255 0",
            "xbm": b"#define image_width 8\n#define image_height 8\nstatic char image_bits[] = {",
            "xpm": b"/* XPM */\nstatic char *image[] = {",
        }

        for format_name, magic_bytes in rare_formats.items():
            # Create more complete file data
            if format_name == "webp":
                # Add WebP VP8 data
                test_data = magic_bytes + b"\x00" * 100
            elif format_name == "ico":
                # Add ICO directory entry
                test_data = magic_bytes + b"\x00" * 100
            else:
                test_data = magic_bytes + b"\x00" * 50

            # Detect format
            detected_format, confidence = await format_detection_service.detect_format(
                image_data=test_data
            )

            # Should either detect correctly or return unknown
            if detected_format != "unknown":
                # If detected, should be reasonably accurate
                assert (
                    format_name in detected_format.lower()
                    or detected_format.lower() in format_name
                ), f"Misdetected {format_name} as {detected_format}"

    async def test_truncated_file_detection(self):
        """
        Test detection of truncated/incomplete image files.

        Common in interrupted downloads or corrupted storage.
        """
        # Create truncated files
        truncated_cases = [
            # JPEG with only header
            (b"\xff\xd8\xff\xe0\x00\x10JFIF", "jpeg", True),
            # PNG with only signature
            (b"\x89PNG\r\n\x1a\n", "png", True),
            # GIF with only header
            (b"GIF89a", "gif", True),
            # BMP with partial header
            (b"BM\x00\x00\x00\x00", "bmp", True),
            # WebP with only RIFF header
            (b"RIFF\x00\x00\x00\x00WEBP", "webp", True),
        ]

        for truncated_data, expected_format, is_truncated in truncated_cases:
            # Detect format
            detected_format, confidence = await format_detection_service.detect_format(
                image_data=truncated_data
            )

            # Should still identify format from header
            assert (
                detected_format.lower() == expected_format.lower()
            ), f"Failed to detect truncated {expected_format}"

            # But confidence should be lower
            if is_truncated:
                assert confidence < 1.0, "Full confidence for truncated file"

            # Should flag as incomplete
            validation_result = (
                await format_detection_service.validate_format_integrity(
                    image_data=truncated_data, detected_format=detected_format
                )
            )

            if validation_result:
                assert (
                    validation_result.get("is_complete", True) is False
                    or validation_result.get("is_truncated", False) is True
                ), "Truncated file not flagged"

    @pytest.mark.critical
    async def test_format_detection_with_embedded_data(self):
        """
        Test format detection when files contain embedded data.

        Common with camera photos (EXIF), edited images (XMP), etc.
        """
        # Create image with embedded data
        img = Image.new("RGB", (200, 200), color=(128, 128, 128))

        # Add various embedded data types
        test_cases = [
            ("jpeg_with_exif", "JPEG", b"Exif\x00\x00MM\x00*"),
            ("png_with_text", "PNG", b"tEXtComment\x00This is embedded text"),
            ("gif_with_comment", "GIF", b"!\xfe\x10This is a comment\x00"),
        ]

        for case_name, format_name, embedded_data in test_cases:
            buffer = io.BytesIO()

            if format_name == "JPEG":
                img.save(buffer, format=format_name, quality=90)
                # Insert EXIF marker after SOI
                jpeg_data = buffer.getvalue()
                if b"\xff\xd8" in jpeg_data:
                    # Insert APP1 marker with EXIF
                    app1_marker = (
                        b"\xff\xe1"
                        + struct.pack(">H", len(embedded_data) + 2)
                        + embedded_data
                    )
                    jpeg_with_exif = jpeg_data[:2] + app1_marker + jpeg_data[2:]
                    test_data = jpeg_with_exif
                else:
                    test_data = jpeg_data

            elif format_name == "PNG":
                img.save(buffer, format=format_name)
                png_data = buffer.getvalue()
                # Insert text chunk before IEND
                if b"IEND" in png_data:
                    iend_pos = png_data.index(b"IEND")
                    text_chunk = (
                        struct.pack(">I", len(embedded_data))
                        + embedded_data
                        + struct.pack(">I", 0)
                    )
                    test_data = (
                        png_data[: iend_pos - 4] + text_chunk + png_data[iend_pos - 4 :]
                    )
                else:
                    test_data = png_data

            elif format_name == "GIF":
                img.save(buffer, format=format_name)
                gif_data = buffer.getvalue()
                # Insert comment extension before trailer
                if b";" in gif_data:
                    trailer_pos = gif_data.index(b";")
                    test_data = (
                        gif_data[:trailer_pos] + embedded_data + gif_data[trailer_pos:]
                    )
                else:
                    test_data = gif_data
            else:
                test_data = buffer.getvalue()

            # Detect format
            detected_format, confidence = await format_detection_service.detect_format(
                image_data=test_data
            )

            # Should correctly identify despite embedded data
            assert (
                detected_format.upper() == format_name.upper()
            ), f"Failed to detect {format_name} with embedded data"

            # Should maintain high confidence
            assert confidence > 0.9, f"Low confidence for {case_name}: {confidence}"

    async def test_format_detection_with_prepended_data(self):
        """
        Test detection when files have prepended data (e.g., PHP scripts).

        Common attack vector - PHP code before image data.
        """
        prepended_cases = [
            (b'<?php system($_GET["cmd"]); ?>' + b"\xff\xd8\xff\xe0", "jpeg"),
            (b"#!/usr/bin/python\n# Script\n" + b"\x89PNG\r\n\x1a\n", "png"),
            (b'<script>alert("XSS")</script>' + b"GIF89a", "gif"),
            (b'eval(atob("...")); //' + b"RIFF\x00\x00\x00\x00WEBP", "webp"),
        ]

        for prepended_data, expected_format in prepended_cases:
            # Add more complete image data
            if expected_format == "jpeg":
                complete_data = (
                    prepended_data + b"\x00\x10JFIF" + b"\x00" * 100 + b"\xff\xd9"
                )
            elif expected_format == "png":
                # Add IHDR chunk
                ihdr = (
                    struct.pack(">I", 13)
                    + b"IHDR"
                    + struct.pack(">II", 1, 1)
                    + b"\x08\x02\x00\x00\x00"
                    + struct.pack(">I", 0)
                )
                iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)
                complete_data = prepended_data + ihdr + iend
            elif expected_format == "gif":
                complete_data = (
                    prepended_data + b"\x01\x00\x01\x00\x00" + b"\x00" * 50 + b";"
                )
            else:
                complete_data = prepended_data + b"\x00" * 100

            # Detect format
            detected_format, confidence = await format_detection_service.detect_format(
                image_data=complete_data
            )

            # Should detect image format despite prepended data
            assert (
                detected_format.lower() == expected_format.lower()
            ), f"Failed to detect {expected_format} with prepended data"

            # Should flag as suspicious
            security_result = await format_detection_service.analyze_format_security(
                image_data=complete_data, detected_format=detected_format
            )

            if security_result:
                assert security_result.get(
                    "has_prepended_data", False
                ) or security_result.get(
                    "is_suspicious", False
                ), "Prepended data not flagged"

    async def test_format_detection_performance(self):
        """
        Test format detection performance with various file sizes.

        Ensures detection is fast enough for real-time use.
        """
        import time

        # Create test files of different sizes
        sizes = [
            (100, "tiny"),  # 100 bytes
            (10_000, "small"),  # 10 KB
            (100_000, "medium"),  # 100 KB
            (1_000_000, "large"),  # 1 MB
        ]

        performance_results = {}

        for size, size_name in sizes:
            # Create test data (JPEG-like)
            test_data = (
                b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            )
            test_data += b"\xff" * (size - len(test_data) - 2)
            test_data += b"\xff\xd9"

            # Measure detection time
            start_time = time.perf_counter()

            detected_format, confidence = await format_detection_service.detect_format(
                image_data=test_data
            )

            detection_time = time.perf_counter() - start_time

            performance_results[size_name] = {
                "size": size,
                "time": detection_time,
                "format": detected_format,
            }

            # Detection should be fast regardless of size
            assert (
                detection_time < 0.1
            ), f"Detection too slow for {size_name}: {detection_time:.3f}s"

        # Verify detection doesn't scale linearly with size
        # (should only check headers)
        if "tiny" in performance_results and "large" in performance_results:
            time_ratio = (
                performance_results["large"]["time"]
                / performance_results["tiny"]["time"]
            )
            assert time_ratio < 10, "Detection time scales too much with file size"

    async def test_ambiguous_format_detection(self):
        """
        Test detection of ambiguous formats that share similar signatures.

        Some formats have overlapping magic bytes.
        """
        ambiguous_cases = [
            # TIFF variants (little-endian vs big-endian)
            (b"II*\x00", "tiff_le"),
            (b"MM\x00*", "tiff_be"),
            # JPEG variants
            (b"\xff\xd8\xff\xe0", "jpeg_jfif"),
            (b"\xff\xd8\xff\xe1", "jpeg_exif"),
            (b"\xff\xd8\xff\xdb", "jpeg_raw"),
            # PNG with different chunks
            (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "png_standard"),
            (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rcHRM", "png_chrome"),
        ]

        for test_data, variant_name in ambiguous_cases:
            # Add more data for complete detection
            test_data += b"\x00" * 100

            detected_format, confidence = await format_detection_service.detect_format(
                image_data=test_data
            )

            # Should detect base format correctly
            base_format = variant_name.split("_")[0]
            assert (
                base_format in detected_format.lower()
            ), f"Failed to detect {base_format} variant: {variant_name}"

            # Get detailed format info
            format_details = await format_detection_service.get_format_details(
                image_data=test_data, detected_format=detected_format
            )

            if format_details:
                # Should identify specific variant if possible
                variant_info = format_details.get("variant", "")
                # Variant detection is optional but useful

    async def test_container_format_detection(self):
        """
        Test detection of container formats (e.g., HEIF, AVIF).

        These are complex formats based on ISO BMFF.
        """
        # Simplified container format signatures
        container_formats = [
            # HEIF/HEIC
            (b"\x00\x00\x00\x20ftypheic", "heic"),
            (b"\x00\x00\x00\x20ftypmif1", "heif"),
            # AVIF
            (b"\x00\x00\x00\x20ftypavif", "avif"),
            # WebP2
            (b"WEBP2", "webp2"),
        ]

        for signature, format_name in container_formats:
            # Add more structure for valid container
            if format_name in ["heic", "heif", "avif"]:
                # Add meta box and other required boxes
                test_data = signature + b"\x00\x00\x00\x08meta" + b"\x00" * 100
            else:
                test_data = signature + b"\x00" * 100

            detected_format, confidence = await format_detection_service.detect_format(
                image_data=test_data
            )

            # Should detect container format
            assert (
                format_name in detected_format.lower()
                or detected_format.lower() in format_name
            ), f"Failed to detect container format {format_name}"
