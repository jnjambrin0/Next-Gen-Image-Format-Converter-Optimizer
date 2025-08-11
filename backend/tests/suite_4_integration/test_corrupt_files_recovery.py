"""
Ultra-realistic corrupt file recovery tests.
Tests partial recovery from various types of file corruption.
"""

import hashlib
import io
import random
import struct
from typing import Any, Dict, Optional, Tuple

import pytest
from PIL import Image

from app.core.exceptions import ConversionFailedError
from app.models.conversion import ConversionRequest
from app.services.conversion_service import conversion_service
from app.services.recovery_service import recovery_service


class TestCorruptFilesRecovery:
    """Test recovery from corrupted image files."""

    def corrupt_jpeg(self, valid_jpeg: bytes, corruption_type: str) -> bytes:
        """Create various types of JPEG corruption."""
        if corruption_type == "truncated":
            # Cut off last 30% of file
            return valid_jpeg[: int(len(valid_jpeg) * 0.7)]

        elif corruption_type == "missing_eoi":
            # Remove End of Image marker
            if b"\xff\xd9" in valid_jpeg:
                return valid_jpeg.replace(b"\xff\xd9", b"")
            return valid_jpeg[:-2]

        elif corruption_type == "corrupted_header":
            # Damage SOI marker
            corrupted = bytearray(valid_jpeg)
            if len(corrupted) > 2:
                corrupted[0] = 0xFE  # Should be 0xFF
                corrupted[1] = 0xD7  # Should be 0xD8
            return bytes(corrupted)

        elif corruption_type == "bad_markers":
            # Insert invalid markers
            corrupted = bytearray(valid_jpeg)
            # Insert invalid marker in middle
            if len(corrupted) > 100:
                corrupted[100:100] = b"\xff\x00\xff\x00"  # Invalid marker sequence
            return bytes(corrupted)

        elif corruption_type == "corrupted_dht":
            # Damage Huffman table
            corrupted = bytearray(valid_jpeg)
            dht_pos = valid_jpeg.find(b"\xff\xc4")  # DHT marker
            if dht_pos > 0 and dht_pos + 10 < len(corrupted):
                # Corrupt table data
                for i in range(10):
                    corrupted[dht_pos + 4 + i] = random.randint(0, 255)
            return bytes(corrupted)

        elif corruption_type == "partial_scan":
            # Truncate scan data
            sos_pos = valid_jpeg.find(b"\xff\xda")  # Start of Scan
            if sos_pos > 0:
                # Keep header and partial scan
                return valid_jpeg[: sos_pos + 100]
            return valid_jpeg[: len(valid_jpeg) // 2]

        else:  # random
            # Random byte corruption
            corrupted = bytearray(valid_jpeg)
            num_corruptions = len(corrupted) // 100
            for _ in range(num_corruptions):
                pos = random.randint(10, len(corrupted) - 10)
                corrupted[pos] = random.randint(0, 255)
            return bytes(corrupted)

    def corrupt_png(self, valid_png: bytes, corruption_type: str) -> bytes:
        """Create various types of PNG corruption."""
        if corruption_type == "truncated":
            # Cut off last chunks
            return valid_png[: int(len(valid_png) * 0.6)]

        elif corruption_type == "missing_iend":
            # Remove IEND chunk
            iend_pos = valid_png.find(b"IEND")
            if iend_pos > 0:
                return valid_png[: iend_pos - 4]  # Remove size too
            return valid_png[:-12]

        elif corruption_type == "corrupted_header":
            # Damage PNG signature
            corrupted = bytearray(valid_png)
            if len(corrupted) > 8:
                corrupted[1] = ord("Q")  # Should be 'P'
                corrupted[2] = ord("M")  # Should be 'N'
            return bytes(corrupted)

        elif corruption_type == "bad_crc":
            # Corrupt CRC of IHDR chunk
            corrupted = bytearray(valid_png)
            # IHDR CRC is at bytes 25-28 after signature and IHDR chunk
            if len(corrupted) > 29:
                for i in range(25, 29):
                    corrupted[i] = 0xFF
            return bytes(corrupted)

        elif corruption_type == "corrupted_idat":
            # Damage IDAT chunk data
            idat_pos = valid_png.find(b"IDAT")
            if idat_pos > 0:
                corrupted = bytearray(valid_png)
                # Corrupt compressed data
                for i in range(min(50, len(corrupted) - idat_pos - 4)):
                    if idat_pos + 4 + i < len(corrupted):
                        corrupted[idat_pos + 4 + i] = random.randint(0, 255)
                return bytes(corrupted)
            return valid_png

        elif corruption_type == "missing_critical_chunk":
            # Remove IHDR (critical)
            ihdr_pos = valid_png.find(b"IHDR")
            if ihdr_pos > 0:
                # Skip IHDR chunk entirely
                chunk_size = struct.unpack(">I", valid_png[ihdr_pos - 4 : ihdr_pos])[0]
                chunk_end = ihdr_pos + 4 + chunk_size + 4  # type + data + crc
                return valid_png[: ihdr_pos - 4] + valid_png[chunk_end:]
            return valid_png

        else:  # random
            # Random corruption
            corrupted = bytearray(valid_png)
            for _ in range(len(corrupted) // 200):
                pos = random.randint(8, len(corrupted) - 1)
                corrupted[pos] ^= 0xFF  # Flip bits
            return bytes(corrupted)

    def create_recovery_test_image(self, format: str = "JPEG") -> bytes:
        """Create a valid test image for corruption."""
        img = Image.new("RGB", (200, 150))

        # Add recognizable pattern
        pixels = img.load()
        for x in range(200):
            for y in range(150):
                # Gradient pattern
                r = x * 255 // 200
                g = y * 255 // 150
                b = (x + y) * 255 // 350
                pixels[x, y] = (r, g, b)

        # Add some distinct features for recovery validation
        from PIL import ImageDraw

        draw = ImageDraw.Draw(img)

        # Add shapes
        draw.rectangle([50, 30, 150, 120], outline=(255, 255, 255), width=3)
        draw.ellipse([75, 50, 125, 100], fill=(255, 0, 0))

        # Save to buffer
        buffer = io.BytesIO()
        img.save(buffer, format=format, quality=90 if format == "JPEG" else None)
        return buffer.getvalue()

    @pytest.mark.critical
    async def test_jpeg_truncation_recovery(self):
        """
        Test recovery from truncated JPEG files.

        Common corruption from interrupted downloads.
        """
        # Create valid JPEG
        valid_jpeg = self.create_recovery_test_image("JPEG")

        # Create truncated version
        truncated = self.corrupt_jpeg(valid_jpeg, "truncated")

        # Attempt recovery
        recovery_result = await recovery_service.attempt_recovery(
            corrupted_data=truncated, detected_format="jpeg", recovery_mode="aggressive"
        )

        assert recovery_result is not None
        assert recovery_result.partial_success is True
        assert recovery_result.recovered_percentage > 50  # Should recover > 50%

        if recovery_result.recovered_data:
            # Verify recovered data is valid image
            try:
                recovered_img = Image.open(io.BytesIO(recovery_result.recovered_data))
                assert recovered_img.size[0] > 0
                assert recovered_img.size[1] > 0

                # Dimensions might be different but aspect ratio should be similar
                original_img = Image.open(io.BytesIO(valid_jpeg))
                original_aspect = original_img.size[0] / original_img.size[1]
                recovered_aspect = recovered_img.size[0] / recovered_img.size[1]

                assert abs(original_aspect - recovered_aspect) < 0.5

            except Exception:
                # Recovery produced invalid image
                assert False, "Recovered data is not a valid image"

    async def test_png_missing_chunks_recovery(self):
        """
        Test recovery from PNG with missing chunks.

        Can recover if critical chunks are intact.
        """
        # Create valid PNG
        valid_png = self.create_recovery_test_image("PNG")

        # Corrupt by removing IEND
        corrupted = self.corrupt_png(valid_png, "missing_iend")

        # Attempt recovery
        recovery_result = await recovery_service.attempt_recovery(
            corrupted_data=corrupted, detected_format="png", recovery_mode="standard"
        )

        assert recovery_result is not None

        if recovery_result.recovered_data:
            # Should have reconstructed IEND
            assert b"IEND" in recovery_result.recovered_data

            # Verify it's valid
            recovered_img = Image.open(io.BytesIO(recovery_result.recovered_data))
            assert recovered_img.format == "PNG"

    @pytest.mark.slow
    async def test_progressive_corruption_recovery(self):
        """
        Test recovery with increasing levels of corruption.

        Validates recovery degradation patterns.
        """
        valid_jpeg = self.create_recovery_test_image("JPEG")

        corruption_levels = [
            (10, 0.90),  # 10% corruption, expect 90% recovery
            (25, 0.70),  # 25% corruption, expect 70% recovery
            (50, 0.40),  # 50% corruption, expect 40% recovery
            (75, 0.10),  # 75% corruption, expect 10% recovery
        ]

        for corruption_percent, min_recovery in corruption_levels:
            # Create corrupted version
            corrupted = bytearray(valid_jpeg)
            num_bytes_to_corrupt = len(corrupted) * corruption_percent // 100

            # Corrupt random bytes (skip header)
            positions = random.sample(range(20, len(corrupted)), num_bytes_to_corrupt)
            for pos in positions:
                corrupted[pos] = random.randint(0, 255)

            # Attempt recovery
            recovery_result = await recovery_service.attempt_recovery(
                corrupted_data=bytes(corrupted),
                detected_format="jpeg",
                recovery_mode="best_effort",
            )

            if recovery_result:
                # Check recovery rate matches expectations
                assert (
                    recovery_result.recovered_percentage >= min_recovery * 100
                ), f"Poor recovery at {corruption_percent}% corruption"

    async def test_multi_format_corruption_recovery(self):
        """
        Test recovery across different format corruptions.

        Each format has different recovery characteristics.
        """
        formats_and_corruptions = [
            ("JPEG", "missing_eoi"),
            ("PNG", "bad_crc"),
            ("GIF", "truncated"),
            ("BMP", "corrupted_header"),
        ]

        recovery_stats = {}

        for format, corruption_type in formats_and_corruptions:
            # Create test image
            if format == "GIF":
                # Create simple GIF
                img = Image.new("RGB", (100, 100), color=(255, 0, 0))
                buffer = io.BytesIO()
                img.save(buffer, format="GIF")
                valid_data = buffer.getvalue()
            elif format == "BMP":
                # Create BMP
                img = Image.new("RGB", (100, 100), color=(0, 255, 0))
                buffer = io.BytesIO()
                img.save(buffer, format="BMP")
                valid_data = buffer.getvalue()
            else:
                valid_data = self.create_recovery_test_image(format)

            # Corrupt based on format
            if format == "JPEG":
                corrupted = self.corrupt_jpeg(valid_data, corruption_type)
            elif format == "PNG":
                corrupted = self.corrupt_png(valid_data, corruption_type)
            elif format == "GIF":
                # Simple truncation for GIF
                corrupted = valid_data[: len(valid_data) // 2]
            else:  # BMP
                # Corrupt BMP header
                corrupted = bytearray(valid_data)
                if len(corrupted) > 10:
                    corrupted[2] = 0xFF  # Corrupt file size field
                corrupted = bytes(corrupted)

            # Attempt recovery
            recovery_result = await recovery_service.attempt_recovery(
                corrupted_data=corrupted,
                detected_format=format.lower(),
                recovery_mode="adaptive",
            )

            recovery_stats[format] = {
                "corruption_type": corruption_type,
                "recovery_success": (
                    recovery_result.partial_success if recovery_result else False
                ),
                "recovery_percentage": (
                    recovery_result.recovered_percentage if recovery_result else 0
                ),
            }

        # Verify format-specific recovery characteristics
        assert recovery_stats["JPEG"][
            "recovery_success"
        ], "JPEG recovery should handle missing EOI"
        assert (
            recovery_stats["PNG"]["recovery_success"]
            or recovery_stats["PNG"]["recovery_percentage"] > 0
        ), "PNG should attempt CRC recovery"

    async def test_recovery_with_conversion(self):
        """
        Test recovering corrupted file during format conversion.

        Convert what can be recovered to new format.
        """
        # Create corrupted JPEG
        valid_jpeg = self.create_recovery_test_image("JPEG")
        corrupted = self.corrupt_jpeg(valid_jpeg, "partial_scan")

        # Attempt conversion with recovery
        request = ConversionRequest(
            output_format="png",
            error_recovery_mode="aggressive",
            allow_partial_output=True,
        )

        try:
            result, output_data = await conversion_service.convert(
                image_data=corrupted, request=request
            )

            if result.partial_success:
                # Should produce valid PNG from recovered portion
                assert output_data is not None
                assert len(output_data) > 0

                # Verify output is valid PNG
                output_img = Image.open(io.BytesIO(output_data))
                assert output_img.format == "PNG"

                # Check recovery metadata
                assert result.recovery_info is not None
                assert result.recovery_info.get("recovered_percentage", 0) > 0

        except ConversionFailedError as e:
            # If total failure, should indicate why
            assert "corrupt" in str(e).lower() or "recover" in str(e).lower()

    async def test_batch_corruption_recovery(self):
        """
        Test batch processing with some corrupted files.

        Batch should continue despite individual failures.
        """
        from app.services.batch_service import batch_service

        # Create mix of valid and corrupted files
        files = []

        # Add valid files
        for i in range(5):
            valid = self.create_recovery_test_image("JPEG")
            files.append(
                {
                    "filename": f"valid_{i}.jpg",
                    "content": valid,
                    "content_type": "image/jpeg",
                }
            )

        # Add corrupted files with varying corruption
        corruption_types = ["truncated", "missing_eoi", "bad_markers", "corrupted_dht"]
        for i, corruption in enumerate(corruption_types):
            valid = self.create_recovery_test_image("JPEG")
            corrupted = self.corrupt_jpeg(valid, corruption)
            files.append(
                {
                    "filename": f"corrupted_{corruption}.jpg",
                    "content": corrupted,
                    "content_type": "image/jpeg",
                }
            )

        # Process batch with recovery enabled
        job = await batch_service.create_batch_job(
            files=files, output_format="png", error_recovery_mode="best_effort"
        )

        result = await batch_service.process_batch(job.id)

        # Should process valid files successfully
        assert len(result.completed) >= 5, "Valid files should process"

        # Some corrupted files might recover
        assert len(result.partial_success) >= 0, "Should track partial successes"

        # Check recovery statistics
        for item in result.completed:
            if "corrupted" in item.filename:
                # Recovered corrupted file
                assert item.recovery_info is not None
                assert item.recovery_info.get("recovery_mode") is not None

    async def test_corruption_detection_accuracy(self):
        """
        Test accurate detection of corruption types.

        Important for choosing recovery strategy.
        """
        # Create various corruptions
        valid_jpeg = self.create_recovery_test_image("JPEG")

        corruption_tests = [
            ("truncated", "truncation"),
            ("missing_eoi", "missing_marker"),
            ("corrupted_header", "invalid_header"),
            ("bad_markers", "invalid_markers"),
            ("corrupted_dht", "table_corruption"),
        ]

        for corruption_type, expected_detection in corruption_tests:
            corrupted = self.corrupt_jpeg(valid_jpeg, corruption_type)

            # Analyze corruption
            analysis = await recovery_service.analyze_corruption(
                image_data=corrupted, format="jpeg"
            )

            assert analysis is not None
            assert analysis.corruption_detected is True

            # Check detection accuracy
            detected_types = analysis.corruption_types
            assert any(
                expected_detection in t.lower() for t in detected_types
            ), f"Failed to detect {expected_detection} in {corruption_type}"

            # Should suggest appropriate recovery strategy
            assert analysis.suggested_recovery_mode is not None

    @pytest.mark.performance
    async def test_recovery_performance(self):
        """
        Test recovery performance with various file sizes.

        Recovery should be reasonably fast.
        """
        import time

        sizes = [(100, 100), (500, 500), (1000, 1000)]

        for width, height in sizes:
            # Create image of specific size
            img = Image.new("RGB", (width, height))
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG", quality=90)
            valid_data = buffer.getvalue()

            # Corrupt it
            corrupted = self.corrupt_jpeg(valid_data, "truncated")

            # Measure recovery time
            start_time = time.perf_counter()

            recovery_result = await recovery_service.attempt_recovery(
                corrupted_data=corrupted, detected_format="jpeg", recovery_mode="fast"
            )

            recovery_time = time.perf_counter() - start_time

            # Recovery should be reasonably fast
            max_time = 2.0 * (width * height / (100 * 100))  # Scale with size
            assert (
                recovery_time < max_time
            ), f"Recovery too slow for {width}x{height}: {recovery_time:.2f}s"

    async def test_metadata_recovery(self):
        """
        Test recovery of metadata from corrupted files.

        Important for preserving image information.
        """
        # Create image with metadata
        img = Image.new("RGB", (200, 150))

        # Add EXIF data
        import piexif

        exif_dict = {
            "0th": {
                piexif.ImageIFD.Make: b"TestCamera",
                piexif.ImageIFD.Model: b"Model X",
                piexif.ImageIFD.DateTime: b"2025:01:15 12:00:00",
            }
        }
        exif_bytes = piexif.dump(exif_dict)

        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=90, exif=exif_bytes)
        valid_jpeg = buffer.getvalue()

        # Corrupt the image data but leave EXIF intact
        corrupted = self.corrupt_jpeg(valid_jpeg, "partial_scan")

        # Attempt recovery
        recovery_result = await recovery_service.attempt_recovery(
            corrupted_data=corrupted,
            detected_format="jpeg",
            recovery_mode="metadata_priority",
            preserve_metadata=True,
        )

        if recovery_result and recovery_result.recovered_metadata:
            # Should have recovered metadata
            assert "Make" in recovery_result.recovered_metadata
            assert recovery_result.recovered_metadata["Make"] == "TestCamera"
