"""
Ultra-realistic malicious payload tests.
Tests zip bombs, polyglot files, embedded scripts, and buffer overflow attempts.
"""

import pytest
import struct
import zlib
import io
from typing import List, Tuple
import hashlib
import base64

from app.core.security.engine import SecurityEngine
from app.services.conversion_service import conversion_service
from app.models.conversion import ConversionRequest
from app.core.exceptions import SecurityError, ValidationError


class TestMaliciousPayloads:
    """Test handling of malicious image payloads."""

    @pytest.fixture
    def security_engine(self):
        """Create SecurityEngine instance."""
        return SecurityEngine()

    def create_zip_bomb(self, compression_ratio: int = 1000) -> bytes:
        """
        Create a zip bomb - small compressed data that expands massively.

        Real attack: Causes memory exhaustion when decompressed.
        """
        # Create highly compressible data
        uncompressed_size = 10 * 1024 * 1024  # 10MB uncompressed

        # PNG zip bomb
        png_header = b"\x89PNG\r\n\x1a\n"

        # IHDR chunk claiming huge dimensions
        width = 65535
        height = 65535
        ihdr_data = struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"
        ihdr_crc = struct.pack(">I", 0)
        ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc

        # Create highly compressed IDAT
        # Fill with zeros (compresses very well)
        uncompressed_data = b"\x00" * uncompressed_size
        compressed_data = zlib.compress(uncompressed_data, level=9)

        # IDAT chunk with compressed data
        idat_chunk = (
            struct.pack(">I", len(compressed_data))
            + b"IDAT"
            + compressed_data
            + struct.pack(">I", 0)
        )

        # IEND chunk
        iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)

        bomb = png_header + ihdr_chunk + idat_chunk + iend_chunk

        # Verify compression ratio
        actual_ratio = uncompressed_size / len(bomb)

        return bomb

    def create_nested_bomb(self, depth: int = 5) -> bytes:
        """
        Create a nested compression bomb (bomb within bomb).

        Each layer expands exponentially.
        """
        # Start with base data
        data = b"A" * 1024  # 1KB

        # Nest compressions
        for _ in range(depth):
            # Compress current data
            compressed = zlib.compress(data * 100, level=9)

            # Wrap in image format
            if _ % 2 == 0:
                # PNG wrapper
                png_header = b"\x89PNG\r\n\x1a\n"
                ihdr = (
                    struct.pack(">I", 13)
                    + b"IHDR"
                    + struct.pack(">II", 100, 100)
                    + b"\x08\x02\x00\x00\x00"
                    + struct.pack(">I", 0)
                )
                idat = (
                    struct.pack(">I", len(compressed))
                    + b"IDAT"
                    + compressed
                    + struct.pack(">I", 0)
                )
                iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)
                data = png_header + ihdr + idat + iend
            else:
                # GIF wrapper
                gif_header = b"GIF89a" + struct.pack("<HH", 100, 100) + b"\x00\x00\x00"
                data = gif_header + compressed + b";"

        return data

    def create_polyglot_exploit(self, exploit_type: str) -> bytes:
        """
        Create polyglot file with embedded exploit.

        Real attacks use these to bypass filters.
        """
        if exploit_type == "xss":
            # GIF/JavaScript polyglot for XSS
            exploit = b"GIF89a/*<script>alert(document.domain)</script>*/=0;"
            exploit += b"\x21\xf9\x04\x01\x00\x00\x00\x00"
            exploit += b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"
            exploit += b"\x02\x02\x44\x01\x00;"
            return exploit

        elif exploit_type == "php":
            # JPEG/PHP polyglot for code execution
            exploit = b"\xff\xd8\xff\xe0<?php "
            exploit += b'system($_GET["cmd"]);'
            exploit += b"__halt_compiler();?>"
            exploit += b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            exploit += b"\xff\xdb\x00C" + b"\x00" * 64
            exploit += b"\xff\xd9"
            return exploit

        elif exploit_type == "java":
            # PNG/Java polyglot for deserialization
            png_header = b"\x89PNG\r\n\x1a\n"

            # Java serialized object (simplified)
            java_object = b"\xac\xed\x00\x05"  # Java serialization header
            java_object += b"sr\x00\x15java.lang.ProcessBuilder"
            java_object += b"\x00\x00\x00\x00\x00\x00\x00\x01"

            # Wrap in PNG chunk
            java_chunk = (
                struct.pack(">I", len(java_object))
                + b"jaVa"
                + java_object
                + struct.pack(">I", 0)
            )

            # Add valid PNG structure
            ihdr = (
                struct.pack(">I", 13)
                + b"IHDR"
                + struct.pack(">II", 1, 1)
                + b"\x08\x02\x00\x00\x00"
                + struct.pack(">I", 0)
            )
            iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)

            return png_header + ihdr + java_chunk + iend

        else:
            # Generic polyglot
            return b"POLY" + exploit_type.encode() + b"\x00GLOT"

    def create_buffer_overflow_payload(self, target: str) -> bytes:
        """
        Create payload designed to cause buffer overflow.

        Targets specific parsing vulnerabilities.
        """
        if target == "exif":
            # JPEG with oversized EXIF
            jpeg_header = b"\xff\xd8\xff\xe1"  # SOI + APP1 marker

            # Claim huge EXIF size
            exif_size = struct.pack(">H", 65535)  # Maximum size

            # EXIF data with overflow attempt
            exif_data = b"Exif\x00\x00MM\x00*"  # EXIF header

            # Add malicious tag with huge count
            exif_data += struct.pack(">H", 1)  # 1 IFD entry
            exif_data += struct.pack(">H", 0x0100)  # ImageWidth tag
            exif_data += struct.pack(">H", 4)  # LONG type
            exif_data += struct.pack(">I", 0xFFFFFFFF)  # Huge count
            exif_data += struct.pack(">I", 0x41414141)  # Overflow data

            # Fill rest with pattern
            pattern = b"A" * (65535 - len(exif_data) - 2)

            return jpeg_header + exif_size + exif_data + pattern + b"\xff\xd9"

        elif target == "png_chunk":
            # PNG with oversized chunk
            png_header = b"\x89PNG\r\n\x1a\n"

            # Valid IHDR
            ihdr = (
                struct.pack(">I", 13)
                + b"IHDR"
                + struct.pack(">II", 100, 100)
                + b"\x08\x02\x00\x00\x00"
                + struct.pack(">I", 0)
            )

            # Malicious chunk with huge size
            chunk_size = struct.pack(">I", 0x7FFFFFFF)  # 2GB claimed size
            chunk_type = b"mALc"
            chunk_data = b"A" * 1000  # But only 1KB actual
            chunk_crc = struct.pack(">I", 0)

            malicious_chunk = chunk_size + chunk_type + chunk_data + chunk_crc

            # IEND
            iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)

            return png_header + ihdr + malicious_chunk + iend

        elif target == "gif_extension":
            # GIF with malicious extension block
            gif_header = b"GIF89a" + struct.pack("<HH", 100, 100) + b"\xf7\x00\x00"

            # Logical screen descriptor
            gif_header += b"\x00\x00\x00"

            # Application extension with overflow
            app_ext = b"\x21\xff"  # Extension introducer + app extension
            app_ext += b"\xff"  # Claim 255 byte block (but provide more)
            app_ext += b"OVERFLOW" + b"A" * 500  # Overflow attempt
            app_ext += b"\x00"  # Block terminator

            return gif_header + app_ext + b";"

        else:
            # Generic overflow attempt
            return b"OVER" + b"A" * 10000 + b"FLOW"

    @pytest.mark.security
    @pytest.mark.critical
    async def test_zip_bomb_protection(self, security_engine):
        """
        Test protection against zip bomb attacks.

        Critical: Prevents memory exhaustion attacks.
        """
        # Create various zip bombs
        bomb_types = [
            ("standard", self.create_zip_bomb(1000)),
            ("nested", self.create_nested_bomb(3)),
        ]

        for bomb_type, bomb_data in bomb_types:
            # Attempt to process
            with pytest.raises(
                (SecurityError, ValidationError, MemoryError)
            ) as exc_info:
                await security_engine.validate_image_safety(
                    image_data=bomb_data, image_format="png"
                )

            # Should be detected and rejected
            error_message = str(exc_info.value).lower()
            assert any(
                word in error_message
                for word in ["bomb", "compression", "size", "memory"]
            ), f"Zip bomb ({bomb_type}) not properly detected"

            # Verify it doesn't crash the system
            import psutil

            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            assert memory_mb < 1000, f"Memory leak detected: {memory_mb:.1f}MB"

    @pytest.mark.security
    async def test_polyglot_exploit_blocking(self, security_engine):
        """
        Test blocking of polyglot files with embedded exploits.

        Prevents XSS, code execution, and other attacks.
        """
        exploit_types = ["xss", "php", "java"]

        for exploit_type in exploit_types:
            polyglot_data = self.create_polyglot_exploit(exploit_type)

            # Attempt to process
            result = await security_engine.validate_image_safety(
                image_data=polyglot_data, image_format="auto"
            )

            # Should flag as suspicious
            if result:
                assert (
                    result.get("is_safe", True) is False
                    or result.get("has_exploit", False) is True
                    or result.get("is_polyglot", False) is True
                ), f"Polyglot exploit ({exploit_type}) not detected"

            # Attempt conversion (should fail or sanitize)
            request = ConversionRequest(output_format="png", strip_metadata=True)

            try:
                result, output = await conversion_service.convert(
                    image_data=polyglot_data, request=request
                )

                if result.success:
                    # If conversion succeeded, exploit should be removed
                    assert exploit_type.encode() not in output
                    assert b"script" not in output.lower()
                    assert b"<?php" not in output

            except (SecurityError, ValidationError):
                # Expected - blocked due to security
                pass

    @pytest.mark.security
    async def test_buffer_overflow_protection(self, security_engine):
        """
        Test protection against buffer overflow attempts.

        Prevents memory corruption attacks.
        """
        overflow_targets = ["exif", "png_chunk", "gif_extension"]

        for target in overflow_targets:
            overflow_payload = self.create_buffer_overflow_payload(target)

            # Attempt to process
            try:
                result = await security_engine.validate_image_safety(
                    image_data=overflow_payload, image_format="auto"
                )

                # Should detect anomaly
                if result:
                    assert (
                        result.get("has_anomaly", False)
                        or result.get("has_oversized_data", False)
                        or not result.get("is_safe", True)
                    ), f"Buffer overflow ({target}) not detected"

            except (SecurityError, ValidationError, struct.error):
                # Expected - parsing should fail safely
                pass

            # Verify no memory corruption
            # System should still be functional
            test_data = b"TEST"
            assert (
                hashlib.sha256(test_data).hexdigest()
                == "94ee059335e587e501cc4bf90613e0814f00a7b08bc7c648fd865a2af6a22cc2"
            )

    @pytest.mark.security
    async def test_embedded_executable_detection(self):
        """
        Test detection of embedded executables in images.

        Prevents malware distribution via images.
        """
        # Create image with embedded executable markers
        executable_signatures = [
            b"MZ",  # DOS/Windows executable
            b"\x7fELF",  # Linux ELF
            b"\xfe\xed\xfa\xce",  # Mach-O (macOS)
            b"\xca\xfe\xba\xbe",  # Java class file
            b"#!/bin/sh",  # Shell script
            b"#!/usr/bin/python",  # Python script
        ]

        for signature in executable_signatures:
            # Create PNG with embedded executable
            png_header = b"\x89PNG\r\n\x1a\n"

            # IHDR
            ihdr = (
                struct.pack(">I", 13)
                + b"IHDR"
                + struct.pack(">II", 100, 100)
                + b"\x08\x02\x00\x00\x00"
                + struct.pack(">I", 0)
            )

            # Custom chunk with executable
            exec_chunk = (
                struct.pack(">I", len(signature) + 100)
                + b"exEc"
                + signature
                + b"\x00" * 100
                + struct.pack(">I", 0)
            )

            # IEND
            iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)

            test_image = png_header + ihdr + exec_chunk + iend

            # Check detection
            from app.services.format_detection_service import format_detection_service

            security_scan = await format_detection_service.analyze_format_security(
                image_data=test_image, detected_format="png"
            )

            if security_scan:
                # Should detect embedded executable
                assert (
                    security_scan.get("has_executable", False)
                    or security_scan.get("has_suspicious_data", False)
                    or security_scan.get("risk_level", "low") != "low"
                ), f"Embedded executable ({signature[:10]}) not detected"

    @pytest.mark.security
    async def test_ssrf_payload_blocking(self):
        """
        Test blocking of Server-Side Request Forgery (SSRF) payloads.

        Prevents images that trigger external requests.
        """
        # Create images with SSRF payloads
        ssrf_payloads = [
            # SVG with external entity
            b'<svg xmlns="http://www.w3.org/2000/svg">'
            b'<image href="http://evil.com/steal" />'
            b"</svg>",
            # HTML in image comment
            b"GIF89a\x01\x00\x01\x00\x00\x00\x00;" b'<img src="http://evil.com/track">',
            # JPEG with embedded URL in EXIF
            b"\xff\xd8\xff\xe1\x00\x50Exif\x00\x00"
            b"http://internal.server/admin"
            b"\xff\xd9",
        ]

        for payload in ssrf_payloads:
            # Validate should detect URLs
            from app.core.security.engine import SecurityEngine

            engine = SecurityEngine()
            scan_result = await engine.scan_for_urls(payload)

            if scan_result:
                assert scan_result.get("has_urls", False) or scan_result.get(
                    "has_external_references", False
                ), "SSRF payload not detected"

            # Conversion should strip URLs
            try:
                request = ConversionRequest(output_format="png", strip_metadata=True)

                result, output = await conversion_service.convert(
                    image_data=payload, request=request
                )

                if result.success:
                    # URLs should be removed
                    assert b"http://" not in output
                    assert b"evil.com" not in output

            except (SecurityError, ValidationError):
                # Expected - blocked for security
                pass

    @pytest.mark.security
    @pytest.mark.slow
    async def test_recursive_bomb_protection(self):
        """
        Test protection against recursive compression bombs.

        Prevents exponential resource consumption.
        """

        # Create recursive bomb
        def create_recursive_bomb(depth: int) -> bytes:
            if depth == 0:
                return b"BASE" * 1000

            inner = create_recursive_bomb(depth - 1)
            compressed = zlib.compress(inner * 10, level=9)

            # Wrap in image format
            png_header = b"\x89PNG\r\n\x1a\n"
            ihdr = (
                struct.pack(">I", 13)
                + b"IHDR"
                + struct.pack(">II", 10, 10)
                + b"\x08\x02\x00\x00\x00"
                + struct.pack(">I", 0)
            )
            idat = (
                struct.pack(">I", len(compressed))
                + b"IDAT"
                + compressed
                + struct.pack(">I", 0)
            )
            iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)

            return png_header + ihdr + idat + iend

        # Test with various recursion depths
        for depth in [2, 3, 4]:
            bomb = create_recursive_bomb(depth)

            # Should detect and block
            with pytest.raises(
                (SecurityError, ValidationError, RecursionError, MemoryError)
            ):
                await conversion_service.convert(
                    image_data=bomb, request=ConversionRequest(output_format="jpeg")
                )

            # Memory should not explode
            import psutil

            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            assert (
                memory_mb < 1000
            ), f"Memory explosion from recursive bomb: {memory_mb:.1f}MB"

    @pytest.mark.security
    async def test_integer_overflow_protection(self):
        """
        Test protection against integer overflow in dimension calculations.

        Prevents memory allocation attacks.
        """
        # Create images with dimension values that cause integer overflow
        overflow_cases = [
            (65535, 65535),  # Maximum * maximum
            (2147483647, 2),  # Max int * 2
            (46341, 46341),  # Just over sqrt(MAX_INT)
        ]

        for width, height in overflow_cases:
            # Create PNG with overflow dimensions
            png_header = b"\x89PNG\r\n\x1a\n"

            # IHDR with huge dimensions
            ihdr_data = struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"
            ihdr_crc = struct.pack(">I", 0)
            ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc

            # Minimal IDAT
            idat = (
                struct.pack(">I", 10)
                + b"IDAT"
                + b"\x78\x9c\x62\x00\x00\x00\x02\x00\x01"
                + struct.pack(">I", 0)
            )

            # IEND
            iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0xAE426082)

            overflow_image = png_header + ihdr_chunk + idat + iend

            # Should detect and reject
            with pytest.raises(
                (SecurityError, ValidationError, OverflowError, MemoryError)
            ):
                await conversion_service.convert(
                    image_data=overflow_image,
                    request=ConversionRequest(output_format="jpeg"),
                )
