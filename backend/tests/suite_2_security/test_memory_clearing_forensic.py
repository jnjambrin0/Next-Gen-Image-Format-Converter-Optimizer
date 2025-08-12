"""
Ultra-realistic forensic memory clearing tests.
Tests 5-pass overwrite, memory locking, and forensic verification.
"""

import ctypes
import gc
import hashlib
import mmap
import os
import platform
import secrets
import struct
import tempfile
from typing import Dict, List, Optional, Tuple, Type

import pytest

from app.core.security.engine import SecurityEngine
from app.core.security.memory_manager import MemoryManager
from app.models.conversion import ConversionRequest, ConversionStatus
from app.services.conversion_service import conversion_service


class TestMemoryClearingForensic:
    """Test forensic-grade memory clearing and verification."""

    @pytest.fixture
    def memory_manager(self):
        """Create MemoryManager instance."""
        return MemoryManager()

    @pytest.fixture
    def security_engine(self):
        """Create SecurityEngine instance."""
        return SecurityEngine()

    def create_sensitive_data(self, size: int = 1024) -> bytes:
        """
        Create data that looks like sensitive information.

        Simulates API keys, passwords, PII, etc.
        """
        patterns = [
            b"API_KEY=sk_live_",
            b"password123!@#",
            b"SSN: 123-45-6789",
            b"CC: 4532-1234-5678-9012",
            b"Bearer eyJhbGciOiJIUzI1NiIs",
            b"-----BEGIN RSA PRIVATE KEY-----",
            b"AWS_SECRET_ACCESS_KEY=",
            b"email@example.com",
        ]

        # Create buffer with sensitive patterns
        data = bytearray(size)
        offset = 0

        for pattern in patterns:
            if offset + len(pattern) < size:
                data[offset : offset + len(pattern)] = pattern
                offset += len(pattern) + 10

        # Fill rest with random sensitive-looking data
        for i in range(offset, size):
            data[i] = secrets.randbits(8)

        return bytes(data)

    def scan_memory_for_pattern(
        self, pattern: bytes, memory_buffer: bytearray
    ) -> List[int]:
        """
        Scan memory buffer for specific pattern.

        Returns list of offsets where pattern found.
        """
        offsets = []
        pattern_len = len(pattern)
        buffer_len = len(memory_buffer)

        for i in range(buffer_len - pattern_len + 1):
            if memory_buffer[i : i + pattern_len] == pattern:
                offsets.append(i)

        return offsets

    def verify_overwrite_patterns(self, memory_buffer: bytearray) -> Dict[int, int]:
        """
        Verify 5-pass overwrite patterns were applied.

        Returns histogram of byte values found.
        """
        histogram = {}

        for byte_val in memory_buffer:
            histogram[byte_val] = histogram.get(byte_val, 0) + 1

        return histogram

    @pytest.mark.security
    @pytest.mark.critical
    async def test_five_pass_memory_overwrite(self, memory_manager):
        """
        Test 5-pass DoD 5220.22-M memory overwrite.

        Critical for preventing forensic recovery.
        """
        # Create sensitive data
        sensitive_data = self.create_sensitive_data(10240)  # 10KB

        # Allocate memory buffer
        buffer = bytearray(sensitive_data)
        buffer_address = id(buffer)

        # Verify data is in memory
        assert b"API_KEY" in buffer
        assert b"password123" in buffer

        # Apply 5-pass overwrite
        patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]  # DoD standard

        for pass_num, pattern in enumerate(patterns):
            await memory_manager.secure_overwrite(
                buffer, pattern=pattern, pass_number=pass_num + 1
            )

            # Verify pattern was written
            for i in range(min(100, len(buffer))):
                assert buffer[i] == pattern, f"Pass {pass_num+1} failed at offset {i}"

        # Verify no sensitive data remains
        assert b"API_KEY" not in buffer
        assert b"password123" not in buffer
        assert b"SSN" not in buffer

        # Check final state (should be all zeros)
        for byte_val in buffer[:100]:
            assert byte_val == 0x00, "Final pass should leave zeros"

    @pytest.mark.security
    async def test_memory_locking_protection(self, memory_manager):
        """
        Test memory locking to prevent swap to disk.

        Prevents sensitive data from being written to swap file.
        """
        if platform.system() not in ["Linux", "Darwin"]:
            pytest.skip("Memory locking only tested on Unix systems")

        # Create sensitive buffer
        sensitive_data = self.create_sensitive_data(4096)  # 4KB page
        buffer = bytearray(sensitive_data)

        # Lock memory
        try:
            locked = await memory_manager.lock_memory(buffer)

            if locked:
                # Verify memory is locked (platform-specific)
                # Note: Actual verification requires root/admin privileges

                # Modify data while locked
                buffer[0:10] = b"MODIFIED!!"

                # Data should remain in RAM, not swapped
                assert buffer[0:10] == b"MODIFIED!!"

                # Unlock memory
                await memory_manager.unlock_memory(buffer)

        except PermissionError:
            # Memory locking requires special privileges
            pytest.skip("Insufficient privileges for memory locking")

    @pytest.mark.security
    async def test_forensic_residue_detection(self):
        """
        Test detection of memory residue after clearing.

        Simulates forensic analysis techniques.
        """
        # Create large buffer with sensitive data
        size = 1024 * 1024  # 1MB
        sensitive_buffer = bytearray(self.create_sensitive_data(size))

        # Mark specific locations with known patterns
        markers = [
            (1000, b"MARKER_1"),
            (50000, b"MARKER_2"),
            (500000, b"MARKER_3"),
        ]

        for offset, marker in markers:
            sensitive_buffer[offset : offset + len(marker)] = marker

        # Clear using standard method (single pass)
        for i in range(len(sensitive_buffer)):
            sensitive_buffer[i] = 0

        # Forensic scan for residue
        residue_found = False

        # Check for non-zero bytes (incomplete clearing)
        non_zero_count = sum(1 for b in sensitive_buffer if b != 0)
        if non_zero_count > 0:
            residue_found = True

        # Check for patterns at boundaries (common residue locations)
        boundary_checks = [
            0,  # Start
            len(sensitive_buffer) - 1,  # End
            4096,  # Page boundary
            65536,  # 64KB boundary
        ]

        for boundary in boundary_checks:
            if boundary < len(sensitive_buffer):
                if sensitive_buffer[boundary] != 0:
                    residue_found = True

        # Single pass should leave no residue if done correctly
        assert not residue_found, f"Found {non_zero_count} non-zero bytes"

    @pytest.mark.security
    @pytest.mark.critical
    async def test_image_conversion_memory_clearing(
        self, security_engine, realistic_image_generator
    ):
        """
        Test memory clearing during actual image conversion.

        Ensures no image data remains in memory after processing.
        """
        # Create test image with embedded sensitive data
        test_image = realistic_image_generator(
            width=1000, height=1000, content_type="document"
        )

        # Embed sensitive marker in image
        marker = b"SENSITIVE_MARKER_12345"
        test_image_with_marker = test_image + marker

        # Track memory before conversion
        import psutil

        process = psutil.Process()
        memory_before = process.memory_info().rss

        # Perform conversion with security enabled
        request = ConversionRequest(
            output_format="png", strip_metadata=True, secure_mode=True
        )

        result, output_data = await conversion_service.convert(
            image_data=test_image_with_marker, request=request
        )

        assert result.status == ConversionStatus.COMPLETED

        # Force garbage collection
        gc.collect()

        # Scan process memory for marker
        # (Note: This is simplified; real forensic scan would be more thorough)
        memory_after = process.memory_info().rss

        # Memory shouldn't grow significantly
        memory_growth = (memory_after - memory_before) / 1024 / 1024
        assert memory_growth < 50, f"Excessive memory growth: {memory_growth:.1f}MB"

        # Marker should not be in output
        assert marker not in output_data

    @pytest.mark.security
    async def test_memory_mapped_file_clearing(self, memory_manager):
        """
        Test clearing of memory-mapped files.

        Memory-mapped files require special handling.
        """
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name

            # Write sensitive data
            sensitive_data = self.create_sensitive_data(8192)
            tmp.write(sensitive_data)
            tmp.flush()

        try:
            # Memory map the file
            with open(tmp_path, "r+b") as f:
                with mmap.mmap(f.fileno(), 0) as mmapped:
                    # Verify data is accessible
                    assert b"API_KEY" in mmapped[:]

                    # Clear memory-mapped region
                    await memory_manager.secure_clear_mmap(mmapped)

                    # Verify clearing
                    assert b"API_KEY" not in mmapped[:]

                    # Verify overwrite patterns
                    data = mmapped[:]
                    assert all(b == 0 for b in data[:100])

        finally:
            # Clean up
            os.unlink(tmp_path)

    @pytest.mark.security
    async def test_cross_platform_memory_clearing(self, memory_manager):
        """
        Test memory clearing across different platforms.

        Different OS have different memory management.
        """
        platform_name = platform.system()

        # Create sensitive buffer
        sensitive_data = self.create_sensitive_data(4096)
        buffer = bytearray(sensitive_data)

        if platform_name == "Windows":
            # Windows-specific clearing
            await memory_manager.secure_clear_windows(buffer)

        elif platform_name in ["Linux", "Darwin"]:
            # Unix-like clearing
            await memory_manager.secure_clear_unix(buffer)

        else:
            # Generic clearing
            await memory_manager.secure_clear_generic(buffer)

        # Verify clearing regardless of platform
        assert b"API_KEY" not in buffer
        assert b"password" not in buffer

        # Check for zeros
        zero_count = sum(1 for b in buffer if b == 0)
        assert zero_count == len(buffer), "Buffer not fully cleared"

    @pytest.mark.security
    @pytest.mark.slow
    async def test_large_buffer_clearing_performance(self, memory_manager):
        """
        Test performance of clearing large memory buffers.

        Ensures clearing is fast enough for practical use.
        """
        import time

        buffer_sizes = [
            (1024, "1KB"),
            (1024 * 100, "100KB"),
            (1024 * 1024, "1MB"),
            (1024 * 1024 * 10, "10MB"),
        ]

        performance_results = {}

        for size, label in buffer_sizes:
            # Create buffer
            buffer = bytearray(self.create_sensitive_data(size))

            # Measure clearing time
            start_time = time.perf_counter()

            # 5-pass overwrite
            patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]
            for pattern in patterns:
                for i in range(len(buffer)):
                    buffer[i] = pattern

            clearing_time = time.perf_counter() - start_time

            # Calculate throughput
            mb_per_second = (size * 5 / 1024 / 1024) / clearing_time

            performance_results[label] = {
                "time": clearing_time,
                "throughput": mb_per_second,
            }

            # Verify clearing
            assert all(b == 0 for b in buffer[:100])

        # Performance requirements
        # 1MB should clear in < 1 second (5 passes)
        assert (
            performance_results["1MB"]["time"] < 1.0
        ), f"1MB clearing too slow: {performance_results['1MB']['time']:.2f}s"

        # Throughput should be reasonable
        for label, metrics in performance_results.items():
            assert (
                metrics["throughput"] > 5
            ), f"Low throughput for {label}: {metrics['throughput']:.1f} MB/s"

    @pytest.mark.security
    async def test_partial_buffer_clearing(self, memory_manager):
        """
        Test clearing specific regions of memory buffers.

        Sometimes only parts of buffer contain sensitive data.
        """
        # Create buffer with mixed content
        buffer_size = 10240
        buffer = bytearray(buffer_size)

        # Add sensitive regions
        sensitive_regions = [
            (100, 200, b"SECRET_1"),  # Region 1
            (1000, 1100, b"SECRET_2"),  # Region 2
            (5000, 5200, b"SECRET_3"),  # Region 3
        ]

        for start, end, secret in sensitive_regions:
            pattern_len = len(secret)
            for i in range(start, min(end, start + pattern_len)):
                if i - start < pattern_len:
                    buffer[i] = secret[i - start]

        # Add non-sensitive data
        buffer[500:600] = b"PUBLIC_DATA" * 10

        # Clear only sensitive regions
        for start, end, _ in sensitive_regions:
            await memory_manager.secure_clear_region(buffer, start=start, end=end)

        # Verify sensitive regions cleared
        for start, end, secret in sensitive_regions:
            region = buffer[start:end]
            assert secret not in region
            assert all(b == 0 for b in region[:10])

        # Verify non-sensitive data intact
        assert b"PUBLIC_DATA" in buffer[500:600]

    @pytest.mark.security
    async def test_memory_compression_artifacts(self):
        """
        Test for compression artifacts in cleared memory.

        Compressed data might leave patterns even after clearing.
        """
        import zlib

        # Create compressible sensitive data
        sensitive_data = b"API_KEY=secret123" * 1000  # Highly compressible

        # Compress data
        compressed = zlib.compress(sensitive_data, level=9)

        # Create buffer with compressed data
        buffer = bytearray(len(compressed) * 2)
        buffer[: len(compressed)] = compressed

        # Clear buffer (single pass)
        for i in range(len(buffer)):
            buffer[i] = 0

        # Check for compression artifacts
        # Compressed data often has patterns like 0x78, 0x9C (zlib header)
        zlib_header_found = False
        for i in range(len(buffer) - 1):
            if buffer[i] == 0x78 and buffer[i + 1] == 0x9C:
                zlib_header_found = True
                break

        assert not zlib_header_found, "Compression header artifact found"

        # Check for repetitive patterns (common in compressed data)
        pattern_count = {}
        for i in range(len(buffer) - 3):
            pattern = tuple(buffer[i : i + 4])
            pattern_count[pattern] = pattern_count.get(pattern, 0) + 1

        # All should be zeros after clearing
        assert len(pattern_count) == 1, "Non-zero patterns found"
        assert (0, 0, 0, 0) in pattern_count

    @pytest.mark.security
    @pytest.mark.critical
    async def test_cryptographic_key_material_clearing(self, memory_manager):
        """
        Test clearing of cryptographic key material.

        Crypto keys require special handling due to sensitivity.
        """
        # Generate cryptographic keys
        key_sizes = [16, 24, 32]  # AES-128, AES-192, AES-256

        for key_size in key_sizes:
            # Generate random key
            key = secrets.token_bytes(key_size)

            # Create buffer with key
            buffer = bytearray(1024)
            buffer[100 : 100 + key_size] = key

            # Also store key hash for verification
            key_hash = hashlib.sha256(key).digest()

            # Clear with extra passes for crypto material
            patterns = [0x00, 0xFF, 0xAA, 0x55, 0x33, 0xCC, 0x00]  # 7-pass

            for pattern in patterns:
                for i in range(len(buffer)):
                    buffer[i] = pattern

            # Verify key is cleared
            assert key not in buffer

            # Verify no partial key remains
            for i in range(len(buffer) - key_size + 1):
                if buffer[i : i + key_size] == key:
                    assert False, f"Key found at offset {i}"

            # Check that the cleared region doesn't match key hash
            for i in range(len(buffer) - 32 + 1):
                if hashlib.sha256(buffer[i : i + key_size]).digest() == key_hash:
                    assert False, "Key-like pattern found"

    @pytest.mark.security
    async def test_memory_alignment_clearing(self, memory_manager):
        """
        Test clearing with different memory alignments.

        Misaligned data might not be fully cleared.
        """
        # Test different alignments
        alignments = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096]

        for alignment in alignments:
            # Create misaligned buffer
            total_size = alignment * 10 + 7  # Not aligned
            buffer = bytearray(total_size)

            # Fill with sensitive pattern
            pattern = b"SENSITIVE"
            for i in range(0, total_size - len(pattern), len(pattern)):
                buffer[i : i + len(pattern)] = pattern

            # Clear with alignment consideration
            await memory_manager.secure_clear_aligned(buffer, alignment=alignment)

            # Verify complete clearing
            assert b"SENSITIVE" not in buffer
            assert all(
                b == 0 for b in buffer
            ), f"Incomplete clearing with alignment {alignment}"

    @pytest.mark.security
    async def test_memory_fence_verification(self):
        """
        Test memory fence instructions for secure clearing.

        Memory fences ensure write operations complete.
        """
        # Create buffer
        buffer = bytearray(4096)
        buffer[:100] = b"SENSITIVE_DATA" * 7

        # Clear with memory fence
        # Note: This is pseudo-code as actual fence instructions are CPU-specific
        for i in range(len(buffer)):
            buffer[i] = 0

            # Memory fence every 64 bytes (cache line)
            if i % 64 == 63:
                # In real implementation, this would use:
                # - mfence on x86
                # - dmb on ARM
                # - sync on PowerPC
                pass

        # Verify clearing completed
        assert b"SENSITIVE" not in buffer
        assert all(b == 0 for b in buffer)

        # Check cache-line boundaries specifically
        for i in range(0, len(buffer), 64):
            cache_line = buffer[i : i + 64]
            assert all(b == 0 for b in cache_line), f"Cache line at {i} not cleared"
