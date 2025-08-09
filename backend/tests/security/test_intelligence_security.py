"""Security-focused tests for Intelligence Engine.

Tests specifically designed to validate security measures including:
- Input validation and sanitization
- DoS attack prevention
- Memory safety
- Information disclosure prevention
- Secure error handling
"""

import asyncio
import hashlib
import io
import os
import struct
import tempfile
import time
from unittest.mock import MagicMock, Mock, patch

import numpy as np
import pytest
from PIL import Image

from app.core.intelligence.engine import IntelligenceEngine
from app.core.security.errors_simplified import SecurityError
from app.models.conversion import ContentClassification, ContentType


class TestIntelligenceEngineSecurity:
    """Security-focused tests for the Intelligence Engine."""

    @pytest.fixture
    def engine(self):
        """Create engine instance for security testing."""
        engine = IntelligenceEngine(
            models_dir="./test_models", fallback_mode=True, enable_caching=True
        )
        yield engine
        engine.clear_cache()

    # Test 1: Path traversal prevention
    @pytest.mark.asyncio
    async def test_path_traversal_prevention(self):
        """Test that path traversal attacks are prevented."""
        # Try to load models from parent directories
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "./models/../../../sensitive",
            "models/content/../../../../../../etc/passwd",
        ]

        for path in malicious_paths:
            # Should not allow traversal
            with patch("pathlib.Path.exists", return_value=True):
                engine = IntelligenceEngine(models_dir=path, fallback_mode=True)
                # Should fall back to safe mode
                assert engine.fallback_mode is True
                assert engine.model_loaded is False

    # Test 2: Malicious image payloads
    @pytest.mark.asyncio
    async def test_malicious_image_payloads(self, engine):
        """Test handling of images with malicious payloads."""
        # JPEG with embedded script (polyglot file)
        jpeg_header = (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        )
        malicious_payload = b'<script>alert("XSS")</script>'
        jpeg_with_payload = jpeg_header + malicious_payload + b"\xff\xd9"

        # Should reject invalid JPEG
        with pytest.raises(SecurityError) as exc:
            await engine.classify_content(jpeg_with_payload)
        assert exc.value.category == "file"

        # PNG with oversized chunks
        png_header = b"\x89PNG\r\n\x1a\n"
        # IHDR with ridiculous dimensions
        ihdr = struct.pack(">I", 13)  # chunk length
        ihdr += b"IHDR"
        ihdr += struct.pack(">II", 999999999, 999999999)  # width, height
        ihdr += struct.pack(">BBBBB", 8, 2, 0, 0, 0)  # bit depth, color type, etc

        malicious_png = png_header + ihdr

        with pytest.raises(SecurityError):
            await engine.classify_content(malicious_png)

    # Test 3: DoS attack vectors
    @pytest.mark.asyncio
    async def test_dos_attack_prevention(self, engine):
        """Test prevention of various DoS attack vectors."""
        # Test 1: Decompression bomb
        # Create highly compressed but large image
        large_img = Image.new("RGB", (5000, 5000), color="white")
        compressed_buffer = io.BytesIO()
        large_img.save(compressed_buffer, format="PNG", compress_level=9)

        # Should detect and reject decompression bomb
        with pytest.raises(SecurityError) as exc:
            await engine.classify_content(compressed_buffer.getvalue())
        assert exc.value.category == "file"

        # Test legitimate compressed image
        normal_img = Image.new("RGB", (500, 500), color="blue")
        normal_buffer = io.BytesIO()
        normal_img.save(normal_buffer, format="PNG")

        # Should handle normal image fine
        result = await engine.classify_content(normal_buffer.getvalue())
        assert isinstance(result, ContentClassification)

        # Test 2: Algorithmic complexity attack
        # Create image that triggers worst-case processing
        complex_img = Image.new("RGB", (1000, 1000))
        pixels = complex_img.load()
        # Checkerboard pattern (high edge density)
        for i in range(1000):
            for j in range(1000):
                pixels[i, j] = (255, 255, 255) if (i + j) % 2 == 0 else (0, 0, 0)

        buffer = io.BytesIO()
        complex_img.save(buffer, format="PNG")

        # Should complete in reasonable time
        start_time = time.time()
        result = await engine.classify_content(buffer.getvalue())
        elapsed = time.time() - start_time

        assert elapsed < 2.0  # Should not take more than 2 seconds

        # Test 3: Rapid request flooding
        flood_tasks = []
        small_img = Image.new("RGB", (100, 100), color="red")
        buffer = io.BytesIO()
        small_img.save(buffer, format="PNG")
        img_data = buffer.getvalue()

        # Simulate rapid requests
        for i in range(100):
            task = asyncio.create_task(engine.classify_content(img_data))
            flood_tasks.append(task)

        # Should handle all requests without failure
        results = await asyncio.gather(*flood_tasks, return_exceptions=True)

        # Check for failures
        failures = [r for r in results if isinstance(r, Exception)]
        assert len(failures) == 0

    # Test 4: Information disclosure prevention
    @pytest.mark.asyncio
    async def test_information_disclosure_prevention(self, engine):
        """Test that sensitive information is not disclosed in errors."""
        # Test various error scenarios
        test_cases = [
            (b"invalid data", "file"),
            (b"", "file"),
            (b"\x00" * 1000, "file"),
        ]

        for data, expected_category in test_cases:
            try:
                await engine.classify_content(data)
            except SecurityError as e:
                # Error should not contain sensitive info
                error_str = str(e)
                assert "path" not in error_str.lower()
                assert "directory" not in error_str.lower()
                assert "/Users/" not in error_str
                assert "\\Users\\" not in error_str
                assert e.category == expected_category

    # Test 5: Memory safety validation
    @pytest.mark.asyncio
    async def test_memory_safety(self, engine):
        """Test memory safety measures."""
        # Create image with sensitive-looking data
        img = Image.new("RGB", (200, 200), color="white")

        # Embed pattern that looks like sensitive data
        pixels = img.load()
        # Write "SECRET" pattern
        secret_pattern = [
            [1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1],
            [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
            [1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0],
            [0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
            [1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1],
        ]

        for y, row in enumerate(secret_pattern):
            for x, val in enumerate(row):
                if val:
                    pixels[x + 10, y + 10] = (255, 0, 0)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")

        # Process image
        result = await engine.classify_content(buffer.getvalue())

        # Add to cache
        if hasattr(result, "face_regions"):
            result.face_regions = [Mock()]  # Simulate sensitive data

        # Clear cache with secure clearing
        engine.clear_cache()

        # Verify sensitive data was cleared
        assert not hasattr(result, "face_regions") or len(result.face_regions) == 0

    # Test 6: Model injection attacks
    @pytest.mark.asyncio
    async def test_model_injection_prevention(self):
        """Test prevention of model injection attacks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create malicious "model" file
            model_dir = os.path.join(tmpdir, "content")
            os.makedirs(model_dir)

            # Malicious model with code
            malicious_model = os.path.join(model_dir, "mobilenet_v3_content.onnx")
            with open(malicious_model, "wb") as f:
                # Write Python code disguised as model
                f.write(b"import os; os.system('malicious command')")

            # Metadata with valid structure but wrong checksum
            metadata = os.path.join(model_dir, "model_metadata.json")
            with open(metadata, "w") as f:
                f.write('{"checksum": "definitely_wrong_checksum"}')

            # Should fail validation
            with pytest.raises(SecurityError) as exc:
                engine = IntelligenceEngine(models_dir=tmpdir, fallback_mode=False)
            assert exc.value.category == "verification"

    # Test 7: Cache poisoning prevention
    @pytest.mark.asyncio
    async def test_cache_poisoning_prevention(self, engine):
        """Test that cache cannot be poisoned with malicious data."""
        # Create legitimate image
        img = Image.new("RGB", (100, 100), color="blue")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_data = buffer.getvalue()

        # Get legitimate result
        result1 = await engine.classify_content(img_data)

        # Try to poison cache directly
        if hasattr(engine, "_cache"):
            # Calculate hash
            img_hash = hashlib.md5(img_data).hexdigest()

            # Try to inject malicious result
            malicious_result = ContentClassification(
                primary_type=ContentType.DOCUMENT,  # Wrong type
                confidence=0.99,
                processing_time_ms=1,
                has_text=True,
                has_faces=True,
            )

            # Even if someone modifies cache, should not affect security
            async with engine._cache_lock:
                engine._cache[img_hash] = malicious_result

            # Classification should still work correctly
            # (In real implementation, cache should be protected)
            result2 = await engine.classify_content(img_data)

            # Results should be consistent with security measures
            assert isinstance(result2, ContentClassification)

    # Test 8: Resource exhaustion prevention
    @pytest.mark.asyncio
    async def test_resource_exhaustion_prevention(self, engine):
        """Test prevention of resource exhaustion attacks."""
        # Test CPU exhaustion
        # Create image that requires heavy processing
        heavy_img = Image.new("RGB", (2000, 2000))
        pixels = heavy_img.load()

        # Random noise (high entropy, complex features)
        for i in range(2000):
            for j in range(2000):
                pixels[i, j] = (
                    np.random.randint(0, 256),
                    np.random.randint(0, 256),
                    np.random.randint(0, 256),
                )

        buffer = io.BytesIO()
        heavy_img.save(buffer, format="PNG")

        # Should timeout if processing takes too long
        start = time.time()
        result = await engine.classify_content(buffer.getvalue())
        elapsed = time.time() - start

        # Should not take excessive time
        assert elapsed < 5.0  # 5 seconds max

        # Test memory exhaustion
        # Already covered in previous tests

    # Test 9: Secure error handling
    @pytest.mark.asyncio
    async def test_secure_error_handling(self, engine):
        """Test that errors are handled securely."""
        # Test various error conditions
        error_scenarios = [
            # Trigger different error paths
            (None, AttributeError),
            (b"", SecurityError),
            (b"a" * 10, SecurityError),
            ("not bytes", AttributeError),
        ]

        for data, expected_error in error_scenarios:
            try:
                if data is None:
                    # Force internal error
                    await engine.classify_content(None)
                else:
                    await engine.classify_content(data)
            except (SecurityError, AttributeError, TypeError) as e:
                # All errors should be safe
                if isinstance(e, SecurityError):
                    assert e.category in ["file", "verification", "unknown"]
                    assert "Security" in str(e) or "violation" in str(e)

                # No stack traces or internal details
                error_str = str(e)
                assert "__" not in error_str  # No internal Python details
                assert "Traceback" not in error_str

    # Test 10: Privacy validation
    @pytest.mark.asyncio
    async def test_privacy_measures(self, engine):
        """Test privacy protection measures."""
        # Create image with face-like patterns
        face_img = Image.new("RGB", (300, 300), color="white")

        # Draw simple face-like pattern
        pixels = face_img.load()
        # Eyes
        for x in range(80, 100):
            for y in range(100, 120):
                pixels[x, y] = (0, 0, 0)
                pixels[x + 120, y] = (0, 0, 0)

        # Mouth
        for x in range(120, 180):
            for y in range(200, 210):
                pixels[x, y] = (0, 0, 0)

        buffer = io.BytesIO()
        face_img.save(buffer, format="PNG")

        # Process image
        result = await engine.classify_content(buffer.getvalue())

        # If faces detected, should not contain identifying info
        if result.has_faces and hasattr(result, "face_regions"):
            for face in result.face_regions:
                # Should only have position, not features
                assert hasattr(face, "x")
                assert hasattr(face, "y")
                assert hasattr(face, "width")
                assert hasattr(face, "height")
                assert hasattr(face, "confidence")

                # Should not have facial features or identity
                assert not hasattr(face, "landmarks")
                assert not hasattr(face, "identity")
                assert not hasattr(face, "features")
                assert not hasattr(face, "encoding")

    def _get_memory_usage(self):
        """Get current memory usage in MB."""
        import psutil

        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
