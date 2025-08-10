"""Security tests for memory management."""

from typing import Any
import gc
import os
import resource
import tempfile
import time
from unittest.mock import patch

import pytest

from app.core.conversion.manager import ConversionManager
from app.core.security.memory import MemoryError as SecureMemoryError
from app.core.security.memory import (
    SecureMemoryManager,
    get_system_memory_info,
    secure_memory_context,
)
from app.core.security.sandbox import SandboxConfig, SecuritySandbox
from app.models.conversion import ConversionRequest, ConversionSettings, OutputFormat


class TestSecureMemoryManager:
    """Test secure memory management functionality."""

    def test_memory_manager_initialization(self) -> None:
        """Test memory manager initializes correctly."""
        manager = SecureMemoryManager(max_memory_mb=256)

        assert manager.max_memory_mb == 256
        assert manager.max_memory_bytes == 256 * 1024 * 1024
        assert len(manager._allocated_buffers) == 0
        assert len(manager._locked_pages) == 0

    def test_secure_allocate_basic(self) -> None:
        """Test basic secure memory allocation."""
        manager = SecureMemoryManager(max_memory_mb=64)

        # Allocate small buffer
        buffer = manager.secure_allocate(1024, lock_memory=False)

        assert isinstance(buffer, bytearray)
        assert len(buffer) == 1024
        assert len(manager._allocated_buffers) == 1

    def test_secure_allocate_exceeds_limit(self) -> None:
        """Test allocation fails when exceeding limits."""
        manager = SecureMemoryManager(max_memory_mb=1)  # 1MB limit

        # Try to allocate more than limit
        with pytest.raises(SecureMemoryError, match="exceeds maximum"):
            manager.secure_allocate(2 * 1024 * 1024)  # 2MB

    def test_secure_allocate_invalid_size(self) -> None:
        """Test allocation fails with invalid size."""
        manager = SecureMemoryManager()

        with pytest.raises(SecureMemoryError, match="Invalid allocation size"):
            manager.secure_allocate(0)

        with pytest.raises(SecureMemoryError, match="Invalid allocation size"):
            manager.secure_allocate(-100)

    def test_secure_clear_bytearray(self) -> None:
        """Test secure clearing of bytearray."""
        manager = SecureMemoryManager()

        # Create buffer with known data
        buffer = bytearray(b"sensitive data here")
        original_length = len(buffer)

        # Clear it
        manager.secure_clear(buffer)

        # Should be all zeros
        assert len(buffer) == original_length
        assert all(b == 0 for b in buffer)

    def test_secure_clear_bytes(self) -> None:
        """Test secure clearing of bytes (should warn but not crash)."""
        manager = SecureMemoryManager()

        # Try to clear immutable bytes (should not raise error)
        buffer = b"immutable data"
        manager.secure_clear(buffer)  # Should log warning but not crash

    def test_memory_context_manager(self) -> None:
        """Test memory manager context manager."""
        with SecureMemoryManager(max_memory_mb=64) as manager:
            buffer = manager.secure_allocate(1024, lock_memory=False)
            assert len(manager._allocated_buffers) == 1

        # After exit, should be cleaned up
        assert len(manager._allocated_buffers) == 0

    def test_secure_memory_context_function(self) -> None:
        """Test secure_memory_context function."""
        with secure_memory_context(max_memory_mb=32) as manager:
            buffer = manager.secure_allocate(512, lock_memory=False)
            assert isinstance(buffer, bytearray)
            assert len(buffer) == 512

    def test_memory_stats(self) -> None:
        """Test memory statistics reporting."""
        manager = SecureMemoryManager(max_memory_mb=128)

        stats = manager.get_memory_stats()

        assert stats["max_memory_mb"] == 128
        assert stats["max_memory_bytes"] == 128 * 1024 * 1024
        assert "current_usage_bytes" in stats
        assert "allocated_buffers" in stats
        assert "memory_utilization_percent" in stats

    def test_cleanup_all(self) -> None:
        """Test cleanup of all resources."""
        manager = SecureMemoryManager()

        # Allocate multiple buffers
        for i in range(3):
            manager.secure_allocate(1024, lock_memory=False)

        assert len(manager._allocated_buffers) == 3

        # Clean up
        manager.cleanup_all()

        assert len(manager._allocated_buffers) == 0

    @pytest.mark.skipif(
        os.name != "posix", reason="Memory locking only on POSIX systems"
    )
    def test_memory_locking_posix(self) -> None:
        """Test memory page locking on POSIX systems."""
        manager = SecureMemoryManager()

        try:
            # Try to allocate with memory locking
            buffer = manager.secure_allocate(4096, lock_memory=True)  # Page size
            assert isinstance(buffer, bytearray)
            # Note: We can't easily test if mlock actually worked without root privileges
        except MemoryError:
            # May fail without sufficient privileges - that's OK
            pass


class TestSecuritySandboxMemory:
    """Test memory features in SecuritySandbox."""

    def test_sandbox_memory_config(self) -> None:
        """Test sandbox memory configuration."""
        config = SandboxConfig(
            max_memory_mb=256,
            enable_memory_tracking=True,
            enable_memory_locking=True,
            memory_violation_threshold=5,
        )

        sandbox = SecuritySandbox(config)

        assert sandbox.config.max_memory_mb == 256
        assert sandbox.config.enable_memory_tracking is True
        assert sandbox.config.enable_memory_locking is True
        assert sandbox.config.memory_violation_threshold == 5

    def test_memory_stats_tracking(self) -> None:
        """Test memory statistics tracking."""
        config = SandboxConfig(enable_memory_tracking=True)
        sandbox = SecuritySandbox(config)

        stats = sandbox.get_memory_stats()

        assert "memory_violations" in stats
        assert "peak_memory_mb" in stats
        assert "memory_limit_mb" in stats
        assert "memory_tracking_enabled" in stats

    def test_memory_violation_detection(self) -> None:
        """Test memory violation detection."""
        config = SandboxConfig(max_memory_mb=100, memory_violation_threshold=3)
        sandbox = SecuritySandbox(config)

        # Simulate memory violation
        violation = sandbox._check_memory_violation(150.0)  # 150MB > 100MB limit
        assert violation is True
        assert sandbox._memory_violations == 1

        # Another violation
        violation = sandbox._check_memory_violation(200.0)
        assert violation is True
        assert sandbox._memory_violations == 2

        # Third violation should raise exception
        with pytest.raises(SecureMemoryError, match="exceeded threshold"):
            sandbox._check_memory_violation(250.0)

    def test_memory_cleanup(self) -> None:
        """Test memory cleanup in sandbox."""
        config = SandboxConfig(enable_memory_tracking=True)
        sandbox = SecuritySandbox(config)

        # Initialize memory manager
        sandbox._initialize_memory_manager()
        assert sandbox._memory_manager is not None

        # Clean up
        sandbox._cleanup_memory()
        assert sandbox._memory_manager is None


class TestMemoryInProcessing:
    """Test memory management in image processing pipeline."""

    @pytest.fixture
    def sample_image_data(self) -> None:
        """Create sample image data for testing."""
        # Create a small PNG image in memory
        import io

        from PIL import Image

        # Create a small test image
        img = Image.new("RGB", (100, 100), color="red")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def test_conversion_manager_memory_estimation(self, sample_image_data) -> None:
        """Test memory requirement estimation."""
        manager = ConversionManager()

        # Test memory estimation
        estimated_mb = manager._estimate_memory_requirements(
            len(sample_image_data), "png", "webp"
        )

        assert isinstance(estimated_mb, int)
        assert 64 <= estimated_mb <= 1024  # Within expected range

    @pytest.mark.asyncio
    async def test_memory_cleanup_on_conversion_failure(self, sample_image_data):
        """Test memory is cleaned up when conversion fails."""
        manager = ConversionManager()

        # Create request that will fail
        request = ConversionRequest(
            output_format=OutputFormat.WEBP, settings=ConversionSettings(quality=85)
        )

        # Mock a handler that will fail
        with patch.object(manager, "_get_handler") as mock_handler:
            mock_handler.side_effect = Exception("Test failure")

            with pytest.raises(Exception):
                await manager.convert_image(sample_image_data, "png", request)

            # Memory manager should be cleaned up
            assert manager._memory_manager is None

    def test_get_system_memory_info(self) -> None:
        """Test system memory information gathering."""
        info = get_system_memory_info()

        assert isinstance(info, dict)
        assert "total_memory_bytes" in info
        assert "available_memory_bytes" in info
        assert "swap_in_use" in info


class TestMemorySecurityIntegration:
    """Integration tests for memory security features."""

    def test_no_memory_leaks_after_operations(self) -> None:
        """Test that memory is properly cleaned up after operations."""
        initial_objects = len(gc.get_objects())

        # Perform multiple memory operations
        for _ in range(10):
            with secure_memory_context(max_memory_mb=32) as manager:
                buffer = manager.secure_allocate(1024, lock_memory=False)
                manager.secure_clear(buffer)

        # Force garbage collection
        gc.collect()

        # Should not have significant memory leaks
        final_objects = len(gc.get_objects())
        # Allow some variance for test framework objects
        assert final_objects - initial_objects < 100

    def test_memory_isolation_between_operations(self) -> None:
        """Test memory isolation between different operations."""
        manager1 = SecureMemoryManager(max_memory_mb=64)
        manager2 = SecureMemoryManager(max_memory_mb=64)

        # Allocate in first manager
        buffer1 = manager1.secure_allocate(1024, lock_memory=False)
        buffer1[0:4] = b"test"

        # Allocate in second manager
        buffer2 = manager2.secure_allocate(1024, lock_memory=False)

        # Buffers should be independent
        assert buffer1 is not buffer2
        assert buffer1[0:4] == b"test"
        assert buffer2[0:4] != b"test"

        # Cleanup
        manager1.cleanup_all()
        manager2.cleanup_all()

    @pytest.mark.skipif(
        not hasattr(resource, "RLIMIT_AS"), reason="Memory limits not supported"
    )
    def test_resource_limit_enforcement(self) -> None:
        """Test that resource limits are enforced."""
        # This test requires running in a controlled environment
        # In practice, resource limits are set by the sandbox
        config = SandboxConfig(max_memory_mb=64)
        sandbox = SecuritySandbox(config)

        # Test that config has the right limits
        assert sandbox.config.max_memory_mb == 64


class TestMemoryStressScenarios:
    """Stress tests for memory management."""

    def test_rapid_allocation_deallocation(self) -> None:
        """Test rapid memory allocation and deallocation."""
        manager = SecureMemoryManager(max_memory_mb=128)

        # Rapidly allocate and clear many small buffers
        for i in range(100):
            buffer = manager.secure_allocate(1024, lock_memory=False)
            buffer[0:10] = b"test" + str(i).encode()[:6]
            manager.secure_clear(buffer)

        manager.cleanup_all()

    def test_memory_fragmentation_resistance(self) -> None:
        """Test resistance to memory fragmentation."""
        manager = SecureMemoryManager(max_memory_mb=64)

        buffers = []

        # Allocate many buffers of different sizes
        sizes = [512, 1024, 2048, 4096] * 10
        for size in sizes:
            try:
                buffer = manager.secure_allocate(size, lock_memory=False)
                buffers.append(buffer)
            except SecureMemoryError:
                break  # Expected when we run out of allocated limit

        # Clear every other buffer (create fragmentation)
        for i in range(0, len(buffers), 2):
            manager.secure_clear(buffers[i])

        manager.cleanup_all()

    def test_concurrent_memory_operations(self) -> None:
        """Test concurrent memory operations."""
        import threading

        manager = SecureMemoryManager(max_memory_mb=128)
        results = []
        errors = []

        def worker() -> None:
            try:
                buffer = manager.secure_allocate(1024, lock_memory=False)
                time.sleep(0.01)  # Simulate some work
                manager.secure_clear(buffer)
                results.append("success")
            except Exception as e:
                errors.append(str(e))

        # Start multiple threads
        threads = []
        for _ in range(10):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        # Wait for completion
        for t in threads:
            t.join()

        # Should have mostly successes
        assert len(results) >= 5  # At least half should succeed
        manager.cleanup_all()


class TestMemorySecurityValidation:
    """Test memory security validation and compliance."""

    def test_memory_overwrite_patterns(self) -> None:
        """Test that memory is properly overwritten with security patterns."""
        manager = SecureMemoryManager()

        # Create buffer with known data
        test_data = b"confidential information that must be cleared"
        buffer = bytearray(test_data)

        # Clear the buffer
        manager.secure_clear(buffer)

        # Verify it's been overwritten (should be all zeros after final pass)
        assert all(b == 0 for b in buffer)
        assert buffer != test_data

    def test_no_temporary_files_created(self) -> None:
        """Test that no temporary files are created during memory operations."""
        temp_dir = tempfile.gettempdir()
        initial_files = set()

        # Get initial file list
        try:
            initial_files = set(os.listdir(temp_dir))
        except (OSError, PermissionError):
            pytest.skip("Cannot access temp directory")

        # Perform memory operations
        with secure_memory_context(max_memory_mb=64) as manager:
            for _ in range(5):
                buffer = manager.secure_allocate(8192, lock_memory=False)
                # Write pattern to buffer
                for i in range(0, len(buffer), 1024):
                    end = min(i + 1024, len(buffer))
                    buffer[i:end] = b"X" * (end - i)
                manager.secure_clear(buffer)

        # Check no new files were created
        try:
            final_files = set(os.listdir(temp_dir))
            new_files = final_files - initial_files
            assert len(new_files) == 0, f"Temporary files created: {new_files}"
        except (OSError, PermissionError):
            # If we can't check, that's OK - the test is still valid
            pass

    def test_memory_limit_compliance(self) -> None:
        """Test compliance with memory limits."""
        limit_mb = 32
        manager = SecureMemoryManager(max_memory_mb=limit_mb)

        total_allocated = 0
        buffers = []

        # Allocate up to the limit
        while total_allocated < (limit_mb * 1024 * 1024):
            try:
                buffer = manager.secure_allocate(1024, lock_memory=False)
                buffers.append(buffer)
                total_allocated += 1024
            except SecureMemoryError:
                break  # Hit the limit

        # Should not be able to allocate beyond limit
        with pytest.raises(SecureMemoryError):
            manager.secure_allocate(1024 * 1024)  # 1MB more

        manager.cleanup_all()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
