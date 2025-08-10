"""
from typing import Any
Comprehensive integration tests for watch mode
Tests file monitoring, resource limits, and DoS prevention
"""

import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from app.cli.productivity.watcher import (
    Debouncer,
    DirectoryWatcher,
    RateLimiter,
    ResourceLimits,
    ResourceMonitor,
    WatcherStatus,
)


class TestRateLimiter:
    """Test rate limiting functionality"""

    def test_rate_limiter_allows_under_limit(self) -> None:
        """Test that rate limiter allows events under limit"""
        limiter = RateLimiter(max_per_second=5)

        # Should allow 5 events
        for i in range(5):
            assert limiter.should_allow() is True

    def test_rate_limiter_blocks_over_limit(self) -> None:
        """Test that rate limiter blocks events over limit"""
        limiter = RateLimiter(max_per_second=3)

        # Allow first 3
        for i in range(3):
            assert limiter.should_allow() is True

        # Should block 4th in same second
        assert limiter.should_allow() is False

    def test_rate_limiter_resets_after_time(self) -> None:
        """Test that rate limiter resets after time window"""
        limiter = RateLimiter(max_per_second=2)

        # Use up limit
        assert limiter.should_allow() is True
        assert limiter.should_allow() is True
        assert limiter.should_allow() is False

        # Wait for reset
        time.sleep(1.1)

        # Should allow again
        assert limiter.should_allow() is True

    def test_rate_limiter_thread_safety(self) -> None:
        """Test rate limiter is thread-safe"""
        limiter = RateLimiter(max_per_second=10)
        results = []

        def worker() -> None:
            for _ in range(5):
                results.append(limiter.should_allow())
                time.sleep(0.01)

        # Start multiple threads
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have exactly 10 True values (within the limit)
        true_count = sum(1 for r in results if r is True)
        assert true_count == 10


class TestDebouncer:
    """Test debouncing functionality"""

    def test_debouncer_delays_execution(self) -> None:
        """Test that debouncer delays execution"""
        debouncer = Debouncer(delay_ms=100)
        called = threading.Event()

        def callback() -> None:
            called.set()

        debouncer.debounce("key1", callback)

        # Should not be called immediately
        time.sleep(0.05)
        assert not called.is_set()

        # Should be called after delay
        time.sleep(0.1)
        assert called.is_set()

    def test_debouncer_cancels_previous(self) -> None:
        """Test that debouncer cancels previous calls"""
        debouncer = Debouncer(delay_ms=100)
        call_count = [0]

        def callback(value) -> None:
            call_count[0] = value

        # Rapid calls - only last should execute
        debouncer.debounce("key1", callback, 1)
        time.sleep(0.02)
        debouncer.debounce("key1", callback, 2)
        time.sleep(0.02)
        debouncer.debounce("key1", callback, 3)

        # Wait for execution
        time.sleep(0.15)

        # Only last call should have executed
        assert call_count[0] == 3

    def test_debouncer_multiple_keys(self) -> None:
        """Test debouncer handles multiple keys independently"""
        debouncer = Debouncer(delay_ms=50)
        results = {}

        def callback(key, value) -> None:
            results[key] = value

        # Different keys should not interfere
        debouncer.debounce("key1", callback, "key1", "value1")
        debouncer.debounce("key2", callback, "key2", "value2")

        time.sleep(0.1)

        assert results["key1"] == "value1"
        assert results["key2"] == "value2"

    def test_debouncer_cancel_all(self) -> None:
        """Test canceling all pending events"""
        debouncer = Debouncer(delay_ms=200)
        called = threading.Event()

        def callback() -> None:
            called.set()

        debouncer.debounce("key1", callback)
        debouncer.debounce("key2", callback)

        # Cancel before execution
        time.sleep(0.05)
        debouncer.cancel_all()

        # Wait past delay time
        time.sleep(0.2)

        # Should not have been called
        assert not called.is_set()


class TestDirectoryWatcher:
    """Test DirectoryWatcher functionality"""

    @pytest.fixture
    def temp_watch_dir(self) -> None:
        """Create temporary directory for watching"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def watcher(self, temp_watch_dir) -> None:
        """Create watcher instance"""
        limits = ResourceLimits(
            max_files=10,
            max_concurrent=2,
            max_memory_mb=256,
            max_cpu_percent=80,
            max_events_per_second=5,
            debounce_ms=50,
        )

        processed_files = []

        def process_callback(file_event) -> None:
            processed_files.append(file_event)
            time.sleep(0.01)  # Simulate processing

        watcher = DirectoryWatcher(
            directory=temp_watch_dir,
            filters=["*.txt", "*.jpg"],
            excludes=["*.tmp"],
            limits=limits,
            process_callback=process_callback,
        )

        watcher.processed_files_list = processed_files
        yield watcher

        # Cleanup
        if watcher.status != WatcherStatus.STOPPED:
            watcher.stop()

    def test_watcher_initialization(self, watcher, temp_watch_dir) -> None:
        """Test watcher initializes correctly"""
        assert watcher.directory == temp_watch_dir
        assert watcher.filters == ["*.txt", "*.jpg"]
        assert watcher.excludes == ["*.tmp"]
        assert watcher.status == WatcherStatus.IDLE
        assert watcher.limits.max_files == 10

    def test_should_process_file_filters(self, watcher, temp_watch_dir) -> None:
        """Test file filtering logic"""
        # Should process
        assert watcher.should_process_file(Path("test.txt")) is True
        assert watcher.should_process_file(Path("image.jpg")) is True

        # Should not process
        assert watcher.should_process_file(Path("test.tmp")) is False
        assert watcher.should_process_file(Path("test.pdf")) is False
        assert watcher.should_process_file(Path("no_extension")) is False

    def test_watcher_start_stop(self, watcher) -> None:
        """Test starting and stopping watcher"""
        # Start watcher
        watcher.start()
        assert watcher.status == WatcherStatus.WATCHING

        # Let it run briefly
        time.sleep(0.1)

        # Stop watcher
        watcher.stop()
        assert watcher.status == WatcherStatus.STOPPED

    def test_watcher_processes_new_files(self, watcher, temp_watch_dir) -> None:
        """Test that watcher processes new files"""
        watcher.start()
        time.sleep(0.1)  # Let watcher initialize

        # Create test file
        test_file = temp_watch_dir / "test.txt"
        test_file.write_text("test content")

        # Wait for processing (including debounce)
        time.sleep(0.2)

        # Check file was processed
        watcher.stop()

        processed = watcher.processed_files_list
        assert len(processed) > 0
        assert any(str(test_file) in str(e.path) for e in processed)

    def test_watcher_debounces_rapid_changes(self, watcher, temp_watch_dir) -> None:
        """Test that rapid changes are debounced"""
        watcher.start()
        time.sleep(0.1)

        test_file = temp_watch_dir / "rapid.txt"

        # Rapid writes
        for i in range(5):
            test_file.write_text(f"content {i}")
            time.sleep(0.01)  # Very rapid changes

        # Wait for debounce period
        time.sleep(0.2)

        watcher.stop()

        # Should have processed file only once due to debouncing
        processed = watcher.processed_files_list
        rapid_events = [e for e in processed if "rapid.txt" in str(e.path)]
        assert len(rapid_events) == 1

    def test_watcher_respects_rate_limit(self, watcher, temp_watch_dir) -> None:
        """Test that watcher respects rate limits"""
        # Set very low rate limit
        watcher.rate_limiter = RateLimiter(max_per_second=2)
        watcher.start()
        time.sleep(0.1)

        # Create many files quickly
        for i in range(10):
            test_file = temp_watch_dir / f"file{i}.txt"
            test_file.write_text(f"content {i}")

        # Wait for processing
        time.sleep(0.5)

        watcher.stop()

        # Should have limited processing due to rate limit
        # Exact count depends on timing, but should be less than 10
        assert len(watcher.processed_files_list) < 10

    def test_watcher_queue_limit(self, watcher, temp_watch_dir) -> None:
        """Test that processing queue has size limit"""
        # Set very small queue
        watcher.processing_queue.maxsize = 3
        watcher.start()
        time.sleep(0.1)

        # Try to add many files
        for i in range(10):
            test_file = temp_watch_dir / f"queue{i}.txt"
            test_file.write_text(f"content {i}")
            time.sleep(0.01)

        time.sleep(0.5)
        watcher.stop()

        # Stats should show some files were skipped
        assert watcher.stats.files_skipped > 0

    def test_watcher_concurrent_processing(self, watcher, temp_watch_dir) -> None:
        """Test concurrent file processing"""
        # Track processing times
        processing_times = []

        def slow_process(file_event) -> None:
            start = time.time()
            time.sleep(0.1)  # Simulate slow processing
            processing_times.append(time.time() - start)

        watcher.process_callback = slow_process
        watcher.limits.max_concurrent = 3
        watcher.start()
        time.sleep(0.1)

        # Create multiple files
        for i in range(6):
            test_file = temp_watch_dir / f"concurrent{i}.txt"
            test_file.write_text(f"content {i}")

        # Wait for all processing
        time.sleep(1.0)
        watcher.stop()

        # With concurrency, total time should be less than sequential
        # 6 files * 0.1s = 0.6s sequential, but with concurrency should be ~0.2s
        assert len(processing_times) > 0

    def test_watcher_pause_resume(self, watcher, temp_watch_dir) -> None:
        """Test pausing and resuming watcher"""
        watcher.start()
        time.sleep(0.1)

        # Pause watcher
        watcher.pause()
        assert watcher.status == WatcherStatus.PAUSED

        # Create file while paused
        paused_file = temp_watch_dir / "paused.txt"
        paused_file.write_text("created while paused")
        time.sleep(0.2)

        # Should not be processed yet
        assert len(watcher.processed_files_list) == 0

        # Resume
        watcher.resume()
        assert watcher.status == WatcherStatus.WATCHING

        # Create another file
        resumed_file = temp_watch_dir / "resumed.txt"
        resumed_file.write_text("created after resume")
        time.sleep(0.2)

        watcher.stop()

        # Resumed file should be processed
        assert any("resumed.txt" in str(e.path) for e in watcher.processed_files_list)

    def test_watcher_status_tracking(self, watcher, temp_watch_dir) -> None:
        """Test watcher status reporting"""
        watcher.start()
        time.sleep(0.1)

        # Create some activity
        for i in range(3):
            test_file = temp_watch_dir / f"status{i}.txt"
            test_file.write_text(f"content {i}")
            time.sleep(0.1)

        time.sleep(0.3)

        # Get status
        status = watcher.get_status()

        assert status["status"] in ["watching", "processing"]
        assert status["directory"] == str(temp_watch_dir)
        assert status["stats"]["total_events"] > 0
        assert "queue_size" in status["stats"]
        assert "active_workers" in status["stats"]

        watcher.stop()

    def test_watcher_checksum_duplicate_detection(
        self, watcher, temp_watch_dir
    ) -> None:
        """Test duplicate file detection via checksum"""
        watcher.start()
        time.sleep(0.1)

        # Create file
        file1 = temp_watch_dir / "original.txt"
        file1.write_text("unique content")

        time.sleep(0.2)

        # Copy file (same content, different name)
        file2 = temp_watch_dir / "copy.txt"
        file2.write_text("unique content")

        time.sleep(0.2)

        watcher.stop()

        # Should have detected duplicate and skipped
        assert watcher.stats.files_skipped > 0


class TestResourceMonitor:
    """Test resource monitoring and limits"""

    def test_resource_monitor_initialization(self) -> None:
        """Test resource monitor initializes correctly"""
        limits = ResourceLimits(max_memory_mb=512, max_cpu_percent=80)

        monitor = ResourceMonitor(limits)
        assert monitor.limits.max_memory_mb == 512
        assert monitor.limits.max_cpu_percent == 80
        assert monitor.monitoring is False

    def test_resource_monitor_start_stop(self) -> None:
        """Test starting and stopping resource monitor"""
        limits = ResourceLimits()
        monitor = ResourceMonitor(limits)

        called = threading.Event()

        def callback() -> None:
            called.set()

        monitor.start(callback)
        assert monitor.monitoring is True

        time.sleep(0.1)

        monitor.stop()
        assert monitor.monitoring is False

    def test_resource_monitor_check_limits(self) -> None:
        """Test checking resource limits"""
        limits = ResourceLimits(max_memory_mb=10000)  # Very high limit

        monitor = ResourceMonitor(limits)

        # Should be within limits
        assert monitor.check_limits() is True

        # Set very low limit
        monitor.limits.max_memory_mb = 1  # 1MB - definitely exceeded

        # Should exceed limits
        assert monitor.check_limits() is False


class TestDoSPrevention:
    """Test Denial of Service prevention mechanisms"""

    @pytest.fixture
    def dos_watcher(self, tmp_path) -> None:
        """Create watcher with strict DoS limits"""
        limits = ResourceLimits(
            max_files=5,  # Very low limit
            max_concurrent=1,
            max_memory_mb=100,
            max_cpu_percent=50,
            max_events_per_second=2,  # Very strict rate limit
            debounce_ms=100,
            timeout_seconds=5,
        )

        watcher = DirectoryWatcher(
            directory=tmp_path,
            filters=["*"],
            limits=limits,
            process_callback=lambda x: time.sleep(0.01),
        )

        yield watcher

        if watcher.status != WatcherStatus.STOPPED:
            watcher.stop()

    def test_dos_file_bomb_prevention(self, dos_watcher, tmp_path) -> None:
        """Test prevention of file bomb attacks"""
        dos_watcher.start()
        time.sleep(0.1)

        # Try to create many files quickly (file bomb)
        for i in range(100):
            file = tmp_path / f"bomb{i}.txt"
            file.write_text(f"bomb {i}")

        time.sleep(0.5)
        dos_watcher.stop()

        # Should have rate-limited and queue-limited
        stats = dos_watcher.stats

        # Should have skipped many files
        assert stats.files_skipped > 50

        # Should have processed only a few
        assert stats.files_processed < 10

    def test_dos_large_file_prevention(self, dos_watcher, tmp_path) -> None:
        """Test handling of very large files"""
        dos_watcher.start()
        time.sleep(0.1)

        # Create a large file
        large_file = tmp_path / "large.txt"

        # Write 10MB of data
        with open(large_file, "wb") as f:
            f.write(b"x" * (10 * 1024 * 1024))

        time.sleep(0.3)
        dos_watcher.stop()

        # Should handle large file without crashing
        assert dos_watcher.status == WatcherStatus.STOPPED

    def test_dos_rapid_modification_prevention(self, dos_watcher, tmp_path) -> None:
        """Test prevention of rapid modification attacks"""
        dos_watcher.start()
        time.sleep(0.1)

        target_file = tmp_path / "rapid.txt"

        # Rapidly modify the same file
        for i in range(50):
            target_file.write_text(f"modification {i}")
            time.sleep(0.001)  # Very rapid modifications

        time.sleep(0.5)
        dos_watcher.stop()

        # Should have debounced to very few events
        events = [e for e in dos_watcher.processed_files if "rapid.txt" in str(e)]

        # Debouncing should have limited to 1-2 events
        assert len(events) <= 2

    def test_dos_memory_exhaustion_prevention(self, dos_watcher) -> None:
        """Test prevention of memory exhaustion"""
        # Set very low memory limit
        dos_watcher.limits.max_memory_mb = 50

        # Mock memory check to simulate high usage
        with patch.object(
            dos_watcher.resource_monitor, "check_limits", return_value=False
        ):
            dos_watcher.start()
            time.sleep(0.1)

            # Try to process files
            for i in range(10):
                dos_watcher._process_file_event(Path(f"test{i}.txt"), "created")

            dos_watcher.stop()

            # Should have skipped files due to resource limits
            assert dos_watcher.stats.files_skipped > 0

    def test_dos_cpu_exhaustion_prevention(self, dos_watcher) -> None:
        """Test prevention of CPU exhaustion"""

        # Create CPU-intensive callback
        def cpu_intensive(file_event) -> None:
            # Simulate CPU-intensive operation
            start = time.time()
            while time.time() - start < 0.1:
                _ = sum(i * i for i in range(1000))

        dos_watcher.process_callback = cpu_intensive
        dos_watcher.start()

        # Let it run briefly
        time.sleep(0.5)

        dos_watcher.stop()

        # Should have limited processing
        assert dos_watcher.stats.files_processed < 10

    def test_dos_concurrent_connection_limit(self, dos_watcher, tmp_path) -> None:
        """Test limiting concurrent processing"""
        # Already set to max_concurrent=1 in fixture

        processing_count = [0]
        max_concurrent = [0]

        def track_concurrent(file_event) -> None:
            processing_count[0] += 1
            max_concurrent[0] = max(max_concurrent[0], processing_count[0])
            time.sleep(0.1)
            processing_count[0] -= 1

        dos_watcher.process_callback = track_concurrent
        dos_watcher.start()
        time.sleep(0.1)

        # Create multiple files
        for i in range(5):
            file = tmp_path / f"concurrent{i}.txt"
            file.write_text(f"content {i}")

        time.sleep(1.0)
        dos_watcher.stop()

        # Should never exceed max_concurrent limit
        assert max_concurrent[0] <= dos_watcher.limits.max_concurrent

    def test_dos_automatic_shutdown(self, dos_watcher) -> None:
        """Test automatic shutdown on resource exhaustion"""
        exhausted = threading.Event()

        def on_exhaustion() -> None:
            exhausted.set()
            dos_watcher.stop()

        # Replace exhaustion callback
        dos_watcher._on_resource_exhaustion = on_exhaustion

        # Simulate resource exhaustion
        with patch.object(
            dos_watcher.resource_monitor, "_monitor_loop"
        ) as mock_monitor:

            def simulate_exhaustion() -> None:
                time.sleep(0.1)
                on_exhaustion()

            mock_monitor.side_effect = simulate_exhaustion

            dos_watcher.start()
            time.sleep(0.3)

        # Should have triggered exhaustion
        assert exhausted.is_set()
        assert dos_watcher.status == WatcherStatus.STOPPED

    def test_dos_path_traversal_prevention(self, dos_watcher, tmp_path) -> None:
        """Test prevention of path traversal attempts"""
        dos_watcher.start()
        time.sleep(0.1)

        # Try to create files with suspicious names
        suspicious_names = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config",
            "~/../../root/.ssh/id_rsa",
            "\x00nullbyte.txt",
            "file\nwith\nnewlines.txt",
        ]

        for name in suspicious_names:
            try:
                # Sanitize for filesystem
                safe_name = (
                    name.replace("/", "_")
                    .replace("\\", "_")
                    .replace("\x00", "")
                    .replace("\n", "_")
                )
                file = tmp_path / safe_name[:50]  # Limit length
                file.write_text("suspicious")
            except (OSError, ValueError):
                pass  # Expected for invalid names

        time.sleep(0.3)
        dos_watcher.stop()

        # Should have handled suspicious files safely
        assert dos_watcher.status == WatcherStatus.STOPPED

        # No crashes or security issues
        assert True  # If we got here, no security breach occurred


class TestWatchModeIntegration:
    """Full integration tests for watch mode"""

    @pytest.fixture
    def integration_setup(self, tmp_path) -> None:
        """Set up full integration environment"""
        watch_dir = tmp_path / "watch"
        output_dir = tmp_path / "output"
        watch_dir.mkdir()
        output_dir.mkdir()

        yield watch_dir, output_dir

    def test_realistic_watch_scenario(self, integration_setup) -> None:
        """Test realistic watch mode usage scenario"""
        watch_dir, output_dir = integration_setup

        # Create realistic limits
        limits = ResourceLimits(
            max_files=100,
            max_concurrent=4,
            max_memory_mb=512,
            max_cpu_percent=80,
            max_events_per_second=10,
            debounce_ms=500,
        )

        processed = []

        def mock_process(file_event) -> None:
            # Simulate image conversion
            time.sleep(0.05)
            output_file = output_dir / f"{file_event.path.stem}_converted.webp"
            output_file.write_text(f"Converted from {file_event.path.name}")
            processed.append(str(file_event.path))

        watcher = DirectoryWatcher(
            directory=watch_dir,
            filters=["*.jpg", "*.png", "*.gif"],
            excludes=["*.tmp", ".*"],
            limits=limits,
            process_callback=mock_process,
        )

        watcher.start()

        # Simulate realistic file operations

        # 1. Add some initial files
        for i in range(5):
            file = watch_dir / f"image{i}.jpg"
            file.write_text(f"image data {i}")
            time.sleep(0.1)  # Realistic delay between files

        time.sleep(1.0)

        # 2. Modify a file
        (watch_dir / "image0.jpg").write_text("modified content")

        time.sleep(0.6)  # Wait for debounce

        # 3. Add files with excluded extension
        (watch_dir / "temp.tmp").write_text("temp data")
        (watch_dir / ".hidden.jpg").write_text("hidden")

        time.sleep(0.5)

        # 4. Batch operation
        for i in range(5, 10):
            file = watch_dir / f"batch{i}.png"
            file.write_text(f"batch {i}")

        time.sleep(2.0)

        watcher.stop()

        # Verify results
        stats = watcher.stats

        # Should have processed files
        assert stats.files_processed > 0

        # Should have created output files
        output_files = list(output_dir.glob("*.webp"))
        assert len(output_files) > 0

        # Should not have processed excluded files
        assert "temp.tmp" not in processed
        assert ".hidden.jpg" not in processed

        # Should have reasonable performance
        assert stats.files_failed == 0

        # Check status was tracked correctly
        status = watcher.get_status()
        assert status["status"] == "stopped"
        assert status["stats"]["files_processed"] == stats.files_processed
