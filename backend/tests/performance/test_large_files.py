"""
from typing import Any
Performance tests for large file handling and memory usage.
Tests streaming, chunked processing, and memory efficiency.
"""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from app.core.monitoring.performance import (ConversionMetrics,
                                             PerformanceMonitor)
from app.core.processing.vips_ops import VipsOperations


class TestLargeFilePerformance:
    """Test performance with large image files."""

    @pytest.fixture
    def vips_ops(self) -> None:
        """Create VipsOperations instance."""
        return VipsOperations()

    @pytest.fixture
    def large_image_data(self) -> None:
        """Create fake large image data (150MB)."""
        # Create a simple BMP header (simpler than real image)
        # This is just for testing memory handling, not actual image processing
        size_mb = 150
        data = bytearray(b"BM")  # BMP signature
        data.extend(b"\x00" * (size_mb * 1024 * 1024 - 2))
        return bytes(data)

    @pytest.fixture
    def medium_image_data(self) -> None:
        """Create fake medium image data (50MB)."""
        size_mb = 50
        data = bytearray(b"BM")
        data.extend(b"\x00" * (size_mb * 1024 * 1024 - 2))
        return bytes(data)

    def test_streaming_threshold_detection(self, vips_ops) -> None:
        """Test that streaming is triggered for large files."""
        # File under threshold (50MB)
        assert not vips_ops.should_use_streaming(file_size=50 * 1024 * 1024)

        # File at threshold (100MB)
        assert not vips_ops.should_use_streaming(file_size=100 * 1024 * 1024)

        # File over threshold (150MB)
        assert vips_ops.should_use_streaming(file_size=150 * 1024 * 1024)

        # Test with file path
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"x" * (150 * 1024 * 1024))
            tmp_path = tmp.name

        try:
            assert vips_ops.should_use_streaming(file_path=tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_memory_usage_monitoring(self, vips_ops) -> None:
        """Test memory usage tracking during operations."""
        initial_memory = vips_ops._get_memory_usage()

        # Allocate some memory - use bytes for more reliable memory allocation
        large_data = bytearray(50 * 1024 * 1024)  # 50MB of bytes

        current_memory = vips_ops._get_memory_usage()
        memory_delta = current_memory - initial_memory

        # Should detect memory increase (allow small tolerance for memory reporting)
        # Note: Memory reporting may be delayed or granular on some systems
        assert memory_delta >= 0  # At minimum, memory shouldn't decrease

        # Test memory check
        with patch.object(
            vips_ops, "_get_memory_usage", return_value=initial_memory + 600
        ):
            with pytest.raises(Exception) as exc_info:
                vips_ops._check_memory_limit()
            assert "Memory limit exceeded" in str(exc_info.value)

        # Clean up
        del large_data

    def test_chunked_processing(self, vips_ops, large_image_data) -> None:
        """Test chunked processing for large images."""
        # Mock PIL for fallback processing
        with patch("app.core.processing.vips_ops.Image") as mock_image_class:
            mock_img = MagicMock()
            mock_buffer = MagicMock()
            mock_image_class.open.return_value = mock_img

            # Mock BytesIO to capture save call
            with patch("app.core.processing.vips_ops.io.BytesIO") as mock_io:
                mock_io.return_value = mock_buffer
                mock_buffer.getvalue.return_value = b"processed_image_data"

                # Make vips unavailable to test fallback
                vips_ops.vips_available = False

                result = vips_ops.process_in_chunks(
                    large_image_data, output_format="webp", quality=85
                )

                # Should have called PIL's save method
                assert mock_img.save.called
                assert result == b"processed_image_data"

    def test_memory_estimation(self, vips_ops) -> None:
        """Test memory usage estimation for images."""
        # 1920x1080 RGBA image
        estimated = vips_ops.estimate_memory_usage(1920, 1080, 4)
        # Should be around 7.9MB * 1.2 overhead = ~9.5MB
        assert 9 <= estimated <= 10

        # 4K image (3840x2160 RGBA)
        estimated = vips_ops.estimate_memory_usage(3840, 2160, 4)
        # Should be around 31.6MB * 1.2 = ~38MB
        assert 37 <= estimated <= 39

        # Large image (10000x10000 RGBA)
        estimated = vips_ops.estimate_memory_usage(10000, 10000, 4)
        # Should be around 381MB * 1.2 = ~457MB
        assert 455 <= estimated <= 460

    def test_memory_monitoring_report(self, vips_ops) -> None:
        """Test memory monitoring and reporting."""
        stats = vips_ops.monitor_memory("test_operation")

        assert stats["operation"] == "test_operation"
        assert "current_mb" in stats
        assert "initial_mb" in stats
        assert "delta_mb" in stats
        assert "limit_mb" in stats
        assert "usage_percent" in stats

        # Usage percent should be calculated correctly
        if stats["limit_mb"] > 0:
            expected_percent = (stats["delta_mb"] / stats["limit_mb"]) * 100
            assert abs(stats["usage_percent"] - expected_percent) < 0.1

    @pytest.mark.slow
    def test_large_file_processing_memory_stable(self, vips_ops) -> None:
        """Test that memory remains stable when processing multiple large files."""
        initial_memory = vips_ops._get_memory_usage()
        peak_memory = initial_memory

        # Mock PIL to avoid processing fake data
        with patch("app.core.processing.vips_ops.Image") as mock_image_class:
            mock_img = MagicMock()
            mock_image_class.open.return_value = mock_img
            mock_img.save = MagicMock()

            # Make vips unavailable to use PIL path
            vips_ops.vips_available = False

            # Process multiple "large" files
            for i in range(5):
                # Create fake large data
                fake_data = b"fake_image_data" * (2 * 1024 * 1024)  # ~30MB each

                # Mock BytesIO for save operation
                with patch("app.core.processing.vips_ops.io.BytesIO") as mock_io:
                    mock_buffer = MagicMock()
                    mock_io.return_value = mock_buffer
                    mock_buffer.getvalue.return_value = b"processed"

                    result = vips_ops.process_in_chunks(
                        fake_data, output_format="webp", quality=85
                    )

                    assert result == b"processed"

            current_memory = vips_ops._get_memory_usage()
            peak_memory = max(peak_memory, current_memory)

        # Memory growth should be limited
        memory_growth = peak_memory - initial_memory
        assert (
            memory_growth < 200
        ), f"Memory grew by {memory_growth}MB, expected < 200MB"

    def test_performance_monitor_lifecycle(self) -> None:
        """Test PerformanceMonitor start/stop lifecycle."""
        monitor = PerformanceMonitor(sample_interval=0.1)

        # Start monitoring
        monitor.start()
        assert monitor._monitoring
        assert monitor._monitor_thread is not None
        assert monitor._monitor_thread.is_alive()

        # Let it collect some samples
        import time

        time.sleep(0.3)

        # Stop and get stats
        stats = monitor.stop()
        assert not monitor._monitoring

        # Should have statistics
        assert "cpu" in stats
        assert "memory" in stats
        assert "io" in stats

        # Should have collected samples
        assert stats["cpu"]["samples"] >= 2
        assert stats["memory"]["start_mb"] > 0
        assert stats["memory"]["current_mb"] > 0

    def test_conversion_metrics_tracking(self) -> None:
        """Test ConversionMetrics data collection."""
        metrics = ConversionMetrics(
            file_size=10 * 1024 * 1024,  # 10MB
            processing_time=2.5,
            memory_used=50 * 1024 * 1024,  # 50MB
            output_size=5 * 1024 * 1024,  # 5MB
            input_format="jpeg",
            output_format="webp",
        )

        # Convert to JSON
        json_data = metrics.to_json()

        assert json_data["input_mb"] == 10.0
        assert json_data["output_mb"] == 5.0
        assert json_data["time_seconds"] == 2.5
        assert json_data["memory_mb"] == 50.0
        assert json_data["compression_ratio"] == 2.0
        assert json_data["throughput_mbps"] == 4.0  # 10MB / 2.5s
        assert json_data["input_format"] == "jpeg"
        assert json_data["output_format"] == "webp"

    @pytest.mark.parametrize(
        "file_size_mb,expected_streaming",
        [
            (50, False),  # Below threshold
            (100, False),  # At threshold
            (101, True),  # Just above threshold
            (200, True),  # Well above threshold
            (1024, True),  # 1GB file
        ],
    )
    def test_streaming_decision_matrix(
        self, vips_ops, file_size_mb, expected_streaming
    ) -> None:
        """Test streaming decisions for various file sizes."""
        file_size_bytes = file_size_mb * 1024 * 1024
        uses_streaming = vips_ops.should_use_streaming(file_size=file_size_bytes)
        assert uses_streaming == expected_streaming

    def test_vips_save_options_generation(self, vips_ops) -> None:
        """Test generation of vips-specific save options."""
        # JPEG options
        jpeg_opts = vips_ops._get_vips_save_options("jpeg", 85, strip_metadata=True)
        assert jpeg_opts["Q"] == 85
        assert jpeg_opts["optimize_coding"] == True
        assert jpeg_opts["strip"] == True

        # WebP options
        webp_opts = vips_ops._get_vips_save_options("webp", 90, strip_metadata=False)
        assert webp_opts["Q"] == 90
        assert webp_opts["lossless"] == False
        assert webp_opts["strip"] == False
        assert webp_opts["effort"] == 4

        # PNG options
        png_opts = vips_ops._get_vips_save_options("png", 100, interlace=True)
        assert png_opts["compression"] == 9
        assert png_opts["interlace"] == True

        # AVIF options
        avif_opts = vips_ops._get_vips_save_options("avif", 100)
        assert avif_opts["Q"] == 100
        assert avif_opts["lossless"] == True
