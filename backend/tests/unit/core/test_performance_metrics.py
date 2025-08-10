"""
Unit tests for performance metrics accuracy.
Tests metrics collection, calculation, and reporting.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from app.cli.utils.profiler import CLIProfiler, cli_profiler
from app.core.monitoring.metrics import MetricsCollector
from app.core.monitoring.performance import (
    BatchMetrics,
    ConversionMetrics,
    PerformanceMonitor,
    PerformanceProfiler,
)


class TestConversionMetrics:
    """Test ConversionMetrics accuracy."""

    def test_metrics_calculation(self):
        """Test that metrics are calculated correctly."""
        metrics = ConversionMetrics(
            file_size=1024 * 1024,  # 1MB
            processing_time=0.5,
            memory_used=10 * 1024 * 1024,  # 10MB
            output_size=512 * 1024,  # 512KB
            input_format="png",
            output_format="webp",
        )

        # Test JSON conversion
        json_data = metrics.to_json()

        assert json_data["input_mb"] == 1.0
        assert json_data["output_mb"] == 0.5
        assert json_data["time_seconds"] == 0.5
        assert json_data["memory_mb"] == 10.0
        assert json_data["compression_ratio"] == 2.0
        assert json_data["throughput_mbps"] == 2.0  # 1MB / 0.5s

    def test_zero_handling(self):
        """Test metrics handle zero values correctly."""
        metrics = ConversionMetrics(
            file_size=0, processing_time=0, memory_used=0, output_size=0
        )

        json_data = metrics.to_json()

        assert json_data["compression_ratio"] == 0
        assert json_data["throughput_mbps"] == 0
        assert json_data["input_mb"] == 0
        assert json_data["output_mb"] == 0


class TestBatchMetrics:
    """Test BatchMetrics accuracy."""

    def test_batch_metrics_properties(self):
        """Test batch metrics calculated properties."""
        metrics = BatchMetrics(job_id="test_job", total_files=10, worker_count=4)

        # Simulate processing
        metrics.completed_files = 8
        metrics.failed_files = 2

        # Add file metrics
        for i in range(10):
            file_metric = ConversionMetrics(
                file_size=1024 * 1024,
                processing_time=0.5,
                memory_used=5 * 1024 * 1024,
                output_size=768 * 1024,
            )
            metrics.file_metrics.append(file_metric)

        # Test properties
        assert metrics.elapsed_time > 0
        assert metrics.throughput > 0
        assert metrics.average_time_per_file == 0.5

        # Test worker efficiency
        # With 4 workers and 0.5s per file, ideal time would be 1.25s for 10 files
        # Actual time depends on elapsed_time
        efficiency = metrics.worker_efficiency
        assert 0 <= efficiency <= 100

    def test_batch_metrics_json_report(self):
        """Test batch metrics JSON report generation."""
        metrics = BatchMetrics(job_id="test_batch", total_files=5, worker_count=2)

        metrics.completed_files = 4
        metrics.failed_files = 1
        metrics.total_input_size = 5 * 1024 * 1024
        metrics.total_output_size = 3 * 1024 * 1024
        metrics.peak_memory_mb = 150.5

        # Set times for predictable results
        metrics.start_time = time.time() - 10
        metrics.end_time = time.time()

        report = metrics.to_json()

        # Check summary
        assert report["summary"]["total_files"] == 5
        assert report["summary"]["completed"] == 4
        assert report["summary"]["failed"] == 1
        assert report["summary"]["success_rate"] == 80.0
        assert report["summary"]["worker_count"] == 2

        # Check performance
        assert report["performance"]["total_input_mb"] == 5.0
        assert report["performance"]["total_output_mb"] == 3.0
        assert report["performance"]["compression_ratio"] == pytest.approx(1.67, 0.01)
        assert report["performance"]["peak_memory_mb"] == 150.5


class TestMetricsCollector:
    """Test MetricsCollector from existing metrics module."""

    @pytest.fixture
    def collector(self):
        return MetricsCollector(max_history=10)

    def test_conversion_tracking_lifecycle(self, collector):
        """Test complete conversion tracking lifecycle."""
        conversion_id = "test_conv_1"

        # Start conversion
        metrics = collector.start_conversion(
            conversion_id=conversion_id,
            input_format="jpeg",
            output_format="webp",
            requested_format="webp",
            input_size=2 * 1024 * 1024,
            estimated_memory_mb=20,
        )

        assert metrics is not None
        assert metrics.conversion_id == conversion_id
        assert metrics.input_size_bytes == 2 * 1024 * 1024

        # Simulate processing
        time.sleep(0.1)

        # Complete conversion
        collector.complete_conversion(
            conversion_id=conversion_id, output_size=1 * 1024 * 1024, peak_memory_mb=25
        )

        # Check metrics moved to history
        assert conversion_id not in collector._current_metrics
        assert len(collector._metrics_history) == 1

        completed_metrics = collector._metrics_history[0]
        assert completed_metrics.output_size_bytes == 1 * 1024 * 1024
        assert completed_metrics.peak_memory_mb == 25
        assert completed_metrics.duration_ms > 0

    def test_aggregate_statistics(self, collector):
        """Test aggregate statistics calculation."""
        # Add several conversions
        for i in range(5):
            conversion_id = f"conv_{i}"
            metrics = collector.start_conversion(
                conversion_id=conversion_id,
                input_format="png",
                output_format="webp",
                requested_format="webp",
                input_size=1024 * 1024,
                estimated_memory_mb=10,
            )

            # Mark as complete or failed
            if i < 4:
                collector.complete_conversion(
                    conversion_id=conversion_id, output_size=512 * 1024
                )
            else:
                collector.fail_conversion(
                    conversion_id=conversion_id,
                    error_type="TestError",
                    error_message="Test failure",
                )

        # Get aggregate stats
        stats = collector.get_aggregate_stats()

        assert stats["total_conversions"] == 5
        assert stats["success_rate"] == 80.0  # 4 out of 5
        assert stats["formats_used"]["png->webp"] == 5
        assert stats["average_compression_ratio"] == 2.0  # 1MB to 512KB


class TestPerformanceProfiler:
    """Test PerformanceProfiler accuracy."""

    @pytest.fixture
    def profiler(self):
        return PerformanceProfiler()

    def test_profile_lifecycle(self, profiler):
        """Test profiling lifecycle and report generation."""
        # Start profile
        profiler.start_profile("test_operation")

        # Add operations
        profiler.add_operation("step1", 0.5, input_size=1000)
        profiler.add_operation("step2", 0.3, output_size=800)
        profiler.add_operation("step1", 0.4, input_size=1200)  # Another step1

        # Stop and get report
        report = profiler.stop_profile()

        assert report is not None
        assert report["profile_name"] == "test_operation"
        assert report["operations_count"] == 3

        # Check operation statistics
        op_stats = report["operation_stats"]
        assert "step1" in op_stats
        assert "step2" in op_stats

        # Step1 should have 2 operations
        assert op_stats["step1"]["count"] == 2
        assert op_stats["step1"]["total_seconds"] == 0.9
        assert op_stats["step1"]["average_seconds"] == 0.45

        # Step2 should have 1 operation
        assert op_stats["step2"]["count"] == 1
        assert op_stats["step2"]["total_seconds"] == 0.3

    def test_profile_save_to_file(self, profiler, tmp_path):
        """Test saving profile to JSON file."""
        profiler.start_profile("save_test")
        profiler.add_operation("test_op", 1.5)

        # Save to file
        profile_path = tmp_path / "profile.json"
        profiler.save_profile(profile_path)

        # Check file exists and contains valid JSON
        assert profile_path.exists()

        with open(profile_path) as f:
            data = json.load(f)

        assert data["profile_name"] == "save_test"
        assert "operation_stats" in data
        assert "test_op" in data["operation_stats"]


class TestCLIProfiler:
    """Test CLI-specific profiler."""

    def test_cli_profiler_enable_disable(self):
        """Test enabling and disabling CLI profiler."""
        profiler = CLIProfiler()

        # Initially disabled
        assert not profiler.enabled

        # Enable profiling
        profiler.enable(show_summary=False)
        assert profiler.enabled
        assert not profiler.show_summary

        # Disable profiling
        profiler.disable()
        assert not profiler.enabled

    def test_conversion_tracking(self):
        """Test tracking conversion metrics in CLI profiler."""
        profiler = CLIProfiler()
        profiler.enable()

        # Track a conversion
        profiler.track_conversion(
            input_size=2 * 1024 * 1024,
            output_size=1 * 1024 * 1024,
            duration=1.5,
            input_format="png",
            output_format="webp",
            memory_used=20 * 1024 * 1024,
        )

        # Check metrics were created
        assert profiler.current_metrics is not None
        assert profiler.current_metrics.file_size == 2 * 1024 * 1024
        assert profiler.current_metrics.output_size == 1 * 1024 * 1024
        assert profiler.current_metrics.processing_time == 1.5

    @patch("app.cli.utils.profiler.console")
    def test_profile_context_manager(self, mock_console):
        """Test profile operation context manager."""
        profiler = CLIProfiler()
        profiler.enable()

        with profiler.profile_operation("test_op"):
            # Simulate some work
            time.sleep(0.01)

        # Should have started and stopped profiling
        # Mock console should have been called if show_summary was True
        profiler.show_summary = True
        with profiler.profile_operation("test_op2"):
            time.sleep(0.01)


class TestPerformanceMonitor:
    """Test PerformanceMonitor accuracy."""

    def test_monitor_sampling(self):
        """Test that monitor samples data correctly."""
        monitor = PerformanceMonitor(sample_interval=0.05)

        monitor.start()
        time.sleep(0.2)  # Allow time for sampling
        stats = monitor.stop()

        # Should have collected multiple samples
        assert stats["cpu"]["samples"] >= 3

        # Should have CPU and memory data
        assert stats["cpu"]["average_percent"] >= 0
        assert stats["memory"]["start_mb"] > 0
        assert stats["memory"]["current_mb"] > 0

        # Delta should be calculated
        assert "delta_mb" in stats["memory"]

    def test_peak_memory_tracking(self):
        """Test that peak memory is tracked correctly."""
        monitor = PerformanceMonitor()

        # Record initial state
        initial_memory = monitor.get_current_memory_mb()

        monitor.start()

        # Allocate and deallocate memory
        large_data = [0] * (5 * 1024 * 1024)  # ~40MB
        time.sleep(0.1)
        del large_data
        time.sleep(0.1)

        stats = monitor.stop()

        # Peak should be higher than current
        assert stats["memory"]["peak_mb"] >= stats["memory"]["current_mb"]
        assert stats["memory"]["peak_mb"] >= stats["memory"]["start_mb"]


class TestMetricsIntegration:
    """Test integration between different metrics components."""

    def test_metrics_flow_integration(self):
        """Test complete metrics flow from collection to reporting."""
        # Create components
        collector = MetricsCollector()
        profiler = PerformanceProfiler()
        monitor = PerformanceMonitor()

        # Start monitoring
        monitor.start()
        profiler.start_profile("integration_test")

        # Simulate conversion
        conversion_id = "test_conv"
        metrics = collector.start_conversion(
            conversion_id=conversion_id,
            input_format="jpeg",
            output_format="avif",
            requested_format="avif",
            input_size=3 * 1024 * 1024,
            estimated_memory_mb=30,
        )

        # Add to profiler
        profiler.add_operation("conversion", 2.0)

        # Complete conversion
        collector.complete_conversion(
            conversion_id=conversion_id, output_size=1 * 1024 * 1024, peak_memory_mb=35
        )

        # Stop profiling and monitoring
        profile_report = profiler.stop_profile()
        monitor_stats = monitor.stop()

        # Get aggregate stats
        aggregate_stats = collector.get_aggregate_stats()

        # Verify all components collected data
        assert aggregate_stats["total_conversions"] == 1
        assert aggregate_stats["success_rate"] == 100.0

        assert profile_report["operations_count"] == 1
        assert "conversion" in profile_report["operation_stats"]

        assert monitor_stats["cpu"]["samples"] > 0
        assert monitor_stats["memory"]["start_mb"] > 0
