"""
Performance monitoring and metrics collection for image conversions.
Provides detailed timing, memory, and throughput metrics.
"""

import json
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ConversionMetrics:
    """Metrics for a single conversion operation."""

    file_size: int
    processing_time: float
    memory_used: int
    output_size: int
    input_format: str = ""
    output_format: str = ""
    worker_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_json(self) -> dict:
        """Convert to JSON-serializable dictionary."""
        return {
            "input_mb": round(self.file_size / 1024 / 1024, 2),
            "output_mb": round(self.output_size / 1024 / 1024, 2),
            "time_seconds": round(self.processing_time, 3),
            "memory_mb": round(self.memory_used / 1024 / 1024, 2),
            "compression_ratio": (
                round(self.file_size / self.output_size, 2)
                if self.output_size > 0
                else 0
            ),
            "throughput_mbps": (
                round((self.file_size / 1024 / 1024) / self.processing_time, 2)
                if self.processing_time > 0
                else 0
            ),
            "input_format": self.input_format,
            "output_format": self.output_format,
            "worker_id": self.worker_id,
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
        }


@dataclass
class BatchMetrics:
    """Metrics for batch processing operations."""

    job_id: str
    total_files: int
    completed_files: int = 0
    failed_files: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    worker_count: int = 1
    peak_memory_mb: float = 0
    total_input_size: int = 0
    total_output_size: int = 0
    file_metrics: List[ConversionMetrics] = field(default_factory=list)

    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    @property
    def throughput(self) -> float:
        """Calculate overall throughput in files per second."""
        if self.elapsed_time > 0:
            return (self.completed_files + self.failed_files) / self.elapsed_time
        return 0

    @property
    def average_time_per_file(self) -> float:
        """Calculate average processing time per file."""
        if self.file_metrics:
            total_time = sum(m.processing_time for m in self.file_metrics)
            return total_time / len(self.file_metrics)
        return 0

    @property
    def worker_efficiency(self) -> float:
        """Calculate worker efficiency as percentage."""
        if self.worker_count > 0 and self.elapsed_time > 0:
            ideal_time = (
                self.average_time_per_file * self.total_files / self.worker_count
            )
            actual_time = self.elapsed_time
            return min((ideal_time / actual_time) * 100, 100) if actual_time > 0 else 0
        return 0

    def to_json(self) -> dict:
        """Convert to JSON report."""
        return {
            "job_id": self.job_id,
            "summary": {
                "total_files": self.total_files,
                "completed": self.completed_files,
                "failed": self.failed_files,
                "success_rate": round(
                    (
                        (self.completed_files / self.total_files * 100)
                        if self.total_files > 0
                        else 0
                    ),
                    2,
                ),
                "elapsed_time_seconds": round(self.elapsed_time, 2),
                "worker_count": self.worker_count,
                "worker_efficiency_percent": round(self.worker_efficiency, 2),
            },
            "performance": {
                "throughput_files_per_second": round(self.throughput, 2),
                "average_time_per_file": round(self.average_time_per_file, 3),
                "total_input_mb": round(self.total_input_size / 1024 / 1024, 2),
                "total_output_mb": round(self.total_output_size / 1024 / 1024, 2),
                "compression_ratio": (
                    round(self.total_input_size / self.total_output_size, 2)
                    if self.total_output_size > 0
                    else 0
                ),
                "peak_memory_mb": round(self.peak_memory_mb, 2),
            },
            "file_details": [
                m.to_json() for m in self.file_metrics[-10:]
            ],  # Last 10 files
            "timestamp": datetime.fromtimestamp(self.start_time).isoformat(),
        }


class PerformanceMonitor:
    """
    Monitors system performance during image processing operations.
    Tracks CPU, memory, and I/O metrics.
    """

    def __init__(self, sample_interval: float = 0.5):
        """
        Initialize performance monitor.

        Args:
            sample_interval: Interval between performance samples in seconds
        """
        self.sample_interval = sample_interval
        self._process = psutil.Process()
        self._monitoring = False
        self._monitor_thread = None
        self._samples = deque(maxlen=1000)  # Keep last 1000 samples
        self._start_memory = self._process.memory_info().rss
        self._peak_memory = self._start_memory

    def start(self):
        """Start performance monitoring."""
        if self._monitoring:
            return

        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.debug("Performance monitoring started")

    def stop(self) -> Dict[str, Any]:
        """
        Stop monitoring and return statistics.

        Returns:
            Dictionary with performance statistics
        """
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1)

        if not self._samples:
            return {}

        # Calculate statistics
        cpu_samples = [s["cpu_percent"] for s in self._samples]
        memory_samples = [s["memory_mb"] for s in self._samples]

        current_memory = self._process.memory_info().rss

        # Update peak memory one last time in case it increased after last sample
        if current_memory > self._peak_memory:
            self._peak_memory = current_memory

        stats = {
            "cpu": {
                "average_percent": (
                    round(sum(cpu_samples) / len(cpu_samples), 2) if cpu_samples else 0
                ),
                "peak_percent": round(max(cpu_samples), 2) if cpu_samples else 0,
                "samples": len(cpu_samples),
            },
            "memory": {
                "start_mb": round(self._start_memory / 1024 / 1024, 2),
                "current_mb": round(current_memory / 1024 / 1024, 2),
                "peak_mb": round(self._peak_memory / 1024 / 1024, 2),
                "average_mb": (
                    round(sum(memory_samples) / len(memory_samples), 2)
                    if memory_samples
                    else 0
                ),
                "delta_mb": round(
                    (current_memory - self._start_memory) / 1024 / 1024, 2
                ),
            },
            "io": {
                "read_mb": round(self._get_io_counters()["read_mb"], 2),
                "write_mb": round(self._get_io_counters()["write_mb"], 2),
            },
        }

        logger.debug("Performance monitoring stopped", **stats)
        return stats

    def _monitor_loop(self):
        """Background monitoring loop."""
        while self._monitoring:
            try:
                sample = self._collect_sample()
                self._samples.append(sample)

                # Update peak memory
                current_memory = self._process.memory_info().rss
                if current_memory > self._peak_memory:
                    self._peak_memory = current_memory

            except Exception as e:
                logger.error(f"Error collecting performance sample: {e}")

            time.sleep(self.sample_interval)

    def _collect_sample(self) -> Dict[str, Any]:
        """Collect a single performance sample."""
        memory_info = self._process.memory_info()

        return {
            "timestamp": time.time(),
            "cpu_percent": self._process.cpu_percent(),
            "memory_mb": memory_info.rss / 1024 / 1024,
            "memory_percent": self._process.memory_percent(),
            "num_threads": self._process.num_threads(),
        }

    def _get_io_counters(self) -> Dict[str, float]:
        """Get I/O statistics."""
        try:
            io = self._process.io_counters()
            return {
                "read_mb": io.read_bytes / 1024 / 1024,
                "write_mb": io.write_bytes / 1024 / 1024,
            }
        except (AttributeError, psutil.AccessDenied):
            # I/O counters not available on all platforms
            return {"read_mb": 0, "write_mb": 0}

    def get_current_memory_mb(self) -> float:
        """Get current memory usage in MB."""
        return self._process.memory_info().rss / 1024 / 1024


class PerformanceProfiler:
    """
    Profiler for tracking detailed performance metrics of operations.
    Used by CLI for --profile flag functionality.
    """

    def __init__(self):
        """Initialize profiler."""
        self._profiles: Dict[str, Any] = {}
        self._monitor = PerformanceMonitor()
        self._active_profile = None

    def start_profile(self, name: str) -> None:
        """
        Start profiling an operation.

        Args:
            name: Name of the operation to profile
        """
        if self._active_profile:
            logger.warning(f"Profile {self._active_profile} still active, stopping it")
            self.stop_profile()

        self._active_profile = name
        self._profiles[name] = {"start_time": time.time(), "operations": []}
        self._monitor.start()
        logger.debug(f"Started profiling: {name}")

    def add_operation(self, operation: str, duration: float, **kwargs) -> None:
        """
        Add an operation to the current profile.

        Args:
            operation: Name of the operation
            duration: Duration in seconds
            **kwargs: Additional metrics
        """
        if not self._active_profile:
            return

        self._profiles[self._active_profile]["operations"].append(
            {
                "operation": operation,
                "duration": duration,
                "timestamp": time.time(),
                **kwargs,
            }
        )

    def stop_profile(self) -> Optional[Dict[str, Any]]:
        """
        Stop profiling and return results.

        Returns:
            Profile results or None if no active profile
        """
        if not self._active_profile:
            return None

        name = self._active_profile
        profile = self._profiles[name]

        # Stop monitoring and get stats
        perf_stats = self._monitor.stop()

        # Calculate totals
        profile["end_time"] = time.time()
        profile["total_duration"] = profile["end_time"] - profile["start_time"]
        profile["performance"] = perf_stats

        # Generate report
        report = self._generate_report(name, profile)

        self._active_profile = None
        logger.debug(f"Stopped profiling: {name}")

        return report

    def _generate_report(self, name: str, profile: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a performance report."""
        operations = profile.get("operations", [])

        # Group operations by type
        op_times = {}
        for op in operations:
            op_name = op["operation"]
            if op_name not in op_times:
                op_times[op_name] = []
            op_times[op_name].append(op["duration"])

        # Calculate statistics per operation
        op_stats = {}
        for op_name, times in op_times.items():
            op_stats[op_name] = {
                "count": len(times),
                "total_seconds": round(sum(times), 3),
                "average_seconds": round(sum(times) / len(times), 3) if times else 0,
                "min_seconds": round(min(times), 3) if times else 0,
                "max_seconds": round(max(times), 3) if times else 0,
            }

        return {
            "profile_name": name,
            "total_duration_seconds": round(profile["total_duration"], 3),
            "operations_count": len(operations),
            "operation_stats": op_stats,
            "performance": profile.get("performance", {}),
            "timestamp": datetime.fromtimestamp(profile["start_time"]).isoformat(),
        }

    def save_profile(self, filepath: Path) -> None:
        """
        Save the current profile to a JSON file.

        Args:
            filepath: Path to save the profile
        """
        if self._active_profile:
            report = self.stop_profile()
        else:
            # Get the last profile
            if not self._profiles:
                logger.warning("No profiles to save")
                return

            last_name = list(self._profiles.keys())[-1]
            report = self._generate_report(last_name, self._profiles[last_name])

        if report:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Profile saved to {filepath}")


# Create singleton instances
performance_monitor = PerformanceMonitor()
performance_profiler = PerformanceProfiler()
