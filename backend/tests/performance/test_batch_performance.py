"""Performance tests for batch processing system."""

import asyncio
import gc
import io
import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Tuple

import psutil
import pytest
from PIL import Image

from app.core.batch.models import BatchItemStatus, BatchStatus
from app.services.batch_service import batch_service
from app.services.conversion_service import conversion_service
from app.utils.logging import get_logger

logger = get_logger(__name__)


class MemoryMonitor:
    """Monitor memory usage during batch processing."""

    def __init__(self):
        self.process = psutil.Process()
        self.baseline_memory = self.get_memory_usage()
        self.peak_memory = self.baseline_memory
        self.samples: List[Tuple[float, float]] = []
        self.monitoring = False
        self._monitor_task = None

    def get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        return self.process.memory_info().rss / 1024 / 1024

    async def start_monitoring(self, interval: float = 0.1):
        """Start monitoring memory usage."""
        self.monitoring = True
        self.baseline_memory = self.get_memory_usage()
        self.peak_memory = self.baseline_memory
        self.samples.clear()

        async def monitor():
            start_time = time.time()
            while self.monitoring:
                current_memory = self.get_memory_usage()
                self.peak_memory = max(self.peak_memory, current_memory)
                self.samples.append((time.time() - start_time, current_memory))
                await asyncio.sleep(interval)

        self._monitor_task = asyncio.create_task(monitor())

    async def stop_monitoring(self) -> Dict[str, float]:
        """Stop monitoring and return statistics."""
        self.monitoring = False
        if self._monitor_task:
            await self._monitor_task

        if not self.samples:
            return {
                "baseline_mb": self.baseline_memory,
                "peak_mb": self.peak_memory,
                "average_mb": self.baseline_memory,
                "max_delta_mb": 0,
            }

        memory_values = [sample[1] for sample in self.samples]
        return {
            "baseline_mb": self.baseline_memory,
            "peak_mb": self.peak_memory,
            "average_mb": sum(memory_values) / len(memory_values),
            "max_delta_mb": self.peak_memory - self.baseline_memory,
            "samples": len(self.samples),
        }


class PerformanceMetrics:
    """Collect performance metrics for batch processing."""

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.file_metrics: List[Dict[str, Any]] = []
        self.worker_metrics: Dict[int, float] = {}

    def start(self):
        """Start timing."""
        self.start_time = time.time()

    def end(self):
        """End timing."""
        self.end_time = time.time()

    def add_file_metric(
        self,
        file_index: int,
        processing_time: float,
        success: bool,
        output_size: int = 0,
    ):
        """Add metrics for a processed file."""
        self.file_metrics.append(
            {
                "file_index": file_index,
                "processing_time": processing_time,
                "success": success,
                "output_size": output_size,
            }
        )

    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        if not self.file_metrics:
            return {}

        total_time = self.end_time - self.start_time if self.end_time else 0
        successful_files = [m for m in self.file_metrics if m["success"]]
        processing_times = [m["processing_time"] for m in successful_files]

        return {
            "total_files": len(self.file_metrics),
            "successful_files": len(successful_files),
            "failed_files": len(self.file_metrics) - len(successful_files),
            "total_time_seconds": total_time,
            "average_time_per_file": (
                sum(processing_times) / len(processing_times) if processing_times else 0
            ),
            "min_time_per_file": min(processing_times) if processing_times else 0,
            "max_time_per_file": max(processing_times) if processing_times else 0,
            "throughput_files_per_second": (
                len(successful_files) / total_time if total_time > 0 else 0
            ),
            "total_output_size_mb": sum(m["output_size"] for m in successful_files)
            / 1024
            / 1024,
        }


def create_test_image(
    size: Tuple[int, int] = (1920, 1080), format: str = "JPEG"
) -> bytes:
    """Create a test image with specified size."""
    # Create an image with some complexity (not just solid color)
    img = Image.new("RGB", size)
    pixels = img.load()

    # Add gradient pattern for realistic compression
    for x in range(size[0]):
        for y in range(size[1]):
            r = int(255 * (x / size[0]))
            g = int(255 * (y / size[1]))
            b = int(255 * ((x + y) / (size[0] + size[1])))
            pixels[x, y] = (r, g, b)

    # Add some noise for more realistic file sizes
    import random

    for _ in range(1000):
        x = random.randint(0, size[0] - 1)
        y = random.randint(0, size[1] - 1)
        pixels[x, y] = (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
        )

    # Save to bytes
    buffer = io.BytesIO()
    img.save(buffer, format=format, quality=85)
    return buffer.getvalue()


class MockUploadFile:
    """Mock UploadFile for testing."""

    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self.content = content

    async def read(self) -> bytes:
        return self.content


class TestBatchPerformance:
    """Performance tests for batch processing."""

    @pytest.fixture
    def setup_batch_service(self):
        """Ensure batch service is properly initialized."""
        # The batch service should already be initialized in main.py
        # but we ensure conversion service is set
        if batch_service.conversion_service is None:
            batch_service.set_conversion_service(conversion_service)
        yield batch_service

    async def test_small_batch_performance(self, setup_batch_service):
        """Test performance with small batch (10 files)."""
        memory_monitor = MemoryMonitor()
        metrics = PerformanceMetrics()

        # Create test files
        files = []
        for i in range(10):
            content = create_test_image((800, 600), "JPEG")
            files.append(MockUploadFile(f"test_{i}.jpg", content))

        # Start monitoring
        await memory_monitor.start_monitoring()
        metrics.start()

        # Create batch job
        job = await setup_batch_service.create_batch_job(
            files=files, output_format="webp", settings={"quality": 85}
        )

        # Wait for completion
        max_wait = 30  # 30 seconds max
        start_wait = time.time()

        while time.time() - start_wait < max_wait:
            job_status = await setup_batch_service.get_job(job.job_id)
            if job_status.status in [BatchStatus.COMPLETED, BatchStatus.FAILED]:
                break
            await asyncio.sleep(0.5)

        metrics.end()
        memory_stats = await memory_monitor.stop_monitoring()

        # Collect file metrics
        for item in job_status.items:
            metrics.add_file_metric(
                file_index=item.file_index,
                processing_time=item.processing_time or 0,
                success=item.status == BatchItemStatus.COMPLETED,
                output_size=item.output_size or 0,
            )

        # Get summary
        summary = metrics.get_summary()

        # Assertions
        assert summary["successful_files"] >= 8  # Allow up to 20% failure
        assert summary["average_time_per_file"] < 2.0  # Less than 2 seconds per file
        assert memory_stats["max_delta_mb"] < 200  # Less than 200MB memory increase

        logger.info(f"Small batch performance summary: {summary}")
        logger.info(f"Memory stats: {memory_stats}")

    async def test_medium_batch_performance(self, setup_batch_service):
        """Test performance with medium batch (50 files)."""
        memory_monitor = MemoryMonitor()
        metrics = PerformanceMetrics()

        # Create test files with varying sizes
        files = []
        sizes = [(1920, 1080), (1280, 720), (800, 600), (640, 480)]

        for i in range(50):
            size = sizes[i % len(sizes)]
            content = create_test_image(size, "JPEG")
            files.append(MockUploadFile(f"medium_{i}.jpg", content))

        # Start monitoring
        await memory_monitor.start_monitoring()
        metrics.start()

        # Create batch job
        job = await setup_batch_service.create_batch_job(
            files=files, output_format="avif", settings={"quality": 75}
        )

        # Monitor progress
        progress_samples = []
        max_wait = 120  # 2 minutes max
        start_wait = time.time()

        while time.time() - start_wait < max_wait:
            job_status = await setup_batch_service.get_job(job.job_id)
            progress_samples.append(
                {
                    "time": time.time() - start_wait,
                    "completed": job_status.completed_files,
                    "failed": job_status.failed_files,
                    "progress": job_status.progress_percentage,
                }
            )

            if job_status.status in [BatchStatus.COMPLETED, BatchStatus.FAILED]:
                break
            await asyncio.sleep(1)

        metrics.end()
        memory_stats = await memory_monitor.stop_monitoring()

        # Analyze progress curve
        if len(progress_samples) > 5:
            # Check if progress is relatively linear
            mid_point = len(progress_samples) // 2
            mid_progress = progress_samples[mid_point]["progress"]
            expected_mid_progress = 50  # Should be around 50% at midpoint
            assert (
                abs(mid_progress - expected_mid_progress) < 20
            )  # Within 20% tolerance

        # Get summary
        summary = metrics.get_summary()

        # Assertions
        assert summary["successful_files"] >= 45  # At least 90% success
        assert summary["average_time_per_file"] < 2.5  # Less than 2.5 seconds per file
        assert (
            summary["throughput_files_per_second"] > 0.5
        )  # At least 0.5 files per second
        assert memory_stats["max_delta_mb"] < 500  # Less than 500MB memory increase

        logger.info(f"Medium batch performance summary: {summary}")
        logger.info(f"Memory stats: {memory_stats}")
        logger.info(f"Progress samples: {len(progress_samples)}")

    async def test_large_batch_performance(self, setup_batch_service):
        """Test performance with large batch (100 files)."""
        memory_monitor = MemoryMonitor()
        metrics = PerformanceMetrics()

        # Force garbage collection before test
        gc.collect()

        # Create test files
        files = []
        for i in range(100):
            # Vary sizes to simulate real-world scenario
            if i % 10 == 0:
                size = (3840, 2160)  # 4K
            elif i % 5 == 0:
                size = (1920, 1080)  # Full HD
            else:
                size = (1280, 720)  # HD

            content = create_test_image(size, "JPEG")
            files.append(MockUploadFile(f"large_{i}.jpg", content))

        # Start monitoring
        await memory_monitor.start_monitoring(interval=0.5)
        metrics.start()

        # Create batch job
        job = await setup_batch_service.create_batch_job(
            files=files,
            output_format="webp",
            settings={"quality": 80, "optimization_mode": "balanced"},
        )

        # Monitor with more detailed tracking
        worker_activity = {}
        max_wait = 300  # 5 minutes max
        start_wait = time.time()
        last_completed = 0

        while time.time() - start_wait < max_wait:
            job_status = await setup_batch_service.get_job(job.job_id)

            # Track worker efficiency
            current_completed = job_status.completed_files + job_status.failed_files
            if current_completed > last_completed:
                elapsed = time.time() - start_wait
                worker_activity[elapsed] = current_completed - last_completed
                last_completed = current_completed

            if job_status.status in [BatchStatus.COMPLETED, BatchStatus.FAILED]:
                break

            await asyncio.sleep(2)

        metrics.end()
        memory_stats = await memory_monitor.stop_monitoring()

        # Collect detailed metrics
        for item in job_status.items:
            metrics.add_file_metric(
                file_index=item.file_index,
                processing_time=item.processing_time or 0,
                success=item.status == BatchItemStatus.COMPLETED,
                output_size=item.output_size or 0,
            )

        # Get summary
        summary = metrics.get_summary()

        # Calculate worker efficiency
        if worker_activity:
            avg_files_per_sample = sum(worker_activity.values()) / len(worker_activity)
            worker_efficiency = avg_files_per_sample / (
                max(worker_activity.keys()) / len(worker_activity)
            )
        else:
            worker_efficiency = 0

        # Performance assertions
        assert summary["successful_files"] >= 90  # At least 90% success
        assert summary["total_time_seconds"] < 180  # Less than 3 minutes
        assert summary["average_time_per_file"] < 3.0  # Less than 3 seconds per file
        assert (
            summary["throughput_files_per_second"] > 0.5
        )  # At least 0.5 files per second

        # Memory assertions
        assert memory_stats["max_delta_mb"] < 1000  # Less than 1GB memory increase
        avg_memory_per_file = memory_stats["max_delta_mb"] / 100
        assert avg_memory_per_file < 10  # Less than 10MB per file on average

        logger.info(f"Large batch performance summary: {summary}")
        logger.info(f"Memory stats: {memory_stats}")
        logger.info(f"Worker efficiency: {worker_efficiency:.2f} files per interval")

        # Cleanup results to free memory
        await setup_batch_service.batch_manager.cleanup_job_results(job.job_id)

    async def test_concurrent_batch_performance(self, setup_batch_service):
        """Test performance with multiple concurrent batches."""
        memory_monitor = MemoryMonitor()

        # Create 3 concurrent batches of 20 files each
        batch_configs = [
            {"output_format": "webp", "quality": 85},
            {"output_format": "avif", "quality": 75},
            {"output_format": "jpeg", "quality": 90},
        ]

        async def create_and_process_batch(batch_index: int, config: Dict[str, Any]):
            # Create files
            files = []
            for i in range(20):
                content = create_test_image((1280, 720), "JPEG")
                files.append(
                    MockUploadFile(f"concurrent_{batch_index}_{i}.jpg", content)
                )

            # Create job
            start_time = time.time()
            job = await setup_batch_service.create_batch_job(
                files=files,
                output_format=config["output_format"],
                settings={"quality": config["quality"]},
            )

            # Wait for completion
            max_wait = 60
            while time.time() - start_time < max_wait:
                job_status = await setup_batch_service.get_job(job.job_id)
                if job_status.status in [BatchStatus.COMPLETED, BatchStatus.FAILED]:
                    break
                await asyncio.sleep(1)

            processing_time = time.time() - start_time
            return {
                "job_id": job.job_id,
                "completed": job_status.completed_files,
                "failed": job_status.failed_files,
                "processing_time": processing_time,
            }

        # Start monitoring
        await memory_monitor.start_monitoring()
        start_time = time.time()

        # Run batches concurrently
        results = await asyncio.gather(
            *[
                create_and_process_batch(i, config)
                for i, config in enumerate(batch_configs)
            ]
        )

        total_time = time.time() - start_time
        memory_stats = await memory_monitor.stop_monitoring()

        # Analyze results
        total_files = sum(r["completed"] + r["failed"] for r in results)
        total_completed = sum(r["completed"] for r in results)

        # Assertions
        assert total_completed >= 54  # At least 90% success across all batches
        assert total_time < 90  # All batches complete within 90 seconds
        assert memory_stats["max_delta_mb"] < 800  # Memory stays under control

        # Check that concurrent processing is actually happening
        # (total time should be less than sum of individual times)
        sum_individual_times = sum(r["processing_time"] for r in results)
        assert total_time < sum_individual_times * 0.7  # At least 30% time saving

        logger.info(f"Concurrent batch results: {results}")
        logger.info(
            f"Total time: {total_time:.2f}s, Memory delta: {memory_stats['max_delta_mb']:.2f}MB"
        )

    async def test_worker_pool_optimization(self, setup_batch_service):
        """Test and validate worker pool sizing."""
        import multiprocessing

        cpu_count = multiprocessing.cpu_count()

        # Test different worker counts
        worker_counts = [2, int(cpu_count * 0.5), int(cpu_count * 0.8), cpu_count]
        results = []

        for worker_count in worker_counts:
            # Temporarily modify worker count
            original_workers = setup_batch_service.batch_manager._max_workers
            setup_batch_service.batch_manager._max_workers = min(worker_count, 10)

            # Create test batch
            files = []
            for i in range(30):
                content = create_test_image((1280, 720), "JPEG")
                files.append(MockUploadFile(f"worker_test_{i}.jpg", content))

            start_time = time.time()
            job = await setup_batch_service.create_batch_job(
                files=files, output_format="webp", settings={"quality": 85}
            )

            # Wait for completion
            max_wait = 60
            while time.time() - start_time < max_wait:
                job_status = await setup_batch_service.get_job(job.job_id)
                if job_status.status in [BatchStatus.COMPLETED, BatchStatus.FAILED]:
                    break
                await asyncio.sleep(0.5)

            processing_time = time.time() - start_time

            results.append(
                {
                    "worker_count": worker_count,
                    "processing_time": processing_time,
                    "throughput": job_status.completed_files / processing_time,
                }
            )

            # Restore original worker count
            setup_batch_service.batch_manager._max_workers = original_workers

            # Cleanup
            await setup_batch_service.batch_manager.cleanup_job_results(job.job_id)

        # Analyze results
        logger.info(f"Worker optimization results: {results}")

        # Find optimal worker count (best throughput)
        optimal = max(results, key=lambda x: x["throughput"])
        logger.info(
            f"Optimal worker count: {optimal['worker_count']} "
            f"(throughput: {optimal['throughput']:.2f} files/sec)"
        )

        # Verify that more workers generally improve performance up to a point
        # (but not necessarily linearly due to resource contention)
        throughputs = [r["throughput"] for r in results[:3]]  # Exclude full CPU count
        assert throughputs[-1] >= throughputs[0] * 1.2  # At least 20% improvement
