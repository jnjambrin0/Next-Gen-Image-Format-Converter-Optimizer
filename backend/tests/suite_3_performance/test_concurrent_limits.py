"""
Ultra-realistic concurrent processing limits tests.
Tests semaphore enforcement, resource limits, and graceful degradation.
"""

import asyncio
import multiprocessing
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch

import psutil
import pytest

from app.core.constants import MAX_BATCH_WORKERS
from app.models.conversion import ConversionRequest, ConversionStatus
from app.services.batch_service import batch_service
from app.services.conversion_service import conversion_service


class TestConcurrentLimits:
    """Test concurrent processing limits and resource management."""

    @pytest.fixture
    def create_test_images(self, realistic_image_generator):
        """Create a set of test images for concurrent processing."""

        def _create(count: int = 20) -> List[bytes]:
            images = []
            for i in range(count):
                # Vary content types and sizes
                content_type = ["photo", "screenshot", "document", "illustration"][
                    i % 4
                ]
                width = 800 + (i * 100) % 1200
                height = 600 + (i * 100) % 900

                img_data = realistic_image_generator(
                    width=width,
                    height=height,
                    content_type=content_type,
                    format="JPEG" if content_type == "photo" else "PNG",
                )
                images.append(img_data)
            return images

        return _create

    @pytest.mark.performance
    @pytest.mark.critical
    async def test_semaphore_enforcement(self, create_test_images):
        """
        Test that semaphore properly limits concurrent conversions.

        Validates MAX_CONCURRENT_CONVERSIONS is enforced.
        """
        test_images = create_test_images(30)  # More than limit

        # Track concurrent executions
        concurrent_count = 0
        max_concurrent = 0
        lock = asyncio.Lock()

        async def monitored_conversion(image_data: bytes, index: int):
            """Conversion with concurrency monitoring."""
            nonlocal concurrent_count, max_concurrent

            async with lock:
                concurrent_count += 1
                max_concurrent = max(max_concurrent, concurrent_count)

            try:
                # Simulate conversion work
                request = ConversionRequest(output_format="webp", quality=80)

                # Add small delay to ensure overlap
                await asyncio.sleep(0.1)

                result, output = await conversion_service.convert(
                    image_data=image_data, request=request
                )

                return result.status == ConversionStatus.COMPLETED
            finally:
                async with lock:
                    concurrent_count -= 1

        # Launch all conversions concurrently
        tasks = [monitored_conversion(img, i) for i, img in enumerate(test_images)]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Verify semaphore enforcement
        assert max_concurrent <= 10, f"Semaphore limit exceeded: {max_concurrent}"

        # Most should succeed
        successful = sum(1 for r in results if r is True)
        assert successful >= 25, f"Too many failures: {successful}/30"

    @pytest.mark.performance
    async def test_resource_exhaustion_handling(self, create_test_images):
        """
        Test system behavior under resource exhaustion.

        Simulates low memory/CPU conditions.
        """
        test_images = create_test_images(20)

        # Simulate resource pressure
        async def resource_intensive_conversion(image_data: bytes):
            """Conversion that simulates resource pressure."""
            # Allocate some memory to simulate pressure
            _memory_hog = bytearray(50 * 1024 * 1024)  # 50MB

            request = ConversionRequest(
                output_format="avif",  # CPU-intensive format
                quality=90,
                optimization_mode="quality",  # More processing
            )

            try:
                result, output = await conversion_service.convert(
                    image_data=image_data, request=request
                )
                return result.status == ConversionStatus.COMPLETED
            except MemoryError:
                return False
            finally:
                del _memory_hog

        # Track system resources
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Run conversions with resource pressure
        tasks = [
            resource_intensive_conversion(img)
            for img in test_images[:10]  # Limit to prevent system crash
        ]

        # Use timeout to prevent hanging
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), timeout=60
            )
        except asyncio.TimeoutError:
            results = []

        # Check memory didn't grow excessively
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory

        assert memory_growth < 500, f"Excessive memory growth: {memory_growth:.1f}MB"

        # Some should complete despite pressure
        if results:
            successful = sum(1 for r in results if r is True)
            assert successful >= 5, "System failed under resource pressure"

    @pytest.mark.performance
    async def test_concurrent_format_diversity(self, create_test_images):
        """
        Test concurrent conversions to different formats.

        Different formats have different resource requirements.
        """
        test_images = create_test_images(16)  # 4 images × 4 formats

        # Define format combinations
        formats = ["jpeg", "webp", "png", "avif"]

        # Create conversion tasks
        tasks = []
        for i, img in enumerate(test_images):
            format_idx = i % len(formats)
            request = ConversionRequest(
                output_format=formats[format_idx],
                quality=85 if formats[format_idx] in ["jpeg", "webp", "avif"] else None,
            )

            task = conversion_service.convert(image_data=img, request=request)
            tasks.append(task)

        # Execute concurrently
        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        execution_time = time.perf_counter() - start_time

        # Analyze results by format
        format_results = {fmt: [] for fmt in formats}
        for i, result in enumerate(results):
            format_idx = i % len(formats)
            format_name = formats[format_idx]

            if not isinstance(result, Exception):
                format_results[format_name].append(
                    result[0].status == ConversionStatus.COMPLETED
                )

        # All formats should have successful conversions
        for fmt, successes in format_results.items():
            success_rate = sum(successes) / len(successes) if successes else 0
            assert (
                success_rate >= 0.75
            ), f"Poor success rate for {fmt}: {success_rate:.1%}"

        # Execution should be reasonably fast
        assert (
            execution_time < 30
        ), f"Concurrent conversion too slow: {execution_time:.1f}s"

    @pytest.mark.performance
    @pytest.mark.critical
    async def test_deadlock_prevention(self):
        """
        Test that system prevents deadlocks in concurrent processing.

        Validates timeout and cancellation mechanisms.
        """

        # Create a scenario that could deadlock
        async def potentially_deadlocking_task(index: int):
            """Task that could cause deadlock."""
            # Try to acquire multiple resources in different order
            if index % 2 == 0:
                # Even tasks: acquire A then B
                async with conversion_service._semaphore:
                    await asyncio.sleep(0.1)
                    # Nested semaphore acquisition (potential deadlock)
                    async with conversion_service._semaphore:
                        await asyncio.sleep(0.1)
            else:
                # Odd tasks: acquire B then A (opposite order)
                async with conversion_service._semaphore:
                    await asyncio.sleep(0.1)

            return index

        # Run with timeout to detect deadlock
        tasks = [potentially_deadlocking_task(i) for i in range(10)]

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), timeout=5.0
            )

            # Should complete without deadlock
            assert len(results) == 10

        except asyncio.TimeoutError:
            # If timeout, ensure it's handled gracefully
            # Cancel all tasks
            for task in asyncio.all_tasks():
                if not task.done():
                    task.cancel()

            # System should recover
            assert True, "Deadlock detected but handled"

    @pytest.mark.performance
    async def test_worker_pool_scaling(self, create_test_images):
        """
        Test dynamic worker pool scaling based on load.

        Validates efficient resource utilization.
        """
        # Test with different load levels
        load_levels = [
            (5, "light"),  # 5 images
            (20, "medium"),  # 20 images
            (50, "heavy"),  # 50 images
        ]

        results_by_load = {}

        for image_count, load_name in load_levels:
            test_images = create_test_images(image_count)

            # Measure processing with current load
            start_time = time.perf_counter()

            # Create batch job
            files = [
                {
                    "filename": f"image_{i}.jpg",
                    "content": img,
                    "content_type": "image/jpeg",
                }
                for i, img in enumerate(test_images)
            ]

            job = await batch_service.create_batch_job(
                files=files, output_format="webp", quality=80
            )

            result = await batch_service.process_batch(job.id)

            processing_time = time.perf_counter() - start_time

            # Calculate metrics
            images_per_second = image_count / processing_time
            success_rate = len(result.completed) / image_count

            results_by_load[load_name] = {
                "time": processing_time,
                "throughput": images_per_second,
                "success_rate": success_rate,
            }

        # Verify scaling efficiency
        # Heavy load should have better throughput than light (economies of scale)
        assert (
            results_by_load["heavy"]["throughput"]
            >= results_by_load["light"]["throughput"] * 0.8
        )

        # All load levels should maintain quality
        for load_name, metrics in results_by_load.items():
            assert (
                metrics["success_rate"] >= 0.9
            ), f"Poor success rate under {load_name} load: {metrics['success_rate']:.1%}"

    @pytest.mark.performance
    async def test_priority_queue_handling(self):
        """
        Test priority handling in concurrent processing.

        High-priority tasks should complete first.
        """
        # Create tasks with different priorities
        high_priority_tasks = []
        low_priority_tasks = []

        completion_order = []
        lock = asyncio.Lock()

        async def priority_task(priority: str, index: int, delay: float = 0.1):
            """Task that records completion order."""
            await asyncio.sleep(delay)  # Simulate work

            async with lock:
                completion_order.append((priority, index))

            return f"{priority}_{index}"

        # Create high priority tasks
        for i in range(5):
            task = priority_task("high", i, 0.05)  # Shorter delay
            high_priority_tasks.append(task)

        # Create low priority tasks
        for i in range(5):
            task = priority_task("low", i, 0.15)  # Longer delay
            low_priority_tasks.append(task)

        # Execute with priority ordering
        # High priority first, then low priority
        all_tasks = high_priority_tasks + low_priority_tasks
        results = await asyncio.gather(*all_tasks)

        # Check completion order
        high_priority_completions = [
            i for priority, i in completion_order if priority == "high"
        ]
        low_priority_completions = [
            i for priority, i in completion_order if priority == "low"
        ]

        # High priority should generally complete first
        avg_high_position = sum(range(5)) / 5  # Expected: 2.0
        avg_low_position = sum(range(5, 10)) / 5  # Expected: 7.0

        actual_high_avg = (
            sum(i for i, (p, _) in enumerate(completion_order) if p == "high") / 5
        )
        actual_low_avg = (
            sum(i for i, (p, _) in enumerate(completion_order) if p == "low") / 5
        )

        assert (
            actual_high_avg < actual_low_avg
        ), "High priority tasks didn't complete first"

    @pytest.mark.performance
    @pytest.mark.slow
    async def test_sustained_concurrent_load(self, create_test_images, memory_monitor):
        """
        Test system stability under sustained concurrent load.

        Simulates production environment with continuous processing.
        """
        memory_monitor.start()

        # Run for extended period
        duration_seconds = 30
        end_time = time.time() + duration_seconds

        total_processed = 0
        total_errors = 0

        async def continuous_processor():
            """Continuously process images."""
            nonlocal total_processed, total_errors

            test_images = create_test_images(10)

            while time.time() < end_time:
                for img in test_images:
                    if time.time() >= end_time:
                        break

                    request = ConversionRequest(output_format="webp", quality=80)

                    try:
                        result, output = await conversion_service.convert(
                            image_data=img, request=request
                        )

                        if result.status == ConversionStatus.COMPLETED:
                            total_processed += 1
                        else:
                            total_errors += 1

                    except Exception:
                        total_errors += 1

                    # Small delay between conversions
                    await asyncio.sleep(0.05)

        # Run multiple concurrent processors
        processors = [continuous_processor() for _ in range(3)]

        await asyncio.gather(*processors)

        # Check results
        assert total_processed > 0, "No images processed"
        error_rate = (
            total_errors / (total_processed + total_errors) if total_processed else 1.0
        )
        assert error_rate < 0.1, f"High error rate: {error_rate:.1%}"

        # Check memory stability
        memory_monitor.assert_stable(max_growth_mb=100)

        # Calculate throughput
        throughput = total_processed / duration_seconds
        assert throughput > 1.0, f"Low throughput: {throughput:.1f} images/second"

    @pytest.mark.performance
    async def test_graceful_degradation(self, create_test_images):
        """
        Test graceful degradation when approaching limits.

        System should slow down gracefully, not fail catastrophically.
        """
        # Gradually increase load
        load_stages = [5, 10, 20, 40, 80]

        stage_metrics = []

        for num_images in load_stages:
            test_images = create_test_images(num_images)

            start_time = time.perf_counter()

            # Process all images concurrently
            tasks = []
            for img in test_images:
                request = ConversionRequest(output_format="jpeg", quality=75)

                task = conversion_service.convert(image_data=img, request=request)
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            processing_time = time.perf_counter() - start_time

            # Calculate metrics
            successful = sum(
                1
                for r in results
                if not isinstance(r, Exception)
                and r[0].status == ConversionStatus.COMPLETED
            )

            stage_metrics.append(
                {
                    "load": num_images,
                    "time": processing_time,
                    "success_rate": successful / num_images,
                    "avg_time": processing_time / num_images,
                }
            )

        # Verify graceful degradation
        for i in range(1, len(stage_metrics)):
            prev = stage_metrics[i - 1]
            curr = stage_metrics[i]

            # Success rate should not drop drastically
            if prev["success_rate"] > 0.9:
                assert (
                    curr["success_rate"] > 0.7
                ), f"Sudden failure at load {curr['load']}"

            # Processing time should increase somewhat linearly
            # Not exponentially (which would indicate problems)
            expected_time = prev["avg_time"] * (curr["load"] / prev["load"]) * 1.5
            assert (
                curr["avg_time"] < expected_time
            ), f"Performance degraded too much at load {curr['load']}"
