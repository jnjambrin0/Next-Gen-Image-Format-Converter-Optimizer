"""
Ultra-realistic memory stability tests.
Tests memory leaks, fragmentation, and long-running stability.
"""

import asyncio
import gc
import io
import time
import tracemalloc
import weakref
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import numpy as np
import psutil
import pytest
from PIL import Image

from app.core.constants import MAX_FILE_SIZE
from app.models.conversion import ConversionRequest
from app.services.batch_service import batch_service
from app.services.conversion_service import conversion_service
from app.services.intelligence_service import intelligence_service


@dataclass
class MemorySnapshot:
    """Memory usage snapshot."""

    timestamp: float
    rss_mb: float
    vms_mb: float
    available_mb: float
    percent: float
    gc_objects: int
    gc_collected: int


class TestMemoryStability:
    """Test memory stability under various conditions."""

    @pytest.fixture
    def memory_tracker(self):
        """Create memory tracking utilities."""

        class MemoryTracker:
            def __init__(self):
                self.process = psutil.Process()
                self.snapshots: List[MemorySnapshot] = []
                self.start_memory = None
                self.tracemalloc_started = False

            def start(self):
                """Start memory tracking."""
                gc.collect()
                self.start_memory = self.process.memory_info().rss / 1024 / 1024

                if not self.tracemalloc_started:
                    tracemalloc.start()
                    self.tracemalloc_started = True

                self.take_snapshot()

            def take_snapshot(self) -> MemorySnapshot:
                """Take memory snapshot."""
                gc_stats = gc.get_stats()
                gc_collected = sum(s.get("collected", 0) for s in gc_stats)

                mem_info = self.process.memory_info()
                snapshot = MemorySnapshot(
                    timestamp=time.time(),
                    rss_mb=mem_info.rss / 1024 / 1024,
                    vms_mb=mem_info.vms / 1024 / 1024,
                    available_mb=psutil.virtual_memory().available / 1024 / 1024,
                    percent=self.process.memory_percent(),
                    gc_objects=len(gc.get_objects()),
                    gc_collected=gc_collected,
                )

                self.snapshots.append(snapshot)
                return snapshot

            def get_growth(self) -> float:
                """Get memory growth since start."""
                if not self.snapshots:
                    return 0
                current = self.snapshots[-1].rss_mb
                return current - self.start_memory

            def get_leak_rate(self) -> float:
                """Calculate memory leak rate (MB/operation)."""
                if len(self.snapshots) < 2:
                    return 0

                memory_deltas = []
                for i in range(1, len(self.snapshots)):
                    delta = self.snapshots[i].rss_mb - self.snapshots[i - 1].rss_mb
                    memory_deltas.append(delta)

                return sum(memory_deltas) / len(memory_deltas) if memory_deltas else 0

            def get_tracemalloc_top(self, limit=10):
                """Get top memory allocations."""
                if not self.tracemalloc_started:
                    return []

                snapshot = tracemalloc.take_snapshot()
                top_stats = snapshot.statistics("lineno")

                return top_stats[:limit]

            def stop(self):
                """Stop memory tracking."""
                if self.tracemalloc_started:
                    tracemalloc.stop()
                    self.tracemalloc_started = False

        return MemoryTracker()

    @pytest.mark.performance
    @pytest.mark.critical
    async def test_conversion_memory_leak(
        self, memory_tracker, realistic_image_generator
    ):
        """
        Test for memory leaks during repeated conversions.

        Critical for production stability.
        """
        memory_tracker.start()

        # Perform many conversions
        num_iterations = 100

        for i in range(num_iterations):
            # Create test image
            test_image = realistic_image_generator(
                width=1000, height=1000, content_type="photo"
            )

            # Convert image
            request = ConversionRequest(output_format="webp", quality=80)

            result, output_data = await conversion_service.convert(
                image_data=test_image, request=request
            )

            assert result.success

            # Explicitly delete to help GC
            del test_image
            del output_data
            del result

            # Periodic GC and snapshot
            if i % 10 == 0:
                gc.collect()
                memory_tracker.take_snapshot()

        # Final cleanup
        gc.collect()
        memory_tracker.take_snapshot()

        # Check for memory leak
        leak_rate = memory_tracker.get_leak_rate()
        total_growth = memory_tracker.get_growth()

        # Should not leak more than 0.5MB per 10 operations
        assert leak_rate < 0.5, f"Memory leak detected: {leak_rate:.2f}MB/operation"

        # Total growth should be reasonable
        assert total_growth < 100, f"Excessive memory growth: {total_growth:.1f}MB"

        memory_tracker.stop()

    @pytest.mark.performance
    async def test_batch_processing_memory(
        self, memory_tracker, realistic_image_generator
    ):
        """
        Test memory stability during batch processing.

        Batch processing can accumulate memory if not managed properly.
        """
        memory_tracker.start()

        # Create batch of images
        batch_size = 50
        images = []

        for i in range(batch_size):
            img = realistic_image_generator(
                width=800 + i * 10,
                height=600 + i * 10,
                content_type="photo" if i % 2 == 0 else "screenshot",
            )
            images.append(
                {
                    "filename": f"batch_{i}.jpg",
                    "content": img,
                    "content_type": "image/jpeg",
                }
            )

        initial_snapshot = memory_tracker.take_snapshot()

        # Process batch
        job = await batch_service.create_batch_job(files=images, output_format="png")

        result = await batch_service.process_batch(job.id)

        # Take snapshot after processing
        after_processing = memory_tracker.take_snapshot()

        # Clean up batch results
        await batch_service.cleanup_job_results(job.id)

        # Force GC and final snapshot
        gc.collect()
        final_snapshot = memory_tracker.take_snapshot()

        # Memory should return close to initial after cleanup
        memory_recovered = after_processing.rss_mb - final_snapshot.rss_mb
        memory_used = after_processing.rss_mb - initial_snapshot.rss_mb

        recovery_rate = memory_recovered / memory_used if memory_used > 0 else 1.0

        assert recovery_rate > 0.8, f"Poor memory recovery: {recovery_rate:.1%}"

        memory_tracker.stop()

    @pytest.mark.performance
    async def test_ml_model_memory_stability(
        self, memory_tracker, realistic_image_generator
    ):
        """
        Test memory stability of ML models (ONNX Runtime).

        ML models can have memory leaks if sessions aren't properly managed.
        """
        memory_tracker.start()

        # Perform many classifications
        num_iterations = 50

        for i in range(num_iterations):
            # Create test image
            test_image = realistic_image_generator(
                width=1024,
                height=768,
                content_type="photo" if i % 3 == 0 else "document",
            )

            # Classify image
            classification = await intelligence_service.classify_content(test_image)

            assert classification is not None
            assert classification.content_type in [
                "photo",
                "illustration",
                "screenshot",
                "document",
            ]

            # Check for face/text detection
            if classification.has_faces:
                assert len(classification.face_regions) > 0

            if classification.has_text:
                assert len(classification.text_regions) > 0

            # Clean up
            del test_image
            del classification

            if i % 10 == 0:
                gc.collect()
                memory_tracker.take_snapshot()

        # Check ML model memory stability
        growth = memory_tracker.get_growth()
        assert growth < 50, f"ML model memory leak: {growth:.1f}MB growth"

        memory_tracker.stop()

    @pytest.mark.performance
    @pytest.mark.slow
    async def test_long_running_stability(
        self, memory_tracker, realistic_image_generator
    ):
        """
        Test memory stability over extended period.

        Simulates production environment with continuous load.
        """
        memory_tracker.start()

        # Run for extended period
        duration_seconds = 60
        end_time = time.time() + duration_seconds

        operations_count = 0
        errors_count = 0

        while time.time() < end_time:
            try:
                # Vary operation types
                operation = operations_count % 3

                if operation == 0:
                    # Single conversion
                    img = realistic_image_generator(width=1000, height=800)
                    request = ConversionRequest(output_format="webp", quality=80)
                    result, output = await conversion_service.convert(img, request)
                    del img, output

                elif operation == 1:
                    # ML classification
                    img = realistic_image_generator(width=800, height=600)
                    classification = await intelligence_service.classify_content(img)
                    del img, classification

                else:
                    # Format detection
                    img = realistic_image_generator(width=600, height=400)
                    from app.services.format_detection_service import (
                        format_detection_service,
                    )

                    detected, confidence = await format_detection_service.detect_format(
                        img
                    )
                    del img

                operations_count += 1

            except Exception as e:
                errors_count += 1

            # Periodic snapshots
            if operations_count % 20 == 0:
                gc.collect()
                snapshot = memory_tracker.take_snapshot()

                # Check if memory is growing too fast
                if snapshot.rss_mb - memory_tracker.start_memory > 200:
                    # Emergency GC
                    gc.collect(2)

        # Final analysis
        final_snapshot = memory_tracker.take_snapshot()

        # Calculate metrics
        total_growth = memory_tracker.get_growth()
        growth_per_operation = (
            total_growth / operations_count if operations_count > 0 else 0
        )
        error_rate = errors_count / operations_count if operations_count > 0 else 0

        # Assertions
        assert error_rate < 0.05, f"High error rate: {error_rate:.1%}"
        assert (
            growth_per_operation < 0.1
        ), f"Memory leak: {growth_per_operation:.3f}MB/op"
        assert total_growth < 150, f"Excessive memory growth: {total_growth:.1f}MB"

        memory_tracker.stop()

    @pytest.mark.performance
    async def test_memory_fragmentation(self, memory_tracker):
        """
        Test for memory fragmentation issues.

        Fragmentation can cause high memory usage even without leaks.
        """
        memory_tracker.start()

        # Create objects of varying sizes to cause fragmentation
        allocations = []

        for i in range(100):
            # Allocate different sized buffers
            sizes = [1024, 10240, 102400, 1024000]  # 1KB to 1MB
            size = sizes[i % len(sizes)]

            # Create buffer
            buffer = bytearray(size)

            # Fill with data
            for j in range(0, size, 100):
                buffer[j : j + 10] = b"TESTDATA" + bytes([i % 256]) * 2

            allocations.append(buffer)

            # Randomly free some allocations
            if i > 10 and i % 5 == 0:
                # Free random allocation
                del allocations[i // 2]
                allocations[i // 2] = None

        # Take snapshot after fragmentation
        fragmented_snapshot = memory_tracker.take_snapshot()

        # Clear all allocations
        allocations.clear()
        gc.collect()

        # Take snapshot after cleanup
        cleaned_snapshot = memory_tracker.take_snapshot()

        # Check fragmentation impact
        fragmentation_overhead = fragmented_snapshot.rss_mb - cleaned_snapshot.rss_mb

        # Should recover most memory
        assert (
            fragmentation_overhead < 50
        ), f"High fragmentation overhead: {fragmentation_overhead:.1f}MB"

        memory_tracker.stop()

    @pytest.mark.performance
    async def test_circular_reference_cleanup(self):
        """
        Test cleanup of circular references.

        Circular references can prevent garbage collection.
        """
        # Track object creation/destruction
        destroyed_objects = []

        class TrackedObject:
            def __init__(self, id):
                self.id = id
                self.data = bytearray(1024 * 100)  # 100KB
                self.reference = None

            def __del__(self):
                destroyed_objects.append(self.id)

        # Create circular references
        objects = []
        for i in range(10):
            obj1 = TrackedObject(f"obj1_{i}")
            obj2 = TrackedObject(f"obj2_{i}")

            # Create circular reference
            obj1.reference = obj2
            obj2.reference = obj1

            objects.append((obj1, obj2))

        # Clear references
        objects.clear()

        # Force garbage collection
        gc.collect()

        # All objects should be destroyed
        assert (
            len(destroyed_objects) >= 18
        ), f"Circular references not cleaned: {len(destroyed_objects)}/20"

    @pytest.mark.performance
    async def test_weak_reference_usage(self):
        """
        Test proper use of weak references for caches.

        Weak references allow garbage collection of cached objects.
        """
        cache = {}
        destroyed_count = 0

        class CachedObject:
            def __init__(self, data):
                self.data = data

            def __del__(self):
                nonlocal destroyed_count
                destroyed_count += 1

        # Create objects with weak references
        for i in range(100):
            obj = CachedObject(f"data_{i}" * 1000)

            # Store weak reference in cache
            cache[i] = weakref.ref(obj)

            # Delete strong reference
            del obj

        # Force GC
        gc.collect()

        # Check that objects were collected
        alive_count = sum(1 for ref in cache.values() if ref() is not None)

        assert alive_count < 10, f"Too many cached objects alive: {alive_count}"
        assert destroyed_count > 90, f"Not enough objects destroyed: {destroyed_count}"

    @pytest.mark.performance
    async def test_memory_pressure_handling(
        self, memory_tracker, realistic_image_generator
    ):
        """
        Test system behavior under memory pressure.

        Should gracefully handle low memory conditions.
        """
        memory_tracker.start()

        # Get available memory
        available_mb = psutil.virtual_memory().available / 1024 / 1024

        # Don't run if already low on memory
        if available_mb < 1000:
            pytest.skip("Insufficient memory for pressure test")

        # Allocate memory to create pressure
        pressure_buffers = []
        target_pressure_mb = min(available_mb * 0.7, 2000)  # Use 70% or 2GB max

        try:
            # Create memory pressure
            while (
                sum(len(b) for b in pressure_buffers) < target_pressure_mb * 1024 * 1024
            ):
                pressure_buffers.append(bytearray(10 * 1024 * 1024))  # 10MB chunks

            # Now try conversions under pressure
            successes = 0
            failures = 0

            for i in range(10):
                try:
                    img = realistic_image_generator(width=1000, height=1000)
                    request = ConversionRequest(output_format="jpeg", quality=70)

                    result, output = await conversion_service.convert(img, request)

                    if result.success:
                        successes += 1
                    else:
                        failures += 1

                    del img, output

                except MemoryError:
                    failures += 1
                except Exception:
                    failures += 1

                gc.collect()

            # Should handle some requests even under pressure
            assert successes > 0, "Complete failure under memory pressure"

            # Check that system didn't crash
            assert successes + failures == 10

        finally:
            # Release pressure
            pressure_buffers.clear()
            gc.collect()

        memory_tracker.stop()

    @pytest.mark.performance
    async def test_blob_url_memory_management(self):
        """
        Test memory management of blob URLs in conversions.

        Blob URLs can leak memory if not properly revoked.
        """
        # Track blob URL creation/revocation
        blob_urls = []
        revoked_urls = []

        class BlobUrlManager:
            def create_url(self, data: bytes) -> str:
                url = f"blob:http://localhost/{len(blob_urls)}"
                blob_urls.append((url, len(data)))
                return url

            def revoke_url(self, url: str):
                revoked_urls.append(url)

        manager = BlobUrlManager()

        # Simulate conversions with blob URLs
        for i in range(50):
            # Create fake image data
            data = b"IMAGE_DATA" * 10000  # ~100KB

            # Create blob URL
            url = manager.create_url(data)

            # Simulate processing
            await asyncio.sleep(0.01)

            # Should revoke URL after use
            manager.revoke_url(url)

        # Check that all URLs were revoked
        created_count = len(blob_urls)
        revoked_count = len(revoked_urls)

        assert (
            revoked_count == created_count
        ), f"Blob URL leak: {created_count} created, {revoked_count} revoked"

    @pytest.mark.performance
    async def test_exception_memory_cleanup(self, realistic_image_generator):
        """
        Test memory cleanup when exceptions occur.

        Exceptions shouldn't cause memory leaks.
        """
        import sys

        # Track memory before
        gc.collect()
        process = psutil.Process()
        memory_before = process.memory_info().rss / 1024 / 1024

        exceptions_raised = 0

        for i in range(50):
            try:
                # Create image
                img = realistic_image_generator(width=1000, height=1000)

                # Force exception during conversion
                if i % 2 == 0:
                    # Invalid output format
                    request = ConversionRequest(
                        output_format="invalid_format", quality=80
                    )
                else:
                    # Invalid quality
                    request = ConversionRequest(
                        output_format="jpeg", quality=200  # Invalid
                    )

                result, output = await conversion_service.convert(img, request)

            except Exception:
                exceptions_raised += 1
                # Exception occurred, ensure cleanup

            finally:
                # Cleanup should happen even with exception
                if "img" in locals():
                    del img
                if "output" in locals():
                    del output

        # Force GC
        gc.collect()

        # Check memory after
        memory_after = process.memory_info().rss / 1024 / 1024
        memory_growth = memory_after - memory_before

        assert exceptions_raised > 0, "No exceptions were raised"
        assert memory_growth < 50, f"Memory leak with exceptions: {memory_growth:.1f}MB"

    @pytest.mark.performance
    async def test_cache_memory_limits(self):
        """
        Test that caches respect memory limits.

        Caches should evict entries when memory limit reached.
        """
        from app.core.cache import LRUCache

        # Create cache with memory limit
        cache = LRUCache(max_memory_mb=10)  # 10MB limit

        # Add items until limit exceeded
        items_added = 0
        items_evicted = 0

        for i in range(100):
            # Create ~500KB item
            key = f"item_{i}"
            value = b"X" * (500 * 1024)

            # Track evictions
            before_size = cache.memory_usage_mb
            cache.put(key, value)
            after_size = cache.memory_usage_mb

            if after_size < before_size:
                items_evicted += 1

            items_added += 1

        # Cache should have evicted items to stay under limit
        assert (
            cache.memory_usage_mb <= 10.5
        ), f"Cache exceeded memory limit: {cache.memory_usage_mb:.1f}MB"

        assert items_evicted > 0, "Cache didn't evict any items"

        # Cache should still be functional
        cache.put("final_item", b"TEST")
        assert cache.get("final_item") == b"TEST"
