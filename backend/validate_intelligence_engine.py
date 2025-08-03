#!/usr/bin/env python3
"""Validate Intelligence Engine in real-world conditions.

This script validates that the Intelligence Engine works correctly under
realistic conditions including various image formats, sizes, and edge cases.
"""

import asyncio
import io
import time
import os
from pathlib import Path
from PIL import Image
import numpy as np

from app.core.intelligence.engine import IntelligenceEngine
from app.models.conversion import ContentType, ContentClassification
from app.core.intelligence.performance_monitor import performance_monitor


async def test_image_format(engine: IntelligenceEngine, format_name: str, image: Image.Image) -> dict:
    """Test classification for a specific image format."""
    buffer = io.BytesIO()
    
    # Handle format-specific save options
    save_kwargs = {"format": format_name}
    if format_name == "JPEG":
        save_kwargs["quality"] = 95
    elif format_name == "PNG":
        save_kwargs["compress_level"] = 6
    
    try:
        image.save(buffer, **save_kwargs)
        data = buffer.getvalue()
        
        start_time = time.time()
        result = await engine.classify_content(data)
        elapsed = (time.time() - start_time) * 1000
        
        return {
            "format": format_name,
            "success": True,
            "content_type": result.primary_type.value,
            "confidence": result.confidence,
            "processing_time_ms": elapsed,
            "data_size_kb": len(data) / 1024,
            "has_text": result.has_text,
            "has_faces": result.has_faces,
        }
    except Exception as e:
        return {
            "format": format_name,
            "success": False,
            "error": str(e),
            "data_size_kb": 0,
        }


async def test_edge_cases(engine: IntelligenceEngine) -> list:
    """Test various edge cases."""
    results = []
    
    # Test 1: Tiny image
    tiny = Image.new('RGB', (1, 1), color='red')
    result = await test_image_format(engine, "PNG", tiny)
    result["test_case"] = "1x1 pixel"
    results.append(result)
    
    # Test 2: Large image
    large = Image.new('RGB', (4000, 3000), color='blue')
    result = await test_image_format(engine, "JPEG", large)
    result["test_case"] = "4000x3000 large"
    results.append(result)
    
    # Test 3: Grayscale
    gray = Image.new('L', (800, 600), color=128)
    result = await test_image_format(engine, "PNG", gray)
    result["test_case"] = "Grayscale"
    results.append(result)
    
    # Test 4: Transparent
    transparent = Image.new('RGBA', (500, 500), color=(255, 255, 255, 0))
    result = await test_image_format(engine, "PNG", transparent)
    result["test_case"] = "Transparent"
    results.append(result)
    
    # Test 5: High entropy (noise)
    noise = Image.new('RGB', (300, 300))
    pixels = np.random.randint(0, 256, (300, 300, 3), dtype=np.uint8)
    noise = Image.fromarray(pixels)
    result = await test_image_format(engine, "PNG", noise)
    result["test_case"] = "Random noise"
    results.append(result)
    
    return results


async def test_concurrent_load(engine: IntelligenceEngine, num_requests: int = 20) -> dict:
    """Test concurrent request handling."""
    # Create test image
    test_img = Image.new('RGB', (640, 480), color='green')
    buffer = io.BytesIO()
    test_img.save(buffer, format='PNG')
    data = buffer.getvalue()
    
    # Create concurrent tasks
    tasks = []
    start_time = time.time()
    
    for i in range(num_requests):
        # Add slight variation to avoid cache
        varied_img = test_img.copy()
        varied_img.putpixel((i % 640, i % 480), (255, 0, 0))
        buf = io.BytesIO()
        varied_img.save(buf, format='PNG')
        
        task = engine.classify_content(buf.getvalue())
        tasks.append(task)
    
    # Execute concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    elapsed = time.time() - start_time
    
    # Analyze results
    successful = sum(1 for r in results if isinstance(r, ContentClassification))
    failed = len(results) - successful
    
    if successful > 0:
        avg_confidence = sum(r.confidence for r in results if isinstance(r, ContentClassification)) / successful
        content_types = [r.primary_type.value for r in results if isinstance(r, ContentClassification)]
    else:
        avg_confidence = 0
        content_types = []
    
    return {
        "total_requests": num_requests,
        "successful": successful,
        "failed": failed,
        "total_time_seconds": elapsed,
        "avg_time_per_request_ms": (elapsed / num_requests) * 1000,
        "avg_confidence": avg_confidence,
        "content_types": list(set(content_types)),
    }


async def test_memory_stability(engine: IntelligenceEngine, iterations: int = 50) -> dict:
    """Test memory stability over multiple classifications."""
    import psutil
    import gc
    
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024
    
    # Process many images
    for i in range(iterations):
        # Create different sized images
        size = 200 + (i * 10) % 800
        img = Image.new('RGB', (size, size), color=(i % 255, 100, 150))
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        
        await engine.classify_content(buffer.getvalue())
        
        # Periodic cleanup
        if i % 10 == 0:
            engine.clear_cache()
            gc.collect()
    
    # Final cleanup
    engine.clear_cache()
    gc.collect()
    await asyncio.sleep(0.1)
    
    final_memory = process.memory_info().rss / 1024 / 1024
    memory_growth = final_memory - initial_memory
    
    return {
        "iterations": iterations,
        "initial_memory_mb": initial_memory,
        "final_memory_mb": final_memory,
        "memory_growth_mb": memory_growth,
        "growth_per_iteration": memory_growth / iterations,
        "memory_stable": memory_growth < 50,  # Less than 50MB growth
    }


async def main():
    """Run comprehensive validation tests."""
    print("🔍 Intelligence Engine Validation Suite")
    print("=" * 60)
    
    # Initialize engine
    engine = IntelligenceEngine(
        models_dir="./ml_models",
        fallback_mode=True,
        enable_caching=True
    )
    
    # Test 1: Format Support
    print("\n📋 Testing Image Format Support...")
    formats_to_test = ["PNG", "JPEG", "BMP", "WEBP"]
    
    # Create test images for each content type
    test_images = {
        "photo": create_photo_like_image(),
        "screenshot": create_screenshot_like_image(),
        "document": create_document_like_image(),
        "illustration": create_illustration_like_image(),
    }
    
    format_results = []
    for img_type, img in test_images.items():
        for fmt in formats_to_test:
            if fmt == "WEBP" and img.mode == "L":
                img = img.convert("RGB")  # WebP doesn't support L mode well
            
            result = await test_image_format(engine, fmt, img)
            result["image_type"] = img_type
            format_results.append(result)
            
            status = "✅" if result["success"] else "❌"
            print(f"{status} {img_type}/{fmt}: {result.get('content_type', 'FAILED')} "
                  f"({result.get('confidence', 0):.2f}) - "
                  f"{result.get('processing_time_ms', 0):.1f}ms")
    
    # Test 2: Edge Cases
    print("\n🔧 Testing Edge Cases...")
    edge_results = await test_edge_cases(engine)
    for result in edge_results:
        status = "✅" if result["success"] else "❌"
        print(f"{status} {result['test_case']}: "
              f"{result.get('processing_time_ms', 0):.1f}ms")
    
    # Test 3: Concurrent Load
    print("\n⚡ Testing Concurrent Processing...")
    concurrency_result = await test_concurrent_load(engine, num_requests=30)
    print(f"Processed {concurrency_result['successful']}/{concurrency_result['total_requests']} "
          f"requests in {concurrency_result['total_time_seconds']:.2f}s")
    print(f"Average: {concurrency_result['avg_time_per_request_ms']:.1f}ms per request")
    
    # Test 4: Memory Stability
    print("\n💾 Testing Memory Stability...")
    memory_result = await test_memory_stability(engine, iterations=50)
    status = "✅" if memory_result["memory_stable"] else "❌"
    print(f"{status} Memory growth: {memory_result['memory_growth_mb']:.1f}MB "
          f"({memory_result['growth_per_iteration']:.2f}MB per iteration)")
    
    # Test 5: Performance Summary
    print("\n📊 Performance Summary")
    print("=" * 60)
    
    perf_stats = performance_monitor.get_current_stats()
    summary = perf_stats["summary"]
    
    print(f"Total Classifications: {summary['total_classifications']}")
    print(f"Average Latency: {summary['average_latency_ms']:.1f}ms")
    print(f"P95 Latency: {summary['p95_latency_ms']:.1f}ms")
    print(f"Cache Hit Rate: {summary['cache_hit_rate']:.1%}")
    print(f"Current Memory: {summary['current_memory_mb']:.1f}MB")
    
    # Final verdict
    print("\n" + "=" * 60)
    all_format_tests_passed = all(r["success"] for r in format_results)
    all_edge_tests_passed = all(r["success"] for r in edge_results)
    concurrency_passed = concurrency_result["failed"] == 0
    memory_stable = memory_result["memory_stable"]
    performance_acceptable = summary["average_latency_ms"] < 500
    
    if all([all_format_tests_passed, all_edge_tests_passed, 
            concurrency_passed, memory_stable, performance_acceptable]):
        print("✅ ALL TESTS PASSED - Intelligence Engine is production ready!")
        return 0
    else:
        print("❌ Some tests failed - review the results above")
        return 1


def create_photo_like_image() -> Image.Image:
    """Create a photo-like test image."""
    img = Image.new('RGB', (800, 600))
    pixels = img.load()
    
    # Add natural variation
    for x in range(800):
        for y in range(600):
            # Sky gradient
            if y < 300:
                r = 135 + int(20 * (y / 300))
                g = 206 + int(20 * (y / 300))
                b = 235 - int(50 * (y / 300))
            else:
                # Ground
                r = 34 + np.random.randint(-10, 10)
                g = 139 + np.random.randint(-10, 10)
                b = 34 + np.random.randint(-10, 10)
            
            pixels[x, y] = (
                max(0, min(255, r)),
                max(0, min(255, g)),
                max(0, min(255, b))
            )
    
    return img


def create_screenshot_like_image() -> Image.Image:
    """Create a screenshot-like test image."""
    img = Image.new('RGB', (1280, 720), color=(245, 245, 245))
    
    # Add UI elements
    # Header bar
    img.paste(Image.new('RGB', (1280, 60), color=(50, 50, 50)), (0, 0))
    
    # Sidebar
    img.paste(Image.new('RGB', (200, 660), color=(230, 230, 230)), (0, 60))
    
    # Content area with rectangles
    for i in range(3):
        y = 100 + i * 150
        img.paste(Image.new('RGB', (800, 120), color=(255, 255, 255)), (250, y))
    
    return img


def create_document_like_image() -> Image.Image:
    """Create a document-like test image."""
    img = Image.new('L', (850, 1100), color=255)
    pixels = img.load()
    
    # Add text-like lines
    for line in range(50):
        y = 100 + line * 20
        for x in range(100, 750):
            if np.random.random() > 0.3:
                pixels[x, y] = 0
    
    return img


def create_illustration_like_image() -> Image.Image:
    """Create an illustration-like test image."""
    img = Image.new('RGB', (600, 600))
    
    # Add geometric shapes with solid colors
    colors = [(255, 99, 71), (60, 179, 113), (106, 90, 205), (255, 165, 0)]
    
    for i in range(2):
        for j in range(2):
            color = colors[i * 2 + j]
            img.paste(
                Image.new('RGB', (300, 300), color=color),
                (i * 300, j * 300)
            )
    
    return img


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)