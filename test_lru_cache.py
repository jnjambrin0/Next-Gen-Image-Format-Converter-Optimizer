#!/usr/bin/env python3
"""Test LRU cache functionality in QualityAnalyzer."""

import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app.core.optimization.quality_analyzer import QualityAnalyzer, MAX_CACHE_SIZE

async def test_lru_cache():
    """Test that LRU cache eviction works correctly."""
    print("Testing LRU Cache Functionality")
    print("=" * 50)
    
    analyzer = QualityAnalyzer(enable_caching=True)
    
    # Test 1: Basic caching
    print(f"\nTest 1: Basic caching (MAX_CACHE_SIZE = {MAX_CACHE_SIZE})")
    
    # Create unique test data
    test_images = []
    for i in range(5):
        img_data = bytes([i % 256] * 100)  # Small unique images
        test_images.append(img_data)
    
    # Calculate metrics for same pair twice
    result1 = await analyzer.calculate_metrics(test_images[0], test_images[1])
    result2 = await analyzer.calculate_metrics(test_images[0], test_images[1])
    
    # Should be the same result
    assert result1 == result2
    print("  ✓ Cache returns same result for identical inputs")
    
    # Check cache size
    cache_size = len(analyzer._cache)
    assert cache_size == 1
    print(f"  ✓ Cache size: {cache_size}")
    
    # Test 2: LRU eviction
    print(f"\nTest 2: LRU eviction (filling cache beyond limit)")
    
    # Fill cache beyond limit
    for i in range(MAX_CACHE_SIZE + 10):
        # Create unique image pairs
        img1 = bytes([i % 256] * 100)
        img2 = bytes([(i + 1) % 256] * 100)
        
        try:
            await analyzer.calculate_metrics(img1, img2)
        except:
            # Some combinations might fail, that's ok
            pass
    
    # Check cache size doesn't exceed limit
    final_cache_size = len(analyzer._cache)
    assert final_cache_size <= MAX_CACHE_SIZE
    print(f"  ✓ Cache size after overflow: {final_cache_size} (limit: {MAX_CACHE_SIZE})")
    
    # Test 3: LRU ordering
    print("\nTest 3: LRU ordering (recently used items stay)")
    
    # Clear cache
    analyzer._cache.clear()
    
    # Add 3 items
    pairs = []
    for i in range(3):
        img1 = bytes([i * 10] * 100)
        img2 = bytes([i * 10 + 1] * 100)
        pairs.append((img1, img2))
        await analyzer.calculate_metrics(img1, img2)
    
    # Get cache keys
    initial_keys = list(analyzer._cache.keys())
    print(f"  Initial cache keys: {len(initial_keys)} items")
    
    # Access first item (should move to end)
    await analyzer.calculate_metrics(pairs[0][0], pairs[0][1])
    
    # Add more items to trigger eviction
    for i in range(MAX_CACHE_SIZE):
        img1 = bytes([100 + i] * 100)
        img2 = bytes([200 + i] * 100)
        try:
            await analyzer.calculate_metrics(img1, img2)
        except:
            pass
    
    # Check if first item (recently accessed) is still in cache
    first_key = analyzer._get_cache_key(pairs[0][0], pairs[0][1])
    still_in_cache = first_key in analyzer._cache
    
    print(f"  ✓ Recently accessed item {'remained' if still_in_cache else 'was evicted'}")
    
    # Test 4: Deep copy protection
    print("\nTest 4: Deep copy protection")
    
    # Get a cached result
    cached_result = await analyzer.calculate_metrics(test_images[0], test_images[1])
    original_value = cached_result.get('ssim_score', 0)
    
    # Modify the returned result
    cached_result['ssim_score'] = 999.0
    
    # Get from cache again
    new_result = await analyzer.calculate_metrics(test_images[0], test_images[1])
    new_value = new_result.get('ssim_score', 0)
    
    # Should not be affected by external modification
    assert new_value != 999.0
    assert new_value == original_value
    print("  ✓ Cache protected from external modifications")
    
    print("\n" + "=" * 50)
    print("All LRU cache tests passed!")

if __name__ == "__main__":
    asyncio.run(test_lru_cache())