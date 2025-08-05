#!/usr/bin/env python3
"""Test timeout functionality for optimization endpoints."""

import asyncio
import time
from unittest.mock import patch, AsyncMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from fastapi.testclient import TestClient
from app.main import app
from app.services.optimization_service import optimization_service
from app.models.optimization import OptimizationResponse, OptimizationMode

# Mock slow optimization function
async def slow_optimization(*args, **kwargs):
    """Simulate a slow optimization that will timeout."""
    await asyncio.sleep(5)  # Simulate slow operation
    return OptimizationResponse(
        conversion_id="test-id",
        success=True,
        original_size=1000,
        optimized_size=500,
        output_format="jpeg",
        optimization_mode=OptimizationMode.BALANCED,
        total_processing_time=35.0,
        encoding_options_applied={}
    )

def test_optimization_timeout():
    """Test that optimization endpoints timeout correctly."""
    client = TestClient(app)
    
    print("Testing Optimization Timeout Functionality")
    print("=" * 50)
    
    # Create test image data
    test_image = b"fake_image_data"
    
    # Test 1: Test /optimize/advanced endpoint timeout
    print("\nTest 1: /optimize/advanced endpoint timeout")
    
    with patch.object(optimization_service, 'optimize_image', new=slow_optimization):
        start_time = time.time()
        
        response = client.post(
            "/api/optimize/advanced",
            files={"file": ("test.jpg", test_image, "image/jpeg")},
            data={
                "output_format": "webp",
                "optimization_mode": "balanced",
                "multi_pass": "true"
            }
        )
        
        elapsed = time.time() - start_time
        
        print(f"  Response status: {response.status_code}")
        print(f"  Elapsed time: {elapsed:.1f}s")
        
        if response.status_code == 504 and elapsed < 35:
            print("  ✓ Timeout working correctly (504 Gateway Timeout)")
            print(f"  ✓ Timed out after ~30s (actual: {elapsed:.1f}s)")
        else:
            print("  ✗ Timeout not working properly")
            
    # Test 2: Test normal operation (no timeout)
    print("\nTest 2: Normal operation (should not timeout)")
    
    # Mock fast optimization
    async def fast_optimization(*args, **kwargs):
        return OptimizationResponse(
            conversion_id="test-id",
            success=True,
            original_size=1000,
            optimized_size=500,
            output_format="jpeg",
            optimization_mode=OptimizationMode.BALANCED,
            total_processing_time=0.5,
            encoding_options_applied={}
        )
    
    with patch.object(optimization_service, 'optimize_image', new=fast_optimization):
        start_time = time.time()
        
        response = client.post(
            "/api/optimize/advanced",
            files={"file": ("test.jpg", test_image, "image/jpeg")},
            data={
                "output_format": "webp",
                "optimization_mode": "balanced"
            }
        )
        
        elapsed = time.time() - start_time
        
        print(f"  Response status: {response.status_code}")
        print(f"  Elapsed time: {elapsed:.1f}s")
        
        if response.status_code == 200:
            print("  ✓ Normal operation successful")
        else:
            print("  ✗ Normal operation failed")
            
    print("\n" + "=" * 50)
    print("Timeout functionality test completed")

if __name__ == "__main__":
    test_optimization_timeout()