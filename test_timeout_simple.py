#!/usr/bin/env python3
"""Simple test for timeout functionality."""

import asyncio
import time

async def slow_operation():
    """Simulate a slow operation."""
    print("Starting slow operation...")
    await asyncio.sleep(5)  # 5 seconds
    print("Slow operation completed")
    return "Success"

async def test_timeout():
    """Test asyncio timeout functionality."""
    print("Test 1: Operation that should timeout (3s timeout, 5s operation)")
    
    try:
        start = time.time()
        result = await asyncio.wait_for(slow_operation(), timeout=3.0)
        elapsed = time.time() - start
        print(f"✗ Operation completed in {elapsed:.1f}s - should have timed out!")
    except asyncio.TimeoutError:
        elapsed = time.time() - start
        print(f"✓ Operation timed out after {elapsed:.1f}s as expected")
    
    print("\nTest 2: Operation that should complete (10s timeout, 2s operation)")
    
    async def fast_operation():
        print("Starting fast operation...")
        await asyncio.sleep(2)
        print("Fast operation completed")
        return "Success"
    
    try:
        start = time.time()
        result = await asyncio.wait_for(fast_operation(), timeout=10.0)
        elapsed = time.time() - start
        print(f"✓ Operation completed in {elapsed:.1f}s - {result}")
    except asyncio.TimeoutError:
        elapsed = time.time() - start
        print(f"✗ Operation timed out after {elapsed:.1f}s - should have completed!")

async def test_optimization_timeout_direct():
    """Test optimization service timeout directly."""
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))
    
    from app.services.optimization_service import optimization_service
    from app.models.optimization import OptimizationRequest, OptimizationMode
    
    print("\nTest 3: Direct optimization service timeout test")
    
    # Create a slow conversion function
    async def slow_conversion(*args, **kwargs):
        print("Starting slow conversion...")
        await asyncio.sleep(35)  # Longer than 30s timeout
        return b"fake_result"
    
    # Set up service
    optimization_service.conversion_func = slow_conversion
    
    # Create test request
    request = OptimizationRequest(
        output_format="webp",
        optimization_mode=OptimizationMode.BALANCED,
        multi_pass=True
    )
    
    # Test with timeout
    try:
        start = time.time()
        result = await asyncio.wait_for(
            optimization_service.optimize_image(
                b"fake_image_data",
                request,
                "jpeg"
            ),
            timeout=30.0
        )
        elapsed = time.time() - start
        print(f"✗ Optimization completed in {elapsed:.1f}s - should have timed out!")
    except asyncio.TimeoutError:
        elapsed = time.time() - start
        print(f"✓ Optimization timed out after {elapsed:.1f}s as expected")

if __name__ == "__main__":
    print("Testing Timeout Functionality")
    print("=" * 50)
    
    # Run basic timeout tests
    asyncio.run(test_timeout())
    
    # Run optimization timeout test
    asyncio.run(test_optimization_timeout_direct())