#!/usr/bin/env python3
"""Test memory cleanup functionality."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app.services.optimization_service import optimization_service
from app.models.optimization import OptimizationResponse, OptimizationMode
import gc

def test_memory_cleanup():
    """Test that _last_optimized_data is properly cleaned up."""
    print("Testing Memory Cleanup")
    print("=" * 50)
    
    # Test 1: Direct memory cleanup
    print("\nTest 1: Direct memory cleanup")
    
    # Set some test data
    test_data = b"x" * 1000000  # 1MB of test data
    optimization_service._last_optimized_data = test_data
    
    # Verify data is stored
    assert optimization_service._last_optimized_data is not None
    print("  ✓ Data stored in memory")
    
    # Get data (should clear it)
    retrieved_data = optimization_service.get_last_optimized_data()
    
    # Verify data was retrieved correctly
    assert retrieved_data == test_data
    print("  ✓ Data retrieved correctly")
    
    # Verify data was cleared
    assert optimization_service._last_optimized_data is None
    print("  ✓ Data cleared from memory after retrieval")
    
    # Try to get data again (should return None)
    second_retrieval = optimization_service.get_last_optimized_data()
    assert second_retrieval is None
    print("  ✓ Second retrieval returns None")
    
    # Test 2: Clear method
    print("\nTest 2: Explicit clear method")
    
    # Set data again
    optimization_service._last_optimized_data = test_data
    assert optimization_service._last_optimized_data is not None
    print("  ✓ Data stored in memory")
    
    # Clear explicitly
    optimization_service.clear_optimized_data()
    assert optimization_service._last_optimized_data is None
    print("  ✓ Data cleared using clear_optimized_data()")
    
    # Test 3: Memory reference test
    print("\nTest 3: Memory reference cleanup")
    
    # Create large data
    large_data = b"y" * 10000000  # 10MB
    optimization_service._last_optimized_data = large_data
    
    # Store reference
    data_id = id(optimization_service._last_optimized_data)
    print(f"  Data object ID: {data_id}")
    
    # Clear data
    optimization_service.clear_optimized_data()
    
    # Force garbage collection
    gc.collect()
    
    # Verify no reference remains
    assert optimization_service._last_optimized_data is None
    print("  ✓ No reference remains after cleanup")
    
    print("\n" + "=" * 50)
    print("All memory cleanup tests passed!")

if __name__ == "__main__":
    test_memory_cleanup()