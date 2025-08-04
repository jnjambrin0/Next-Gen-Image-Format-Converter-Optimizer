#!/usr/bin/env python3
"""Test script to verify advanced parameter functionality before and after security fixes."""

import asyncio
import io
import json
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from PIL import Image
from app.services.optimization_service import optimization_service
from app.services.conversion_service import conversion_service
from app.services.format_detection_service import format_detection_service
from app.models.optimization import OptimizationRequest, OptimizationMode

async def test_advanced_params():
    """Test various advanced parameter combinations."""
    # Create a test image
    test_image = Image.new('RGB', (100, 100), color='red')
    buffer = io.BytesIO()
    test_image.save(buffer, format='PNG')
    test_data = buffer.getvalue()
    
    # Test cases with different advanced parameters
    test_cases = [
        {
            "name": "Progressive JPEG",
            "format": "jpeg",
            "params": {"progressive": True},
            "expected": "progressive encoding"
        },
        {
            "name": "WebP Lossless",
            "format": "webp", 
            "params": {"lossless": True},
            "expected": "lossless compression"
        },
        {
            "name": "WebP with Alpha Quality",
            "format": "webp",
            "params": {"alpha_quality": 90},
            "expected": "alpha quality setting"
        },
        {
            "name": "JPEG with Chroma Subsampling",
            "format": "jpeg",
            "params": {"subsampling": 2},  # 4:2:0
            "expected": "chroma subsampling"
        },
        {
            "name": "PNG with Compression Level",
            "format": "png",
            "params": {"compress_level": 9},
            "expected": "max compression"
        }
    ]
    
    print("Testing current advanced parameter functionality...\n")
    
    for test_case in test_cases:
        print(f"Test: {test_case['name']}")
        print(f"  Format: {test_case['format']}")
        print(f"  Params: {test_case['params']}")
        
        try:
            # Test via conversion service directly
            result = await conversion_service.convert_with_advanced_options(
                test_data,
                test_case['format'],
                quality=85,
                **test_case['params']
            )
            
            print(f"  ✓ Success - Output size: {len(result)} bytes")
            
            # Verify the output is valid
            output_img = Image.open(io.BytesIO(result))
            print(f"  ✓ Valid {test_case['format'].upper()} image")
            
        except Exception as e:
            print(f"  ✗ Failed: {str(e)}")
        
        print()

async def test_injection_vulnerability():
    """Test potential injection vulnerabilities."""
    print("\nTesting injection vulnerability scenarios...\n")
    
    # Create test image
    test_image = Image.new('RGB', (50, 50), color='blue')
    buffer = io.BytesIO()
    test_image.save(buffer, format='PNG')
    test_data = buffer.getvalue()
    
    # Malicious parameter attempts
    malicious_cases = [
        {
            "name": "Arbitrary save parameter injection",
            "params": {"__class__": "evil", "format": "BMP"},
            "should_fail": True
        },
        {
            "name": "Invalid parameter type",
            "params": {"quality": "not_a_number"},
            "should_fail": True
        },
        {
            "name": "Excessive values",
            "params": {"compress_level": 9999},
            "should_fail": True
        }
    ]
    
    for case in malicious_cases:
        print(f"Test: {case['name']}")
        print(f"  Params: {case['params']}")
        
        try:
            result = await conversion_service.convert_with_advanced_options(
                test_data,
                "png",
                quality=85,
                **case['params']
            )
            
            if case['should_fail']:
                print(f"  ✗ SECURITY ISSUE - Should have failed but succeeded!")
            else:
                print(f"  ✓ Success as expected")
                
        except Exception as e:
            if case['should_fail']:
                print(f"  ✓ Failed as expected: {type(e).__name__}")
            else:
                print(f"  ✗ Unexpected failure: {str(e)}")
        
        print()

if __name__ == "__main__":
    # Initialize services
    from app.core.intelligence.engine import IntelligenceEngine
    from app.core.monitoring.stats import StatsCollector
    from app.core.conversion.manager import ConversionManager
    
    # Basic initialization
    stats_collector = StatsCollector()
    conversion_service.stats_collector = stats_collector
    conversion_service.conversion_manager = ConversionManager()
    
    # Run tests
    asyncio.run(test_advanced_params())
    asyncio.run(test_injection_vulnerability())