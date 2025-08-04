#!/usr/bin/env python3
"""Detailed test of sandboxed_convert.py parameter validation."""

import subprocess
import sys
import json
import io
from PIL import Image

def test_parameter_validation():
    """Test parameter validation in detail."""
    
    # Create test image
    img = Image.new('RGB', (100, 100), color='red')
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    image_data = buffer.getvalue()
    
    test_cases = [
        {
            "name": "Valid JPEG progressive",
            "format": "jpeg",
            "params": {"progressive": True},
            "should_succeed": True
        },
        {
            "name": "Invalid JPEG parameter",
            "format": "jpeg", 
            "params": {"__class__": "evil"},
            "should_succeed": False
        },
        {
            "name": "Out of range subsampling",
            "format": "jpeg",
            "params": {"subsampling": 99},
            "should_succeed": False
        },
        {
            "name": "Wrong type for progressive",
            "format": "jpeg",
            "params": {"progressive": "yes"},
            "should_succeed": True  # Should convert to bool
        },
        {
            "name": "WebP lossless valid",
            "format": "webp",
            "params": {"lossless": True},
            "should_succeed": True
        },
        {
            "name": "WebP invalid method",
            "format": "webp",
            "params": {"method": 99},
            "should_succeed": False
        },
        {
            "name": "PNG compress level valid",
            "format": "png",
            "params": {"compress_level": 9},
            "should_succeed": True
        },
        {
            "name": "PNG compress level out of range",
            "format": "png",
            "params": {"compress_level": 999},
            "should_succeed": False
        },
        {
            "name": "Format override attempt",
            "format": "jpeg",
            "params": {"format": "BMP"},
            "should_succeed": False
        }
    ]
    
    print("Detailed parameter validation test:\n")
    
    for test in test_cases:
        print(f"Test: {test['name']}")
        print(f"  Format: {test['format']}")
        print(f"  Params: {test['params']}")
        
        cmd = [
            sys.executable,
            'backend/app/core/conversion/sandboxed_convert.py',
            'png',
            test['format'],
            '85',
            json.dumps(test['params'])
        ]
        
        try:
            result = subprocess.run(
                cmd,
                input=image_data,
                capture_output=True,
                timeout=5
            )
            
            success = result.returncode == 0
            
            if success and not test['should_succeed']:
                print(f"  ✗ SECURITY ISSUE: Invalid params accepted!")
            elif not success and test['should_succeed']:
                print(f"  ✗ FAILED: Valid params rejected!")
                if result.stderr:
                    try:
                        error = json.loads(result.stderr)
                        print(f"    Error: {error.get('message', 'Unknown')}")
                    except:
                        print(f"    Error: {result.stderr.decode()}")
            else:
                print(f"  ✓ {'Success' if success else 'Rejected'} as expected")
                if success:
                    print(f"    Output size: {len(result.stdout)} bytes")
                    
        except Exception as e:
            print(f"  ✗ Exception: {str(e)}")
            
        print()

if __name__ == "__main__":
    test_parameter_validation()