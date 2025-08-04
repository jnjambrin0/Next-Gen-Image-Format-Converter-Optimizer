#!/usr/bin/env python3
"""Test sandboxed_convert.py security before and after fixes."""

import subprocess
import sys
import json
import io
from PIL import Image

def create_test_image():
    """Create a simple test image."""
    img = Image.new('RGB', (100, 100), color='red')
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()

def test_sandboxed_convert(input_format, output_format, quality, advanced_params=None):
    """Test sandboxed_convert.py with given parameters."""
    cmd = [
        sys.executable,
        'backend/app/core/conversion/sandboxed_convert.py',
        input_format,
        output_format,
        str(quality)
    ]
    
    if advanced_params:
        cmd.append(json.dumps(advanced_params))
    
    # Create test image
    image_data = create_test_image()
    
    try:
        result = subprocess.run(
            cmd,
            input=image_data,
            capture_output=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return True, len(result.stdout), None
        else:
            # Parse error from stderr
            try:
                error = json.loads(result.stderr)
                return False, 0, error.get('message', 'Unknown error')
            except:
                return False, 0, result.stderr.decode()
                
    except subprocess.TimeoutExpired:
        return False, 0, "Timeout"
    except Exception as e:
        return False, 0, str(e)

def main():
    print("Testing sandboxed_convert.py security...\n")
    
    # Test 1: Normal operation
    print("Test 1: Normal conversion (should succeed)")
    success, size, error = test_sandboxed_convert('png', 'jpeg', 85)
    print(f"  Result: {'✓ Success' if success else '✗ Failed'}")
    if success:
        print(f"  Output size: {size} bytes")
    else:
        print(f"  Error: {error}")
    print()
    
    # Test 2: Valid advanced parameters
    print("Test 2: Valid advanced parameters (should succeed)")
    success, size, error = test_sandboxed_convert(
        'png', 'jpeg', 85, 
        {"progressive": True, "subsampling": 2}
    )
    print(f"  Result: {'✓ Success' if success else '✗ Failed'}")
    if success:
        print(f"  Output size: {size} bytes")
    else:
        print(f"  Error: {error}")
    print()
    
    # Test 3: Injection attempt - arbitrary parameters
    print("Test 3: Injection - arbitrary parameters (security test)")
    malicious_params = {
        "__class__": "evil",
        "format": "BMP",  # Try to override format
        "quality": "not_a_number",
        "some_internal_param": "hack"
    }
    success, size, error = test_sandboxed_convert(
        'png', 'jpeg', 85, 
        malicious_params
    )
    print(f"  Result: {'✓ Success' if success else '✗ Failed'}")
    if success:
        print(f"  WARNING: Potential security issue - arbitrary params accepted")
        print(f"  Output size: {size} bytes")
    else:
        print(f"  Error: {error}")
    print()
    
    # Test 4: WebP specific parameters
    print("Test 4: WebP with lossless (should succeed)")
    success, size, error = test_sandboxed_convert(
        'png', 'webp', 85,
        {"lossless": True, "method": 6}
    )
    print(f"  Result: {'✓ Success' if success else '✗ Failed'}")
    if success:
        print(f"  Output size: {size} bytes")
    else:
        print(f"  Error: {error}")
    print()
    
    # Test 5: Invalid parameter values
    print("Test 5: Invalid parameter values (security test)")
    invalid_params = {
        "compress_level": 9999,  # Way out of range
        "quality": -100,
        "progressive": "yes"  # Should be boolean
    }
    success, size, error = test_sandboxed_convert(
        'png', 'png', 85,
        invalid_params
    )
    print(f"  Result: {'✓ Success' if success else '✗ Failed'}")
    if success:
        print(f"  WARNING: Invalid values accepted")
        print(f"  Output size: {size} bytes")
    else:
        print(f"  Error: {error}")
    print()

if __name__ == "__main__":
    main()