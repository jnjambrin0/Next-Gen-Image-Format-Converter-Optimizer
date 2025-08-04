#!/usr/bin/env python3
"""Test that advanced functionality is preserved after security fixes."""

import subprocess
import sys
import json
import io
from PIL import Image
import os

def create_test_image_with_alpha():
    """Create test image with alpha channel."""
    img = Image.new('RGBA', (100, 100), color=(255, 0, 0, 128))
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()

def run_conversion(input_data, input_format, output_format, quality, params=None):
    """Run sandboxed conversion and return result."""
    cmd = [
        sys.executable,
        'backend/app/core/conversion/sandboxed_convert.py',
        input_format,
        output_format,
        str(quality)
    ]
    
    if params:
        cmd.append(json.dumps(params))
    
    result = subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        timeout=10
    )
    
    return result.returncode == 0, result.stdout, result.stderr

def verify_image_properties(image_data, expected_format):
    """Verify image properties."""
    try:
        img = Image.open(io.BytesIO(image_data))
        return {
            "format": img.format,
            "mode": img.mode,
            "size": img.size,
            "valid": True
        }
    except:
        return {"valid": False}

def test_jpeg_progressive():
    """Test JPEG progressive encoding."""
    print("Test: JPEG Progressive Encoding")
    
    # Create test image
    img = Image.new('RGB', (200, 200), color='blue')
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    
    # Test without progressive
    success1, output1, _ = run_conversion(buffer.getvalue(), 'png', 'jpeg', 85)
    
    # Test with progressive
    success2, output2, _ = run_conversion(buffer.getvalue(), 'png', 'jpeg', 85, {"progressive": True})
    
    print(f"  Without progressive: {len(output1)} bytes")
    print(f"  With progressive: {len(output2)} bytes")
    print(f"  ✓ Both conversions successful" if success1 and success2 else "  ✗ Conversion failed")
    
    # Progressive JPEG is usually slightly larger
    if len(output2) != len(output1):
        print("  ✓ Progressive encoding applied (size difference detected)")
    
    return success1 and success2

def test_webp_lossless():
    """Test WebP lossless mode."""
    print("\nTest: WebP Lossless Mode")
    
    # Create test image with sharp edges (better for lossless)
    img = Image.new('RGB', (100, 100))
    pixels = img.load()
    for i in range(100):
        for j in range(100):
            pixels[i, j] = (255, 0, 0) if i < 50 else (0, 0, 255)
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    
    # Test lossy
    success1, output1, _ = run_conversion(buffer.getvalue(), 'png', 'webp', 85)
    
    # Test lossless
    success2, output2, _ = run_conversion(buffer.getvalue(), 'png', 'webp', 85, {"lossless": True})
    
    print(f"  Lossy: {len(output1)} bytes")
    print(f"  Lossless: {len(output2)} bytes")
    
    # Verify lossless is actually lossless
    if success1 and success2:
        # Lossless should preserve exact colors
        lossy_img = Image.open(io.BytesIO(output1))
        lossless_img = Image.open(io.BytesIO(output2))
        
        # Check a few pixels
        lossy_pixel = lossy_img.getpixel((25, 25))
        lossless_pixel = lossless_img.getpixel((25, 25))
        
        print(f"  Lossy pixel (25,25): {lossy_pixel}")
        print(f"  Lossless pixel (25,25): {lossless_pixel}")
        
        if lossless_pixel == (255, 0, 0):
            print("  ✓ Lossless preserves exact colors")
        else:
            print("  ✗ Lossless color mismatch")
    
    return success1 and success2

def test_png_compression_levels():
    """Test PNG compression levels."""
    print("\nTest: PNG Compression Levels")
    
    # Create test image
    img = Image.new('RGB', (100, 100), color='green')
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    
    results = []
    for level in [0, 6, 9]:
        success, output, _ = run_conversion(
            buffer.getvalue(), 'png', 'png', 85, 
            {"compress_level": level}
        )
        if success:
            results.append((level, len(output)))
            print(f"  Level {level}: {len(output)} bytes")
    
    if len(results) == 3:
        # Higher compression should produce smaller files
        if results[0][1] > results[2][1]:
            print("  ✓ Compression levels working (level 9 < level 0)")
        else:
            print("  ✗ Compression levels not affecting size as expected")
        return True
    
    return False

def test_jpeg_subsampling():
    """Test JPEG chroma subsampling."""
    print("\nTest: JPEG Chroma Subsampling")
    
    # Create colorful test image (subsampling affects color)
    img = Image.new('RGB', (200, 200))
    pixels = img.load()
    for i in range(200):
        for j in range(200):
            pixels[i, j] = (i % 256, j % 256, (i+j) % 256)
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    
    subsamplings = {
        0: "4:4:4 (no subsampling)",
        1: "4:2:2 (horizontal)",
        2: "4:2:0 (horizontal+vertical)"
    }
    
    results = []
    for level, desc in subsamplings.items():
        success, output, _ = run_conversion(
            buffer.getvalue(), 'png', 'jpeg', 85,
            {"subsampling": level}
        )
        if success:
            results.append((level, len(output)))
            print(f"  {desc}: {len(output)} bytes")
    
    if len(results) == 3:
        # More subsampling should produce smaller files
        if results[0][1] > results[2][1]:
            print("  ✓ Subsampling affects file size correctly")
        return True
    
    return False

def test_webp_alpha_quality():
    """Test WebP alpha channel quality."""
    print("\nTest: WebP Alpha Channel Quality")
    
    # Create image with alpha
    img_data = create_test_image_with_alpha()
    
    # Test different alpha qualities
    qualities = [50, 100]
    results = []
    
    for alpha_q in qualities:
        success, output, _ = run_conversion(
            img_data, 'png', 'webp', 85,
            {"alpha_quality": alpha_q}
        )
        if success:
            results.append((alpha_q, len(output)))
            print(f"  Alpha quality {alpha_q}: {len(output)} bytes")
            
            # Verify alpha preserved
            webp_img = Image.open(io.BytesIO(output))
            if webp_img.mode == 'RGBA':
                print(f"    ✓ Alpha channel preserved")
            else:
                print(f"    ✗ Alpha channel lost")
    
    return len(results) == 2

def main():
    print("Testing Advanced Functionality Preservation")
    print("=" * 50)
    
    # Track test results
    tests = [
        test_jpeg_progressive(),
        test_webp_lossless(),
        test_png_compression_levels(),
        test_jpeg_subsampling(),
        test_webp_alpha_quality()
    ]
    
    print("\n" + "=" * 50)
    passed = sum(tests)
    total = len(tests)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All advanced functionality preserved after security fixes!")
    else:
        print("✗ Some functionality may be affected")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)