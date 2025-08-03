#!/usr/bin/env python3
"""
Test Format Detection Service
Tests robust format detection regardless of file extensions
"""

import asyncio
import sys
import os
from pathlib import Path

sys.path.insert(0, '.')

from app.services.format_detection_service import format_detection_service


async def test_format_detection():
    """Test format detection with various image samples."""
    
    print("🔍 Testing Format Detection Service")
    print("=" * 60)
    
    # Test with real sample images
    sample_dir = Path("images_sample")
    if not sample_dir.exists():
        print("❌ Sample images directory not found")
        return False
        
    test_results = []
    
    # Test all sample images
    for format_dir in sample_dir.iterdir():
        if not format_dir.is_dir():
            continue
            
        print(f"\n📁 Testing {format_dir.name} format:")
        
        for image_file in format_dir.glob("*"):
            if not image_file.is_file() or image_file.name.startswith('.'):
                continue
                
            # Read file
            try:
                with open(image_file, 'rb') as f:
                    image_data = f.read()
                    
                # Detect format
                detected_format, confident = await format_detection_service.detect_format(image_data)
                
                # Expected format from directory name
                expected = format_dir.name
                if expected == "jpg":
                    expected = "jpeg"
                elif expected == "heic":
                    expected = "heif"
                    
                # Check if detection matches
                matches = detected_format == expected
                
                result = {
                    "file": image_file.name,
                    "expected": expected,
                    "detected": detected_format,
                    "confident": confident,
                    "matches": matches
                }
                
                test_results.append(result)
                
                # Print result
                status = "✅" if matches else "❌"
                confidence = "confident" if confident else "uncertain"
                print(f"  {status} {image_file.name}: detected as {detected_format} ({confidence})")
                
                if not matches:
                    print(f"     Expected: {expected}, Got: {detected_format}")
                    
            except Exception as e:
                print(f"  ❌ {image_file.name}: Error - {str(e)}")
                test_results.append({
                    "file": image_file.name,
                    "expected": format_dir.name,
                    "error": str(e)
                })
    
    # Test edge cases
    print("\n🧪 Testing edge cases:")
    
    # Empty data
    try:
        await format_detection_service.detect_format(b"")
    except ValueError:
        print("  ✅ Empty data correctly rejected")
    else:
        print("  ❌ Empty data should raise ValueError")
        
    # Too small data
    try:
        await format_detection_service.detect_format(b"ABC")
    except ValueError:
        print("  ✅ Too small data correctly rejected")
    else:
        print("  ❌ Too small data should raise ValueError")
        
    # Invalid data
    try:
        await format_detection_service.detect_format(b"This is not an image at all!")
    except ValueError:
        print("  ✅ Invalid data correctly rejected")
    else:
        print("  ❌ Invalid data should raise ValueError")
        
    # Test specific format detection
    print("\n🎯 Testing specific format signatures:")
    
    # JPEG with EXIF
    jpeg_exif = b'\xff\xd8\xff\xe1\x00\x18Exif\x00\x00' + b'\x00' * 100
    fmt, conf = await format_detection_service.detect_format(jpeg_exif)
    print(f"  {'✅' if fmt == 'jpeg' else '❌'} JPEG with EXIF: {fmt}")
    
    # WebP
    webp_data = b'RIFF\x00\x00\x00\x00WEBP' + b'\x00' * 100
    fmt, conf = await format_detection_service.detect_format(webp_data)
    print(f"  {'✅' if fmt == 'webp' else '❌'} WebP: {fmt}")
    
    # HEIF
    heif_data = b'\x00\x00\x00\x20ftypheic\x00\x00\x00\x00' + b'\x00' * 100
    fmt, conf = await format_detection_service.detect_format(heif_data)
    print(f"  {'✅' if fmt == 'heif' else '❌'} HEIF/HEIC: {fmt}")
    
    # AVIF
    avif_data = b'\x00\x00\x00\x20ftypavif\x00\x00\x00\x00' + b'\x00' * 100
    fmt, conf = await format_detection_service.detect_format(avif_data)
    print(f"  {'✅' if fmt == 'avif' else '❌'} AVIF: {fmt}")
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Summary:")
    
    total = len(test_results)
    successful = sum(1 for r in test_results if r.get('matches', False))
    errors = sum(1 for r in test_results if 'error' in r)
    
    print(f"Total tests: {total}")
    print(f"✅ Successful: {successful}")
    print(f"❌ Mismatches: {total - successful - errors}")
    print(f"⚠️  Errors: {errors}")
    
    success_rate = (successful / total * 100) if total > 0 else 0
    print(f"\nSuccess rate: {success_rate:.1f}%")
    
    # Show mismatches
    mismatches = [r for r in test_results if not r.get('matches', False) and 'error' not in r]
    if mismatches:
        print("\n⚠️  Format mismatches:")
        for m in mismatches:
            print(f"  - {m['file']}: expected {m['expected']}, got {m['detected']}")
    
    return success_rate > 90  # Allow some flexibility for edge cases


async def main():
    """Main test runner."""
    try:
        success = await test_format_detection()
        print(f"\n{'✅ Tests passed!' if success else '❌ Tests failed!'}")
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())