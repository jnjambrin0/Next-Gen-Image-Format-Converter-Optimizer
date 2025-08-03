#!/usr/bin/env python3
"""
Test that the system can now handle misnamed files correctly
"""

import asyncio
import sys
import os
from pathlib import Path

sys.path.insert(0, '.')

from app.services.conversion_service import conversion_service
from app.services.intelligence_service import intelligence_service
from app.core.monitoring.stats import stats_collector
from app.models.requests import ConversionApiRequest
from app.models.conversion import OutputFormat, ConversionSettings


async def test_misnamed_files():
    """Test conversion of files with wrong extensions."""
    
    print("🔄 Testing Misnamed File Handling")
    print("=" * 60)
    
    # Initialize services
    conversion_service.stats_collector = stats_collector
    intelligence_service.stats_collector = stats_collector
    await intelligence_service.initialize()
    
    test_cases = [
        {
            "file": "images_sample/heic/lofi_cat.heic",  # Actually a PNG
            "claimed_format": "heic",
            "actual_format": "png",
            "output_format": OutputFormat.WEBP
        },
        {
            "file": "images_sample/gif/tumblr_ku2pvuJkJG1qz9qooo1_r1_400.gif.webp",  # Actually WebP
            "claimed_format": "gif",
            "actual_format": "webp", 
            "output_format": OutputFormat.JPEG
        }
    ]
    
    all_passed = True
    
    for test in test_cases:
        print(f"\n📄 Testing: {test['file']}")
        print(f"   Claimed format: {test['claimed_format']}")
        print(f"   Actual format: {test['actual_format']}")
        
        try:
            # Read file
            with open(test['file'], 'rb') as f:
                image_data = f.read()
                
            # Create request with wrong format (from extension)
            request = ConversionApiRequest(
                filename=Path(test['file']).name,
                input_format=test['claimed_format'],
                output_format=test['output_format'],
                settings=ConversionSettings(quality=85)
            )
            
            # Try conversion - should work now!
            result, output_data = await conversion_service.convert(
                image_data=image_data,
                request=request,
                timeout=30.0
            )
            
            if output_data and len(output_data) > 0:
                print(f"   ✅ Conversion successful!")
                print(f"   Output size: {len(output_data):,} bytes")
                print(f"   Processing time: {result.processing_time:.2f}s")
            else:
                print(f"   ❌ Conversion failed - no output data")
                all_passed = False
                
        except Exception as e:
            print(f"   ❌ Conversion failed: {str(e)}")
            all_passed = False
            
    # Test with correct detection from API level
    print("\n\n🌐 Testing with format auto-detection:")
    
    try:
        # Simulate what happens at API level
        from app.services.format_detection_service import format_detection_service
        
        with open("images_sample/heic/lofi_cat.heic", 'rb') as f:
            image_data = f.read()
            
        # Detect format
        detected_format, confident = await format_detection_service.detect_format(image_data)
        print(f"   Detected format: {detected_format} (confident: {confident})")
        
        # Create request with detected format
        request = ConversionApiRequest(
            filename="lofi_cat.heic",
            input_format=detected_format,  # Use detected format
            output_format=OutputFormat.AVIF,
            settings=ConversionSettings(quality=90)
        )
        
        result, output_data = await conversion_service.convert(
            image_data=image_data,
            request=request,
            timeout=30.0
        )
        
        if output_data:
            print(f"   ✅ Conversion with detected format successful!")
            print(f"   Output size: {len(output_data):,} bytes")
        else:
            print(f"   ❌ Conversion failed")
            all_passed = False
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
        all_passed = False
        
    print("\n" + "=" * 60)
    print(f"{'✅ All tests passed!' if all_passed else '❌ Some tests failed'}")
    
    return all_passed


async def main():
    """Main test runner."""
    try:
        success = await test_misnamed_files()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())