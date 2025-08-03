#!/usr/bin/env python3
"""
Production-Ready Test Suite for Image Converter
Comprehensive testing with real sample images
"""

import asyncio
import os
import sys
import time
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from collections import defaultdict
import mimetypes

sys.path.insert(0, '.')

# Import application components
from app.services.conversion_service import conversion_service
from app.services.intelligence_service import intelligence_service
from app.core.monitoring.stats import stats_collector
from app.models.requests import ConversionApiRequest
from app.models.conversion import OutputFormat, ConversionSettings
from app.core.exceptions import (
    ConversionError,
    InvalidImageError,
    UnsupportedFormatError,
)

# Test configuration
SAMPLE_IMAGES_DIR = Path("images_sample")
RESULTS_DIR = Path("test_results")
RESULTS_DIR.mkdir(exist_ok=True)

# Known issues with sample files
KNOWN_ISSUES = {
    "lofi_cat.heic": "Actually a PNG file misnamed as HEIC",
    "tumblr_ku2pvuJkJG1qz9qooo1_r1_400.gif.webp": "WebP file in GIF directory",
}

# Output formats to test
OUTPUT_FORMATS = [
    OutputFormat.WEBP,
    OutputFormat.JPEG,
    OutputFormat.PNG,
]

# Additional formats if available
OPTIONAL_FORMATS = [
    OutputFormat.AVIF,
    OutputFormat.JPEG_OPTIMIZED,
    OutputFormat.PNG_OPTIMIZED,
    OutputFormat.HEIF,
]


class TestMetrics:
    """Track test metrics and results"""
    
    def __init__(self):
        self.conversions = []
        self.errors = []
        self.skipped = []
        self.timing = defaultdict(list)
        self.compression_ratios = defaultdict(list)
        
    def add_conversion(self, input_file: str, output_format: str, 
                      time_taken: float, input_size: int, output_size: int,
                      metadata: Dict[str, Any] = None):
        """Record successful conversion"""
        self.conversions.append({
            "input_file": input_file,
            "output_format": output_format,
            "time_taken": time_taken,
            "input_size": input_size,
            "output_size": output_size,
            "compression_ratio": input_size / output_size if output_size > 0 else 0,
            "metadata": metadata or {}
        })
        
        format_pair = f"{Path(input_file).suffix.lower()} -> {output_format}"
        self.timing[format_pair].append(time_taken)
        self.compression_ratios[format_pair].append(input_size / output_size if output_size > 0 else 0)
        
    def add_error(self, input_file: str, output_format: str, error: str, error_type: str):
        """Record conversion error"""
        self.errors.append({
            "input_file": input_file,
            "output_format": output_format,
            "error": error,
            "error_type": error_type
        })
        
    def add_skip(self, input_file: str, reason: str):
        """Record skipped test"""
        self.skipped.append({
            "input_file": input_file,
            "reason": reason
        })
        
    def get_summary(self) -> Dict[str, Any]:
        """Generate test summary"""
        total_tests = len(self.conversions) + len(self.errors)
        
        # Calculate average times by format
        avg_times = {}
        for format_pair, times in self.timing.items():
            avg_times[format_pair] = sum(times) / len(times) if times else 0
            
        # Calculate average compression ratios
        avg_compression = {}
        for format_pair, ratios in self.compression_ratios.items():
            avg_compression[format_pair] = sum(ratios) / len(ratios) if ratios else 0
            
        return {
            "total_tests": total_tests,
            "successful": len(self.conversions),
            "failed": len(self.errors),
            "skipped": len(self.skipped),
            "success_rate": f"{(len(self.conversions) / total_tests * 100):.1f}%" if total_tests > 0 else "0%",
            "average_times": avg_times,
            "average_compression": avg_compression,
            "fastest_conversion": min(self.timing.items(), key=lambda x: min(x[1]) if x[1] else float('inf'))[0] if self.timing else "N/A",
            "best_compression": max(self.compression_ratios.items(), key=lambda x: max(x[1]) if x[1] else 0)[0] if self.compression_ratios else "N/A"
        }


async def initialize_services():
    """Initialize required services"""
    print("🔧 Initializing services...")
    
    # Inject stats collector
    conversion_service.stats_collector = stats_collector
    intelligence_service.stats_collector = stats_collector
    
    # Initialize intelligence service
    await intelligence_service.initialize()
    
    print("✅ Services initialized\n")


def detect_actual_format(file_path: Path) -> str:
    """Detect actual file format from magic bytes"""
    with open(file_path, 'rb') as f:
        header = f.read(32)
        
    # Check common image formats
    if header.startswith(b'\x89PNG'):
        return 'png'
    elif header.startswith(b'\xff\xd8\xff'):
        return 'jpeg'
    elif header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
        return 'gif'
    elif header.startswith(b'BM'):
        return 'bmp'
    elif header.startswith(b'RIFF') and b'WEBP' in header:
        return 'webp'
    elif len(header) > 12 and header[4:8] == b'ftyp':
        brand = header[8:12]
        if brand in [b'avif', b'avis']:
            return 'avif'
        elif brand in [b'heic', b'heix', b'hevc', b'hevx', b'mif1', b'msf1']:
            return 'heif'
    elif header.startswith(b'II*\x00') or header.startswith(b'MM\x00*'):
        return 'tiff'
        
    # Fallback to extension
    return file_path.suffix.lower().strip('.')


async def test_single_conversion(
    input_path: Path,
    output_format: OutputFormat,
    metrics: TestMetrics
) -> bool:
    """Test a single image conversion"""
    
    # Detect actual format
    actual_format = detect_actual_format(input_path)
    claimed_format = input_path.suffix.lower().strip('.')
    
    # Handle known issues
    if input_path.name in KNOWN_ISSUES:
        metrics.add_skip(str(input_path), KNOWN_ISSUES[input_path.name])
        return True
        
    # Skip if format mismatch
    if actual_format != claimed_format and claimed_format != 'jpg':  # jpg/jpeg are equivalent
        metrics.add_skip(
            str(input_path),
            f"Format mismatch: file is {actual_format} but named as {claimed_format}"
        )
        return True
        
    # Skip same format conversions
    if actual_format == output_format.value or (actual_format == 'jpeg' and output_format.value == 'jpg'):
        return True
        
    start_time = time.time()
    
    try:
        # Read input file
        with open(input_path, 'rb') as f:
            image_data = f.read()
            
        input_size = len(image_data)
        
        # Create conversion request
        settings = ConversionSettings(
            quality=85,
            strip_metadata=True,
            preserve_metadata=False,
            preserve_gps=False
        )
        
        # Fix format names
        if actual_format == 'jpg':
            actual_format = 'jpeg'
            
        request = ConversionApiRequest(
            filename=input_path.name,
            input_format=actual_format,
            output_format=output_format,
            settings=settings
        )
        
        # Perform conversion
        result, output_data = await conversion_service.convert(
            image_data=image_data,
            request=request,
            timeout=30.0
        )
        
        if not output_data:
            raise ConversionError("No output data received")
            
        # Record metrics
        time_taken = time.time() - start_time
        output_size = len(output_data)
        
        metrics.add_conversion(
            str(input_path),
            output_format.value,
            time_taken,
            input_size,
            output_size
        )
        
        # Save output for inspection
        output_dir = RESULTS_DIR / actual_format
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f"{input_path.stem}_to_{output_format.value}.{output_format.value}"
        with open(output_file, 'wb') as f:
            f.write(output_data)
            
        return True
        
    except Exception as e:
        metrics.add_error(
            str(input_path),
            output_format.value,
            str(e),
            type(e).__name__
        )
        return False


async def test_batch_conversions(files: List[Path], metrics: TestMetrics):
    """Test batch conversions"""
    print("🔄 Testing format conversions...")
    
    # Test each file with each output format
    for i, input_file in enumerate(files):
        print(f"\n📷 [{i+1}/{len(files)}] {input_file.name}")
        
        successes = []
        for output_format in OUTPUT_FORMATS + OPTIONAL_FORMATS:
            success = await test_single_conversion(input_file, output_format, metrics)
            
            if success and str(input_file) not in [s["input_file"] for s in metrics.skipped]:
                # Find the conversion in metrics
                for conv in reversed(metrics.conversions):
                    if conv["input_file"] == str(input_file) and conv["output_format"] == output_format.value:
                        successes.append(f"✅ {output_format.value} ({conv['time_taken']:.2f}s, {conv['compression_ratio']:.1f}x)")
                        break
                        
        if successes:
            for s in successes:
                print(f"  {s}")


async def test_error_handling(metrics: TestMetrics):
    """Test error handling scenarios"""
    print("\n⚠️  Testing error handling...")
    
    test_cases = [
        ("Empty file", b"", "jpeg"),
        ("Invalid data", b"Not an image", "png"),
        ("Corrupted header", b"\x89PNG\r\n\x1a\nBROKEN", "png"),
    ]
    
    for test_name, data, format_type in test_cases:
        try:
            request = ConversionApiRequest(
                filename=f"test_{test_name.lower().replace(' ', '_')}.{format_type}",
                input_format=format_type,
                output_format=OutputFormat.WEBP,
                settings=ConversionSettings(quality=85)
            )
            
            await conversion_service.convert(data, request)
            print(f"  ❌ {test_name}: Should have failed but didn't")
            
        except Exception as e:
            print(f"  ✅ {test_name}: Correctly rejected ({type(e).__name__})")


async def test_security_features(metrics: TestMetrics):
    """Test security features"""
    print("\n🔒 Testing security features...")
    
    # Find a JPEG file with metadata
    jpeg_files = list(SAMPLE_IMAGES_DIR.glob("jpg/*.jpg"))
    if not jpeg_files:
        print("  ⏭️  No JPEG files found for metadata test")
        return
        
    test_file = jpeg_files[0]
    
    with open(test_file, 'rb') as f:
        image_data = f.read()
        
    # Test metadata stripping
    request_strip = ConversionApiRequest(
        filename=test_file.name,
        input_format="jpeg",
        output_format=OutputFormat.JPEG,
        settings=ConversionSettings(
            quality=95,
            strip_metadata=True,
            preserve_metadata=False
        )
    )
    
    request_preserve = ConversionApiRequest(
        filename=test_file.name,
        input_format="jpeg",
        output_format=OutputFormat.JPEG,
        settings=ConversionSettings(
            quality=95,
            strip_metadata=False,
            preserve_metadata=True
        )
    )
    
    _, output_stripped = await conversion_service.convert(image_data, request_strip)
    _, output_preserved = await conversion_service.convert(image_data, request_preserve)
    
    size_diff = len(output_preserved) - len(output_stripped) if output_preserved and output_stripped else 0
    
    if size_diff > 0:
        print(f"  ✅ Metadata stripping: Removed {size_diff:,} bytes")
    else:
        print(f"  ⚠️  Metadata stripping: No size difference detected")


async def run_production_tests():
    """Run all production tests"""
    print("🚀 Production-Ready Test Suite for Image Converter")
    print("=" * 60)
    
    metrics = TestMetrics()
    start_time = time.time()
    
    # Initialize services
    await initialize_services()
    
    # Collect sample files
    sample_files = []
    for format_dir in SAMPLE_IMAGES_DIR.iterdir():
        if format_dir.is_dir():
            for file_path in format_dir.glob("*"):
                if file_path.is_file() and not file_path.name.startswith('.'):
                    sample_files.append(file_path)
                    
    print(f"📁 Found {len(sample_files)} sample files")
    
    # Run tests
    await test_batch_conversions(sample_files, metrics)
    await test_error_handling(metrics)
    await test_security_features(metrics)
    
    # Generate summary
    total_time = time.time() - start_time
    summary = metrics.get_summary()
    
    # Print results
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS")
    print("=" * 60)
    print(f"⏱️  Total time: {total_time:.1f}s")
    print(f"📈 Tests run: {summary['total_tests']}")
    print(f"✅ Successful: {summary['successful']}")
    print(f"❌ Failed: {summary['failed']}")
    print(f"⏭️  Skipped: {summary['skipped']}")
    print(f"📊 Success rate: {summary['success_rate']}")
    
    if summary['average_times']:
        print(f"\n⚡ Performance:")
        print(f"  Fastest: {summary['fastest_conversion']}")
        print(f"  Best compression: {summary['best_compression']}")
    
    # Save detailed report
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_time": total_time,
        "summary": summary,
        "conversions": metrics.conversions,
        "errors": metrics.errors,
        "skipped": metrics.skipped
    }
    
    report_path = RESULTS_DIR / f"production_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
        
    print(f"\n📄 Detailed report: {report_path}")
    
    # Show errors if any
    if metrics.errors:
        print("\n❌ Errors encountered:")
        for error in metrics.errors[:5]:  # Show first 5 errors
            print(f"  {error['input_file']} → {error['output_format']}: {error['error_type']}")
        if len(metrics.errors) > 5:
            print(f"  ... and {len(metrics.errors) - 5} more")
            
    return summary['failed'] == 0


async def main():
    """Main entry point"""
    try:
        success = await run_production_tests()
        print(f"\n{'✅ All tests passed!' if success else '❌ Some tests failed'}")
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test suite error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())