#!/usr/bin/env python3
"""
Comprehensive End-to-End Test Suite for Image Converter
Tests all format conversions using real sample images
"""

import asyncio
import os
import sys
import time
import json
import traceback
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from collections import defaultdict
import hashlib

sys.path.insert(0, '.')

# Import application components
from app.services.conversion_service import conversion_service
from app.services.intelligence_service import intelligence_service
from app.core.monitoring.stats import stats_collector
from app.models.requests import ConversionApiRequest
from app.models.conversion import OutputFormat, ConversionSettings, OptimizationSettings
from app.core.exceptions import (
    ConversionError,
    InvalidImageError,
    UnsupportedFormatError,
    ConversionFailedError,
)
from app.config import settings

# Test configuration
SAMPLE_IMAGES_DIR = Path("images_sample")
RESULTS_DIR = Path("test_results")
RESULTS_DIR.mkdir(exist_ok=True)

# Output formats to test
OUTPUT_FORMATS = [
    OutputFormat.WEBP,
    OutputFormat.AVIF,
    OutputFormat.JPEG,
    OutputFormat.JPEG_OPTIMIZED,
    OutputFormat.PNG,
    OutputFormat.PNG_OPTIMIZED,
    OutputFormat.HEIF,
    # OutputFormat.JXL,  # Uncomment if JPEG XL is available
    # OutputFormat.WEBP2,  # Uncomment if WebP2 is available
]

# Quality settings to test
QUALITY_SETTINGS = [85, 95, 60]  # Default, high, low

class TestResult:
    """Container for test results"""
    def __init__(self):
        self.total_tests = 0
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.errors: List[Dict[str, Any]] = []
        self.metrics: List[Dict[str, Any]] = []
        self.performance: Dict[str, List[float]] = defaultdict(list)
        
    def add_success(self, input_file: str, output_format: str, metrics: Dict[str, Any]):
        self.total_tests += 1
        self.passed += 1
        self.metrics.append({
            "input_file": input_file,
            "output_format": output_format,
            "status": "success",
            **metrics
        })
        
    def add_failure(self, input_file: str, output_format: str, error: str, error_type: str = "unknown"):
        self.total_tests += 1
        self.failed += 1
        self.errors.append({
            "input_file": input_file,
            "output_format": output_format,
            "error": error,
            "error_type": error_type
        })
        
    def add_skip(self, input_file: str, output_format: str, reason: str):
        self.total_tests += 1
        self.skipped += 1
        self.errors.append({
            "input_file": input_file,
            "output_format": output_format,
            "error": f"Skipped: {reason}",
            "error_type": "skip"
        })
        
    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "success_rate": f"{(self.passed / self.total_tests * 100):.2f}%" if self.total_tests > 0 else "0%",
            "avg_conversion_time": self._calculate_avg_time(),
            "avg_compression_ratio": self._calculate_avg_compression()
        }
        
    def _calculate_avg_time(self) -> float:
        all_times = []
        for metric in self.metrics:
            if "conversion_time" in metric:
                all_times.append(metric["conversion_time"])
        return sum(all_times) / len(all_times) if all_times else 0
        
    def _calculate_avg_compression(self) -> float:
        all_ratios = []
        for metric in self.metrics:
            if "compression_ratio" in metric:
                all_ratios.append(metric["compression_ratio"])
        return sum(all_ratios) / len(all_ratios) if all_ratios else 0


async def initialize_services():
    """Initialize all required services"""
    print("🔧 Initializing services...")
    
    # Initialize stats collector
    conversion_service.stats_collector = stats_collector
    intelligence_service.stats_collector = stats_collector
    
    # Initialize intelligence service
    await intelligence_service.initialize()
    
    print("✅ Services initialized")


async def test_single_conversion(
    input_path: Path,
    output_format: OutputFormat,
    quality: int = 85,
    preserve_metadata: bool = False
) -> Tuple[bool, Dict[str, Any]]:
    """Test a single image conversion"""
    
    start_time = time.time()
    metrics = {
        "input_size": input_path.stat().st_size,
        "input_format": input_path.suffix.lower().strip('.'),
        "quality": quality,
        "preserve_metadata": preserve_metadata
    }
    
    try:
        # Read input file
        with open(input_path, 'rb') as f:
            image_data = f.read()
            
        # Detect input format from filename
        input_format = input_path.suffix.lower().strip('.')
        if input_format == 'jpg':
            input_format = 'jpeg'
            
        # Create conversion request
        settings_obj = ConversionSettings(
            quality=quality,
            strip_metadata=not preserve_metadata,
            preserve_metadata=preserve_metadata,
            preserve_gps=False
        )
        
        request = ConversionApiRequest(
            filename=input_path.name,
            input_format=input_format,
            output_format=output_format,
            settings=settings_obj
        )
        
        # Perform conversion
        result, output_data = await conversion_service.convert(
            image_data=image_data,
            request=request,
            timeout=30.0
        )
        
        # Calculate metrics
        conversion_time = time.time() - start_time
        output_size = len(output_data) if output_data else 0
        compression_ratio = metrics["input_size"] / output_size if output_size > 0 else 0
        
        metrics.update({
            "conversion_time": conversion_time,
            "output_size": output_size,
            "compression_ratio": compression_ratio,
            "status": result.status.value,
            "has_output": output_data is not None
        })
        
        # Save output file for manual inspection
        if output_data:
            output_dir = RESULTS_DIR / input_format
            output_dir.mkdir(exist_ok=True)
            output_filename = f"{input_path.stem}_to_{output_format.value}_q{quality}.{output_format.value}"
            output_path = output_dir / output_filename
            with open(output_path, 'wb') as f:
                f.write(output_data)
            metrics["output_path"] = str(output_path)
            
        return True, metrics
        
    except Exception as e:
        conversion_time = time.time() - start_time
        metrics["conversion_time"] = conversion_time
        metrics["error"] = str(e)
        metrics["error_type"] = type(e).__name__
        return False, metrics


async def test_content_detection(input_path: Path) -> Dict[str, Any]:
    """Test content detection using intelligence service"""
    try:
        with open(input_path, 'rb') as f:
            image_data = f.read()
            
        result = await intelligence_service.analyze_image(image_data, debug=True)
        
        return {
            "content_type": result.primary_type.value,
            "confidence": result.confidence,
            "has_text": result.has_text,
            "has_faces": result.has_faces,
            "processing_time_ms": result.processing_time_ms
        }
    except Exception as e:
        return {
            "error": str(e),
            "content_type": "unknown"
        }


async def test_metadata_handling(input_path: Path) -> Dict[str, Any]:
    """Test metadata stripping functionality"""
    try:
        with open(input_path, 'rb') as f:
            image_data = f.read()
            
        input_format = input_path.suffix.lower().strip('.')
        if input_format == 'jpg':
            input_format = 'jpeg'
            
        # Test with metadata preserved
        request_preserve = ConversionApiRequest(
            filename=input_path.name,
            input_format=input_format,
            output_format=OutputFormat.JPEG,
            settings=ConversionSettings(
                quality=95,
                strip_metadata=False,
                preserve_metadata=True,
                preserve_gps=True
            )
        )
        
        # Test with metadata stripped
        request_strip = ConversionApiRequest(
            filename=input_path.name,
            input_format=input_format,
            output_format=OutputFormat.JPEG,
            settings=ConversionSettings(
                quality=95,
                strip_metadata=True,
                preserve_metadata=False,
                preserve_gps=False
            )
        )
        
        _, output_preserve = await conversion_service.convert(image_data, request_preserve)
        _, output_strip = await conversion_service.convert(image_data, request_strip)
        
        size_with_metadata = len(output_preserve) if output_preserve else 0
        size_without_metadata = len(output_strip) if output_strip else 0
        
        return {
            "size_with_metadata": size_with_metadata,
            "size_without_metadata": size_without_metadata,
            "metadata_size": size_with_metadata - size_without_metadata,
            "metadata_stripped": size_without_metadata < size_with_metadata
        }
        
    except Exception as e:
        return {
            "error": str(e),
            "metadata_stripped": None
        }


async def test_concurrent_conversions(image_paths: List[Path], max_concurrent: int = 5):
    """Test concurrent conversion handling"""
    print(f"\n🔄 Testing concurrent conversions (max {max_concurrent})...")
    
    tasks = []
    for i, path in enumerate(image_paths[:max_concurrent]):
        output_format = OUTPUT_FORMATS[i % len(OUTPUT_FORMATS)]
        task = test_single_conversion(path, output_format)
        tasks.append(task)
        
    start_time = time.time()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    total_time = time.time() - start_time
    
    successful = sum(1 for r in results if isinstance(r, tuple) and r[0])
    
    return {
        "total_concurrent": len(tasks),
        "successful": successful,
        "failed": len(tasks) - successful,
        "total_time": total_time,
        "avg_time_per_conversion": total_time / len(tasks)
    }


async def test_error_scenarios():
    """Test various error scenarios"""
    print("\n⚠️  Testing error scenarios...")
    
    error_results = []
    
    # Test 1: Empty file
    try:
        request = ConversionApiRequest(
            filename="empty.jpg",
            input_format="jpeg",
            output_format=OutputFormat.WEBP,
            settings=ConversionSettings(quality=85)
        )
        await conversion_service.convert(b"", request)
        error_results.append(("Empty file", "Failed - should have raised error"))
    except Exception as e:
        error_results.append(("Empty file", f"Passed - {type(e).__name__}"))
        
    # Test 2: Invalid image data
    try:
        request = ConversionApiRequest(
            filename="invalid.jpg",
            input_format="jpeg",
            output_format=OutputFormat.WEBP,
            settings=ConversionSettings(quality=85)
        )
        await conversion_service.convert(b"This is not an image", request)
        error_results.append(("Invalid data", "Failed - should have raised error"))
    except Exception as e:
        error_results.append(("Invalid data", f"Passed - {type(e).__name__}"))
        
    # Test 3: Mismatched format
    try:
        # PNG data but claiming it's JPEG
        png_path = next(SAMPLE_IMAGES_DIR.glob("png/*.png"))
        with open(png_path, 'rb') as f:
            png_data = f.read()
            
        request = ConversionApiRequest(
            filename="fake.jpg",
            input_format="jpeg",
            output_format=OutputFormat.WEBP,
            settings=ConversionSettings(quality=85)
        )
        await conversion_service.convert(png_data, request)
        error_results.append(("Format mismatch", "Failed - should have raised error"))
    except Exception as e:
        error_results.append(("Format mismatch", f"Passed - {type(e).__name__}"))
        
    return error_results


async def run_comprehensive_tests():
    """Run all tests and generate report"""
    print("🚀 Starting Comprehensive Image Converter Test Suite")
    print("=" * 60)
    
    results = TestResult()
    all_metrics = []
    
    # Initialize services
    await initialize_services()
    
    # Get all sample images
    image_files = []
    for format_dir in SAMPLE_IMAGES_DIR.iterdir():
        if format_dir.is_dir():
            for img_file in format_dir.glob("*"):
                if img_file.is_file() and not img_file.name.startswith('.'):
                    image_files.append(img_file)
                    
    print(f"\n📁 Found {len(image_files)} sample images")
    
    # Test 1: All format conversions
    print("\n🔄 Testing all format conversions...")
    for input_file in image_files:
        print(f"\n  📷 Testing: {input_file.name}")
        
        # Test content detection
        content_info = await test_content_detection(input_file)
        print(f"    Content type: {content_info.get('content_type', 'unknown')}")
        
        # Test metadata handling (only for formats that support metadata)
        if input_file.suffix.lower() in ['.jpg', '.jpeg', '.tiff', '.png']:
            metadata_info = await test_metadata_handling(input_file)
            if metadata_info.get('metadata_stripped') is not None:
                print(f"    Metadata handling: {'✅ Working' if metadata_info['metadata_stripped'] else '❌ Failed'}")
        
        # Test conversions to all output formats
        for output_format in OUTPUT_FORMATS:
            # Skip converting to same format
            input_format = input_file.suffix.lower().strip('.')
            if input_format == output_format.value or (input_format == 'jpg' and output_format.value == 'jpeg'):
                results.add_skip(
                    str(input_file),
                    output_format.value,
                    "Same format conversion"
                )
                continue
                
            # Test with default quality
            success, metrics = await test_single_conversion(
                input_file,
                output_format,
                quality=85
            )
            
            if success:
                results.add_success(str(input_file), output_format.value, metrics)
                print(f"    ✅ {output_format.value}: {metrics['conversion_time']:.2f}s, "
                      f"ratio: {metrics['compression_ratio']:.2f}x")
            else:
                results.add_failure(
                    str(input_file),
                    output_format.value,
                    metrics.get('error', 'Unknown error'),
                    metrics.get('error_type', 'unknown')
                )
                print(f"    ❌ {output_format.value}: {metrics.get('error_type', 'Error')}")
    
    # Test 2: Concurrent conversions
    concurrent_results = await test_concurrent_conversions(image_files[:5])
    print(f"\n✅ Concurrent test: {concurrent_results['successful']}/{concurrent_results['total_concurrent']} "
          f"succeeded in {concurrent_results['total_time']:.2f}s")
    
    # Test 3: Error scenarios
    error_results = await test_error_scenarios()
    print("\n✅ Error handling tests:")
    for scenario, result in error_results:
        print(f"    {scenario}: {result}")
    
    # Generate report
    summary = results.get_summary()
    
    report = {
        "test_run": datetime.now().isoformat(),
        "summary": summary,
        "concurrent_test": concurrent_results,
        "error_handling": error_results,
        "detailed_metrics": results.metrics,
        "errors": results.errors
    }
    
    # Save report
    report_path = RESULTS_DIR / f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
        
    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    print(f"Total tests: {summary['total_tests']}")
    print(f"✅ Passed: {summary['passed']}")
    print(f"❌ Failed: {summary['failed']}")
    print(f"⏭️  Skipped: {summary['skipped']}")
    print(f"Success rate: {summary['success_rate']}")
    print(f"Avg conversion time: {summary['avg_conversion_time']:.3f}s")
    print(f"Avg compression ratio: {summary['avg_compression_ratio']:.2f}x")
    print(f"\n📄 Full report saved to: {report_path}")
    
    # Print failures if any
    if results.failed > 0:
        print("\n❌ FAILURES:")
        for error in results.errors:
            if error.get('error_type') != 'skip':
                print(f"  - {error['input_file']} → {error['output_format']}: {error['error']}")
    
    return summary['failed'] == 0


async def main():
    """Main entry point"""
    try:
        success = await run_comprehensive_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Test suite failed: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())