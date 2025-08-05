#!/usr/bin/env python3
"""
Comprehensive test for batch processing with all supported formats.
Tests batch conversion functionality with realistic scenarios.
"""

import asyncio
import aiohttp
import aiofiles
import json
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime
import io
from PIL import Image

# Test configuration
API_BASE_URL = "http://localhost:8080"
BATCH_ENDPOINT = f"{API_BASE_URL}/api/batch/"
WEBSOCKET_BASE = "ws://localhost:8080"

# Supported formats
INPUT_FORMATS = ["jpeg", "png", "webp", "gif", "bmp", "tiff", "avif"]
OUTPUT_FORMATS = ["webp", "avif", "jpeg", "png", "jxl", "heif", "jpeg_optimized", "png_optimized"]

# Test image directory
TEST_IMAGE_DIR = Path("images_sample")


class BatchTestRunner:
    """Comprehensive batch processing test runner."""
    
    def __init__(self):
        self.session = None
        self.results = []
        self.websocket = None
        
    async def setup(self):
        """Initialize test session."""
        self.session = aiohttp.ClientSession()
        
    async def cleanup(self):
        """Clean up test session."""
        if self.session:
            await self.session.close()
        if self.websocket:
            await self.websocket.close()
            
    async def create_test_image(self, format_name: str, index: int) -> Tuple[str, bytes]:
        """Create a test image with specified format."""
        # Create unique image with different colors for variety
        colors = ["red", "blue", "green", "yellow", "purple", "orange", "pink", "cyan"]
        color = colors[index % len(colors)]
        
        # Create image with text to make it unique
        img = Image.new('RGB', (200, 200), color=color)
        
        # Add some content to make compression interesting
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        for i in range(0, 200, 20):
            draw.line([(0, i), (200, i)], fill="white", width=1)
            draw.line([(i, 0), (i, 200)], fill="black", width=1)
        draw.text((50, 90), f"Test {format_name}\n{index}", fill="white")
        
        # Convert to bytes
        img_buffer = io.BytesIO()
        
        # Handle different formats
        save_format = format_name.upper()
        if save_format == "JPEG":
            save_format = "JPEG"
        elif save_format == "JPG":
            save_format = "JPEG"
        elif save_format == "AVIF":
            # For test purposes, save as PNG if AVIF not supported
            save_format = "PNG"
            
        img.save(img_buffer, format=save_format)
        img_data = img_buffer.getvalue()
        
        filename = f"test_{format_name}_{index}.{format_name.lower()}"
        return filename, img_data
        
    async def find_test_images(self) -> Dict[str, List[Path]]:
        """Find existing test images by format."""
        format_images = {}
        
        if TEST_IMAGE_DIR.exists():
            for format_dir in TEST_IMAGE_DIR.iterdir():
                if format_dir.is_dir():
                    format_name = format_dir.name.lower()
                    images = list(format_dir.glob("*.*"))
                    if images:
                        format_images[format_name] = images[:2]  # Max 2 per format
                        
        # Also check for specific test images
        test_files = [
            ("jpg", "images_sample/jpg/routine.jpg"),
            ("png", "images_sample/png/lofi_cat.png"),
            ("webp", "images_sample/webp/astronaut-nord.webp"),
            ("gif", "images_sample/gif/XOsX.gif"),
            ("bmp", "images_sample/bmp/planet_minimal.bmp"),
            ("tiff", "images_sample/tiff/planet_minimal.tiff"),
            ("avif", "images_sample/avif/planet_minimal.avif"),
        ]
        
        for fmt, path in test_files:
            file_path = Path(path)
            if file_path.exists() and fmt not in format_images:
                format_images[fmt] = [file_path]
                
        return format_images
        
    async def test_single_format_batch(self, format_name: str, count: int = 5):
        """Test batch conversion with multiple files of same format."""
        print(f"\n{'='*60}")
        print(f"Testing batch with {count} {format_name.upper()} files")
        print(f"{'='*60}")
        
        # Create test files
        files = []
        for i in range(count):
            filename, data = await self.create_test_image(format_name, i)
            files.append(('files', (filename, data, f'image/{format_name}')))
            
        # Create batch job
        data = aiohttp.FormData()
        for field_name, file_info in files:
            data.add_field(field_name, file_info[1], 
                          filename=file_info[0], 
                          content_type=file_info[2])
        data.add_field('output_format', 'webp')
        data.add_field('quality', '85')
        
        async with self.session.post(BATCH_ENDPOINT, data=data) as resp:
            if resp.status != 202:
                error_text = await resp.text()
                print(f"❌ Failed to create batch: {resp.status} - {error_text}")
                return False
                
            result = await resp.json()
            job_id = result['job_id']
            print(f"✅ Batch job created: {job_id}")
            print(f"   Total files: {result['total_files']}")
            
            # Monitor progress
            success = await self.monitor_job_progress(job_id)
            
            if success:
                # Download results
                await self.download_results(job_id)
                
            return success
            
    async def test_mixed_format_batch(self):
        """Test batch conversion with mixed format files."""
        print(f"\n{'='*60}")
        print(f"Testing batch with mixed format files")
        print(f"{'='*60}")
        
        # Find or create test images
        format_images = await self.find_test_images()
        
        files = []
        file_count = 0
        
        # Use existing test images if available
        for fmt, image_paths in format_images.items():
            if fmt in INPUT_FORMATS:
                for path in image_paths[:1]:  # One file per format
                    with open(path, 'rb') as f:
                        data = f.read()
                    files.append(('files', (path.name, data, f'image/{fmt}')))
                    file_count += 1
                    print(f"  Adding {path.name} ({fmt})")
                    
        # Create synthetic images for missing formats
        for fmt in INPUT_FORMATS:
            if fmt not in format_images:
                filename, data = await self.create_test_image(fmt, file_count)
                files.append(('files', (filename, data, f'image/{fmt}')))
                file_count += 1
                print(f"  Creating synthetic {filename} ({fmt})")
                
        print(f"\nTotal files: {file_count}")
        
        # Create batch job with mixed formats
        data = aiohttp.FormData()
        for field_name, file_info in files:
            data.add_field(field_name, file_info[1], 
                          filename=file_info[0], 
                          content_type=file_info[2])
        data.add_field('output_format', 'avif')
        data.add_field('quality', '90')
        data.add_field('optimization_mode', 'balanced')
        
        async with self.session.post(BATCH_ENDPOINT, data=data) as resp:
            if resp.status != 202:
                error_text = await resp.text()
                print(f"❌ Failed to create mixed batch: {resp.status} - {error_text}")
                return False
                
            result = await resp.json()
            job_id = result['job_id']
            print(f"\n✅ Mixed format batch created: {job_id}")
            
            # Monitor with WebSocket if possible
            ws_url = result.get('websocket_url')
            if ws_url:
                await self.monitor_with_websocket(job_id, ws_url)
            else:
                await self.monitor_job_progress(job_id)
                
            # Get results
            await self.get_batch_results(job_id)
            
            return True
            
    async def test_large_batch(self, size: int = 50):
        """Test batch with many files."""
        print(f"\n{'='*60}")
        print(f"Testing large batch with {size} files")
        print(f"{'='*60}")
        
        # Create files with different formats
        files = []
        formats = ["png", "jpeg", "gif", "bmp"]
        
        for i in range(size):
            fmt = formats[i % len(formats)]
            filename, data = await self.create_test_image(fmt, i)
            files.append(('files', (filename, data, f'image/{fmt}')))
            
        print(f"Created {len(files)} test files")
        
        # Create batch job
        data = aiohttp.FormData()
        for field_name, file_info in files:
            data.add_field(field_name, file_info[1], 
                          filename=file_info[0], 
                          content_type=file_info[2])
        data.add_field('output_format', 'webp')
        data.add_field('quality', '80')
        data.add_field('preserve_metadata', 'false')
        
        start_time = time.time()
        
        async with self.session.post(BATCH_ENDPOINT, data=data) as resp:
            if resp.status != 202:
                error_text = await resp.text()
                print(f"❌ Failed to create large batch: {resp.status} - {error_text}")
                return False
                
            result = await resp.json()
            job_id = result['job_id']
            print(f"✅ Large batch created: {job_id}")
            
            # Monitor progress
            success = await self.monitor_job_progress(job_id, check_interval=1)
            
            end_time = time.time()
            duration = end_time - start_time
            
            if success:
                print(f"\n⏱️  Total processing time: {duration:.2f} seconds")
                print(f"   Average per file: {duration/size:.2f} seconds")
                
                # Get metrics
                await self.get_job_metrics(job_id)
                
            return success
            
    async def test_error_handling(self):
        """Test batch error handling with invalid files."""
        print(f"\n{'='*60}")
        print(f"Testing batch error handling")
        print(f"{'='*60}")
        
        # Mix of valid and invalid files
        files = []
        
        # Valid file
        filename, data = await self.create_test_image("png", 0)
        files.append(('files', (filename, data, 'image/png')))
        
        # Invalid file (empty)
        files.append(('files', ('empty.jpg', b'', 'image/jpeg')))
        
        # Invalid file (not an image)
        files.append(('files', ('text.png', b'This is not an image', 'image/png')))
        
        # Valid file
        filename, data = await self.create_test_image("jpeg", 1)
        files.append(('files', (filename, data, 'image/jpeg')))
        
        # Create batch
        data = aiohttp.FormData()
        for field_name, file_info in files:
            data.add_field(field_name, file_info[1], 
                          filename=file_info[0], 
                          content_type=file_info[2])
        data.add_field('output_format', 'webp')
        
        async with self.session.post(BATCH_ENDPOINT, data=data) as resp:
            if resp.status != 202:
                error_text = await resp.text()
                print(f"❌ Batch creation failed as expected: {resp.status}")
                return True  # Expected failure
                
            result = await resp.json()
            job_id = result['job_id']
            print(f"✅ Batch created with mixed valid/invalid files: {job_id}")
            
            # Monitor and check for partial success
            await self.monitor_job_progress(job_id)
            
            # Get detailed results
            results = await self.get_batch_results(job_id)
            
            if results:
                failed = results.get('failed_files', [])
                successful = results.get('successful_files', [])
                
                print(f"\n📊 Results:")
                print(f"   Successful: {len(successful)}")
                print(f"   Failed: {len(failed)}")
                
                for fail in failed:
                    print(f"   ❌ {fail['filename']}: {fail.get('error', 'Unknown error')}")
                    
            return True
            
    async def monitor_job_progress(self, job_id: str, check_interval: float = 0.5) -> bool:
        """Monitor job progress via polling."""
        print(f"\n📊 Monitoring progress...")
        
        max_checks = 120  # Max 60 seconds
        checks = 0
        last_progress = -1
        
        while checks < max_checks:
            async with self.session.get(f"{API_BASE_URL}/api/batch/{job_id}/status") as resp:
                if resp.status != 200:
                    print(f"❌ Failed to get status: {resp.status}")
                    return False
                    
                status = await resp.json()
                
                progress = status.get('progress_percentage', 0)
                if progress != last_progress:
                    print(f"   Progress: {progress}% - "
                          f"Completed: {status.get('completed_files', 0)}/{status.get('total_files', 0)} - "
                          f"Status: {status.get('status', 'unknown')}")
                    last_progress = progress
                    
                if status.get('status') in ['completed', 'failed', 'cancelled']:
                    if status.get('status') == 'completed':
                        print(f"✅ Batch completed successfully!")
                        return True
                    else:
                        print(f"❌ Batch {status.get('status')}")
                        return False
                        
            checks += 1
            await asyncio.sleep(check_interval)
            
        print(f"❌ Timeout waiting for batch completion")
        return False
        
    async def monitor_with_websocket(self, job_id: str, ws_url: str):
        """Monitor job progress via WebSocket."""
        print(f"\n🔌 Connecting to WebSocket for real-time updates...")
        
        try:
            async with self.session.ws_connect(ws_url) as ws:
                print(f"✅ WebSocket connected")
                
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        data = json.loads(msg.data)
                        
                        if data.get('type') == 'progress':
                            progress = data.get('data', {})
                            print(f"   Progress update: File {progress.get('file_index')} - "
                                  f"{progress.get('progress')}% - {progress.get('status')}")
                                  
                        elif data.get('type') == 'job_complete':
                            print(f"✅ Job completed via WebSocket notification")
                            break
                            
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        print(f"❌ WebSocket error: {ws.exception()}")
                        break
                        
        except Exception as e:
            print(f"⚠️  WebSocket connection failed: {e}")
            # Fall back to polling
            await self.monitor_job_progress(job_id)
            
    async def get_batch_results(self, job_id: str) -> Dict[str, Any]:
        """Get detailed batch results."""
        async with self.session.get(f"{API_BASE_URL}/api/batch/{job_id}/results") as resp:
            if resp.status == 200:
                results = await resp.json()
                print(f"\n📋 Batch Results:")
                print(f"   Total files: {results.get('total_files', 0)}")
                print(f"   Successful: {len(results.get('successful_files', []))}")
                print(f"   Failed: {len(results.get('failed_files', []))}")
                print(f"   Processing time: {results.get('processing_time_seconds', 0):.2f}s")
                return results
            else:
                print(f"❌ Failed to get results: {resp.status}")
                return {}
                
    async def get_job_metrics(self, job_id: str):
        """Get performance metrics for the job."""
        async with self.session.get(f"{API_BASE_URL}/api/batch/{job_id}/metrics") as resp:
            if resp.status == 200:
                metrics = await resp.json()
                print(f"\n📈 Performance Metrics:")
                print(f"   Memory peak: {metrics.get('memory_peak_mb', 0):.1f} MB")
                print(f"   Avg memory: {metrics.get('memory_avg_mb', 0):.1f} MB")
                print(f"   Throughput: {metrics.get('throughput_files_per_second', 0):.2f} files/sec")
                print(f"   Concurrent workers: {metrics.get('concurrent_workers', 0)}")
                
    async def download_results(self, job_id: str):
        """Download batch results as ZIP."""
        print(f"\n📥 Downloading results...")
        
        async with self.session.get(f"{API_BASE_URL}/api/batch/{job_id}/download") as resp:
            if resp.status == 200:
                content = await resp.read()
                
                # Save ZIP file
                output_path = f"batch_{job_id[:8]}_results.zip"
                with open(output_path, 'wb') as f:
                    f.write(content)
                    
                print(f"✅ Results saved to: {output_path}")
                
                # Verify ZIP contents
                with zipfile.ZipFile(output_path, 'r') as zf:
                    files = zf.namelist()
                    print(f"   ZIP contains {len(files)} files")
                    
                # Clean up
                os.remove(output_path)
            else:
                print(f"❌ Failed to download results: {resp.status}")
                
    async def test_cancellation(self):
        """Test batch job cancellation."""
        print(f"\n{'='*60}")
        print(f"Testing batch cancellation")
        print(f"{'='*60}")
        
        # Create a large batch
        files = []
        for i in range(20):
            filename, data = await self.create_test_image("png", i)
            files.append(('files', (filename, data, 'image/png')))
            
        data = aiohttp.FormData()
        for field_name, file_info in files:
            data.add_field(field_name, file_info[1], 
                          filename=file_info[0], 
                          content_type=file_info[2])
        data.add_field('output_format', 'avif')  # Slow conversion
        
        async with self.session.post(BATCH_ENDPOINT, data=data) as resp:
            if resp.status != 202:
                print(f"❌ Failed to create batch for cancellation test")
                return False
                
            result = await resp.json()
            job_id = result['job_id']
            print(f"✅ Batch created: {job_id}")
            
            # Wait a bit then cancel
            await asyncio.sleep(1)
            
            print(f"🛑 Cancelling batch job...")
            async with self.session.delete(f"{API_BASE_URL}/api/batch/{job_id}") as resp:
                if resp.status == 200:
                    print(f"✅ Batch cancelled successfully")
                    
                    # Verify status
                    async with self.session.get(f"{API_BASE_URL}/api/batch/{job_id}/status") as status_resp:
                        if status_resp.status == 200:
                            status = await status_resp.json()
                            print(f"   Final status: {status.get('status')}")
                            
                    return True
                else:
                    print(f"❌ Failed to cancel batch: {resp.status}")
                    return False
                    
    async def run_all_tests(self):
        """Run all batch processing tests."""
        print(f"\n{'='*60}")
        print(f"BATCH PROCESSING COMPREHENSIVE TEST SUITE")
        print(f"{'='*60}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        test_results = []
        
        # Test 1: Single format batches
        for fmt in ["png", "jpeg", "gif", "bmp"]:
            try:
                result = await self.test_single_format_batch(fmt, count=3)
                test_results.append((f"Single format ({fmt})", result))
            except Exception as e:
                print(f"❌ Test failed with error: {e}")
                test_results.append((f"Single format ({fmt})", False))
                
        # Test 2: Mixed format batch
        try:
            result = await self.test_mixed_format_batch()
            test_results.append(("Mixed formats", result))
        except Exception as e:
            print(f"❌ Test failed with error: {e}")
            test_results.append(("Mixed formats", False))
            
        # Test 3: Large batch
        try:
            result = await self.test_large_batch(size=25)
            test_results.append(("Large batch (25 files)", result))
        except Exception as e:
            print(f"❌ Test failed with error: {e}")
            test_results.append(("Large batch", False))
            
        # Test 4: Error handling
        try:
            result = await self.test_error_handling()
            test_results.append(("Error handling", result))
        except Exception as e:
            print(f"❌ Test failed with error: {e}")
            test_results.append(("Error handling", False))
            
        # Test 5: Cancellation
        try:
            result = await self.test_cancellation()
            test_results.append(("Cancellation", result))
        except Exception as e:
            print(f"❌ Test failed with error: {e}")
            test_results.append(("Cancellation", False))
            
        # Summary
        print(f"\n{'='*60}")
        print(f"TEST SUMMARY")
        print(f"{'='*60}")
        
        passed = sum(1 for _, result in test_results if result)
        total = len(test_results)
        
        for test_name, result in test_results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{status} - {test_name}")
            
        print(f"\nTotal: {passed}/{total} tests passed")
        print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return passed == total


async def main():
    """Main test execution."""
    # Check if API is running
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{API_BASE_URL}/api/health") as resp:
                if resp.status != 200:
                    print("❌ API is not running. Please start the backend server.")
                    return 1
    except Exception as e:
        print(f"❌ Cannot connect to API: {e}")
        print("Please ensure the backend server is running on port 8080")
        return 1
        
    # Run tests
    runner = BatchTestRunner()
    await runner.setup()
    
    try:
        success = await runner.run_all_tests()
        return 0 if success else 1
    finally:
        await runner.cleanup()
        

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)