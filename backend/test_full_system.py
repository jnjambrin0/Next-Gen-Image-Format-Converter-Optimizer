#!/usr/bin/env python3
"""
Comprehensive system test for the Image Converter API.
Tests all major features and edge cases.
"""

import asyncio
import base64
import io
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import httpx
from PIL import Image
import numpy as np

# Configuration
API_BASE_URL = "http://localhost:8080"
TIMEOUT = 30.0

class ImageConverterTestSuite:
    """Comprehensive test suite for Image Converter API."""
    
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=TIMEOUT, base_url=API_BASE_URL)
        self.results = []
        self.test_images = {}
        
    async def setup(self):
        """Set up test environment."""
        print("🔧 Setting up test environment...")
        
        # Create test images
        await self._create_test_images()
        
        # Verify server is running
        try:
            response = await self.client.get("/api/health")
            if response.status_code == 200:
                health_data = response.json()
                print(f"✅ Server is healthy - Network isolated: {health_data.get('network_isolated', 'unknown')}")
            else:
                print(f"❌ Server health check failed with status: {response.status_code}")
                sys.exit(1)
        except Exception as e:
            print(f"❌ Server health check failed: {e}")
            print("   Make sure the server is running on http://localhost:8080")
            sys.exit(1)
            
    async def _create_test_images(self):
        """Create various test images."""
        print("📸 Creating test images...")
        
        # 1. Simple RGB image
        img = Image.new('RGB', (800, 600), color='red')
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        self.test_images['simple_rgb'] = buffer.getvalue()
        
        # 2. Image with transparency
        img = Image.new('RGBA', (400, 400))
        pixels = img.load()
        for y in range(400):
            for x in range(400):
                # Gradient transparency
                alpha = int((x + y) * 255 / 800)
                pixels[x, y] = (255, 0, 0, alpha)
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        self.test_images['with_alpha'] = buffer.getvalue()
        
        # 3. Large image
        img = Image.new('RGB', (2000, 2000))
        pixels = img.load()
        for y in range(2000):
            for x in range(2000):
                pixels[x, y] = ((x * 255) // 2000, (y * 255) // 2000, 128)
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=90)
        self.test_images['large'] = buffer.getvalue()
        
        # 4. Small image
        img = Image.new('RGB', (50, 50), color='blue')
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        self.test_images['small'] = buffer.getvalue()
        
        # 5. Complex pattern (for compression testing)
        img = Image.new('RGB', (1000, 1000))
        arr = np.zeros((1000, 1000, 3), dtype=np.uint8)
        # Create noise pattern
        arr[:, :, 0] = np.random.randint(0, 256, (1000, 1000))
        arr[:, :, 1] = np.random.randint(0, 256, (1000, 1000))
        arr[:, :, 2] = np.random.randint(0, 256, (1000, 1000))
        img = Image.fromarray(arr)
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        self.test_images['complex'] = buffer.getvalue()
        
        print(f"✅ Created {len(self.test_images)} test images")
        
    async def test_basic_conversion(self):
        """Test basic format conversions."""
        print("\n🧪 Testing basic conversions...")
        
        test_cases = [
            ('simple_rgb', 'png', 'webp', 85),
            ('simple_rgb', 'png', 'jpeg', 90),
            ('with_alpha', 'png', 'webp', 80),
            ('large', 'jpeg', 'webp', 75),
            ('small', 'png', 'jpeg', 95),
        ]
        
        for img_name, input_format, output_format, quality in test_cases:
            try:
                result = await self._convert_image(
                    self.test_images[img_name],
                    f"test_{img_name}.{input_format}",
                    output_format,
                    quality
                )
                
                if result['success']:
                    print(f"  ✅ {img_name}: {input_format} → {output_format} "
                          f"(compression: {result['compression_ratio']:.1%})")
                else:
                    print(f"  ❌ {img_name}: {input_format} → {output_format} failed: {result['error']}")
                    
                self.results.append(result)
                
            except Exception as e:
                print(f"  ❌ {img_name}: Unexpected error: {e}")
                self.results.append({
                    'test': f'{img_name}_{input_format}_to_{output_format}',
                    'success': False,
                    'error': str(e)
                })
                
    async def test_quality_settings(self):
        """Test different quality settings."""
        print("\n🎨 Testing quality settings...")
        
        qualities = [10, 50, 85, 100]
        
        for quality in qualities:
            try:
                result = await self._convert_image(
                    self.test_images['simple_rgb'],
                    'quality_test.png',
                    'jpeg',
                    quality
                )
                
                if result['success']:
                    print(f"  ✅ Quality {quality}: Size = {result['output_size']} bytes")
                else:
                    print(f"  ❌ Quality {quality} failed: {result['error']}")
                    
            except Exception as e:
                print(f"  ❌ Quality {quality}: Unexpected error: {e}")
                
    async def test_advanced_options(self):
        """Test advanced conversion options."""
        print("\n🔧 Testing advanced options...")
        
        # Test progressive JPEG
        try:
            result = await self._convert_image(
                self.test_images['large'],
                'progressive_test.png',
                'jpeg',
                85,
                {'progressive': True}
            )
            print(f"  {'✅' if result['success'] else '❌'} Progressive JPEG")
        except Exception as e:
            print(f"  ❌ Progressive JPEG: {e}")
            
        # Test WebP lossless
        try:
            result = await self._convert_image(
                self.test_images['simple_rgb'],
                'lossless_test.png',
                'webp',
                100,
                {'lossless': True}
            )
            print(f"  {'✅' if result['success'] else '❌'} WebP lossless")
        except Exception as e:
            print(f"  ❌ WebP lossless: {e}")
            
    async def test_error_handling(self):
        """Test error handling."""
        print("\n🚨 Testing error handling...")
        
        # Test invalid format
        try:
            result = await self._convert_image(
                self.test_images['simple_rgb'],
                'test.png',
                'invalid_format',
                85
            )
            print(f"  {'✅' if not result['success'] else '❌'} Invalid format rejection")
        except Exception:
            print("  ✅ Invalid format rejection")
            
        # Test corrupted image
        try:
            result = await self._convert_image(
                b'corrupted data',
                'corrupted.jpg',
                'webp',
                85
            )
            print(f"  {'✅' if not result['success'] else '❌'} Corrupted image rejection")
        except Exception:
            print("  ✅ Corrupted image rejection")
            
    async def test_format_detection(self):
        """Test format detection with misnamed files."""
        print("\n🔍 Testing format detection...")
        
        # PNG data with .jpg extension
        try:
            result = await self._convert_image(
                self.test_images['simple_rgb'],
                'misnamed.jpg',  # Actually PNG data
                'webp',
                85
            )
            print(f"  {'✅' if result['success'] else '❌'} Misnamed file detection")
        except Exception as e:
            print(f"  ❌ Misnamed file detection: {e}")
            
    async def test_performance(self):
        """Test conversion performance."""
        print("\n⏱️  Testing performance...")
        
        # Single large image
        start = time.time()
        try:
            result = await self._convert_image(
                self.test_images['large'],
                'perf_test.jpg',
                'webp',
                85
            )
            elapsed = time.time() - start
            print(f"  ✅ Large image conversion: {elapsed:.2f}s")
        except Exception as e:
            print(f"  ❌ Large image conversion: {e}")
            
        # Multiple concurrent conversions
        start = time.time()
        tasks = []
        for i in range(5):
            task = self._convert_image(
                self.test_images['simple_rgb'],
                f'concurrent_{i}.png',
                'jpeg',
                85
            )
            tasks.append(task)
            
        try:
            results = await asyncio.gather(*tasks)
            elapsed = time.time() - start
            success_count = sum(1 for r in results if r['success'])
            print(f"  ✅ Concurrent conversions: {success_count}/5 succeeded in {elapsed:.2f}s")
        except Exception as e:
            print(f"  ❌ Concurrent conversions: {e}")
            
    async def _convert_image(
        self,
        image_data: bytes,
        filename: str,
        output_format: str,
        quality: int,
        advanced_options: Dict = None
    ) -> Dict:
        """Helper to convert an image via API."""
        
        # Prepare form data
        files = {
            'file': (filename, image_data, 'image/jpeg')
        }
        
        data = {
            'output_format': output_format,
            'quality': quality
        }
        
        if advanced_options:
            data.update(advanced_options)
            
        try:
            response = await self.client.post(
                "/api/convert",
                files=files,
                data=data
            )
            
            if response.status_code == 200:
                # Get output size
                output_size = len(response.content)
                input_size = len(image_data)
                
                return {
                    'test': f'{filename}_to_{output_format}',
                    'success': True,
                    'status_code': response.status_code,
                    'input_size': input_size,
                    'output_size': output_size,
                    'compression_ratio': 1 - (output_size / input_size),
                    'headers': dict(response.headers)
                }
            else:
                return {
                    'test': f'{filename}_to_{output_format}',
                    'success': False,
                    'status_code': response.status_code,
                    'error': response.text
                }
                
        except Exception as e:
            return {
                'test': f'{filename}_to_{output_format}',
                'success': False,
                'error': str(e)
            }
            
    async def cleanup(self):
        """Clean up resources."""
        await self.client.aclose()
        
    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*60)
        print("📊 TEST SUMMARY")
        print("="*60)
        
        total_tests = len(self.results)
        successful = sum(1 for r in self.results if r.get('success', False))
        failed = total_tests - successful
        
        print(f"Total tests: {total_tests}")
        print(f"✅ Passed: {successful}")
        print(f"❌ Failed: {failed}")
        if total_tests > 0:
            print(f"Success rate: {(successful/total_tests*100):.1f}%")
        else:
            print("No tests were executed")
        
        if failed > 0:
            print("\n❌ Failed tests:")
            for result in self.results:
                if not result.get('success', False):
                    print(f"  - {result['test']}: {result.get('error', 'Unknown error')}")
                    
        print("="*60)
        
async def main():
    """Run the test suite."""
    print("🚀 Image Converter API - Comprehensive Test Suite")
    print("="*60)
    
    suite = ImageConverterTestSuite()
    
    try:
        await suite.setup()
        await suite.test_basic_conversion()
        await suite.test_quality_settings()
        await suite.test_advanced_options()
        await suite.test_error_handling()
        await suite.test_format_detection()
        await suite.test_performance()
        
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
    finally:
        await suite.cleanup()
        suite.print_summary()
        
if __name__ == "__main__":
    asyncio.run(main())