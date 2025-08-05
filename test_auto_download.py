#!/usr/bin/env python3
"""
Test script to verify automatic download functionality for batch processing.
This tests the simplified flow without modals.
"""

import asyncio
import aiohttp
import json
import time
from pathlib import Path

# Configuration
API_BASE_URL = "http://localhost:8080/api"
WS_BASE_URL = "ws://localhost:8080/ws"

# Test images directory
IMAGES_DIR = Path("backend/images_sample")

async def test_batch_auto_download():
    """Test the complete batch processing flow with auto-download."""
    print("Starting batch auto-download test...")
    
    async with aiohttp.ClientSession() as session:
        # 1. Get test images
        test_files = []
        # Check the correct folder names (jpg not jpeg)
        for ext, folder_name in [('jpg', 'jpg'), ('png', 'png'), ('webp', 'webp')]:
            folder = IMAGES_DIR / folder_name
            if folder.exists():
                files = list(folder.glob(f'*.{ext}'))[:2]  # Get 2 files per format
                test_files.extend(files)
        
        if not test_files:
            print("❌ No test images found!")
            return False
        
        print(f"✓ Found {len(test_files)} test images")
        
        # 2. Create batch job
        print("\n2. Creating batch job...")
        form_data = aiohttp.FormData()
        
        # Add files
        for file_path in test_files:
            with open(file_path, 'rb') as f:
                form_data.add_field('files', f.read(), 
                                  filename=file_path.name,
                                  content_type='image/*')
        
        # Add conversion settings
        form_data.add_field('output_format', 'webp')
        form_data.add_field('quality', '85')
        form_data.add_field('preserve_metadata', 'false')
        
        async with session.post(f"{API_BASE_URL}/batch/", data=form_data) as resp:
            if resp.status != 202:
                error_text = await resp.text()
                print(f"❌ Failed to create batch job: {resp.status} - {error_text}")
                return False
                
            result = await resp.json()
            job_id = result['job_id']
            print(f"✓ Batch job created: {job_id}")
            print(f"  Total files: {result['total_files']}")
            print(f"  WebSocket URL: {result['websocket_url']}")
        
        # 3. Connect to WebSocket for progress
        print("\n3. Connecting to WebSocket for progress updates...")
        # Fix WebSocket URL if it starts with ws://
        ws_url = result['websocket_url']
        if ws_url.startswith('ws://'):
            # Extract the path part after the host
            import re
            match = re.search(r'ws://[^/]+(/.*)', ws_url)
            if match:
                ws_url = WS_BASE_URL + match.group(1)
        
        try:
            async with session.ws_connect(ws_url) as ws:
                print("✓ WebSocket connected")
                
                # Track completion
                job_completed = False
                download_ready = False
                
                # Listen for messages
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        data = json.loads(msg.data)
                        
                        if data.get('type') == 'progress':
                            print(f"  Progress: File {data.get('file_index', '?')} - "
                                  f"{data.get('status', '?')} ({data.get('progress', 0)}%)")
                        
                        elif data.get('type') == 'job_status':
                            status = data.get('status', '')
                            print(f"  Job status: {status}")
                            
                            if status == 'completed':
                                job_completed = True
                                print("✓ Job completed successfully!")
                                break
                            elif status == 'failed':
                                print("❌ Job failed!")
                                return False
                    
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        print(f"❌ WebSocket error: {ws.exception()}")
                        break
                
        except Exception as e:
            print(f"⚠️  WebSocket connection error: {e}")
            print("   Falling back to polling...")
            
            # Poll for status
            for _ in range(30):  # Max 30 seconds
                await asyncio.sleep(1)
                async with session.get(f"{API_BASE_URL}/batch/{job_id}/status") as resp:
                    if resp.status == 200:
                        status_data = await resp.json()
                        if status_data['status'] == 'completed':
                            job_completed = True
                            print("✓ Job completed (via polling)")
                            break
        
        if not job_completed:
            print("❌ Job did not complete in time")
            return False
        
        # 4. Test automatic download endpoint
        print("\n4. Testing download endpoint...")
        async with session.get(f"{API_BASE_URL}/batch/{job_id}/download") as resp:
            if resp.status != 200:
                error_text = await resp.text()
                print(f"❌ Download failed: {resp.status} - {error_text}")
                return False
            
            # Check response headers
            content_type = resp.headers.get('Content-Type', '')
            content_disposition = resp.headers.get('Content-Disposition', '')
            
            print(f"✓ Download successful!")
            print(f"  Content-Type: {content_type}")
            print(f"  Content-Disposition: {content_disposition}")
            
            # Read ZIP content
            zip_content = await resp.read()
            print(f"  ZIP size: {len(zip_content):,} bytes")
            
            # Verify it's a valid ZIP
            if len(zip_content) > 4 and zip_content[:2] == b'PK':
                print("✓ Valid ZIP file signature detected")
            else:
                print("❌ Invalid ZIP file")
                return False
        
        # 5. Test results endpoint (should also work)
        print("\n5. Testing results endpoint...")
        async with session.get(f"{API_BASE_URL}/batch/{job_id}/results") as resp:
            if resp.status == 200:
                results = await resp.json()
                print(f"✓ Results retrieved:")
                print(f"  Total files: {results['total_files']}")
                print(f"  Successful: {len(results.get('successful_files', []))}")
                print(f"  Failed: {len(results.get('failed_files', []))}")
            else:
                print(f"⚠️  Results endpoint returned {resp.status}")
        
        print("\n✅ All tests passed! Auto-download functionality is working correctly.")
        return True

async def main():
    """Run the test."""
    try:
        success = await test_batch_auto_download()
        exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    asyncio.run(main())