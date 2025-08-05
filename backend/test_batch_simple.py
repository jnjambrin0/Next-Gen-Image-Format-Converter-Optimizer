#!/usr/bin/env python3
"""Simple test to verify batch processing is working."""

import requests
import time
from PIL import Image
import io

API_BASE = "http://localhost:8080"

def test_simple_batch():
    """Test basic batch functionality."""
    print("Testing simple batch processing...")
    
    # Create 2 test images
    files = []
    for i in range(2):
        img = Image.new('RGB', (100, 100), color=['red', 'blue'][i])
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_data = img_buffer.getvalue()
        files.append(('files', (f'test_{i}.png', img_data, 'image/png')))
    
    # Create batch
    data = {
        'output_format': 'webp',
        'quality': '85'
    }
    
    response = requests.post(f"{API_BASE}/api/batch/", files=files, data=data)
    print(f"Create batch response: {response.status_code}")
    
    if response.status_code != 202:
        print(f"Error: {response.text}")
        return False
        
    result = response.json()
    job_id = result['job_id']
    print(f"Job ID: {job_id}")
    print(f"Status URL: {result['status_url']}")
    
    # Check status
    time.sleep(1)
    status_response = requests.get(f"{API_BASE}/api/batch/{job_id}/status")
    print(f"\nStatus response: {status_response.status_code}")
    
    if status_response.status_code == 200:
        status = status_response.json()
        print(f"Job status: {status['status']}")
        print(f"Progress: {status.get('progress_percentage', 0)}%")
        print(f"Completed: {status.get('completed_files', 0)}/{status.get('total_files', 0)}")
        
        # Wait for completion
        max_wait = 10
        while max_wait > 0 and status['status'] not in ['completed', 'failed']:
            time.sleep(1)
            status_response = requests.get(f"{API_BASE}/api/batch/{job_id}/status")
            if status_response.status_code == 200:
                status = status_response.json()
                print(f"Status: {status['status']} - Progress: {status.get('progress_percentage', 0)}%")
            max_wait -= 1
            
        if status['status'] == 'completed':
            print("\n✅ Batch completed successfully!")
            
            # Get results
            results_response = requests.get(f"{API_BASE}/api/batch/{job_id}/results")
            if results_response.status_code == 200:
                results = results_response.json()
                print(f"\nResults:")
                print(f"  Successful: {len(results.get('successful_files', []))}")
                print(f"  Failed: {len(results.get('failed_files', []))}")
                print(f"  Processing time: {results.get('processing_time_seconds', 0):.2f}s")
            
            return True
        else:
            print(f"\n❌ Batch failed with status: {status['status']}")
            return False
    else:
        print(f"Error getting status: {status_response.text}")
        return False

if __name__ == "__main__":
    # First check health
    try:
        health = requests.get(f"{API_BASE}/api/health")
        if health.status_code != 200:
            print("❌ API is not healthy")
            exit(1)
    except:
        print("❌ Cannot connect to API")
        exit(1)
        
    success = test_simple_batch()
    exit(0 if success else 1)