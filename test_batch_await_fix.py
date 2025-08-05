#!/usr/bin/env python3
"""Test batch processing after fixing await issues."""

import asyncio
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app.services.batch_service import batch_service
from app.core.batch.models import BatchJob, BatchItem, BatchItemStatus, BatchStatus
from fastapi import UploadFile
from io import BytesIO

async def test_batch_processing():
    """Test batch processing to verify await fixes."""
    print("Testing Batch Processing After Await Fixes")
    print("=" * 50)
    
    # Create mock files
    files = []
    for i in range(3):
        content = f"fake_image_data_{i}".encode()
        file = UploadFile(
            filename=f"test_{i}.jpg",
            file=BytesIO(content)
        )
        files.append(file)
    
    # Test 1: Create batch job
    print("\nTest 1: Creating batch job...")
    try:
        job = await batch_service.create_batch_job(
            files=files,
            output_format="webp",
            settings={"quality": 85},
            user_ip="127.0.0.1"
        )
        print(f"✓ Job created successfully: {job.job_id}")
        print(f"  Total files: {job.total_files}")
        print(f"  Status: {job.status}")
    except Exception as e:
        print(f"✗ Error creating job: {e}")
        return
    
    # Test 2: Get job status (testing non-async get_job)
    print("\nTest 2: Getting job status...")
    try:
        # This should work without await now
        retrieved_job = batch_service.get_job(job.job_id)
        if retrieved_job:
            print(f"✓ Job retrieved successfully")
            print(f"  Status: {retrieved_job.status}")
            print(f"  Pending: {retrieved_job.pending_files}")
        else:
            print("✗ Job not found")
    except Exception as e:
        print(f"✗ Error getting job: {e}")
    
    # Test 3: Wait a bit and check progress
    print("\nTest 3: Checking progress after 1 second...")
    await asyncio.sleep(1)
    
    try:
        job_status = batch_service.get_job(job.job_id)
        if job_status:
            print(f"✓ Progress check successful")
            print(f"  Status: {job_status.status}")
            print(f"  Completed: {job_status.completed_files}")
            print(f"  Failed: {job_status.failed_files}")
            print(f"  Progress: {job_status.progress_percentage}%")
        else:
            print("✗ Job not found")
    except Exception as e:
        print(f"✗ Error checking progress: {e}")
    
    # Test 4: Cancel job
    print("\nTest 4: Cancelling job...")
    try:
        await batch_service.cancel_job(job.job_id)
        print("✓ Job cancelled successfully")
        
        # Verify cancellation
        cancelled_job = batch_service.get_job(job.job_id)
        if cancelled_job:
            print(f"  Final status: {cancelled_job.status}")
    except Exception as e:
        print(f"✗ Error cancelling job: {e}")
    
    print("\n" + "=" * 50)
    print("Batch processing test completed")
    print("Check server logs for any 'await expression' errors")

if __name__ == "__main__":
    asyncio.run(test_batch_processing())