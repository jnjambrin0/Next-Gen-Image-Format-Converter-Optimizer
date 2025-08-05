#!/usr/bin/env python3
"""Test that await syntax errors are fixed."""

import ast
import os

def check_await_usage(filepath, function_name, line_num):
    """Check if a specific line has incorrect await usage."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Simple check: look for the pattern "await batch_service.get_job"
    lines = content.split('\n')
    if line_num <= len(lines):
        line = lines[line_num - 1]
        if "await batch_service.get_job" in line:
            return False, f"Line {line_num} still has 'await batch_service.get_job'"
        elif "await self.batch_manager.get_job" in line:
            return False, f"Line {line_num} still has 'await self.batch_manager.get_job'"
    
    return True, "OK"

def main():
    print("Checking for incorrect await usage...")
    print("=" * 50)
    
    files_to_check = [
        ("backend/app/api/routes/batch.py", [
            (203, "get_batch_status"),
            (243, "cancel_batch_job"),
            (281, "cancel_batch_item"),
            (333, "download_batch_results"),
            (386, "get_batch_results"),
            (469, "create_websocket_token")
        ]),
        ("backend/app/api/websockets/secure_progress.py", [
            (138, "connect"),
            (362, "create_websocket_token")
        ]),
        ("backend/app/services/batch_service.py", [
            (110, "progress_callback"),
            (153, "get_results"),
            (204, "get_download_zip")
        ])
    ]
    
    all_good = True
    
    for filepath, checks in files_to_check:
        print(f"\nChecking {filepath}:")
        full_path = os.path.join("/Users/jnjambrino/Projects/image_converter", filepath)
        
        if not os.path.exists(full_path):
            print(f"  ✗ File not found")
            all_good = False
            continue
        
        for line_num, func_name in checks:
            ok, msg = check_await_usage(full_path, func_name, line_num)
            if ok:
                print(f"  ✓ Line {line_num} ({func_name}): {msg}")
            else:
                print(f"  ✗ Line {line_num} ({func_name}): {msg}")
                all_good = False
    
    print("\n" + "=" * 50)
    if all_good:
        print("✓ All await issues have been fixed!")
    else:
        print("✗ Some await issues remain")
    
    # Also check that get_job is no longer async
    print("\nChecking batch_service.get_job method...")
    batch_service_path = "/Users/jnjambrino/Projects/image_converter/backend/app/services/batch_service.py"
    with open(batch_service_path, 'r') as f:
        content = f.read()
    
    if "async def get_job(self, job_id: str)" in content:
        print("✗ get_job is still async")
    elif "def get_job(self, job_id: str)" in content:
        print("✓ get_job is correctly non-async")
    else:
        print("? Could not find get_job method")

if __name__ == "__main__":
    main()