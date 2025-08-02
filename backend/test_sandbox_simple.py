#!/usr/bin/env python3
"""Simple test to verify sandbox functionality."""

import asyncio
from app.core.security.sandbox import SecuritySandbox, SandboxConfig

async def test_sandbox():
    """Test basic sandbox functionality."""
    try:
        # Create sandbox
        config = SandboxConfig(
            max_memory_mb=256,
            timeout_seconds=10
        )
        sandbox = SecuritySandbox(config)
        
        # Test a simple command
        print("Testing sandbox with 'echo' command...")
        result = await sandbox.run_subprocess(
            ["echo", "Hello from sandbox"],
            capture_output=True
        )
        
        stdout_data = result['stdout'].decode('utf-8').strip()
        print(f"Output: {stdout_data}")
        print(f"Return code: {result['returncode']}")
        
        if stdout_data == "Hello from sandbox" and result['returncode'] == 0:
            print("✅ Sandbox test PASSED!")
            return True
        else:
            print("❌ Sandbox test FAILED!")
            return False
            
    except Exception as e:
        print(f"❌ Sandbox test FAILED with error: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_sandbox())
    exit(0 if success else 1)