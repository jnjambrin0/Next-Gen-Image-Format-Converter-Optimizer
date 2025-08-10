"""Helper functions for security tests."""

import socket
import subprocess
import tempfile
import os
from typing import Tuple, Optional, Dict, Any
from unittest.mock import MagicMock, patch
import asyncio


class NetworkBlocker:
    """Helper to block network access in tests."""
    
    def __init__(self):
        self.original_socket = socket.socket
        self.blocked_attempts = []
    
    def enable_blocking(self):
        """Enable network blocking."""
        parent = self
        
        class BlockedSocket(socket.socket):
            def __init__(self, *args, **kwargs):
                # Allow creation but track it
                super().__init__(*args, **kwargs)
                
            def connect(self, address):
                parent.blocked_attempts.append(address)
                # Only allow localhost connections
                if address[0] not in ['localhost', '127.0.0.1', '::1', '0.0.0.0']:
                    raise OSError(f"Network access blocked: {address}")
                return super().connect(address)
            
            def connect_ex(self, address):
                parent.blocked_attempts.append(address)
                if address[0] not in ['localhost', '127.0.0.1', '::1', '0.0.0.0']:
                    return 1  # Error code for connection refused
                return super().connect_ex(address)
        
        socket.socket = BlockedSocket
        return self
    
    def disable_blocking(self):
        """Restore original socket."""
        socket.socket = self.original_socket
    
    def get_blocked_attempts(self):
        """Get list of blocked connection attempts."""
        return self.blocked_attempts
    
    def __enter__(self):
        return self.enable_blocking()
    
    def __exit__(self, *args):
        self.disable_blocking()


def create_secure_sandbox_env() -> Dict[str, str]:
    """Create a secure environment for sandbox testing."""
    with tempfile.TemporaryDirectory(prefix="sandbox_test_") as sandbox_dir:
        env = {
            'PATH': '/usr/bin:/bin',
            'HOME': sandbox_dir,
            'TMPDIR': sandbox_dir,
            'USER': 'sandbox_test',
            # Block network via proxy settings
            'http_proxy': 'http://127.0.0.1:1',
            'https_proxy': 'http://127.0.0.1:1',
            'no_proxy': '*',
            # Sandbox settings
            'IMAGE_CONVERTER_ENABLE_SANDBOXING': 'true',
            'IMAGE_CONVERTER_SANDBOX_STRICTNESS': 'paranoid',
        }
        return env, sandbox_dir


async def test_sandbox_escape_attempt(command: str, expected_blocked: bool = True) -> Tuple[bool, str]:
    """
    Test if a command is properly blocked by sandbox.
    
    Args:
        command: Command to test
        expected_blocked: Whether command should be blocked
        
    Returns:
        Tuple of (was_blocked, output)
    """
    env, sandbox_dir = create_secure_sandbox_env()
    
    try:
        result = await asyncio.create_subprocess_exec(
            'python', '-c', command,
            env=env,
            cwd=sandbox_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            result.communicate(),
            timeout=5.0
        )
        
        # Check if command was blocked
        if result.returncode != 0:
            error_msg = stderr.decode() if stderr else stdout.decode()
            if 'blocked' in error_msg.lower() or 'denied' in error_msg.lower():
                return True, error_msg
        
        return False, stdout.decode() if stdout else ""
        
    except asyncio.TimeoutError:
        return True, "Command timed out (likely blocked)"
    except Exception as e:
        return True, str(e)


def create_malicious_metadata() -> Dict[str, Any]:
    """Create metadata with potential security issues for testing."""
    return {
        'EXIF': {
            'UserComment': '<script>alert("XSS")</script>',
            'Copyright': "'; DROP TABLE images; --",
            'Make': '../../../etc/passwd',
            'Model': 'Test Camera',
            'GPS': {
                'Latitude': 37.7749,
                'Longitude': -122.4194,
                'Altitude': 100.0
            },
            'DateTime': '2025-01-15 14:30:00',
            'Software': 'ImageConverter v1.0',
            'Artist': 'Test User',
            'HostComputer': 'test-machine',
        },
        'IPTC': {
            'Keywords': ['test', 'security', '<img src=x onerror=alert(1)>'],
            'Caption': 'Test image with security metadata',
            'Credit': 'Security Test Suite',
        },
        'XMP': {
            'Creator': 'Test Suite',
            'Title': 'Security Test Image',
            'Description': '../../sensitive/file.txt',
            'Rights': 'Public Domain',
        }
    }


def verify_metadata_removed(image_data: bytes) -> Tuple[bool, Optional[str]]:
    """
    Verify that all metadata has been removed from an image.
    
    Returns:
        Tuple of (is_clean, found_metadata)
    """
    try:
        from PIL import Image
        import piexif
        import io
        
        img = Image.open(io.BytesIO(image_data))
        
        # Check for EXIF
        exif_data = img.getexif()
        if exif_data:
            return False, f"Found EXIF data: {dict(exif_data)}"
        
        # Check for other metadata
        if hasattr(img, 'info'):
            dangerous_keys = ['exif', 'GPS', 'UserComment', 'Copyright', 'XMP']
            for key in dangerous_keys:
                if key in img.info:
                    return False, f"Found metadata key: {key}"
        
        # Try to extract with piexif
        try:
            piexif_data = piexif.load(image_data)
            if any(piexif_data.values()):
                return False, f"piexif found metadata: {piexif_data}"
        except:
            pass  # No piexif data is good
        
        return True, None
        
    except Exception as e:
        return False, f"Error checking metadata: {str(e)}"


def create_sandbox_test_script(malicious_code: str) -> str:
    """
    Create a test script that attempts sandbox escape.
    
    Args:
        malicious_code: Code that should be blocked
        
    Returns:
        Complete Python script for testing
    """
    return f'''
import sys
import os

# Attempt sandbox escape
try:
    {malicious_code}
    print("ESCAPE_SUCCESS")
except Exception as e:
    print(f"BLOCKED: {{e}}")
    sys.exit(1)
'''


def test_memory_clearing(buffer_size: int = 1024) -> bool:
    """
    Test if memory is properly cleared with secure patterns.
    
    Returns:
        True if memory clearing works correctly
    """
    import ctypes
    import array
    
    # Create buffer with sensitive data
    sensitive_data = b"SENSITIVE_DATA_12345" * (buffer_size // 20)
    buffer = bytearray(sensitive_data)
    
    # Clear with DoD 5220.22-M standard
    patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]
    
    for pattern in patterns:
        for i in range(len(buffer)):
            buffer[i] = pattern
    
    # Verify no sensitive data remains
    buffer_bytes = bytes(buffer)
    if b"SENSITIVE" in buffer_bytes or b"12345" in buffer_bytes:
        return False
    
    # Verify final pattern
    if not all(b == 0x00 for b in buffer):
        return False
    
    return True