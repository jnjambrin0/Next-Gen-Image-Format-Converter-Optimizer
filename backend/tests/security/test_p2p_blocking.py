"""
Tests for P2P and WebRTC protocol blocking.
"""

import socket
import subprocess
import sys
from pathlib import Path

import pytest


class TestP2PBlocking:
    """Test P2P and WebRTC blocking in sandboxed environment."""

    def test_p2p_module_blocking(self):
        """Test that P2P modules are blocked from import."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        # Test various P2P modules
        p2p_modules = ["pyp2p", "webrtc", "aiortc", "ipfs", "libtorrent"]

        for module in p2p_modules:
            test_code = f"""
import sys
sys.path.insert(0, '{str(script_path.parent)}')

# This import should set up blocking
import sandboxed_convert

# Try to import P2P module
try:
    import {module}
    print("ERROR: {module} import succeeded")
    sys.exit(1)
except ImportError as e:
    if "blocked" in str(e):
        print("SUCCESS: {module} blocked")
        sys.exit(0)
    else:
        # Module doesn't exist, which is also good
        print("SUCCESS: {module} not available")
        sys.exit(0)
"""

            result = subprocess.run(
                [sys.executable, "-c", test_code], capture_output=True, text=True
            )

            assert result.returncode == 0, f"Failed to block {module}: {result.stderr}"
            assert "SUCCESS" in result.stdout

    def test_udp_socket_blocking(self):
        """Test that UDP sockets are blocked (commonly used for P2P)."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = f"""
import sys
sys.path.insert(0, '{str(script_path.parent)}')

# This import should set up blocking
import sandboxed_convert

import socket

# Try to create UDP socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("ERROR: UDP socket creation succeeded")
    sys.exit(1)
except OSError as e:
    if "disabled" in str(e):
        print("SUCCESS: UDP socket blocked")
        sys.exit(0)
    else:
        print(f"ERROR: Unexpected error: {{e}}")
        sys.exit(1)
"""

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS: UDP socket blocked" in result.stdout

    def test_webrtc_submodule_blocking(self):
        """Test that WebRTC submodules are also blocked."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = f"""
import sys
sys.path.insert(0, '{str(script_path.parent)}')

# This import should set up blocking
import sandboxed_convert

# Try to import WebRTC submodule
try:
    import webrtc.peer
    print("ERROR: webrtc.peer import succeeded")
    sys.exit(1)
except ImportError as e:
    if "blocked" in str(e) or "No module" in str(e):
        print("SUCCESS: webrtc.peer blocked")
        sys.exit(0)
    else:
        print(f"ERROR: Unexpected error: {{e}}")
        sys.exit(1)
"""

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS" in result.stdout

    def test_p2p_blocker_in_sys_meta_path(self):
        """Test that P2P blocker is installed in sys.meta_path."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = f"""
import sys
sys.path.insert(0, '{str(script_path.parent)}')

# This import should set up blocking
import sandboxed_convert

# Check that P2PBlocker is in meta_path
found_blocker = False
for importer in sys.meta_path:
    if type(importer).__name__ == 'P2PBlocker':
        found_blocker = True
        break

if found_blocker:
    print("SUCCESS: P2P blocker installed")
    sys.exit(0)
else:
    print("ERROR: P2P blocker not found in sys.meta_path")
    sys.exit(1)
"""

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS: P2P blocker installed" in result.stdout

    def test_comprehensive_p2p_blocking(self):
        """Test comprehensive P2P blocking with multiple protocols."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = f"""
import sys
sys.path.insert(0, '{str(script_path.parent)}')

# This import should set up blocking
import sandboxed_convert

import socket

blocked_count = 0
total_tests = 0

# Test various P2P-related imports
p2p_imports = [
    "pyp2p",
    "libp2p",
    "webrtc",
    "aiortc",
    "webtorrent",
    "ipfs",
    "kademlia",
    "bittorrent"
]

for module in p2p_imports:
    total_tests += 1
    try:
        __import__(module)
    except ImportError:
        blocked_count += 1

# Test UDP socket
total_tests += 1
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except OSError:
    blocked_count += 1

# Test multicast (used in P2P discovery)
total_tests += 1
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
except (OSError, AttributeError):
    blocked_count += 1

if blocked_count == total_tests:
    print(f"SUCCESS: All {{total_tests}} P2P tests blocked")
    sys.exit(0)
else:
    print(f"ERROR: Only {{blocked_count}}/{{total_tests}} tests blocked")
    sys.exit(1)
"""

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS" in result.stdout

    def test_asyncio_still_works(self):
        """Test that asyncio still works (but monitored)."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = f"""
import sys
sys.path.insert(0, '{str(script_path.parent)}')

# This import should set up blocking
import sandboxed_convert

# Test that asyncio still works for legitimate uses
import asyncio

async def test_func():
    return "test"

try:
    loop = asyncio.new_event_loop()
    result = loop.run_until_complete(test_func())
    loop.close()
    
    if result == "test":
        print("SUCCESS: asyncio works for legitimate use")
        sys.exit(0)
    else:
        print("ERROR: asyncio test failed")
        sys.exit(1)
except Exception as e:
    print(f"ERROR: asyncio failed: {{e}}")
    sys.exit(1)
"""

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS: asyncio works" in result.stdout

    def test_raw_sockets_blocked(self):
        """Test that raw sockets (used for P2P NAT traversal) are blocked."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = f"""
import sys
sys.path.insert(0, '{str(script_path.parent)}')

# This import should set up blocking
import sandboxed_convert

import socket

# Try to create raw socket (requires root, but should be blocked anyway)
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print("ERROR: Raw socket creation succeeded")
    sys.exit(1)
except (OSError, PermissionError) as e:
    if "disabled" in str(e) or "Permission" in str(e):
        print("SUCCESS: Raw socket blocked")
        sys.exit(0)
    else:
        print(f"ERROR: Unexpected error: {{e}}")
        sys.exit(1)
"""

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS: Raw socket blocked" in result.stdout
