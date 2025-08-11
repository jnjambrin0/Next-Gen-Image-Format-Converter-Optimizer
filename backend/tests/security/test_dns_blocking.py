"""
Tests for DNS resolution blocking in sandboxed environments.
"""

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest


class TestDNSBlocking:
    """Test DNS blocking in sandboxed conversion script."""

    def test_sandboxed_script_blocks_dns(self):
        """Test that sandboxed conversion script blocks DNS resolution."""
        # Path to sandboxed script
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        # Test script that tries DNS resolution
        test_code = """
import sys
sys.path.insert(0, '{}')

# This import should trigger DNS blocking setup
import sandboxed_convert

# Try DNS resolution
import socket
try:
    socket.getaddrinfo("google.com", 80)
    print("ERROR: DNS resolution succeeded")
    sys.exit(1)
except (socket.gaierror, OSError) as e:
    if "disabled" in str(e):
        print("SUCCESS: DNS blocked")
        sys.exit(0)
    else:
        print(f"ERROR: Unexpected error: {{e}}")
        sys.exit(1)
""".format(
            str(script_path.parent)
        )

        # Run test
        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS: DNS blocked" in result.stdout

    def test_sandboxed_script_blocks_socket_creation(self):
        """Test that sandboxed conversion script blocks socket creation."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = """
import sys
sys.path.insert(0, '{}')

# This import should trigger socket blocking setup
import sandboxed_convert

# Try socket creation
import socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("ERROR: Socket creation succeeded")
    sys.exit(1)
except OSError as e:
    if "disabled" in str(e):
        print("SUCCESS: Socket creation blocked")
        sys.exit(0)
    else:
        print(f"ERROR: Unexpected error: {{e}}")
        sys.exit(1)
""".format(
            str(script_path.parent)
        )

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS: Socket creation blocked" in result.stdout

    def test_sandboxed_script_blocks_urllib(self):
        """Test that sandboxed conversion script blocks urllib."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = """
import sys
sys.path.insert(0, '{}')

# This import should trigger network blocking setup
import sandboxed_convert

# Try urllib
try:
    import urllib.request
    urllib.request.urlopen("http://google.com")
    print("ERROR: urllib request succeeded")
    sys.exit(1)
except OSError as e:
    if "disabled" in str(e):
        print("SUCCESS: urllib blocked")
        sys.exit(0)
    else:
        print(f"ERROR: Unexpected error: {{e}}")
        sys.exit(1)
""".format(
            str(script_path.parent)
        )

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS: urllib blocked" in result.stdout

    def test_sandboxed_script_hostname_returns_localhost(self):
        """Test that hostname functions return localhost."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = """
import sys
sys.path.insert(0, '{}')

# This import should trigger network blocking setup
import sandboxed_convert

import socket

# Test hostname functions
hostname = socket.gethostname()
fqdn = socket.getfqdn()

if hostname == "localhost" and fqdn == "localhost":
    print("SUCCESS: Hostname functions return localhost")
    sys.exit(0)
else:
    print(f"ERROR: hostname={{hostname}}, fqdn={{fqdn}}")
    sys.exit(1)
""".format(
            str(script_path.parent)
        )

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS: Hostname functions return localhost" in result.stdout

    def test_sandbox_blocks_dns_commands(self):
        """Test that sandbox blocks DNS-related commands."""
        from app.core.security.sandbox import SecuritySandbox

        sandbox = SecuritySandbox()

        # DNS commands should be blocked
        dns_commands = [
            ["dig", "google.com"],
            ["nslookup", "google.com"],
            ["host", "google.com"],
        ]

        for cmd in dns_commands:
            with pytest.raises(Exception) as exc_info:
                sandbox.validate_command(cmd)
            assert "Forbidden command" in str(exc_info.value)

    def test_sandbox_blocks_network_commands(self):
        """Test that sandbox blocks network-related commands."""
        from app.core.security.sandbox import SecuritySandbox

        sandbox = SecuritySandbox()

        # Network commands should be blocked
        network_commands = [
            ["ping", "8.8.8.8"],
            ["traceroute", "google.com"],
            ["netstat", "-an"],
            ["ss", "-tlnp"],
            ["curl", "http://example.com"],
            ["wget", "http://example.com"],
        ]

        for cmd in network_commands:
            with pytest.raises(Exception) as exc_info:
                sandbox.validate_command(cmd)
            assert "Forbidden command" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_dns_blocking_in_conversion(self):
        """Test that DNS is blocked during actual conversion."""
        from app.core.security.sandbox import SecuritySandbox

        sandbox = SecuritySandbox()

        # Create a test script that tries DNS during conversion
        test_script = """
import socket
try:
    socket.getaddrinfo("google.com", 80)
    print("DNS_NOT_BLOCKED")
except:
    print("DNS_BLOCKED")
"""

        result = sandbox.execute_sandboxed(
            [sys.executable, "-c", test_script], timeout=5
        )

        output = result["output"].decode("utf-8")
        assert "DNS_BLOCKED" in output
        assert "DNS_NOT_BLOCKED" not in output

    def test_dns_blocking_comprehensive(self):
        """Test comprehensive DNS blocking with various methods."""
        script_path = (
            Path(__file__).parent.parent.parent
            / "app"
            / "core"
            / "conversion"
            / "sandboxed_convert.py"
        )

        test_code = """
import sys
sys.path.insert(0, '{}')

# This import should trigger blocking setup
import sandboxed_convert

import socket

# Test various DNS methods
methods_blocked = []
methods_failed = []

# Test getaddrinfo
try:
    socket.getaddrinfo("example.com", 80)
    methods_failed.append("getaddrinfo")
except (socket.gaierror, OSError):
    methods_blocked.append("getaddrinfo")

# Test gethostbyname
try:
    socket.gethostbyname("example.com")
    methods_failed.append("gethostbyname")
except (socket.gaierror, OSError):
    methods_blocked.append("gethostbyname")

# Test gethostbyaddr
try:
    socket.gethostbyaddr("8.8.8.8")
    methods_failed.append("gethostbyaddr")
except (socket.gaierror, OSError):
    methods_blocked.append("gethostbyaddr")

# Test create_connection
try:
    socket.create_connection(("example.com", 80))
    methods_failed.append("create_connection")
except OSError:
    methods_blocked.append("create_connection")

if methods_failed:
    print(f"ERROR: Methods not blocked: {{methods_failed}}")
    sys.exit(1)
else:
    print(f"SUCCESS: All methods blocked: {{methods_blocked}}")
    sys.exit(0)
""".format(
            str(script_path.parent)
        )

        result = subprocess.run(
            [sys.executable, "-c", test_code], capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "SUCCESS: All methods blocked" in result.stdout
