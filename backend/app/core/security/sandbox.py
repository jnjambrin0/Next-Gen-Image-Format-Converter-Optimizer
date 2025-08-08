"""Process sandboxing implementation for secure image conversion."""

import asyncio
import os
import resource
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
import structlog

from app.core.exceptions import ConversionError
from app.core.security.memory import (
    SecureMemoryManager,
    MemoryError as SecureMemoryError,
)
from app.core.security.errors import (
    SecurityError,
    create_sandbox_error,
    create_file_error,
    handle_security_errors
)
from app.core.constants import (
    SANDBOX_MEMORY_LIMITS,
    SANDBOX_CPU_LIMITS,
    SANDBOX_TIMEOUTS,
    SANDBOX_OUTPUT_LIMITS,
    KB_TO_BYTES_FACTOR,
    MB_TO_BYTES_FACTOR,
    COMMAND_NAME_MAX_LENGTH,
    PROCESS_NICE_LEVEL,
    MEMORY_CHECK_INTERVAL,
    MAX_MEMORY_VIOLATIONS
)

logger = structlog.get_logger()


class SandboxConfig:
    """Configuration for sandbox behavior."""

    def __init__(
        self,
        max_memory_mb: int = SANDBOX_MEMORY_LIMITS["standard"],
        max_cpu_percent: int = SANDBOX_CPU_LIMITS["standard"],
        timeout_seconds: int = SANDBOX_TIMEOUTS["standard"],
        max_output_size_mb: int = SANDBOX_OUTPUT_LIMITS["standard"],
        sandbox_uid: Optional[int] = None,
        sandbox_gid: Optional[int] = None,
        allowed_paths: Optional[List[str]] = None,
        enable_memory_tracking: bool = True,
        enable_memory_locking: bool = True,
        memory_violation_threshold: int = MAX_MEMORY_VIOLATIONS["standard"],
    ):
        self.max_memory_mb = max_memory_mb
        self.max_cpu_percent = max_cpu_percent
        self.timeout_seconds = timeout_seconds
        self.max_output_size_mb = max_output_size_mb
        self.sandbox_uid = sandbox_uid
        self.sandbox_gid = sandbox_gid
        self.allowed_paths = allowed_paths or []
        self.enable_memory_tracking = enable_memory_tracking
        self.enable_memory_locking = enable_memory_locking
        self.memory_violation_threshold = memory_violation_threshold

        # Blocked commands that pose security risks
        self.blocked_commands = {
            "rm",
            "del",
            "format",
            "fdisk",
            "mkfs",
            "dd",
            "curl",
            "wget",
            "nc",
            "netcat",
            "telnet",
            "ssh",
            "ftp",
            "bash",
            "sh",
            "cmd",
            "powershell",
            "python",
            "perl",
            "ruby",
            "chmod",
            "chown",
            "chgrp",
            "mount",
            "umount",
            "su",
            "sudo",
            "kill",
            "killall",
            "pkill",
            "service",
            "systemctl",
            "dig",
            "nslookup",
            "host",
            "ping",
            "traceroute",
            "tracert",
            "arp",
            "ifconfig",
            "ip",
            "route",
            "netstat",
            "ss",
            "lsof",
        }

        # Environment variables to remove for security
        self.blocked_env_vars = {
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SESSION_TOKEN",
            "DATABASE_URL",
            "DB_PASSWORD",
            "DB_USER",
            "API_KEY",
            "SECRET_KEY",
            "GITHUB_TOKEN",
            "SLACK_TOKEN",
            "SSH_PRIVATE_KEY",
            "HOME",
        }


class SecuritySandbox:
    """Secure sandbox for running image conversion processes."""

    def __init__(self, config: Optional[SandboxConfig] = None):
        """Initialize security sandbox with configuration."""
        self.config = config or SandboxConfig()
        self._temp_dirs: List[Path] = []
        self._memory_manager: Optional[SecureMemoryManager] = None
        self._memory_violations: int = 0
        self._peak_memory_mb: float = 0.0

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources."""
        self._cleanup_temp_dirs()
        self._cleanup_memory()

    def create_sandbox(
        self, resource_limits: Optional[Dict[str, Any]] = None
    ) -> "SecuritySandbox":
        """
        Create a new sandbox instance with specified resource limits.

        Args:
            resource_limits: Optional resource limit overrides

        Returns:
            New SecuritySandbox instance
        """
        config = (
            SandboxConfig(
                max_memory_mb=resource_limits.get(
                    "max_memory_mb", self.config.max_memory_mb
                ),
                max_cpu_percent=resource_limits.get(
                    "max_cpu_percent", self.config.max_cpu_percent
                ),
                timeout_seconds=resource_limits.get(
                    "timeout_seconds", self.config.timeout_seconds
                ),
                max_output_size_mb=resource_limits.get(
                    "max_output_size_mb", self.config.max_output_size_mb
                ),
                sandbox_uid=resource_limits.get("sandbox_uid", self.config.sandbox_uid),
                sandbox_gid=resource_limits.get("sandbox_gid", self.config.sandbox_gid),
            )
            if resource_limits
            else self.config
        )

        return SecuritySandbox(config)

    def validate_path(self, path: str) -> None:
        """
        Validate that a file path is safe to access.

        Args:
            path: File path to validate

        Raises:
            SecurityError: If path is unsafe
        """
        # Normalize path to detect traversal attempts
        normalized = os.path.normpath(path)

        # Check for path traversal attempts
        if ".." in normalized or normalized.startswith("/"):
            raise create_file_error(
                operation="path_traversal",
                reason="Path traversal detected"
            )

        # Check for null bytes (common in injection attacks)
        if "\x00" in path:
            raise create_file_error(
                operation="path_traversal",
                reason="Null byte in path"
            )

        # Check for dangerous characters
        dangerous_chars = ["|", "&", ";", "`", "$", "(", ")"]
        if any(char in path for char in dangerous_chars):
            raise create_file_error(
                operation="path_traversal",
                reason="Dangerous characters in path"
            )

    def validate_command(self, command: List[str]) -> None:
        """
        Validate that a command is safe to execute.

        Args:
            command: Command list to validate

        Raises:
            SecurityError: If command is unsafe
        """
        if not command:
            raise create_sandbox_error(
                reason="process_error",
                details="Empty command"
            )

        cmd_name = os.path.basename(command[0]).lower()

        # Check against blocked commands
        if cmd_name in self.config.blocked_commands:
            raise create_sandbox_error(
                reason="forbidden_command",
                command=cmd_name
            )

        # Check all arguments for injection attempts
        for arg in command:
            if any(char in arg for char in ["|", "&", ";", "`", "$"]):
                raise create_sandbox_error(
                    reason="command_injection",
                    details="Command injection attempt detected"
                )

    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a filename for safe use.

        Args:
            filename: Original filename

        Returns:
            Sanitized filename

        Raises:
            SecurityError: If filename contains dangerous patterns
        """
        # Check for injection attempts
        dangerous_patterns = [";", "&&", "||", "|", "`", "$", "\n", "\r"]
        if any(pattern in filename for pattern in dangerous_patterns):
            raise create_file_error(
                operation="validation",
                reason="Filename contains dangerous patterns"
            )

        # Remove null bytes
        filename = filename.replace("\x00", "")

        # Basic sanitization
        safe_chars = set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
        )
        sanitized = "".join(c if c in safe_chars else "_" for c in filename)

        return sanitized[:COMMAND_NAME_MAX_LENGTH]  # Limit length

    def validate_file_access(self, path: str, mode: str = "read") -> None:
        """
        Validate file access permissions.

        Args:
            path: File path to check
            mode: Access mode ('read', 'write')

        Raises:
            SecurityError: If access should be denied
        """
        self.validate_path(path)

        # Check against system paths
        system_paths = [
            "/etc/",
            "/root/",
            "/home/",
            "/usr/bin/",
            "/usr/sbin/",
            "/proc/",
            "/sys/",
            "/dev/",
            "~/",
        ]

        normalized_path = os.path.normpath(path)
        for sys_path in system_paths:
            if normalized_path.startswith(sys_path):
                raise create_file_error(
                    operation="access",
                    reason="Access denied to system path"
                )

    def _create_secure_environment(self) -> Dict[str, str]:
        """Create a secure environment for subprocess execution."""
        # Start with minimal environment
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        }

        # Remove dangerous environment variables from current env
        current_env = os.environ.copy()
        for var_name in current_env:
            if var_name.upper() not in self.config.blocked_env_vars:
                # Only allow safe variables
                if var_name in ["PATH", "LANG", "LC_ALL", "TZ"]:
                    env[var_name] = current_env[var_name]

        return env

    def _create_temp_directory(self) -> Path:
        """Create a temporary directory for sandbox operations."""
        temp_dir = Path(tempfile.mkdtemp(prefix="sandbox_"))
        self._temp_dirs.append(temp_dir)
        return temp_dir

    def _cleanup_temp_dirs(self) -> None:
        """Clean up temporary directories."""
        for temp_dir in self._temp_dirs:
            try:
                if temp_dir.exists():
                    # Remove all contents
                    for item in temp_dir.rglob("*"):
                        if item.is_file():
                            item.unlink()
                        elif item.is_dir():
                            item.rmdir()
                    temp_dir.rmdir()
            except Exception as e:
                logger.warning(f"Failed to cleanup temp directory {temp_dir}: {e}")
        self._temp_dirs.clear()

    def _cleanup_memory(self) -> None:
        """Clean up memory resources."""
        if self._memory_manager:
            try:
                self._memory_manager.cleanup_all()
                logger.debug("Memory manager cleaned up")
            except Exception as e:
                logger.warning(f"Failed to cleanup memory manager: {e}")
            finally:
                self._memory_manager = None

    def _initialize_memory_manager(self) -> None:
        """Initialize memory manager if enabled."""
        if self.config.enable_memory_tracking and not self._memory_manager:
            try:
                self._memory_manager = SecureMemoryManager(
                    max_memory_mb=self.config.max_memory_mb
                )
                logger.debug(
                    "Memory manager initialized",
                    max_memory_mb=self.config.max_memory_mb,
                )
            except Exception as e:
                logger.warning(f"Failed to initialize memory manager: {e}")

    def get_memory_stats(self) -> Dict[str, Any]:
        """Get current memory statistics."""
        stats = {
            "memory_violations": self._memory_violations,
            "peak_memory_mb": self._peak_memory_mb,
            "memory_limit_mb": self.config.max_memory_mb,
            "memory_tracking_enabled": self.config.enable_memory_tracking,
            "memory_locking_enabled": self.config.enable_memory_locking,
        }

        if self._memory_manager:
            stats.update(self._memory_manager.get_memory_stats())

        return stats

    def _check_memory_violation(self, current_memory_mb: float) -> bool:
        """
        Check if current memory usage violates limits.

        Args:
            current_memory_mb: Current memory usage in MB

        Returns:
            True if violation detected
        """
        # Update peak memory tracking
        if current_memory_mb > self._peak_memory_mb:
            self._peak_memory_mb = current_memory_mb

        # Check for violation
        if current_memory_mb > self.config.max_memory_mb:
            self._memory_violations += 1
            logger.warning(
                "Memory limit violation detected",
                current_mb=current_memory_mb,
                limit_mb=self.config.max_memory_mb,
                violations=self._memory_violations,
            )
            
            # Record security event for violation
            try:
                from app.api.routes.monitoring import security_tracker
                asyncio.create_task(security_tracker.record_resource_limit_event(
                    resource_type="memory",
                    limit=float(self.config.max_memory_mb),
                    attempted=float(current_memory_mb),
                    unit="MB"
                ))
            except Exception:
                pass  # Don't fail if tracking fails

            # Check if we've exceeded violation threshold
            if self._memory_violations >= self.config.memory_violation_threshold:
                raise SecureMemoryError(
                    f"Memory violations exceeded threshold: {self._memory_violations} >= {self.config.memory_violation_threshold}"
                )

            return True

        return False

    def _set_resource_limits(self) -> None:
        """Set resource limits for the subprocess."""
        try:
            # Set memory limit (in bytes)
            memory_limit = self.config.max_memory_mb * MB_TO_BYTES_FACTOR
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))

            # Set CPU time limit
            cpu_limit = self.config.timeout_seconds
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))

            # Set file size limit to prevent disk exhaustion
            file_limit = self.config.max_output_size_mb * MB_TO_BYTES_FACTOR
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

            # Drop privileges if configured
            if self.config.sandbox_gid is not None:
                os.setgid(self.config.sandbox_gid)
            if self.config.sandbox_uid is not None:
                os.setuid(self.config.sandbox_uid)

        except Exception as e:
            logger.error(f"Failed to set resource limits: {e}")
            # Don't fail hard here - some systems may not support all limits

    async def execute_sandboxed_async(
        self,
        command: List[str],
        input_data: Optional[bytes] = None,
        timeout: Optional[int] = None,
        max_memory_mb: Optional[int] = None,
        max_output_size_mb: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute a command in the sandbox with security restrictions (async version).
        
        This version uses asyncio subprocess to avoid blocking the event loop,
        allowing other async tasks (like progress updates) to run concurrently.

        Args:
            command: Command to execute
            input_data: Optional input data to pipe to command
            timeout: Override timeout in seconds
            max_memory_mb: Override memory limit
            max_output_size_mb: Override output size limit

        Returns:
            Dict with 'output', 'stderr', 'returncode', 'process_id',
            'memory_used_mb', 'cpu_time', 'wall_time'

        Raises:
            SecurityError: If command violates security policy
            TimeoutError: If command exceeds timeout
            MemoryError: If command exceeds memory limit
        """
        # Initialize memory manager if needed
        self._initialize_memory_manager()

        # Validate command
        self.validate_command(command)

        # Use overrides if provided
        actual_timeout = timeout or self.config.timeout_seconds
        actual_max_memory = max_memory_mb or self.config.max_memory_mb
        actual_max_output = max_output_size_mb or self.config.max_output_size_mb

        # Create secure environment
        env = self._create_secure_environment()

        # Create temporary directory for operation
        temp_dir = self._create_temp_directory()

        try:

            # Create subprocess using asyncio for non-blocking execution
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=str(temp_dir),
                # Note: preexec_fn and start_new_session aren't supported in async subprocess
                # We'll need to handle resource limits differently
            )

            try:
                start_time = time.time()
                
                # Use asyncio.wait_for to apply timeout
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=input_data),
                    timeout=actual_timeout
                )
                
                wall_time = time.time() - start_time

                # Check output size
                if len(stdout) > actual_max_output * MB_TO_BYTES_FACTOR:
                    raise create_sandbox_error(
                        reason="output_violation",
                        output_size=len(stdout),
                        limit=actual_max_output * MB_TO_BYTES_FACTOR
                    )

                # Try to get resource usage info with memory monitoring
                resource_usage = self._get_process_resource_usage(process.pid)

                # Check memory violations if tracking is enabled
                if self.config.enable_memory_tracking:
                    memory_mb = resource_usage.get("memory_mb", 0)
                    if memory_mb > 0:
                        self._check_memory_violation(memory_mb)

                result = {
                    "output": stdout,
                    "stderr": stderr,
                    "returncode": process.returncode,
                    "process_id": process.pid,
                    "memory_used_mb": resource_usage.get("memory_mb", 0),
                    "cpu_time": resource_usage.get("cpu_time", 0),
                    "wall_time": wall_time,
                    "peak_memory_mb": self._peak_memory_mb,
                    "memory_violations": self._memory_violations,
                    "memory_tracking_enabled": self.config.enable_memory_tracking,
                }

                if process.returncode == -9:  # SIGKILL
                    if b"Memory limit exceeded" in stderr:
                        raise create_sandbox_error(
                            reason="memory_violation",
                            details="Memory limit exceeded"
                        )
                    else:
                        raise create_sandbox_error(
                            reason="timeout",
                            details="Process killed (likely timeout)"
                        )


                return result

            except asyncio.TimeoutError:
                # Kill the process
                try:
                    process.kill()
                    await process.wait()  # Ensure process is cleaned up
                except ProcessLookupError:
                    pass
                raise create_sandbox_error(
                    reason="timeout",
                    timeout=actual_timeout,
                    details=f"Execution timeout after {actual_timeout} seconds"
                )

        finally:
            # Ensure process is cleaned up
            try:
                if process and process.returncode is None:
                    process.kill()
                    await process.wait()
            except Exception:
                pass

    def execute_sandboxed(
        self,
        command: List[str],
        input_data: Optional[bytes] = None,
        timeout: Optional[int] = None,
        max_memory_mb: Optional[int] = None,
        max_output_size_mb: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute a command in the sandbox with security restrictions (synchronous version).
        
        DEPRECATED: This synchronous version blocks the event loop.
        Use execute_sandboxed_async() for async contexts to allow concurrent tasks.

        Args:
            command: Command to execute
            input_data: Optional input data to pipe to command
            timeout: Override timeout in seconds
            max_memory_mb: Override memory limit
            max_output_size_mb: Override output size limit

        Returns:
            Dict with 'output', 'stderr', 'returncode', 'process_id',
            'memory_used_mb', 'cpu_time', 'wall_time'

        Raises:
            SecurityError: If command violates security policy
            TimeoutError: If command exceeds timeout
            MemoryError: If command exceeds memory limit
        """
        # Initialize memory manager if needed
        self._initialize_memory_manager()

        # Validate command
        self.validate_command(command)

        # Use overrides if provided
        actual_timeout = timeout or self.config.timeout_seconds
        actual_max_memory = max_memory_mb or self.config.max_memory_mb
        actual_max_output = max_output_size_mb or self.config.max_output_size_mb

        # Create secure environment
        env = self._create_secure_environment()

        # Create temporary directory for operation
        temp_dir = self._create_temp_directory()

        try:
            logger.info(
                "Executing sandboxed command",
                command=command[0],
                timeout=actual_timeout,
                memory_limit=actual_max_memory,
                temp_dir=str(temp_dir),
            )

            # Execute with security restrictions
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=str(temp_dir),
                preexec_fn=self._set_resource_limits,
                start_new_session=True,  # Create new process group
            )

            try:
                start_time = time.time()
                stdout, stderr = process.communicate(
                    input=input_data, timeout=actual_timeout
                )
                wall_time = time.time() - start_time

                # Check output size
                if len(stdout) > actual_max_output * MB_TO_BYTES_FACTOR:
                    raise create_sandbox_error(
                        reason="output_violation",
                        output_size=len(stdout),
                        limit=actual_max_output * MB_TO_BYTES_FACTOR
                    )

                # Try to get resource usage info with memory monitoring
                resource_usage = self._get_process_resource_usage(process.pid)

                # Check memory violations if tracking is enabled
                if self.config.enable_memory_tracking:
                    memory_mb = resource_usage.get("memory_mb", 0)
                    if memory_mb > 0:
                        self._check_memory_violation(memory_mb)

                result = {
                    "output": stdout,
                    "stderr": stderr,
                    "returncode": process.returncode,
                    "process_id": process.pid,
                    "memory_used_mb": resource_usage.get("memory_mb", 0),
                    "cpu_time": resource_usage.get("cpu_time", 0),
                    "wall_time": wall_time,
                    "peak_memory_mb": self._peak_memory_mb,
                    "memory_violations": self._memory_violations,
                    "memory_tracking_enabled": self.config.enable_memory_tracking,
                }

                if process.returncode == -9:  # SIGKILL
                    if b"Memory limit exceeded" in stderr:
                        raise create_sandbox_error(
                            reason="memory_violation",
                            details="Memory limit exceeded"
                        )
                    else:
                        raise create_sandbox_error(
                            reason="timeout",
                            details="Process killed (likely timeout)"
                        )

                logger.info(
                    "Sandboxed command completed",
                    returncode=process.returncode,
                    output_size=len(stdout),
                    memory_used_mb=result["memory_used_mb"],
                    cpu_time=result["cpu_time"],
                    wall_time=result["wall_time"],
                )

                return result

            except subprocess.TimeoutExpired:
                # Kill the process group
                try:
                    os.killpg(os.getpgid(process.pid), 9)
                except ProcessLookupError:
                    pass
                process.kill()
                raise create_sandbox_error(
                    reason="timeout",
                    timeout=actual_timeout,
                    details=f"Execution timeout after {actual_timeout} seconds"
                )

        finally:
            # Ensure process is cleaned up
            try:
                if process.poll() is None:
                    process.kill()
            except Exception:
                pass

    def _get_process_resource_usage(self, pid: int) -> Dict[str, Any]:
        """
        Get resource usage information for a process.

        Args:
            pid: Process ID

        Returns:
            Dict with resource usage metrics
        """
        usage = {
            "memory_mb": 0,
            "cpu_time": 0,
        }

        try:
            # Try to read from /proc filesystem (Linux)
            proc_stat = f"/proc/{pid}/stat"
            if os.path.exists(proc_stat):
                with open(proc_stat, "r") as f:
                    stats = f.read().split()
                    # Field 14 and 15 are utime and stime (user and system CPU time)
                    if len(stats) > 15:
                        utime = int(stats[13])
                        stime = int(stats[14])
                        # Convert from clock ticks to seconds
                        clock_ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
                        usage["cpu_time"] = (utime + stime) / clock_ticks

            # Try to get memory usage
            proc_status = f"/proc/{pid}/status"
            if os.path.exists(proc_status):
                with open(proc_status, "r") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            # Extract memory in KB and convert to MB
                            memory_kb = int(line.split()[1])
                            usage["memory_mb"] = memory_kb / KB_TO_BYTES_FACTOR
                            break

        except Exception as e:
            logger.debug(f"Could not get resource usage for PID {pid}: {e}")

        return usage


def create_sandbox(resource_limits: Optional[Dict[str, Any]] = None) -> SecuritySandbox:
    """
    Factory function to create a new sandbox instance.

    Args:
        resource_limits: Optional resource limit configuration

    Returns:
        New SecuritySandbox instance
    """
    return SecuritySandbox().create_sandbox(resource_limits)
