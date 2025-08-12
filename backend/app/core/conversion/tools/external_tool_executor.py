"""Unified external tool executor with security controls."""

import asyncio
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import structlog

from app.core.exceptions import ConversionFailedError

logger = structlog.get_logger()


@dataclass
class ExecutionResult:
    """Result from external tool execution."""

    stdout: bytes
    stderr: str
    returncode: int
    execution_time: float


class ExternalToolExecutor:
    """Secure executor for external image processing tools."""

    # Default restricted environment for subprocess execution
    # Note: HOME and TMPDIR will be set to secure temp directories at runtime
    DEFAULT_RESTRICTED_ENV = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",  # Minimal PATH
        "LC_ALL": "C",  # Consistent locale
    }

    # Default resource limits
    DEFAULT_TIMEOUT = 30  # seconds
    DEFAULT_NICE_VALUE = 10  # Lower priority

    def __init__(
        self,
        tool_name: str,
        tool_variants: Optional[List[str]] = None,
        custom_env: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize external tool executor.

        Args:
            tool_name: Primary name of the tool
            tool_variants: Alternative names to search for
            custom_env: Custom environment variables to merge with defaults
        """
        self.tool_name = tool_name
        self.tool_variants = tool_variants or [tool_name]
        self.tool_path = self._find_tool()

        # Create secure temporary directory for this executor instance
        self._temp_dir = tempfile.mkdtemp(prefix=f"img_conv_{tool_name}_")
        # Set secure permissions after creation
        os.chmod(self._temp_dir, 0o700)

        # Merge custom environment with defaults
        self.restricted_env = self.DEFAULT_RESTRICTED_ENV.copy()
        # Set secure temporary directories
        self.restricted_env["HOME"] = self._temp_dir
        self.restricted_env["TMPDIR"] = self._temp_dir

        if custom_env:
            self.restricted_env.update(custom_env)

    def _find_tool(self) -> Optional[str]:
        """Find the tool executable in the system."""
        for variant in self.tool_variants:
            tool_path = shutil.which(variant)
            if tool_path:
                logger.debug(
                    "Found external tool",
                    tool_name=self.tool_name,
                    variant=variant,
                    path=tool_path,
                )
                return tool_path

        logger.warning(
            "External tool not found",
            tool_name=self.tool_name,
            variants=self.tool_variants,
        )
        return None

    @property
    def is_available(self) -> bool:
        """Check if the tool is available."""
        return self.tool_path is not None

    def check_version(self, version_args: List[str] = None) -> Optional[str]:
        """
        Check tool version for debugging.

        Args:
            version_args: Arguments to get version (default: ["--version"])

        Returns:
            Version string if available
        """
        if not self.is_available:
            return None

        version_args = version_args or ["--version"]

        try:
            result = subprocess.run(
                [self.tool_path] + version_args,
                capture_output=True,
                text=True,
                timeout=2,
                env=self.restricted_env,
            )

            # Some tools output version to stderr
            version_output = result.stdout or result.stderr
            return version_output.strip() if version_output else None

        except (subprocess.SubprocessError, Exception) as e:
            logger.debug(
                "Failed to get tool version", tool_name=self.tool_name, error=str(e)
            )
            return None

    async def execute_async(
        self,
        args: List[str],
        input_data: Optional[bytes] = None,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        nice_value: Optional[int] = None,
    ) -> ExecutionResult:
        """
        Execute tool asynchronously with security controls.

        Args:
            args: Command line arguments for the tool
            input_data: Optional input data to pipe to stdin
            timeout: Execution timeout in seconds
            cwd: Working directory (default: secure temp directory)
            nice_value: Process nice value for priority

        Returns:
            ExecutionResult with output and status

        Raises:
            ConversionFailedError: If tool is not available or execution fails
        """
        if not self.is_available:
            raise ConversionFailedError(
                f"External tool '{self.tool_name}' not available",
                details={"tool": self.tool_name, "variants": self.tool_variants},
            )

        # Build command
        cmd = [self.tool_path] + args

        # Set resource limits
        timeout = timeout or self.DEFAULT_TIMEOUT
        nice_value = nice_value if nice_value is not None else self.DEFAULT_NICE_VALUE

        # Log execution (privacy-aware)
        logger.debug(
            "Executing external tool",
            tool_name=self.tool_name,
            arg_count=len(args),
            has_input=input_data is not None,
            timeout=timeout,
        )

        # Execute in subprocess
        start_time = asyncio.get_event_loop().time()

        try:
            # Use secure temp directory if no specific cwd provided
            working_dir = cwd or self._temp_dir

            # Run subprocess asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self.restricted_env,
                cwd=working_dir,
                preexec_fn=lambda: os.nice(nice_value) if os.name != "nt" else None,
            )

            # Communicate with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=input_data), timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise ConversionFailedError(
                    f"External tool execution timed out after {timeout}s",
                    details={"tool": self.tool_name, "timeout": timeout},
                )

            execution_time = asyncio.get_event_loop().time() - start_time

            return ExecutionResult(
                stdout=stdout,
                stderr=stderr.decode("utf-8", errors="ignore") if stderr else "",
                returncode=process.returncode,
                execution_time=execution_time,
            )

        except Exception as e:
            if isinstance(e, ConversionFailedError):
                raise
            raise ConversionFailedError(
                f"External tool execution failed: {str(e)}",
                details={"tool": self.tool_name, "error": str(e)},
            )

    def execute(
        self,
        args: List[str],
        input_data: Optional[bytes] = None,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        nice_value: Optional[int] = None,
    ) -> ExecutionResult:
        """
        Execute tool synchronously with security controls.

        Args:
            args: Command line arguments for the tool
            input_data: Optional input data to pipe to stdin
            timeout: Execution timeout in seconds
            cwd: Working directory (default: secure temp directory)
            nice_value: Process nice value for priority

        Returns:
            ExecutionResult with output and status

        Raises:
            ConversionFailedError: If tool is not available or execution fails
        """
        if not self.is_available:
            raise ConversionFailedError(
                f"External tool '{self.tool_name}' not available",
                details={"tool": self.tool_name, "variants": self.tool_variants},
            )

        # Build command
        cmd = [self.tool_path] + args

        # Set resource limits
        timeout = timeout or self.DEFAULT_TIMEOUT
        nice_value = nice_value if nice_value is not None else self.DEFAULT_NICE_VALUE

        # Log execution (privacy-aware)
        logger.debug(
            "Executing external tool",
            tool_name=self.tool_name,
            arg_count=len(args),
            has_input=input_data is not None,
            timeout=timeout,
        )

        # Execute in subprocess
        import time

        start_time = time.time()

        try:
            # Use secure temp directory if no specific cwd provided
            working_dir = cwd or self._temp_dir

            # Use restricted environment
            env = self.restricted_env

            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                timeout=timeout,
                env=env,
                cwd=working_dir,
                preexec_fn=lambda: os.nice(nice_value) if os.name != "nt" else None,
            )

            execution_time = time.time() - start_time

            return ExecutionResult(
                stdout=result.stdout,
                stderr=(
                    result.stderr.decode("utf-8", errors="ignore")
                    if result.stderr
                    else ""
                ),
                returncode=result.returncode,
                execution_time=execution_time,
            )

        except subprocess.TimeoutExpired:
            raise ConversionFailedError(
                f"External tool execution timed out after {timeout}s",
                details={"tool": self.tool_name, "timeout": timeout},
            )
        except Exception as e:
            raise ConversionFailedError(
                f"External tool execution failed: {str(e)}",
                details={"tool": self.tool_name, "error": str(e)},
            )

    def validate_output(self, output: bytes, min_size: int = 100) -> bool:
        """
        Validate tool output.

        Args:
            output: Output data to validate
            min_size: Minimum acceptable size in bytes

        Returns:
            True if output appears valid
        """
        if not output:
            return False

        if len(output) < min_size:
            logger.warning(
                "External tool output suspiciously small",
                tool_name=self.tool_name,
                output_size=len(output),
                min_size=min_size,
            )
            return False

        return True

    def cleanup(self) -> None:
        """Clean up temporary directory."""
        if hasattr(self, "_temp_dir") and os.path.exists(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir)
                logger.debug(
                    "Cleaned up temporary directory",
                    tool_name=self.tool_name,
                    temp_dir=self._temp_dir,
                )
            except Exception as e:
                logger.warning(
                    "Failed to clean up temporary directory",
                    tool_name=self.tool_name,
                    temp_dir=self._temp_dir,
                    error=str(e),
                )

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()

    def __del__(self):
        """Destructor with cleanup."""
        self.cleanup()

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"ExternalToolExecutor(tool_name='{self.tool_name}', "
            f"available={self.is_available}, path='{self.tool_path}')"
        )
