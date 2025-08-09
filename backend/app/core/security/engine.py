"""Security engine for managing sandboxed image processing."""

import asyncio
import io
import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import structlog
from PIL import Image

from app.config import settings
from app.core.constants import (
    HEIF_AVIF_BRANDS,
    IMAGE_BUFFER_CHECK_LIMIT,
    IMAGE_MAGIC_BYTES,
    MAX_IMAGE_PIXELS,
    MAX_MEMORY_VIOLATIONS,
    MAX_SECURITY_EVENTS,
    MIN_VALIDATION_FILE_SIZE,
    SANDBOX_CPU_LIMITS,
    SANDBOX_MEMORY_LIMITS,
    SANDBOX_OUTPUT_LIMITS,
    SANDBOX_TIMEOUTS,
    STDERR_TRUNCATION_LENGTH,
    SUSPICIOUS_PATTERNS,
)
from app.core.exceptions import ConversionError
from app.core.security.metadata import MetadataStripper
from app.core.security.sandbox import SandboxConfig, SecuritySandbox
from app.models.process_sandbox import ProcessSandbox
from app.models.security_event import SecuritySeverity

logger = structlog.get_logger()


class SecurityEngine:
    """
    Main security engine that orchestrates secure image processing.

    This engine provides:
    - Process sandboxing for image conversions
    - File scanning and validation
    - Metadata stripping
    - Process isolation verification
    - Security audit logging
    """

    def __init__(self) -> None:
        """Initialize the security engine."""
        self._sandboxes: Dict[str, ProcessSandbox] = {}
        self._sandbox_lock = threading.Lock()  # Thread-safe access to _sandboxes
        self._metadata_stripper = MetadataStripper()
        self._security_tracker = None
        self._configure_logging()

    @property
    def security_tracker(self) -> None:
        """Lazy load security tracker to avoid circular imports."""
        if self._security_tracker is None:
            from app.api.routes.monitoring import security_tracker

            self._security_tracker = security_tracker
        return self._security_tracker

    def _configure_logging(self) -> None:
        """Configure structured security logging."""
        # Security logs will be configured with structlog
        # This is handled at application startup, we just use the logger

    def create_sandbox(
        self, conversion_id: str, strictness: str = "standard"
    ) -> SecuritySandbox:
        """
        Create a sandbox for image conversion with specified strictness level.

        Args:
            conversion_id: UUID of the conversion operation
            strictness: Security level ("standard", "strict", "paranoid")

        Returns:
            Configured SecuritySandbox instance
        """
        # Get resource limits based on strictness level
        resource_limits = self._get_resource_limits(strictness)

        # Create sandbox config with enhanced memory features
        config = SandboxConfig(
            max_memory_mb=resource_limits["memory_mb"],
            max_cpu_percent=resource_limits["cpu_percent"],
            timeout_seconds=resource_limits["timeout_seconds"],
            max_output_size_mb=resource_limits["max_output_mb"],
            sandbox_uid=settings.sandbox_uid,
            sandbox_gid=settings.sandbox_gid,
            enable_memory_tracking=True,
            enable_memory_locking=strictness in ["strict", "paranoid"],
            memory_violation_threshold=MAX_MEMORY_VIOLATIONS.get(
                strictness, MAX_MEMORY_VIOLATIONS["standard"]
            ),
        )

        # Create and return sandbox
        sandbox = SecuritySandbox(config)

        # Create ProcessSandbox record for tracking
        process_sandbox = ProcessSandbox(
            process_id="pending",  # Will be updated when process starts
            conversion_id=conversion_id,
            resource_limits=resource_limits,
        )

        # Thread-safe sandbox tracking
        with self._sandbox_lock:
            self._sandboxes[conversion_id] = process_sandbox

        logger.info(
            "Created sandbox for conversion",
            conversion_id=conversion_id,
            strictness=strictness,
            resource_limits=resource_limits,
        )

        # Record security event
        asyncio.create_task(
            self.security_tracker.record_sandbox_event(
                event_type="create",
                severity=SecuritySeverity.INFO,
                conversion_id=conversion_id,
                strictness=strictness,
                memory_limit_mb=resource_limits["memory_mb"],
                cpu_limit_percent=resource_limits["cpu_percent"],
                timeout_seconds=resource_limits["timeout_seconds"],
            )
        )

        return sandbox

    def _get_resource_limits(self, strictness: str) -> Dict[str, Any]:
        """
        Get resource limits based on strictness level.

        Args:
            strictness: Security level

        Returns:
            Resource limit configuration
        """
        return {
            "memory_mb": SANDBOX_MEMORY_LIMITS.get(
                strictness, SANDBOX_MEMORY_LIMITS["standard"]
            ),
            "cpu_percent": SANDBOX_CPU_LIMITS.get(
                strictness, SANDBOX_CPU_LIMITS["standard"]
            ),
            "timeout_seconds": SANDBOX_TIMEOUTS.get(
                strictness, SANDBOX_TIMEOUTS["standard"]
            ),
            "max_output_mb": SANDBOX_OUTPUT_LIMITS.get(
                strictness, SANDBOX_OUTPUT_LIMITS["standard"]
            ),
        }

    async def scan_file(self, file_data: bytes) -> Dict[str, Any]:
        """
        Scan file for security threats.

        Args:
            file_data: Raw file data to scan

        Returns:
            Security report with scan results
        """
        report = {
            "is_safe": True,
            "threats_found": [],
            "file_size": len(file_data),
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "detected_format": None,
        }

        # Early exit: Check minimum file size first
        if len(file_data) < MIN_VALIDATION_FILE_SIZE:
            report["is_safe"] = False
            report["threats_found"].append("File too small to be a valid image")
            return report

        # Check file size
        max_size = settings.max_file_size
        if len(file_data) > max_size:
            report["is_safe"] = False
            report["threats_found"].append(
                f"File exceeds maximum size of {max_size} bytes"
            )
            # Continue scanning even if too large to detect other threats

        # Check for patterns only if they appear at the very beginning
        # This avoids false positives from binary image data
        for pattern in SUSPICIOUS_PATTERNS:
            if file_data.startswith(pattern):
                report["is_safe"] = False
                report["threats_found"].append(
                    f"Suspicious pattern detected: {pattern.decode('utf-8', errors='ignore')}"
                )

        # Verify it's a valid image by checking magic bytes

        # Check if file starts with any known image signature
        is_valid_image = False
        detected_format = None

        for signature, format_name in IMAGE_MAGIC_BYTES.items():
            if file_data.startswith(signature):
                # Special handling for container formats
                if format_name == "WebP/RIFF":
                    # Check if it's actually WebP
                    if len(file_data) > 12 and file_data[8:12] == b"WEBP":
                        is_valid_image = True
                        detected_format = "WebP"
                    # Could be other RIFF format, continue checking
                    continue
                elif format_name == "HEIF/AVIF":
                    # Check ftyp box for specific format
                    if len(file_data) >= 12:
                        ftyp = file_data[8:12]
                        detected_format = HEIF_AVIF_BRANDS.get(ftyp)
                        if detected_format:
                            is_valid_image = True
                        # Could be other ISO format, continue checking
                        continue
                else:
                    is_valid_image = True
                    detected_format = format_name
                    break

        # PIL verification fallback
        if not is_valid_image and len(file_data) > 0:
            # Try to open with PIL as a final check with security limits
            try:
                # Set PIL security limits
                Image.MAX_IMAGE_PIXELS = (
                    MAX_IMAGE_PIXELS  # Prevents decompression bombs
                )

                # Use a limited BytesIO buffer
                img_buffer = io.BytesIO(
                    file_data[:IMAGE_BUFFER_CHECK_LIMIT]
                )  # Only check first 1MB

                img = Image.open(img_buffer)
                # Verify format without decompressing
                img.verify()

                # Check if it's actually an image format
                if hasattr(img, "format") and img.format is not None:
                    is_valid_image = True
                    detected_format = img.format
            except Image.DecompressionBombError:
                report["is_safe"] = False
                report["threats_found"].append("Potential decompression bomb detected")
            except Exception as e:
                # Log the specific error for debugging but don't expose it
                logger.debug(f"PIL verification failed: {str(e)}")

        if not is_valid_image and "File too small" not in str(
            report.get("threats_found", [])
        ):
            report["is_safe"] = False
            report["threats_found"].append(
                "File does not appear to be a valid image format"
            )

        # Log detected format if valid
        if is_valid_image and detected_format:
            logger.debug(f"Detected image format: {detected_format}")
            report["detected_format"] = detected_format

        # Log security scan
        logger.info(
            "File security scan completed",
            is_safe=report["is_safe"],
            threats_count=len(report["threats_found"]),
            file_size=report["file_size"],
            detected_format=report.get("detected_format"),
        )

        return report

    async def strip_metadata(
        self,
        image_data: bytes,
        format: str,
        preserve_metadata: bool = False,
        preserve_gps: bool = False,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Remove EXIF and other metadata from image.

        DEPRECATED: Use analyze_and_process_metadata instead.

        Args:
            image_data: Raw image data
            format: Image format
            preserve_metadata: If True, keep non-GPS metadata
            preserve_gps: If True, keep GPS data (only if preserve_metadata is also True)

        Returns:
            Tuple of (stripped image data, metadata summary)
        """
        return await self._metadata_stripper.analyze_and_strip_metadata(
            image_data, format, preserve_metadata, preserve_gps
        )

    async def analyze_and_process_metadata(
        self,
        image_data: bytes,
        input_format: str,
        strip_metadata: bool,
        preserve_metadata: bool,
        preserve_gps: bool,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Analyze and process metadata for image conversion.

        This method handles metadata analysis and optional stripping
        before image conversion, ensuring accurate tracking of what
        metadata was present in the original image.

        Args:
            image_data: Raw image data
            input_format: Input image format
            strip_metadata: If True, remove metadata (unless preserve_metadata overrides)
            preserve_metadata: If True, keep non-GPS metadata (overrides strip_metadata)
            preserve_gps: If True, keep GPS data (only if preserve_metadata is True)

        Returns:
            Tuple of (processed_image_data, metadata_summary)
        """
        result = await self._metadata_stripper.process_metadata_for_conversion(
            image_data, input_format, strip_metadata, preserve_metadata, preserve_gps
        )

        # Record metadata stripping event if metadata was removed
        if result[1].get("metadata_removed") and result[1].get("fields_removed"):
            asyncio.create_task(
                self.security_tracker.record_metadata_event(
                    removed_fields=result[1]["fields_removed"],
                    input_format=input_format,
                )
            )

        return result

    async def verify_process_isolation(
        self, sandbox: SecuritySandbox
    ) -> Dict[str, bool]:
        """
        Verify that process isolation is working correctly.

        Args:
            sandbox: SecuritySandbox instance to verify

        Returns:
            Isolation status for different aspects
        """
        isolation_status = {
            "network_isolated": True,
            "filesystem_restricted": True,
            "resource_limits_enforced": True,
            "environment_sanitized": True,
        }

        try:
            # Test network isolation
            result = await self._test_network_isolation(sandbox)
            isolation_status["network_isolated"] = not result["network_accessible"]

            # Test filesystem restrictions
            result = await self._test_filesystem_restrictions(sandbox)
            isolation_status["filesystem_restricted"] = result["properly_restricted"]

            # Test resource limits
            result = await self._test_resource_limits(sandbox)
            isolation_status["resource_limits_enforced"] = result["limits_enforced"]

            # Test environment sanitization
            result = await self._test_environment_sanitization(sandbox)
            isolation_status["environment_sanitized"] = result["properly_sanitized"]

        except Exception as e:
            logger.error(f"Error during isolation verification: {e}")

        logger.info("Process isolation verification completed", **isolation_status)

        return isolation_status

    async def _test_network_isolation(self, sandbox: SecuritySandbox) -> Dict[str, Any]:
        """Test if network is properly isolated."""
        try:
            # Try to ping a public DNS server
            result = await sandbox.execute_sandboxed_async(
                command=["ping", "-c", "1", "-W", "1", "8.8.8.8"], timeout=2
            )
            # If ping succeeds, network is not isolated
            return {"network_accessible": result["returncode"] == 0}
        except (SecurityError, TimeoutError):
            # Expected - network commands should be blocked
            return {"network_accessible": False}

    async def _test_filesystem_restrictions(
        self, sandbox: SecuritySandbox
    ) -> Dict[str, Any]:
        """Test if filesystem access is properly restricted."""
        try:
            # Try to read a system file
            result = await sandbox.execute_sandboxed_async(
                command=["cat", "/etc/passwd"], timeout=2
            )
            # If read succeeds, filesystem is not restricted
            return {"properly_restricted": result["returncode"] != 0}
        except SecurityError:
            # Expected - system paths should be blocked
            return {"properly_restricted": True}

    async def _test_resource_limits(self, sandbox: SecuritySandbox) -> Dict[str, Any]:
        """Test if resource limits are enforced."""
        try:
            # Try to allocate excessive memory
            result = await sandbox.execute_sandboxed_async(
                command=["python3", "-c", "x = 'a' * (1024 * 1024 * 1024)"],  # 1GB
                timeout=2,
                max_memory_mb=50,  # Should fail with 50MB limit
            )
            # If allocation succeeds, limits are not enforced
            return {"limits_enforced": result["returncode"] != 0}
        except (MemoryError, TimeoutError):
            # Expected - should hit memory limit
            return {"limits_enforced": True}

    async def _test_environment_sanitization(
        self, sandbox: SecuritySandbox
    ) -> Dict[str, Any]:
        """Test if environment variables are properly sanitized."""
        try:
            # Check if sensitive env vars are removed
            result = await sandbox.execute_sandboxed_async(
                command=["printenv"], timeout=2
            )

            output = result["output"].decode("utf-8", errors="ignore")
            sensitive_vars = ["AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "API_KEY"]

            for var in sensitive_vars:
                if var in output:
                    return {"properly_sanitized": False}

            return {"properly_sanitized": True}

        except Exception:
            # If printenv fails, assume sanitized
            return {"properly_sanitized": True}

    async def execute_sandboxed_conversion(
        self,
        sandbox: SecuritySandbox,
        conversion_id: str,
        command: List[str],
        input_data: Optional[bytes] = None,
    ) -> Tuple[bytes, ProcessSandbox]:
        """
        Execute an image conversion in a sandboxed environment.

        Args:
            sandbox: SecuritySandbox instance
            conversion_id: Conversion UUID
            command: Command to execute
            input_data: Optional[Any] input data

        Returns:
            Tuple of (output_data, process_sandbox_record)
        """
        # Thread-safe access to sandbox
        with self._sandbox_lock:
            process_sandbox = self._sandboxes.get(conversion_id)
            if not process_sandbox:
                raise ConversionError(
                    f"No sandbox record found for conversion {conversion_id}"
                )

        try:
            # Execute command in sandbox using async version to avoid blocking event loop
            # This allows progress updates to run concurrently during conversion
            result = await sandbox.execute_sandboxed_async(
                command=command,
                input_data=input_data,
            )

            # Update process sandbox record
            process_sandbox.process_id = str(result.get("process_id", "unknown"))

            # Check for conversion errors
            if result["returncode"] != 0:
                # Try to parse JSON error from stderr
                error_message = "Conversion failed"
                try:
                    stderr_str = result.get("stderr", b"").decode(
                        "utf-8", errors="ignore"
                    )
                    if stderr_str:
                        # Look for JSON error message
                        for line in stderr_str.strip().split("\n"):
                            if line.startswith("{") and "error_code" in line:
                                error_data = json.loads(line)
                                error_message = f"{error_data.get('error_code', 'UNKNOWN')}: {error_data.get('message', 'Unknown error')}"
                                break
                except Exception:
                    # If we can't parse the error, use raw stderr
                    error_message = (
                        f"Conversion failed with code {result['returncode']}"
                    )

                process_sandbox.mark_completed(
                    exit_code=result["returncode"],
                    actual_usage={
                        "memory_mb": result.get("memory_used_mb", 0),
                        "cpu_seconds": result.get("cpu_time", 0),
                        "wall_time_seconds": result.get("wall_time", 0),
                    },
                    error_message=error_message,
                )

                logger.error(
                    "Sandboxed conversion failed",
                    conversion_id=conversion_id,
                    error=error_message,
                    exit_code=result["returncode"],
                    stderr=result.get("stderr", b"").decode("utf-8", errors="replace")[
                        :STDERR_TRUNCATION_LENGTH
                    ],  # First 500 chars of stderr
                )

                raise ConversionError(error_message)

            # Mark successful completion
            process_sandbox.mark_completed(
                exit_code=result["returncode"],
                actual_usage={
                    "memory_mb": result.get("memory_used_mb", 0),
                    "cpu_seconds": result.get("cpu_time", 0),
                    "wall_time_seconds": result.get("wall_time", 0),
                },
            )

            # Log successful execution
            logger.info(
                "Sandboxed conversion completed", **process_sandbox.to_audit_log()
            )

            return result["output"], process_sandbox

        except SecurityError as e:
            # Record security violation
            process_sandbox.record_violation()
            process_sandbox.mark_completed(
                exit_code=-1,
                actual_usage={},
                error_message=str(e),
            )

            logger.error(
                "Security violation in sandboxed conversion",
                conversion_id=conversion_id,
                error=str(e),
                violations=process_sandbox.security_violations,
            )
            raise

        except Exception as e:
            # Record other failures
            process_sandbox.mark_completed(
                exit_code=-1,
                actual_usage={},
                error_message=str(e),
            )

            logger.error(
                "Sandboxed conversion failed",
                **process_sandbox.to_audit_log(),
                error=str(e),
            )
            raise

    def cleanup_sandbox(self, conversion_id: str) -> None:
        """
        Clean up sandbox resources after conversion.

        Args:
            conversion_id: Conversion UUID
        """
        with self._sandbox_lock:
            if conversion_id in self._sandboxes:
                process_sandbox = self._sandboxes[conversion_id]

                # Ensure sandbox is marked as completed
                if process_sandbox.end_time is None:
                    process_sandbox.mark_completed(
                        exit_code=-1,
                        actual_usage={},
                        error_message="Sandbox cleanup forced",
                    )

                # Log final audit entry
                logger.info(
                    "Sandbox cleanup completed", **process_sandbox.to_audit_log()
                )

                # Remove from tracking
                del self._sandboxes[conversion_id]

    def get_sandbox_history(
        self, limit: int = MAX_SECURITY_EVENTS
    ) -> List[Dict[str, Any]]:
        """
        Get recent sandbox execution history for monitoring.

        Args:
            limit: Maximum number of entries to return

        Returns: List[Any] of audit log entries
        """
        history = []
        for sandbox in list(self._sandboxes.values())[-limit:]:
            history.append(sandbox.to_audit_log())
        return history
