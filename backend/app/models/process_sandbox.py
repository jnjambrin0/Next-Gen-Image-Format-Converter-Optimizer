"""Process sandbox model for tracking sandboxed executions."""

from typing import Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict
import uuid


class ProcessSandbox(BaseModel):
    """
    Tracks sandboxed process execution for security audit trail.

    This model captures the execution details of each sandboxed process,
    including resource limits, actual usage, and any security violations.
    """

    model_config = ConfigDict(use_enum_values=True)

    # Unique identifier
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # Process information
    process_id: str = Field(description="System process identifier")
    conversion_id: str = Field(description="Related conversion UUID")

    # Resource configuration
    resource_limits: Dict[str, Any] = Field(
        default_factory=dict,
        description="Configured resource limits (CPU, memory, time)",
    )

    # Actual resource usage
    actual_usage: Dict[str, Any] = Field(
        default_factory=dict, description="Actual resource consumption metrics"
    )

    # Security tracking
    security_violations: int = Field(
        default=0, description="Number of security violation attempts"
    )

    # Execution timeline
    start_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Process start time",
    )
    end_time: Optional[datetime] = Field(
        default=None, description="Process completion time"
    )

    # Status and error tracking
    exit_code: Optional[int] = Field(default=None, description="Process exit code")
    terminated_by_signal: Optional[int] = Field(
        default=None, description="Signal that terminated the process (if any)"
    )
    error_message: Optional[str] = Field(
        default=None, description="Error message if process failed"
    )

    @property
    def execution_time(self) -> Optional[float]:
        """Calculate execution time in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def was_successful(self) -> bool:
        """Check if the process completed successfully."""
        return self.exit_code == 0 and self.terminated_by_signal is None

    @property
    def was_killed(self) -> bool:
        """Check if the process was forcefully terminated."""
        return self.terminated_by_signal is not None

    def mark_completed(
        self,
        exit_code: int,
        actual_usage: Dict[str, Any],
        terminated_by_signal: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Mark the sandbox process as completed.

        Args:
            exit_code: Process exit code
            actual_usage: Actual resource usage metrics
            terminated_by_signal: Signal number if process was killed
            error_message: Optional error message
        """
        self.end_time = datetime.now(timezone.utc)
        self.exit_code = exit_code
        self.actual_usage = actual_usage
        self.terminated_by_signal = terminated_by_signal
        self.error_message = error_message

    def record_violation(self) -> None:
        """Record a security violation attempt."""
        self.security_violations += 1

    def to_audit_log(self) -> Dict[str, Any]:
        """
        Generate privacy-aware audit log entry.

        Returns dict with no sensitive information like filenames or paths.
        """
        return {
            "sandbox_id": self.id,
            "process_id": self.process_id,
            "conversion_id": self.conversion_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "execution_time": self.execution_time,
            "exit_code": self.exit_code,
            "terminated_by_signal": self.terminated_by_signal,
            "resource_limits": self.resource_limits,
            "actual_usage": self.actual_usage,
            "security_violations": self.security_violations,
            "was_successful": self.was_successful,
            "was_killed": self.was_killed,
        }
