"""
Security event model for privacy-compliant audit logging.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
import json


class SecurityEventType(str, Enum):
    """Types of security events."""

    VIOLATION = "violation"
    SCAN = "scan"
    SANDBOX_CREATE = "sandbox_create"
    SANDBOX_DESTROY = "sandbox_destroy"
    METADATA_STRIP = "metadata_strip"
    ACCESS_DENIED = "access_denied"
    RESOURCE_LIMIT = "resource_limit"


class SecuritySeverity(str, Enum):
    """Security event severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    """
    Security event for audit logging.
    All fields must be privacy-compliant (no PII).
    """

    id: Optional[int] = None
    event_type: SecurityEventType
    severity: SecuritySeverity
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)

    @field_validator("details")
    @classmethod
    def validate_no_pii(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure details contain no PII."""
        # List of keys that should not appear in security events
        forbidden_keys = {
            "filename",
            "file_name",
            "filepath",
            "file_path",
            "path",
            "directory",
            "folder",
            "username",
            "user_id",
            "email",
            "ip_address",
            "ip",
            "host",
            "name",
            "identifier",
        }

        def check_dict(d: dict) -> dict:
            """Recursively check dictionary for PII."""
            clean = {}
            for key, value in d.items():
                if any(forbidden in key.lower() for forbidden in forbidden_keys):
                    # Skip PII fields
                    continue
                if isinstance(value, dict):
                    clean[key] = check_dict(value)
                elif isinstance(value, list):
                    clean[key] = [
                        check_dict(item) if isinstance(item, dict) else item
                        for item in value
                    ]
                else:
                    clean[key] = value
            return clean

        return check_dict(v)

    def to_db_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "details": json.dumps(self.details),
            "timestamp": self.timestamp,
        }

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class SecurityEventSummary(BaseModel):
    """Summary of security events for reporting."""

    time_period_hours: int
    total_events: int
    events_by_type: Dict[str, int]
    events_by_severity: Dict[str, int]
    recent_violations: list[Dict[str, Any]]
    privacy_notice: str = "All security events are logged without PII"
