"""
Security event tracking with privacy compliance.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional

from app.core.constants import (DB_CHECK_SAME_THREAD, DEFAULT_MONITORING_HOURS,
                                MAX_RECENT_EVENTS_DISPLAY,
                                SECURITY_EVENT_RETENTION_DAYS)
from app.core.security.rate_limiter import SecurityEventRateLimiter
from app.core.security.types import RateLimitConfig
from app.models.security_event import (SecurityEvent, SecurityEventSummary,
                                       SecurityEventType, SecuritySeverity)
from app.utils.logging import get_logger

logger = get_logger(__name__)


class SecurityEventTracker:
    """
    Tracks security events in a privacy-compliant manner.
    No PII is stored in security events.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        rate_limit_config: Optional[RateLimitConfig] = None,
    ) -> None:
        """
        Initialize security event tracker.

        Args:
            db_path: Path to SQLite database (uses memory if None)
            rate_limit_config: Rate limiting configuration
        """
        self.db_path = db_path or ":memory:"
        self._lock = Lock()
        self._rate_limiter = SecurityEventRateLimiter(rate_limit_config)
        self._rate_limited_events = 0
        self._init_database()

    def _init_database(self) -> None:
        """Initialize SQLite database for security events."""
        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with self._get_db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Create indexes separately
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events (timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_type_severity ON security_events (event_type, severity)"
            )

    @contextmanager
    def _get_db(self) -> None:
        """Get database connection context manager."""
        conn = sqlite3.connect(self.db_path, check_same_thread=DB_CHECK_SAME_THREAD)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    async def record_event(self, event: SecurityEvent) -> int:
        """
        Record a security event.

        Args:
            event: Security event to record

        Returns:
            Event ID (-1 if rate limited)
        """
        # Check rate limit
        if not self._rate_limiter.should_allow_event(event.event_type.value):
            self._rate_limited_events += 1
            logger.warning(
                "Security event rate limited",
                event_type=event.event_type.value,
                severity=event.severity.value,
                rate_limited_count=self._rate_limited_events,
            )
            return -1

        try:
            with self._lock:
                with self._get_db() as conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO security_events 
                        (event_type, severity, details, timestamp)
                        VALUES (?, ?, ?, ?)
                    """,
                        (
                            event.event_type.value,
                            event.severity.value,
                            json.dumps(event.details),
                            event.timestamp,
                        ),
                    )
                    event_id = cursor.lastrowid

            logger.info(
                "Security event recorded",
                event_type=event.event_type.value,
                severity=event.severity.value,
                event_id=event_id,
            )

            return event_id

        except Exception as e:
            logger.error(f"Failed to record security event: {e}")
            return -1

    def get_event_summary(
        self, hours: int = DEFAULT_MONITORING_HOURS
    ) -> SecurityEventSummary:
        """
        Get summary of security events.

        Args:
            hours: Number of hours to look back

        Returns:
            Security event summary
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)

        with self._get_db() as conn:
            # Get total events
            cursor = conn.execute(
                """
                SELECT COUNT(*) as total
                FROM security_events
                WHERE timestamp > ?
            """,
                (cutoff_time,),
            )
            total_events = cursor.fetchone()["total"]

            # Get events by type
            events_by_type = {}
            cursor = conn.execute(
                """
                SELECT event_type, COUNT(*) as count
                FROM security_events
                WHERE timestamp > ?
                GROUP BY event_type
            """,
                (cutoff_time,),
            )
            for row in cursor:
                events_by_type[row["event_type"]] = row["count"]

            # Get events by severity
            events_by_severity = {}
            cursor = conn.execute(
                """
                SELECT severity, COUNT(*) as count
                FROM security_events
                WHERE timestamp > ?
                GROUP BY severity
            """,
                (cutoff_time,),
            )
            for row in cursor:
                events_by_severity[row["severity"]] = row["count"]

            # Get recent violations
            recent_violations = []
            cursor = conn.execute(
                """
                SELECT event_type, severity, details, timestamp
                FROM security_events
                WHERE timestamp > ? AND event_type = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (
                    cutoff_time,
                    SecurityEventType.VIOLATION.value,
                    MAX_RECENT_EVENTS_DISPLAY,
                ),
            )

            for row in cursor:
                recent_violations.append(
                    {
                        "event_type": row["event_type"],
                        "severity": row["severity"],
                        "details": json.loads(row["details"]) if row["details"] else {},
                        "timestamp": row["timestamp"],
                    }
                )

        return SecurityEventSummary(
            time_period_hours=hours,
            total_events=total_events,
            events_by_type=events_by_type,
            events_by_severity=events_by_severity,
            recent_violations=recent_violations,
        )

    async def record_sandbox_event(
        self,
        event_type: str,
        severity: SecuritySeverity = SecuritySeverity.INFO,
        **details,
    ) -> int:
        """
        Record a sandbox-related security event.

        Args:
            event_type: Type of sandbox event
            severity: Event severity
            **details: Event details (must not contain PII)

        Returns:
            Event ID
        """
        # Map to proper event type
        if event_type == "create":
            evt_type = SecurityEventType.SANDBOX_CREATE
        elif event_type == "destroy":
            evt_type = SecurityEventType.SANDBOX_DESTROY
        elif event_type == "violation":
            evt_type = SecurityEventType.VIOLATION
        else:
            evt_type = SecurityEventType.VIOLATION

        event = SecurityEvent(event_type=evt_type, severity=severity, details=details)

        return await self.record_event(event)

    async def record_metadata_event(
        self, removed_fields: List[str], input_format: str
    ) -> int:
        """
        Record metadata stripping event.

        Args:
            removed_fields: List[Any] of metadata fields removed (generic names only)
            input_format: Input image format

        Returns:
            Event ID
        """
        event = SecurityEvent(
            event_type=SecurityEventType.METADATA_STRIP,
            severity=SecuritySeverity.INFO,
            details={
                "removed_fields": removed_fields,
                "field_count": len(removed_fields),
                "input_format": input_format,
            },
        )

        return await self.record_event(event)

    async def record_resource_limit_event(
        self, resource_type: str, limit: float, attempted: float, unit: str
    ) -> int:
        """
        Record resource limit violation.

        Args:
            resource_type: Type of resource (memory, cpu, time)
            limit: Resource limit
            attempted: Attempted usage
            unit: Unit of measurement

        Returns:
            Event ID
        """
        event = SecurityEvent(
            event_type=SecurityEventType.RESOURCE_LIMIT,
            severity=SecuritySeverity.WARNING,
            details={
                "resource_type": resource_type,
                "limit": limit,
                "attempted": attempted,
                "unit": unit,
                "exceeded_by": attempted - limit,
            },
        )

        return await self.record_event(event)

    async def cleanup_old_events(
        self, retention_days: int = SECURITY_EVENT_RETENTION_DAYS
    ):
        """
        Clean up old security events.

        Args:
            retention_days: Days to retain events
        """
        cutoff_time = datetime.now() - timedelta(days=retention_days)

        try:
            with self._get_db() as conn:
                cursor = conn.execute(
                    """
                    DELETE FROM security_events
                    WHERE timestamp < ?
                """,
                    (cutoff_time,),
                )

                deleted_count = cursor.rowcount

            logger.info(
                "Cleaned up old security events",
                deleted_count=deleted_count,
                retention_days=retention_days,
            )

        except Exception as e:
            logger.error(f"Failed to cleanup security events: {e}")

    def get_violation_trends(self, days: int = 7) -> Dict[str, Any]:
        """
        Get violation trends over time.

        Args:
            days: Number of days to analyze

        Returns:
            Violation trend data
        """
        cutoff_time = datetime.now() - timedelta(days=days)

        with self._get_db() as conn:
            # Get daily violation counts
            cursor = conn.execute(
                """
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(*) as count,
                    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count
                FROM security_events
                WHERE timestamp > ? AND event_type = ?
                GROUP BY DATE(timestamp)
                ORDER BY date
            """,
                (cutoff_time, SecurityEventType.VIOLATION.value),
            )

            daily_counts = []
            for row in cursor:
                daily_counts.append(
                    {
                        "date": row["date"],
                        "total": row["count"],
                        "critical": row["critical_count"],
                    }
                )

            # Get violation types
            cursor = conn.execute(
                """
                SELECT 
                    json_extract(details, '$.violation_type') as violation_type,
                    COUNT(*) as count
                FROM security_events
                WHERE timestamp > ? AND event_type = ?
                GROUP BY violation_type
                ORDER BY count DESC
            """,
                (cutoff_time, SecurityEventType.VIOLATION.value),
            )

            violation_types = {}
            for row in cursor:
                if row["violation_type"]:
                    violation_types[row["violation_type"]] = row["count"]

        return {
            "period_days": days,
            "daily_violations": daily_counts,
            "violation_types": violation_types,
            "trend": (
                "increasing"
                if len(daily_counts) > 1
                and daily_counts[-1]["total"] > daily_counts[0]["total"]
                else "stable"
            ),
        }

    def get_rate_limit_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        stats = self._rate_limiter.get_stats()
        stats["rate_limited_events_total"] = self._rate_limited_events
        return stats
