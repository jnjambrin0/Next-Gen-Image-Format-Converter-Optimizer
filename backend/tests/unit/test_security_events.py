import asyncio
from datetime import datetime, timedelta

import pytest

from app.core.monitoring.security_events import SecurityEventTracker
from app.models.security_event import SecurityEvent, SecurityEventType, SecuritySeverity


class TestSecurityEventTracker:
    """Test security event tracking functionality."""

    @pytest.fixture
    def tracker(self):
        """Create a security event tracker instance."""
        return SecurityEventTracker(db_path=":memory:")

    @pytest.mark.asyncio
    async def test_record_sandbox_create_event(self, tracker):
        """Test recording sandbox creation event."""
        event_id = await tracker.record_sandbox_event(
            event_type="create",
            severity=SecuritySeverity.INFO,
            conversion_id="test-123",
            strictness="standard",
            memory_limit_mb=512,
            cpu_limit_percent=80,
            timeout_seconds=30,
        )

        assert event_id > 0

        # Check event was recorded
        summary = tracker.get_event_summary(hours=1)
        assert summary.total_events >= 1
        assert SecurityEventType.SANDBOX_CREATE.value in summary.events_by_type

    @pytest.mark.asyncio
    async def test_record_violation_event(self, tracker):
        """Test recording security violation event."""
        event = SecurityEvent(
            event_type=SecurityEventType.VIOLATION,
            severity=SecuritySeverity.WARNING,
            details={
                "violation_type": "path_traversal",
                "attempted_path": "***PATH_REDACTED***",
                "sandbox_id": "test-sandbox",
            },
        )

        event_id = await tracker.record_event(event)
        assert event_id > 0

        # Check violation appears in summary
        summary = tracker.get_event_summary(hours=1)
        assert len(summary.recent_violations) > 0
        assert summary.recent_violations[0]["severity"] == "warning"

    @pytest.mark.asyncio
    async def test_record_metadata_stripping_event(self, tracker):
        """Test recording metadata stripping event."""
        removed_fields = ["GPS", "DateTime", "Make", "Model"]
        event_id = await tracker.record_metadata_event(
            removed_fields=removed_fields, input_format="jpeg"
        )

        assert event_id > 0

        summary = tracker.get_event_summary(hours=1)
        assert SecurityEventType.METADATA_STRIP.value in summary.events_by_type

    @pytest.mark.asyncio
    async def test_record_resource_limit_event(self, tracker):
        """Test recording resource limit violation."""
        event_id = await tracker.record_resource_limit_event(
            resource_type="memory", limit=256.0, attempted=512.0, unit="MB"
        )

        assert event_id > 0

        summary = tracker.get_event_summary(hours=1)
        assert SecurityEventType.RESOURCE_LIMIT.value in summary.events_by_type
        assert summary.events_by_severity.get("warning", 0) > 0

    @pytest.mark.asyncio
    async def test_event_summary_filtering(self, tracker):
        """Test that event summary respects time filtering."""
        # Record current event
        await tracker.record_sandbox_event(
            event_type="create", severity=SecuritySeverity.INFO
        )

        # Manually add old event
        old_time = datetime.now() - timedelta(hours=48)
        with tracker._get_db() as conn:
            conn.execute(
                """
                INSERT INTO security_events 
                (event_type, severity, details, timestamp)
                VALUES (?, ?, ?, ?)
            """,
                ("violation", "critical", "{}", old_time),
            )

        # Check 24-hour summary
        summary = tracker.get_event_summary(hours=24)
        assert summary.total_events == 1  # Only recent event
        assert "violation" not in summary.events_by_type

    @pytest.mark.asyncio
    async def test_violation_trends(self, tracker):
        """Test violation trend analysis."""
        # Record violations over several days
        now = datetime.now()

        # Add violations for trend analysis
        for days_ago in range(7, 0, -1):
            timestamp = now - timedelta(days=days_ago)
            for i in range(days_ago):  # Increasing violations
                with tracker._get_db() as conn:
                    conn.execute(
                        """
                        INSERT INTO security_events 
                        (event_type, severity, details, timestamp)
                        VALUES (?, ?, ?, ?)
                    """,
                        (
                            SecurityEventType.VIOLATION.value,
                            "warning",
                            '{"violation_type": "memory_limit"}',
                            timestamp,
                        ),
                    )

        trends = tracker.get_violation_trends(days=7)
        assert trends["period_days"] == 7
        assert len(trends["daily_violations"]) > 0
        assert "memory_limit" in trends["violation_types"]
        # Trend should be increasing based on our data
        assert trends["trend"] == "increasing"

    @pytest.mark.asyncio
    async def test_event_cleanup(self, tracker):
        """Test cleanup of old security events."""
        # Add current event
        await tracker.record_sandbox_event(
            event_type="create", severity=SecuritySeverity.INFO
        )

        # Add old event
        old_time = datetime.now() - timedelta(days=100)
        with tracker._get_db() as conn:
            conn.execute(
                """
                INSERT INTO security_events 
                (event_type, severity, timestamp)
                VALUES (?, ?, ?)
            """,
                ("old_event", "info", old_time),
            )

        # Run cleanup
        await tracker.cleanup_old_events(retention_days=90)

        # Check that old event is gone
        with tracker._get_db() as conn:
            cursor = conn.execute(
                """
                SELECT COUNT(*) as count 
                FROM security_events 
                WHERE event_type = 'old_event'
            """
            )
            assert cursor.fetchone()["count"] == 0

    @pytest.mark.asyncio
    async def test_event_details_privacy(self, tracker):
        """Test that event details don't contain PII."""
        # Try to record event with PII
        event = SecurityEvent(
            event_type=SecurityEventType.VIOLATION,
            severity=SecuritySeverity.CRITICAL,
            details={
                "violation_type": "unauthorized_access",
                "filename": "should_be_removed.jpg",
                "user_id": "12345",
                "ip_address": "192.168.1.1",
                "safe_field": "this_is_ok",
            },
        )

        event_id = await tracker.record_event(event)

        # Retrieve and check event
        with tracker._get_db() as conn:
            cursor = conn.execute(
                """
                SELECT details FROM security_events WHERE id = ?
            """,
                (event_id,),
            )
            row = cursor.fetchone()
            import json

            details = json.loads(row["details"])

            # PII should be filtered
            assert "filename" not in details
            assert "user_id" not in details
            assert "ip_address" not in details
            # Safe fields should remain
            assert details["safe_field"] == "this_is_ok"
            assert details["violation_type"] == "unauthorized_access"

    def test_event_summary_model(self):
        """Test SecurityEventSummary model."""
        from app.models.security_event import SecurityEventSummary

        summary = SecurityEventSummary(
            time_period_hours=24,
            total_events=100,
            events_by_type={"violation": 50, "scan": 30, "sandbox_create": 20},
            events_by_severity={"info": 60, "warning": 30, "critical": 10},
            recent_violations=[
                {
                    "event_type": "violation",
                    "severity": "critical",
                    "details": {"violation_type": "memory_limit"},
                    "timestamp": datetime.now().isoformat(),
                }
            ],
        )

        assert summary.privacy_notice == "All security events are logged without PII"
        assert summary.total_events == 100
        assert len(summary.recent_violations) == 1
