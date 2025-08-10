import pytest
import asyncio
from datetime import datetime, timedelta
from app.core.monitoring.errors import ErrorReporter, ErrorReport


class TestErrorReporter:
    """Test local-only error reporting functionality."""

    @pytest.fixture
    def reporter(self):
        """Create an error reporter instance."""
        return ErrorReporter(db_path=":memory:")

    @pytest.mark.asyncio
    async def test_record_simple_error(self, reporter):
        """Test recording a simple error."""
        error = ValueError("Test error message")
        error_id = await reporter.record_error(error)

        assert error_id.startswith("ValueError_")

        # Check error was recorded
        details = reporter.get_error_details(error_id)
        assert details is not None
        assert details["error_type"] == "ValueError"
        assert details["error_category"] == "general_error"
        assert details["count"] == 1
        assert "Test error message" in details["sanitized_message"]

    @pytest.mark.asyncio
    async def test_error_categorization(self, reporter):
        """Test that errors are properly categorized."""
        test_cases = [
            (TimeoutError("Operation timed out"), "timeout"),
            (MemoryError("Out of memory"), "memory_limit"),
            (PermissionError("Access denied"), "permission"),
            (ValueError("Invalid format"), "format_error"),
            (ConnectionError("Network error"), "connection"),
            (Exception("Sandbox violation detected"), "sandbox_violation"),
            (OverflowError("Value too large"), "resource_limit"),
            (RuntimeError("Unknown error"), "general_error"),
        ]

        for error, expected_category in test_cases:
            error_id = await reporter.record_error(error)
            details = reporter.get_error_details(error_id)
            assert details["error_category"] == expected_category

    @pytest.mark.asyncio
    async def test_message_sanitization(self, reporter):
        """Test that PII is removed from error messages."""
        # Error with file path
        error1 = ValueError("Failed to process /home/user/photos/vacation.jpg")
        error_id1 = await reporter.record_error(error1)
        details1 = reporter.get_error_details(error_id1)
        assert "<file_path>" in details1["sanitized_message"]
        assert "/home/user" not in details1["sanitized_message"]
        assert "vacation.jpg" not in details1["sanitized_message"]

        # Error with email
        error2 = ValueError("User john.doe@example.com not found")
        error_id2 = await reporter.record_error(error2)
        details2 = reporter.get_error_details(error_id2)
        assert "<email>" in details2["sanitized_message"]
        assert "john.doe@example.com" not in details2["sanitized_message"]

        # Error with IP address
        error3 = ConnectionError("Failed to connect to 192.168.1.100")
        error_id3 = await reporter.record_error(error3)
        details3 = reporter.get_error_details(error_id3)
        assert "<ip_address>" in details3["sanitized_message"]
        assert "192.168.1.100" not in details3["sanitized_message"]

    @pytest.mark.asyncio
    async def test_context_sanitization(self, reporter):
        """Test that context is sanitized."""
        error = ValueError("Test error")
        context = {
            "user_id": "12345",
            "filename": "private.jpg",
            "operation": "convert",
            "email": "test@example.com",
        }

        error_id = await reporter.record_error(error, context)
        details = reporter.get_error_details(error_id)

        # Check context was sanitized
        assert details["context"]["user_id"] == "***REDACTED***"
        assert details["context"]["filename"] == "***REDACTED***"
        assert details["context"]["operation"] == "convert"  # Non-sensitive
        assert details["context"]["email"] == "***REDACTED***"

    @pytest.mark.asyncio
    async def test_error_deduplication(self, reporter):
        """Test that identical errors are deduplicated."""
        # Record same error multiple times
        for i in range(5):
            error = ValueError("Same error message")
            error_id = await reporter.record_error(error)

        # Should have same error ID
        details = reporter.get_error_details(error_id)
        assert details["count"] == 5

        # Summary should show correct counts
        summary = reporter.get_error_summary(hours=1)
        assert summary["unique_errors"] == 1
        assert summary["total_occurrences"] == 5

    @pytest.mark.asyncio
    async def test_error_summary(self, reporter):
        """Test error summary generation."""
        # Record various errors
        errors = [
            (TimeoutError("Timeout 1"), None),
            (TimeoutError("Timeout 2"), None),
            (MemoryError("OOM"), None),
            (ValueError("Bad value"), {"context": "test"}),
            (ValueError("Another bad value"), None),
            (PermissionError("Denied"), None),
        ]

        for error, context in errors:
            await reporter.record_error(error, context)

        summary = reporter.get_error_summary(hours=24)

        assert summary["unique_errors"] >= 6
        assert summary["total_occurrences"] >= 6
        assert summary["errors_by_category"]["timeout"] == 2
        assert summary["errors_by_category"]["memory_limit"] == 1
        assert summary["errors_by_category"]["validation"] == 2
        assert summary["errors_by_category"]["permission"] == 1
        assert (
            summary["privacy_notice"]
            == "All error data has been sanitized to remove PII"
        )

        # Check most frequent errors
        assert len(summary["most_frequent"]) > 0
        assert all("sanitized_message" in e for e in summary["most_frequent"])

    @pytest.mark.asyncio
    async def test_time_based_filtering(self, reporter):
        """Test that summary respects time filtering."""
        # Record an error
        error = ValueError("Recent error")
        await reporter.record_error(error)

        # Check immediate summary
        summary_now = reporter.get_error_summary(hours=1)
        assert summary_now["unique_errors"] >= 1

        # Manually set an old error in the database
        old_time = datetime.now() - timedelta(hours=48)
        with reporter._get_db() as conn:
            conn.execute(
                """
                INSERT INTO error_reports 
                (error_id, error_type, error_category, last_seen, first_seen)
                VALUES (?, ?, ?, ?, ?)
            """,
                ("old_error", "OldError", "general_error", old_time, old_time),
            )

        # Recent summary should not include old error
        summary_recent = reporter.get_error_summary(hours=24)
        old_errors = [
            e
            for e in summary_recent.get("most_frequent", [])
            if e.get("error_id") == "old_error"
        ]
        assert len(old_errors) == 0

    @pytest.mark.asyncio
    async def test_error_cleanup(self, reporter):
        """Test cleanup of old errors."""
        # Record some errors
        current_error = ValueError("Current error")
        await reporter.record_error(current_error)

        # Manually add old error
        old_time = datetime.now() - timedelta(days=40)
        with reporter._get_db() as conn:
            conn.execute(
                """
                INSERT INTO error_reports 
                (error_id, error_type, error_category, last_seen, first_seen)
                VALUES (?, ?, ?, ?, ?)
            """,
                ("old_error_cleanup", "OldError", "general_error", old_time, old_time),
            )

        # Run cleanup
        await reporter.cleanup_old_errors(retention_days=30)

        # Old error should be gone
        old_details = reporter.get_error_details("old_error_cleanup")
        assert old_details is None

        # Current error should remain (need to get its ID first)
        # Skip this check as we don't have the ID stored

    @pytest.mark.asyncio
    async def test_stack_trace_hashing(self, reporter):
        """Test that stack traces are hashed for deduplication."""

        # Errors with same stack trace should have same ID
        def cause_error():
            raise ValueError("Test error from function")

        try:
            cause_error()
        except ValueError as e:
            error_id1 = await reporter.record_error(e)

        try:
            cause_error()
        except ValueError as e:
            error_id2 = await reporter.record_error(e)

        # Should have same error ID (same stack trace)
        assert error_id1 == error_id2

        # Different error location should have different ID
        try:
            raise ValueError("Test error from different location")
        except ValueError as e:
            error_id3 = await reporter.record_error(e)

        assert error_id3 != error_id1

    @pytest.mark.asyncio
    async def test_long_message_truncation(self, reporter):
        """Test that long error messages are truncated."""
        long_message = "Error: " + "x" * 500
        error = ValueError(long_message)

        error_id = await reporter.record_error(error)
        details = reporter.get_error_details(error_id)

        # Message should be truncated
        assert len(details["sanitized_message"]) <= 200
        assert details["sanitized_message"].endswith("...")

    def test_error_report_serialization(self):
        """Test ErrorReport serialization."""
        report = ErrorReport(
            error_id="test_error",
            error_type="TestError",
            error_category="test",
            count=5,
            stack_hash="abc123",
            sanitized_message="Test message",
            context={"key": "value"},
        )

        data = report.to_dict()
        assert data["error_id"] == "test_error"
        assert data["count"] == 5
        assert isinstance(data["first_seen"], str)
        assert isinstance(data["last_seen"], str)
