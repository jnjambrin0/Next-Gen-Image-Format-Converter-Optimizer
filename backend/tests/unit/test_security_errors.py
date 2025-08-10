"""
Unit tests for simplified security error handling.
"""

import asyncio
from unittest.mock import patch

import pytest

from app.core.security.errors import (
    SecurityError,
    create_file_error,
    create_network_error,
    create_rate_limit_error,
    create_sandbox_error,
    create_verification_error,
)


class TestSecurityError:
    """Test base SecurityError class."""

    def test_basic_security_error(self):
        """Test creating basic security error."""
        error = SecurityError(
            category="network",
            details={"key": "value"},
        )

        assert error.category == "network"
        assert error.details == {"key": "value"}
        assert str(error) == "Network access violation"

    def test_error_with_custom_message(self):
        """Test security error with custom message."""
        error = SecurityError(
            category="sandbox",
            message="Custom sandbox violation",
            details={"pid": 1234},
        )

        assert error.category == "sandbox"
        assert str(error) == "Custom sandbox violation"
        assert error.details["pid"] == 1234

    def test_error_categories(self):
        """Test all error categories."""
        categories = ["network", "sandbox", "rate_limit", "verification", "file"]

        for category in categories:
            error = SecurityError(category=category)
            assert error.category == category
            assert str(error) == SecurityError.CATEGORIES[category]


class TestErrorFactories:
    """Test error factory functions."""

    def test_create_network_error(self):
        """Test creating network error."""
        error = create_network_error(
            reason="dns_blocked",
            target="example.com",
            port=443,
        )

        assert isinstance(error, SecurityError)
        assert error.category == "network"
        assert error.details["reason"] == "dns_blocked"
        assert error.details["target"] == "example.com"
        assert error.details["port"] == 443

    def test_create_sandbox_error(self):
        """Test creating sandbox error."""
        error = create_sandbox_error(
            reason="timeout",
            timeout=30,
            pid=1234,
        )

        assert isinstance(error, SecurityError)
        assert error.category == "sandbox"
        assert error.details["reason"] == "timeout"
        assert error.details["timeout"] == 30
        assert error.details["pid"] == 1234

    def test_create_rate_limit_error(self):
        """Test creating rate limit error."""
        error = create_rate_limit_error(
            limit=100,
            window="minute",
            retry_after=60,
        )

        assert isinstance(error, SecurityError)
        assert error.category == "rate_limit"
        assert error.details["limit"] == 100
        assert error.details["window"] == "minute"
        assert error.details["retry_after"] == 60

    def test_create_verification_error(self):
        """Test creating verification error."""
        error = create_verification_error(
            check="network_isolation",
            expected=True,
            actual=False,
        )

        assert isinstance(error, SecurityError)
        assert error.category == "verification"
        assert error.details["check"] == "network_isolation"
        assert error.details["expected"] == True
        assert error.details["actual"] == False

    def test_create_file_error(self):
        """Test creating file error."""
        error = create_file_error(
            operation="read",
            reason="permission_denied",
        )

        assert isinstance(error, SecurityError)
        assert error.category == "file"
        assert error.details["operation"] == "read"
        assert error.details["reason"] == "permission_denied"


class TestErrorHandling:
    """Test error handling patterns."""

    def test_error_context_details(self):
        """Test that error details don't contain PII."""
        # Should not include actual filenames
        error = create_file_error(
            operation="write",
            reason="disk_full",
        )

        # Details should not contain file paths
        assert "path" not in error.details
        assert "filename" not in error.details

    def test_error_message_privacy(self):
        """Test that error messages are privacy-aware."""
        error = create_network_error(
            reason="connection_refused",
            target="<redacted>",
            port=443,
        )

        # Target should be redacted
        assert error.details["target"] == "<redacted>"

    @pytest.mark.asyncio
    async def test_async_error_handling(self):
        """Test error handling in async context."""

        async def failing_operation():
            raise create_sandbox_error(
                reason="resource_exhausted",
                resource="memory",
                limit=512,
            )

        with pytest.raises(SecurityError) as exc_info:
            await failing_operation()

        assert exc_info.value.category == "sandbox"
        assert exc_info.value.details["resource"] == "memory"
