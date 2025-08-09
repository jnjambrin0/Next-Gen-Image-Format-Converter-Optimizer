"""
Unit tests for simplified security error handling.
"""

import asyncio

import pytest

from app.core.security.errors import (
    SecurityError,
    SecurityErrorHandler,
    create_file_error,
    create_network_error,
    create_rate_limit_error,
    create_sandbox_error,
    create_verification_error,
    handle_security_errors,
)


class TestSecurityError:
    """Test simplified SecurityError class."""

    def test_basic_security_error(self):
        """Test creating basic security error."""
        error = SecurityError("network", {"reason": "test"})
        assert error.category == "network"
        assert error.details == {"reason": "test"}
        assert str(error) == "Network access violation"

    def test_custom_message(self):
        """Test security error with custom message."""
        error = SecurityError("sandbox", {"test": "data"}, "Custom error message")
        assert error.category == "sandbox"
        assert error.details == {"test": "data"}
        assert str(error) == "Custom error message"

    def test_unknown_category(self):
        """Test security error with unknown category."""
        error = SecurityError("unknown_category", {})
        assert error.category == "unknown_category"
        assert str(error) == "Security violation"


class TestErrorFactories:
    """Test error factory functions."""

    def test_create_network_error(self):
        """Test network error creation."""
        error = create_network_error("dns_blocked", host="example.com")
        assert error.category == "network"
        assert error.details["reason"] == "dns_blocked"
        assert error.details["host"] == "example.com"

    def test_create_sandbox_error(self):
        """Test sandbox error creation."""
        error = create_sandbox_error("memory_limit", usage=512)
        assert error.category == "sandbox"
        assert error.details["reason"] == "memory_limit"
        assert error.details["usage"] == 512

    def test_create_rate_limit_error(self):
        """Test rate limit error creation."""
        error = create_rate_limit_error("api_request", limit=100)
        assert error.category == "rate_limit"
        assert error.details["limit_type"] == "api_request"
        assert error.details["limit"] == 100

    def test_create_verification_error(self):
        """Test verification error creation."""
        error = create_verification_error("network_check")
        assert error.category == "verification"
        assert error.details["check_type"] == "network_check"

    def test_create_file_error(self):
        """Test file error creation."""
        error = create_file_error("write", reason="permission_denied")
        assert error.category == "file"
        assert error.details["operation"] == "write"
        assert error.details["reason"] == "permission_denied"


class TestSecurityErrorHandler:
    """Test SecurityErrorHandler class."""

    def test_handle_security_error(self):
        """Test handling SecurityError."""
        error = create_network_error("test")
        handler = SecurityErrorHandler()
        result = handler.handle_error(error)

        assert result["error"] == "security_violation"
        assert result["category"] == "network"
        assert result["message"] == "Network access violation"
        assert result["details"]["reason"] == "test"

    def test_handle_timeout_error(self):
        """Test handling TimeoutError."""
        handler = SecurityErrorHandler()
        result = handler.handle_error(TimeoutError("Test timeout"))

        assert result["error"] == "security_violation"
        assert result["category"] == "sandbox"
        assert result["message"] == "Sandbox security violation"
        assert result["details"]["reason"] in ["timeout", "async_timeout"]

    def test_handle_memory_error(self):
        """Test handling MemoryError."""
        handler = SecurityErrorHandler()
        result = handler.handle_error(MemoryError("Out of memory"))

        assert result["error"] == "security_violation"
        assert result["category"] == "sandbox"
        assert result["message"] == "Sandbox security violation"
        assert result["details"]["reason"] == "memory_limit"

    def test_handle_permission_error(self):
        """Test handling PermissionError."""
        handler = SecurityErrorHandler()
        result = handler.handle_error(PermissionError("Access denied"))

        assert result["error"] == "security_violation"
        assert result["category"] == "file"
        assert result["message"] == "File security violation"
        assert result["details"]["reason"] == "permission_denied"

    def test_handle_unknown_error(self):
        """Test handling unknown error."""
        handler = SecurityErrorHandler()
        result = handler.handle_error(ValueError("Some error"))

        assert result["error"] == "security_violation"
        assert result["category"] == "unknown"
        assert result["message"] == "Security check failed"
        assert result["details"] == {}


class TestSecurityErrorDecorator:
    """Test handle_security_errors decorator."""

    @pytest.mark.asyncio
    async def test_decorator_passes_security_errors(self):
        """Test decorator re-raises SecurityError as-is."""

        @handle_security_errors
        async def test_func():
            raise create_network_error("test")

        with pytest.raises(SecurityError) as exc_info:
            await test_func()

        assert exc_info.value.category == "network"

    @pytest.mark.asyncio
    async def test_decorator_converts_other_errors(self):
        """Test decorator converts other errors to SecurityError."""

        @handle_security_errors
        async def test_func():
            raise TimeoutError("Test timeout")

        with pytest.raises(SecurityError) as exc_info:
            await test_func()

        assert exc_info.value.category == "sandbox"
        assert exc_info.value.details["reason"] in ["timeout", "async_timeout"]

    @pytest.mark.asyncio
    async def test_decorator_successful_execution(self):
        """Test decorator allows successful execution."""

        @handle_security_errors
        async def test_func():
            return "success"

        result = await test_func()
        assert result == "success"
