"""
Unit tests for security error handling.
"""

import pytest
import asyncio
from unittest.mock import patch

from app.core.security.errors import (
    SecurityError,
    SecurityErrorCode,
    NetworkSecurityError,
    SandboxSecurityError,
    RateLimitError,
    VerificationError,
    MemorySecurityError,
    create_network_error,
    create_sandbox_error,
    create_verification_error,
    SecurityErrorHandler,
    handle_security_errors
)


class TestSecurityError:
    """Test base SecurityError class."""
    
    def test_basic_security_error(self):
        """Test creating basic security error."""
        error = SecurityError(
            code=SecurityErrorCode.UNKNOWN_SECURITY_ERROR,
            message="Test error",
            details={"key": "value"}
        )
        
        assert error.code == SecurityErrorCode.UNKNOWN_SECURITY_ERROR
        assert error.message == "Test error"
        assert error.details == {"key": "value"}
        assert str(error) == "[SEC999] Test error"
    
    def test_error_with_cause(self):
        """Test security error with underlying cause."""
        cause = ValueError("Original error")
        error = SecurityError(
            code=SecurityErrorCode.SANDBOX_VIOLATION,
            message="Sandbox violation detected",
            cause=cause
        )
        
        assert error.cause == cause
        assert error.code == SecurityErrorCode.SANDBOX_VIOLATION
    
    def test_to_dict(self):
        """Test converting error to dictionary."""
        error = SecurityError(
            code=SecurityErrorCode.NETWORK_ACCESS_DENIED,
            message="Network access denied",
            details={"target": "example.com", "port": 443}
        )
        
        data = error.to_dict()
        assert data["error"] == "security_error"
        assert data["code"] == "SEC001"
        assert data["message"] == "Network access denied"
        assert data["details"]["target"] == "example.com"
        assert data["details"]["port"] == 443


class TestSpecificErrors:
    """Test specific error subclasses."""
    
    def test_network_security_error(self):
        """Test network security error."""
        error = NetworkSecurityError(
            code=SecurityErrorCode.DNS_RESOLUTION_BLOCKED,
            message="DNS resolution blocked",
            details={"domain": "example.com"}
        )
        
        assert isinstance(error, SecurityError)
        assert error.code == SecurityErrorCode.DNS_RESOLUTION_BLOCKED
        assert error.details["domain"] == "example.com"
    
    def test_sandbox_security_error(self):
        """Test sandbox security error."""
        error = SandboxSecurityError(
            code=SecurityErrorCode.SANDBOX_TIMEOUT,
            message="Process timeout",
            details={"timeout": 30, "pid": 1234}
        )
        
        assert isinstance(error, SecurityError)
        assert error.code == SecurityErrorCode.SANDBOX_TIMEOUT
        assert error.details["timeout"] == 30
    
    def test_rate_limit_error(self):
        """Test rate limit error with retry_after."""
        error = RateLimitError(
            message="Too many requests",
            retry_after=60
        )
        
        assert error.code == SecurityErrorCode.RATE_LIMIT_EXCEEDED
        assert error.details["retry_after"] == 60
        assert error.message == "Too many requests"
    
    def test_verification_error(self):
        """Test verification error."""
        error = VerificationError(
            code=SecurityErrorCode.VERIFICATION_FAILED,
            message="Network verification failed",
            details={"check": "dns_blocking"}
        )
        
        assert isinstance(error, SecurityError)
        assert error.code == SecurityErrorCode.VERIFICATION_FAILED
    
    def test_memory_security_error(self):
        """Test memory security error."""
        error = MemorySecurityError(
            code=SecurityErrorCode.MEMORY_LOCK_FAILED,
            message="Failed to lock memory pages",
            details={"size": 1024}
        )
        
        assert isinstance(error, SecurityError)
        assert error.code == SecurityErrorCode.MEMORY_LOCK_FAILED


class TestErrorFactories:
    """Test error factory functions."""
    
    def test_create_network_error(self):
        """Test creating network error."""
        error = create_network_error(
            "Connection refused",
            code=SecurityErrorCode.NETWORK_ACCESS_DENIED,
            host="example.com",
            port=443
        )
        
        assert isinstance(error, NetworkSecurityError)
        assert error.message == "Connection refused"
        assert error.code == SecurityErrorCode.NETWORK_ACCESS_DENIED
        assert error.details["host"] == "example.com"
        assert error.details["port"] == 443
    
    def test_create_sandbox_error(self):
        """Test creating sandbox error."""
        error = create_sandbox_error(
            "Memory limit exceeded",
            code=SecurityErrorCode.SANDBOX_MEMORY_VIOLATION,
            limit_mb=512,
            used_mb=600
        )
        
        assert isinstance(error, SandboxSecurityError)
        assert error.message == "Memory limit exceeded"
        assert error.code == SecurityErrorCode.SANDBOX_MEMORY_VIOLATION
        assert error.details["limit_mb"] == 512
    
    def test_create_verification_error(self):
        """Test creating verification error."""
        error = create_verification_error(
            "DNS check failed",
            code=SecurityErrorCode.VERIFICATION_FAILED,
            check_type="dns"
        )
        
        assert isinstance(error, VerificationError)
        assert error.message == "DNS check failed"
        assert error.details["check_type"] == "dns"


class TestSecurityErrorHandler:
    """Test SecurityErrorHandler class."""
    
    def test_handle_security_error(self):
        """Test handling SecurityError."""
        handler = SecurityErrorHandler()
        
        error = create_network_error(
            "Network blocked",
            target_ip="192.168.1.1"
        )
        
        response = handler.handle_error(error, {"request_id": "req-123"})
        
        assert response["error"] == "security_error"
        assert response["code"] == "SEC001"
        assert response["message"] == "Network blocked"
        assert response["request_id"] == "req-123"
        assert response["details"]["target_ip"] == "192.168.1.1"
    
    def test_handle_timeout_error(self):
        """Test handling standard TimeoutError."""
        handler = SecurityErrorHandler()
        
        error = TimeoutError("Operation timed out")
        response = handler.handle_error(error)
        
        assert response["code"] == "SEC041"  # SANDBOX_TIMEOUT
        assert response["message"] == "Operation timed out"
    
    def test_handle_memory_error(self):
        """Test handling standard MemoryError."""
        handler = SecurityErrorHandler()
        
        error = MemoryError("Out of memory")
        response = handler.handle_error(error)
        
        assert response["code"] == "SEC042"  # SANDBOX_MEMORY_VIOLATION
        assert response["message"] == "Memory limit exceeded"
    
    def test_handle_permission_error(self):
        """Test handling PermissionError."""
        handler = SecurityErrorHandler()
        
        error = PermissionError("Access denied")
        response = handler.handle_error(error)
        
        assert response["code"] == "SEC051"  # INVALID_FILE_ACCESS
        assert response["message"] == "Permission denied"
    
    def test_handle_unknown_error(self):
        """Test handling unknown error types."""
        handler = SecurityErrorHandler()
        
        error = RuntimeError("Something went wrong")
        response = handler.handle_error(error)
        
        assert response["code"] == "SEC999"  # UNKNOWN_SECURITY_ERROR
        assert response["message"] == "An unexpected security error occurred"
    
    def test_error_statistics(self):
        """Test error statistics tracking."""
        handler = SecurityErrorHandler()
        
        # Generate some errors
        for _ in range(3):
            handler.handle_error(
                create_network_error("Network error")
            )
        
        for _ in range(2):
            handler.handle_error(
                create_sandbox_error("Sandbox error")
            )
        
        stats = handler.get_error_stats()
        assert stats["SEC001"] == 3  # Network errors
        assert stats["SEC040"] == 2  # Sandbox errors


class TestErrorDecorator:
    """Test handle_security_errors decorator."""
    
    def test_sync_function_decorator(self):
        """Test decorator on synchronous function."""
        @handle_security_errors(
            default_code=SecurityErrorCode.SANDBOX_VIOLATION,
            default_message="Function failed"
        )
        def risky_function():
            raise ValueError("Something bad")
        
        with pytest.raises(SecurityError) as exc_info:
            risky_function()
        
        assert exc_info.value.code == SecurityErrorCode.SANDBOX_VIOLATION
        assert exc_info.value.message == "Function failed"
        assert isinstance(exc_info.value.cause, ValueError)
    
    def test_async_function_decorator(self):
        """Test decorator on async function."""
        @handle_security_errors(
            default_code=SecurityErrorCode.NETWORK_ACCESS_DENIED,
            default_message="Async function failed"
        )
        async def async_risky_function():
            raise ConnectionError("Network error")
        
        with pytest.raises(SecurityError) as exc_info:
            asyncio.run(async_risky_function())
        
        assert exc_info.value.code == SecurityErrorCode.NETWORK_ACCESS_DENIED
        assert exc_info.value.message == "Async function failed"
        assert isinstance(exc_info.value.cause, ConnectionError)
    
    def test_decorator_preserves_security_errors(self):
        """Test decorator doesn't wrap existing SecurityError."""
        @handle_security_errors()
        def function_with_security_error():
            raise create_sandbox_error("Original error")
        
        with pytest.raises(SandboxSecurityError) as exc_info:
            function_with_security_error()
        
        assert exc_info.value.message == "Original error"
        assert exc_info.value.code == SecurityErrorCode.SANDBOX_VIOLATION


class TestFormatTraceback:
    """Test traceback formatting."""
    
    def test_format_traceback_privacy(self):
        """Test traceback formatting removes sensitive paths."""
        try:
            raise ValueError("Test error")
        except ValueError as e:
            formatted = SecurityErrorHandler.format_traceback(e, limit=2)
            
            # Should not contain full paths
            assert "/home/" not in formatted
            assert "/Users/" not in formatted
            
            # Should contain error type and message
            assert "ValueError" in formatted
            assert "Test error" in formatted


class TestErrorCodes:
    """Test error code enum."""
    
    def test_error_code_uniqueness(self):
        """Test all error codes are unique."""
        codes = [code.value for code in SecurityErrorCode]
        assert len(codes) == len(set(codes))
    
    def test_error_code_format(self):
        """Test error codes follow format."""
        for code in SecurityErrorCode:
            assert code.value.startswith("SEC")
            assert len(code.value) == 6  # SECXXX