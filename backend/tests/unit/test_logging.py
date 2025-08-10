import json
import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from app.utils.logging import (
    LoggingContext,
    add_correlation_id,
    filter_sensitive_data,
    get_logger,
    setup_logging,
)


class TestLoggingConfiguration:
    """Test logging configuration and utilities."""

    def test_setup_logging_json(self):
        """Test JSON logging setup."""
        with patch("structlog.configure") as mock_configure:
            setup_logging(log_level="INFO", json_logs=True)

            mock_configure.assert_called_once()
            args, kwargs = mock_configure.call_args

            # Check that JSON renderer is used
            processors = kwargs["processors"]
            processor_names = [
                p.__name__ if hasattr(p, "__name__") else str(p) for p in processors
            ]
            assert any("JSONRenderer" in name for name in processor_names)

    def test_setup_logging_console(self):
        """Test console logging setup."""
        with patch("structlog.configure") as mock_configure:
            setup_logging(log_level="DEBUG", json_logs=False)

            mock_configure.assert_called_once()
            args, kwargs = mock_configure.call_args

            # Check that Console renderer is used
            processors = kwargs["processors"]
            processor_names = [
                p.__name__ if hasattr(p, "__name__") else str(p) for p in processors
            ]
            assert any("ConsoleRenderer" in name for name in processor_names)

    def test_filter_sensitive_data(self):
        """Test sensitive data filtering."""
        event_dict = {
            "message": "Test log",
            "password": "secret123",
            "api_key": "key123",
            "token": "token123",
            "file_path": "/path/to/file",
            "email": "user@example.com",
            "safe_field": "visible",
        }

        filtered = filter_sensitive_data(None, None, event_dict.copy())

        assert filtered["password"] == "***REDACTED***"
        assert filtered["api_key"] == "***REDACTED***"
        assert filtered["token"] == "***REDACTED***"
        assert filtered["file_path"] == "***REDACTED***"
        assert filtered["email"] == "***REDACTED***"
        assert filtered["safe_field"] == "visible"
        assert filtered["message"] == "Test log"

    def test_add_correlation_id_new(self):
        """Test correlation ID generation when not present."""
        event_dict = {"message": "Test log"}

        result = add_correlation_id(None, None, event_dict)

        assert "correlation_id" in result
        assert len(result["correlation_id"]) > 0
        # Should be a valid UUID format
        assert result["correlation_id"].count("-") == 4

    def test_add_correlation_id_existing(self):
        """Test correlation ID preservation when already present."""
        existing_id = "test-correlation-id-123"
        event_dict = {"message": "Test log", "correlation_id": existing_id}

        result = add_correlation_id(None, None, event_dict.copy())

        assert result["correlation_id"] == existing_id

    def test_get_logger(self):
        """Test logger creation."""
        logger = get_logger("test_logger")

        assert logger is not None
        # Should be a structlog bound logger
        assert hasattr(logger, "info")
        assert hasattr(logger, "error")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "warning")

    def test_logging_context_manager(self):
        """Test LoggingContext context manager."""
        with patch("structlog.contextvars.bind_contextvars") as mock_bind:
            with patch("structlog.contextvars.unbind_contextvars") as mock_unbind:
                mock_bind.return_value = "token123"

                with LoggingContext(user_id="123", request_id="req456"):
                    # Check that context variables are bound
                    assert mock_bind.call_count == 2

                    # Check the calls
                    calls = mock_bind.call_args_list
                    assert any(call[1] == {"user_id": "123"} for call in calls)
                    assert any(call[1] == {"request_id": "req456"} for call in calls)

                # Check that context variables are unbound
                assert mock_unbind.call_count == 2

    def test_logging_levels(self):
        """Test different logging levels."""
        test_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in test_levels:
            with patch("logging.basicConfig") as mock_config:
                setup_logging(log_level=level)

                mock_config.assert_called_once()
                args, kwargs = mock_config.call_args
                assert kwargs["level"] == getattr(logging, level)

    def test_noisy_logger_suppression(self):
        """Test that noisy loggers are suppressed."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            setup_logging()

            # Check that uvicorn.access logger is set to WARNING
            mock_get_logger.assert_any_call("uvicorn.access")
            mock_get_logger.assert_any_call("PIL")

            # Should set level to WARNING
            assert mock_logger.setLevel.call_count >= 2
            mock_logger.setLevel.assert_any_call(logging.WARNING)

    def test_sensitive_field_variations(self):
        """Test filtering of various sensitive field name variations."""
        event_dict = {
            "user_password": "secret",
            "API_KEY": "key123",
            "Token": "token123",
            "SECRET_KEY": "secret123",
            "authorization": "Bearer token",
            "FILE_PATH": "/secret/path",
            "UserEmail": "test@example.com",
            "ip_address": "192.168.1.1",
        }

        filtered = filter_sensitive_data(None, None, event_dict.copy())

        # All sensitive fields should be redacted
        for key in event_dict.keys():
            assert filtered[key] == "***REDACTED***"
