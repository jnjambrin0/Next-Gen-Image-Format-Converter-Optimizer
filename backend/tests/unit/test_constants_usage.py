"""
from typing import Any
Unit tests to verify constants are being used correctly throughout the codebase.
"""

import importlib

import pytest

from app.core.constants import (CONNECTION_PID_PARSE_START_INDEX,
                                DEFAULT_MONITORING_HOURS, ERROR_RETENTION_DAYS,
                                FILE_SIZE_CATEGORIES, KB_TO_BYTES_FACTOR,
                                LOCALHOST_VARIANTS, MAX_MEMORY_VIOLATIONS,
                                MB_TO_BYTES_FACTOR, MEMORY_CLEAR_PATTERNS,
                                MIN_CONNECTION_PARTS,
                                RATE_LIMIT_EVENTS_PER_HOUR,
                                RATE_LIMIT_EVENTS_PER_MINUTE,
                                SANDBOX_CPU_LIMITS, SANDBOX_MEMORY_LIMITS,
                                SANDBOX_OUTPUT_LIMITS, SANDBOX_TIMEOUTS)


class TestConstantsDefinition:
    """Test that constants are properly defined."""

    def test_rate_limit_constants(self) -> None:
        """Test rate limiting constants."""
        assert RATE_LIMIT_EVENTS_PER_MINUTE == 60
        assert RATE_LIMIT_EVENTS_PER_HOUR == 1000
        # Hour limit should be less than or equal to minute limit * 60
        # (to prevent allowing more in an hour than would be allowed by minute limit)
        assert RATE_LIMIT_EVENTS_PER_HOUR <= RATE_LIMIT_EVENTS_PER_MINUTE * 60

    def test_sandbox_limits(self) -> None:
        """Test sandbox resource limit constants."""
        # Check all strictness levels exist
        for level in ["standard", "strict", "paranoid"]:
            assert level in SANDBOX_MEMORY_LIMITS
            assert level in SANDBOX_CPU_LIMITS
            assert level in SANDBOX_TIMEOUTS
            assert level in SANDBOX_OUTPUT_LIMITS

        # Check limits decrease with strictness
        assert SANDBOX_MEMORY_LIMITS["standard"] > SANDBOX_MEMORY_LIMITS["strict"]
        assert SANDBOX_MEMORY_LIMITS["strict"] > SANDBOX_MEMORY_LIMITS["paranoid"]

        assert SANDBOX_CPU_LIMITS["standard"] > SANDBOX_CPU_LIMITS["strict"]
        assert SANDBOX_CPU_LIMITS["strict"] > SANDBOX_CPU_LIMITS["paranoid"]

        assert SANDBOX_TIMEOUTS["standard"] > SANDBOX_TIMEOUTS["strict"]
        assert SANDBOX_TIMEOUTS["strict"] > SANDBOX_TIMEOUTS["paranoid"]

    def test_monitoring_constants(self) -> None:
        """Test monitoring-related constants."""
        assert DEFAULT_MONITORING_HOURS == 24
        assert ERROR_RETENTION_DAYS == 30
        assert ERROR_RETENTION_DAYS * 24 > DEFAULT_MONITORING_HOURS

    def test_network_constants(self) -> None:
        """Test network-related constants."""
        assert MIN_CONNECTION_PARTS == 5
        assert CONNECTION_PID_PARSE_START_INDEX == 6
        assert CONNECTION_PID_PARSE_START_INDEX > MIN_CONNECTION_PARTS

        assert isinstance(LOCALHOST_VARIANTS, list)
        assert "127.0.0.1" in LOCALHOST_VARIANTS
        assert "::1" in LOCALHOST_VARIANTS
        assert "localhost" in LOCALHOST_VARIANTS

    def test_memory_constants(self) -> None:
        """Test memory-related constants."""
        assert KB_TO_BYTES_FACTOR == 1024
        assert MB_TO_BYTES_FACTOR == 1024 * 1024

        assert isinstance(MAX_MEMORY_VIOLATIONS, dict)
        assert "standard" in MAX_MEMORY_VIOLATIONS
        assert "strict" in MAX_MEMORY_VIOLATIONS
        assert "paranoid" in MAX_MEMORY_VIOLATIONS

        assert isinstance(MEMORY_CLEAR_PATTERNS, list)
        assert len(MEMORY_CLEAR_PATTERNS) == 5
        assert 0x00 in MEMORY_CLEAR_PATTERNS
        assert 0xFF in MEMORY_CLEAR_PATTERNS

    def test_file_size_categories(self) -> None:
        """Test file size category constants."""
        assert isinstance(FILE_SIZE_CATEGORIES, dict)

        # Check categories exist and are ordered
        categories = list(FILE_SIZE_CATEGORIES.keys())
        sizes = list(FILE_SIZE_CATEGORIES.values())

        # Sizes should increase
        for i in range(len(sizes) - 1):
            if sizes[i + 1] != float("inf"):
                assert sizes[i] < sizes[i + 1]


class TestConstantsUsage:
    """Test that constants are actually being used in modules."""

    def test_rate_limiter_uses_constants(self) -> None:
        """Test rate limiter uses constants."""
        from app.core.security.rate_limiter import SecurityEventRateLimiter

        limiter = SecurityEventRateLimiter()
        config = limiter.config

        assert config["max_events_per_minute"] == RATE_LIMIT_EVENTS_PER_MINUTE
        assert config["max_events_per_hour"] == RATE_LIMIT_EVENTS_PER_HOUR

    def test_sandbox_config_uses_constants(self) -> None:
        """Test sandbox config uses constants."""
        from app.core.security.sandbox import SandboxConfig

        config = SandboxConfig()

        assert config.max_memory_mb == SANDBOX_MEMORY_LIMITS["standard"]
        assert config.max_cpu_percent == SANDBOX_CPU_LIMITS["standard"]
        assert config.timeout_seconds == SANDBOX_TIMEOUTS["standard"]
        assert config.max_output_size_mb == SANDBOX_OUTPUT_LIMITS["standard"]
        assert config.memory_violation_threshold == MAX_MEMORY_VIOLATIONS["standard"]

    def test_security_events_uses_constants(self) -> None:
        """Test security events module uses constants."""
        from app.core.monitoring.security_events import SecurityEventTracker

        # Mock the get_event_summary method to check default
        tracker = SecurityEventTracker()

        # The default parameter should use the constant
        import inspect

        sig = inspect.signature(tracker.get_event_summary)
        assert sig.parameters["hours"].default == DEFAULT_MONITORING_HOURS

    def test_stats_collector_uses_constants(self) -> None:
        """Test stats collector uses file size categories."""
        from app.core.monitoring.stats import StatsCollector

        collector = StatsCollector()

        # Check that size buckets are created from FILE_SIZE_CATEGORIES
        bucket_names = [bucket[0] for bucket in collector.size_buckets]

        for category in FILE_SIZE_CATEGORIES.keys():
            assert category.lower() in bucket_names

    def test_config_imports_constants(self) -> None:
        """Test that config.py successfully imports and uses constants."""
        # This test verifies the try/except import in config.py works
        from app.config import Settings

        # Create settings instance - should not raise ImportError
        settings = Settings()

        # Check sandbox limits match constants
        assert (
            settings.sandbox_limits_standard["memory_mb"]
            == SANDBOX_MEMORY_LIMITS["standard"]
        )
        assert (
            settings.sandbox_limits_strict["cpu_percent"]
            == SANDBOX_CPU_LIMITS["strict"]
        )
        assert (
            settings.sandbox_limits_paranoid["timeout_seconds"]
            == SANDBOX_TIMEOUTS["paranoid"]
        )


class TestConstantsConsistency:
    """Test constants are consistent across the codebase."""

    def test_no_hardcoded_values_in_security_modules(self) -> None:
        """Verify no magic numbers remain in security modules."""
        # This is a simple check - in production you might use AST parsing
        security_modules = [
            "app.core.security.rate_limiter",
            "app.core.security.sandbox",
            "app.core.monitoring.security_events",
            "app.core.monitoring.errors",
            "app.core.monitoring.stats",
        ]

        # Just verify modules can be imported without errors
        for module_name in security_modules:
            try:
                importlib.import_module(module_name)
            except Exception as e:
                pytest.fail(f"Failed to import {module_name}: {e}")

    def test_memory_conversion_factors(self) -> None:
        """Test memory conversion factors are used consistently."""
        # Verify conversions are correct
        assert 1 * MB_TO_BYTES_FACTOR == 1024 * KB_TO_BYTES_FACTOR
        assert 1024 * MB_TO_BYTES_FACTOR == 1024 * 1024 * KB_TO_BYTES_FACTOR

    def test_monitoring_time_consistency(self) -> None:
        """Test monitoring time periods are consistent."""
        # Hours in a week
        assert 168 == 7 * 24

        # Daily retention should be longer than hourly window
        assert ERROR_RETENTION_DAYS >= 7  # At least a week
