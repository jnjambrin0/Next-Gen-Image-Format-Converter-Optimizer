"""
Type definitions for security module.
"""

from enum import Enum
from typing import Dict, List, Optional, TypedDict, Union


class NetworkStatus(TypedDict):
    """Type definition for network isolation status."""

    isolated: bool
    verified: bool
    strictness: str
    checks_passed: List[str]
    checks_failed: List[str]
    warnings: List[str]


class ConnectionInfo(TypedDict):
    """Type definition for network connection information."""

    protocol: str
    is_localhost: bool
    state: str
    has_pid: bool
    detected_at: str


class ViolationStats(TypedDict):
    """Type definition for violation statistics."""

    monitoring_active: bool
    baseline_connections: int
    violations_by_pid: Dict[int, int]
    total_violations: int
    terminate_enabled: bool


class VerificationResult(TypedDict):
    """Type definition for verification check results."""

    passed: bool
    warnings: List[str]


class SecurityMetrics(TypedDict):
    """Type definition for security metrics."""

    verification_time_ms: float
    monitoring_cycles: int
    connections_checked: int
    violations_detected: int
    processes_terminated: int
    last_check_timestamp: Optional[str]


class RateLimitConfig(TypedDict):
    """Type definition for rate limit configuration."""

    max_events_per_minute: int
    max_events_per_hour: int
    burst_size: int
    enabled: bool


class NetworkEvent(TypedDict):
    """Type definition for network-related security events."""

    event_type: str
    severity: str
    timestamp: str
    details: Dict[str, Union[str, int, float, bool, List[str]]]
    rate_limited: bool
