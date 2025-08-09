"""
Simplified network output validation for security monitoring.

This module provides basic validation for network command outputs
to ensure no unexpected connections exist in the sandboxed environment.
"""

from typing import List

import structlog

logger = structlog.get_logger()

# Patterns that indicate network activity
NETWORK_ACTIVITY_PATTERNS = [
    "ESTABLISHED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RECEIVED",
    "tcp",
    "udp",
    ":80",
    ":443",
    ":8000",
    "0.0.0.0",
    ":::",
]


def validate_no_network_activity(output: str) -> bool:
    """
    Validate that command output shows no network activity.

    Args:
        output: Command output to validate

    Returns:
        True if no network activity detected, False otherwise
    """
    if not output:
        return True

    # Convert to lowercase for case-insensitive matching
    output_lower = output.lower()

    # Check for any network activity patterns
    for pattern in NETWORK_ACTIVITY_PATTERNS:
        if pattern.lower() in output_lower:
            logger.warning("Network activity detected in sandbox", pattern=pattern)
            return False

    return True


def get_active_connections_count(output: str) -> int:
    """
    Simple count of lines that might represent connections.

    Args:
        output: Command output

    Returns:
        Approximate count of connections (0 if none detected)
    """
    if not output or validate_no_network_activity(output):
        return 0

    # Count non-header lines that contain connection indicators
    lines = output.strip().split("\n")
    connection_count = 0

    for line in lines:
        line_lower = line.lower()
        # Skip headers and empty lines
        if not line.strip() or "proto" in line_lower or "active" in line_lower:
            continue

        # Check if line contains connection indicators
        if any(
            pattern.lower() in line_lower
            for pattern in ["tcp", "udp", "established", "listen"]
        ):
            connection_count += 1

    return connection_count


def check_network_isolation(output: str) -> dict:
    """
    Check if network isolation is properly enforced.

    Args:
        output: Network command output

    Returns:
        Dict with isolation status and details
    """
    is_isolated = validate_no_network_activity(output)
    connection_count = get_active_connections_count(output)

    return {
        "isolated": is_isolated,
        "connection_count": connection_count,
        "status": "isolated" if is_isolated else "connections_detected",
    }


# Backward compatibility alias
def parse_connections(output: str, command: str = "ss") -> List:
    """
    Backward compatibility function.

    Returns empty list if no connections, raises if connections found.
    """
    if not validate_no_network_activity(output):
        from app.core.security.errors import create_network_error

        raise create_network_error(
            reason="connections_detected",
            details="Network connections found in sandboxed environment",
        )

    return []  # No connections should exist
