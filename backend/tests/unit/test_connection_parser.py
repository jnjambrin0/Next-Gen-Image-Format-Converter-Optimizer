"""
from typing import Any
Unit tests for simplified network output validation.
"""

from app.core.security.parsers import (NETWORK_ACTIVITY_PATTERNS,
                                       check_network_isolation,
                                       validate_no_network_activity)


class TestNetworkValidation:
    """Test network output validation functions."""

    def test_validate_no_network_activity_empty(self) -> None:
        """Test validation with empty output."""
        assert validate_no_network_activity("") == True
        assert validate_no_network_activity(None) == True

    def test_validate_no_network_activity_clean(self) -> None:
        """Test validation with clean output."""
        clean_output = """
        No network connections found
        System is isolated
        """
        assert validate_no_network_activity(clean_output) == True

    def test_validate_no_network_activity_with_connections(self) -> None:
        """Test validation detects network connections."""
        outputs_with_activity = [
            "tcp 0 0 localhost:8000 ESTABLISHED",
            "udp 0 0 0.0.0.0:53",
            "LISTEN on port 443",
            "Connection to 192.168.1.1:80",
        ]

        for output in outputs_with_activity:
            assert validate_no_network_activity(output) == False

    def test_check_network_isolation(self) -> None:
        """Test network isolation checking."""
        # Test with clean output
        clean_output = """
        Active Internet connections
        Proto Local Address Foreign Address State
        """
        result = check_network_isolation(clean_output)
        assert result["isolated"] == True

        # Test with network activity
        active_output = "tcp ESTABLISHED connection"
        result = check_network_isolation(active_output)
        assert result["isolated"] == False

    def test_network_activity_patterns(self) -> None:
        """Test that all patterns are defined."""
        assert len(NETWORK_ACTIVITY_PATTERNS) > 0
        assert "ESTABLISHED" in NETWORK_ACTIVITY_PATTERNS
        assert "LISTEN" in NETWORK_ACTIVITY_PATTERNS
        assert ":80" in NETWORK_ACTIVITY_PATTERNS
        assert ":443" in NETWORK_ACTIVITY_PATTERNS

    def test_case_insensitive_detection(self) -> None:
        """Test case-insensitive pattern matching."""
        test_cases = [
            "TCP connection ESTABLISHED",
            "tcp connection established",
            "Tcp Connection Established",
        ]

        for test_case in test_cases:
            assert validate_no_network_activity(test_case) == False

    def test_partial_pattern_matching(self) -> None:
        """Test partial pattern matching in output."""
        output = """
        Lorem ipsum dolor sit amet
        Some random text here
        Connection status: ESTABLISHED
        More random text
        """
        assert validate_no_network_activity(output) == False

    def test_port_detection(self) -> None:
        """Test detection of common ports."""
        ports_to_test = [":80", ":443", ":8000"]

        for port in ports_to_test:
            output = f"Listening on 127.0.0.1{port}"
            assert validate_no_network_activity(output) == False
