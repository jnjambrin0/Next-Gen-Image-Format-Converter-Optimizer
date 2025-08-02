"""
Tests for enhanced network isolation verification.
"""

import pytest
import asyncio
import socket
import shutil
from unittest.mock import patch, MagicMock
from app.core.security.network_verifier import (
    NetworkVerifier,
    NetworkStrictness,
    verify_network_at_startup
)


def command_available(cmd: str) -> bool:
    """Check if a system command is available."""
    return shutil.which(cmd) is not None


class TestNetworkVerifier:
    """Test suite for NetworkVerifier functionality."""
    
    @pytest.mark.asyncio
    async def test_standard_verification(self):
        """Test basic network verification in standard mode."""
        verifier = NetworkVerifier(strictness=NetworkStrictness.STANDARD)
        
        # Mock subprocess calls
        with patch('subprocess.check_output') as mock_output:
            mock_output.return_value = "tcp    LISTEN     0      128    127.0.0.1:8080"
            
            status = await verifier.verify_network_isolation()
            
            assert status["verified"] is True
            assert "localhost_binding" in status["checks_passed"]
            # Standard mode doesn't check active connections
            assert "no_active_connections" not in status["checks_passed"]
            assert "no_active_connections" not in status["checks_failed"]
    
    @pytest.mark.asyncio
    async def test_strict_verification(self):
        """Test network verification in strict mode."""
        verifier = NetworkVerifier(strictness=NetworkStrictness.STRICT)
        
        # Mock subprocess calls
        with patch('subprocess.check_output') as mock_output:
            # First call for localhost binding check
            mock_output.side_effect = [
                "tcp    LISTEN     0      128    127.0.0.1:8080",  # localhost binding
                "tcp    ESTAB      0      0      127.0.0.1:8080"   # active connections
            ]
            
            status = await verifier.verify_network_isolation()
            
            assert status["verified"] is True
            assert "localhost_binding" in status["checks_passed"]
            # Strict mode checks active connections
            assert "no_active_connections" in status["checks_passed"]
    
    @pytest.mark.asyncio
    async def test_paranoid_verification(self):
        """Test network verification in paranoid mode."""
        verifier = NetworkVerifier(strictness=NetworkStrictness.PARANOID)
        
        # Mock subprocess calls
        with patch('subprocess.check_output') as mock_output:
            mock_output.side_effect = [
                "tcp    LISTEN     0      128    127.0.0.1:8080",  # localhost binding
                "tcp    ESTAB      0      0      127.0.0.1:8080",  # active connections
                "lo: <LOOPBACK,UP> state UNKNOWN"                   # network interfaces
            ]
            
            # Mock DNS check
            with patch('socket.getaddrinfo') as mock_dns:
                mock_dns.side_effect = Exception("DNS blocked")
                
                status = await verifier.verify_network_isolation()
                
                assert status["verified"] is True
                assert "network_interfaces" in status["checks_passed"]
                assert "dns_blocking" in status["checks_passed"]
    
    @pytest.mark.skipif(
        not (command_available("ss") or command_available("netstat")),
        reason="Requires ss or netstat command"
    )
    def test_localhost_binding_check_failure(self):
        """Test detection of non-localhost binding."""
        verifier = NetworkVerifier()
        
        with patch('subprocess.check_output') as mock_output:
            # Simulate binding to all interfaces
            mock_output.return_value = "tcp    LISTEN     0      128    0.0.0.0:8080     python"
            
            result = verifier._verify_localhost_binding()
            
            assert result["passed"] is False
            assert len(result["warnings"]) > 0
            assert "all interfaces" in result["warnings"][0]
    
    def test_active_connections_check_failure(self):
        """Test detection of non-localhost connections."""
        verifier = NetworkVerifier()
        
        with patch('subprocess.check_output') as mock_output:
            # Simulate external connection
            mock_output.return_value = "tcp    ESTAB    0    0    192.168.1.1:443    python"
            
            result = verifier._verify_no_active_connections()
            
            assert result["passed"] is False
            assert len(result["warnings"]) > 0
            assert "non-localhost connection" in result["warnings"][0]
    
    @pytest.mark.asyncio
    async def test_dns_blocking_check(self):
        """Test DNS blocking verification."""
        verifier = NetworkVerifier()
        
        # Test with DNS blocked (expected behavior)
        with patch('socket.getaddrinfo') as mock_dns:
            mock_dns.side_effect = socket.gaierror("DNS resolution failed")
            
            result = await verifier._verify_dns_blocking()
            
            assert result["passed"] is True
            assert len(result["warnings"]) == 0
        
        # Test with DNS not blocked (failure case)
        with patch('socket.getaddrinfo') as mock_dns:
            mock_dns.return_value = [("8.8.8.8", 80)]
            
            result = await verifier._verify_dns_blocking()
            
            assert result["passed"] is False
            assert len(result["warnings"]) > 0
    
    def test_network_interfaces_check(self):
        """Test network interface verification."""
        verifier = NetworkVerifier()
        
        # Test with only loopback interface
        with patch('subprocess.check_output') as mock_output:
            mock_output.return_value = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
    inet 127.0.0.1/8 scope host lo
"""
            result = verifier._verify_network_interfaces()
            
            assert result["passed"] is True
            assert len(result["warnings"]) == 0
        
        # Test with active external interface
        with patch('subprocess.check_output') as mock_output:
            mock_output.return_value = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0
"""
            result = verifier._verify_network_interfaces()
            
            assert result["passed"] is True  # We just warn, don't fail
            assert len(result["warnings"]) > 0
            # Check for any non-loopback interface warning
            assert any("Non-loopback network interface" in w for w in result["warnings"])
    
    def test_get_status_summary(self):
        """Test status summary generation."""
        verifier = NetworkVerifier(strictness=NetworkStrictness.STRICT)
        
        # Before verification
        summary = verifier.get_status_summary()
        assert "not yet verified" in summary
        
        # After successful verification
        verifier._network_status = {
            "verified": True,
            "isolated": True,
            "strictness": "strict",
            "checks_passed": ["localhost_binding", "dns_blocking"],
            "checks_failed": []
        }
        summary = verifier.get_status_summary()
        assert "properly isolated" in summary
        assert "strict" in summary
        
        # After failed verification
        verifier._network_status["isolated"] = False
        verifier._network_status["checks_failed"] = ["active_connections"]
        summary = verifier.get_status_summary()
        assert "issues detected" in summary
        assert "active_connections" in summary
    
    @pytest.mark.asyncio
    async def test_security_event_recording(self):
        """Test that security events are recorded on failure."""
        from app.core.monitoring.security_events import SecurityEventTracker
        
        # Mock security tracker
        mock_tracker = MagicMock(spec=SecurityEventTracker)
        mock_tracker.record_event = MagicMock(return_value=asyncio.Future())
        mock_tracker.record_event.return_value.set_result(1)
        
        verifier = NetworkVerifier(
            strictness=NetworkStrictness.PARANOID,
            security_tracker=mock_tracker
        )
        
        # Force a failure
        with patch('subprocess.check_output') as mock_output:
            mock_output.return_value = "tcp    LISTEN     0      128    0.0.0.0:8080     python"
            
            await verifier.verify_network_isolation()
            
            # Verify security event was recorded
            mock_tracker.record_event.assert_called_once()
            call_args = mock_tracker.record_event.call_args[0][0]
            assert call_args["details"]["violation_type"] == "network_isolation_failed"
    
    @pytest.mark.asyncio
    async def test_verify_network_at_startup(self):
        """Test the convenience startup function."""
        with patch('subprocess.check_output') as mock_output:
            mock_output.return_value = "tcp    LISTEN     0      128    127.0.0.1:8080"
            
            status = await verify_network_at_startup(NetworkStrictness.STANDARD)
            
            assert status["verified"] is True
            assert status["isolated"] is True
            assert status["strictness"] == "standard"
    
    def test_get_metrics(self):
        """Test metrics collection and retrieval."""
        verifier = NetworkVerifier(strictness=NetworkStrictness.STRICT)
        
        # Get initial metrics
        metrics = verifier.get_metrics()
        
        assert "raw_metrics" in metrics
        assert "summary" in metrics
        assert "network_status" in metrics
        
        # Check raw metrics structure
        raw = metrics["raw_metrics"]
        assert "verification_time_ms" in raw
        assert "violations_detected" in raw
        assert raw["monitoring_cycles"] == 0