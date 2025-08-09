"""
from typing import Any
Tests for real-time network connection monitoring.
"""

import asyncio
import os
import shutil
from unittest.mock import AsyncMock, patch

import pytest

from app.core.security.network_monitor import NetworkMonitor


def command_available(cmd: str) -> bool:
    """Check if a system command is available."""
    return shutil.which(cmd) is not None


def get_network_command() -> None:
    """Get available network command (ss or netstat)."""
    if command_available("ss"):
        return "ss"
    elif command_available("netstat"):
        return "netstat"
    return None


class TestNetworkConnection:
    """Test NetworkConnection class."""

    def test_localhost_detection(self) -> None:
        """Test localhost connection detection."""
        # Localhost connections
        conn1 = NetworkConnection(
            "tcp", "127.0.0.1", 8000, "127.0.0.1", 45678, "ESTABLISHED"
        )
        assert conn1.is_localhost() is True

        conn2 = NetworkConnection("tcp", "::1", 8000, "::1", 45678, "ESTABLISHED")
        assert conn2.is_localhost() is True

        # External connection
        conn3 = NetworkConnection(
            "tcp", "192.168.1.100", 8000, "8.8.8.8", 443, "ESTABLISHED"
        )
        assert conn3.is_localhost() is False

    def test_to_dict_privacy(self) -> None:
        """Test that to_dict doesn't leak sensitive info."""
        conn = NetworkConnection(
            "tcp",
            "192.168.1.100",
            8000,
            "8.8.8.8",
            443,
            "ESTABLISHED",
            pid=1234,
            process_name="python",
        )

        data = conn.to_dict()

        # Should not contain actual IPs or ports
        assert "192.168.1.100" not in str(data)
        assert "8.8.8.8" not in str(data)
        assert 8000 not in data.values()
        assert 443 not in data.values()

        # Should contain safe metadata
        assert data["protocol"] == "tcp"
        assert data["is_localhost"] is False
        assert data["state"] == "ESTABLISHED"
        assert data["has_pid"] is True


class TestNetworkMonitor:
    """Test NetworkMonitor class."""

    @pytest.mark.asyncio
    async def test_start_stop_monitoring(self):
        """Test starting and stopping monitoring."""
        monitor = NetworkMonitor(check_interval=1)

        assert monitor._monitoring is False

        await monitor.start_monitoring()
        assert monitor._monitoring is True
        assert monitor._monitor_task is not None

        await monitor.stop_monitoring()
        assert monitor._monitoring is False
        assert monitor._monitor_task is None

    @pytest.mark.asyncio
    async def test_baseline_establishment(self):
        """Test baseline connection establishment."""
        monitor = NetworkMonitor()

        # Mock connection data
        mock_connections = [
            NetworkConnection("tcp", "127.0.0.1", 8000, "0.0.0.0", 0, "LISTEN"),
            NetworkConnection(
                "tcp", "127.0.0.1", 45678, "127.0.0.1", 8000, "ESTABLISHED"
            ),
            NetworkConnection(
                "tcp", "192.168.1.100", 45679, "8.8.8.8", 443, "ESTABLISHED"
            ),
        ]

        with patch.object(
            monitor, "_get_current_connections", return_value=mock_connections
        ):
            await monitor._establish_baseline()

            # Should allow localhost and listening
            assert len(monitor._baseline_connections) == 2

    def test_parse_connection_line(self) -> None:
        """Test parsing connection lines from ss/netstat."""
        monitor = NetworkMonitor()

        # Test ss output format
        line1 = 'tcp    ESTAB      0      0      127.0.0.1:8000      127.0.0.1:45678     users:(("python",pid=1234,fd=3))'
        conn1 = monitor._parse_connection_line(line1)

        assert conn1 is not None
        assert conn1.protocol == "tcp"
        assert conn1.local_addr == "127.0.0.1"
        assert conn1.local_port == 8000
        assert conn1.remote_addr == "127.0.0.1"
        assert conn1.remote_port == 45678
        assert conn1.state == "ESTAB"
        assert conn1.pid == 1234

        # Test netstat output format
        line2 = "tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      1234/python"
        conn2 = monitor._parse_connection_line(line2)

        assert conn2 is not None
        assert conn2.state == "LISTEN"
        assert conn2.pid == 1234
        assert conn2.process_name == "python"

        # Test malformed lines (should return None)
        assert monitor._parse_connection_line("") is None
        assert monitor._parse_connection_line("invalid line") is None

    def test_parse_address(self) -> None:
        """Test address parsing."""
        monitor = NetworkMonitor()

        # IPv4
        addr, port = monitor._parse_address("127.0.0.1:8000")
        assert addr == "127.0.0.1"
        assert port == 8000

        # IPv6
        addr, port = monitor._parse_address("[::1]:8000")
        assert addr == "::1"
        assert port == 8000

        # Wildcard
        addr, port = monitor._parse_address("*")
        assert addr == "*"
        assert port == 0

    def test_is_our_process(self) -> None:
        """Test process ownership detection."""
        monitor = NetworkMonitor()

        # Our PID
        assert monitor._is_our_process(monitor._our_pid) is True

        # Other PID (mock /proc check)
        with patch("builtins.open", side_effect=FileNotFoundError):
            assert monitor._is_our_process(99999) is False

    @pytest.mark.asyncio
    async def test_violation_detection(self):
        """Test detection of network violations."""
        from app.core.monitoring.security_events import SecurityEventTracker

        mock_tracker = AsyncMock(spec=SecurityEventTracker)
        monitor = NetworkMonitor(security_tracker=mock_tracker)

        # Set up baseline (only localhost)
        baseline_conns = [
            NetworkConnection("tcp", "127.0.0.1", 8000, "0.0.0.0", 0, "LISTEN")
        ]
        with patch.object(
            monitor, "_get_current_connections", return_value=baseline_conns
        ):
            await monitor._establish_baseline()

        # Simulate violation (external connection)
        violation_conns = baseline_conns + [
            NetworkConnection(
                "tcp",
                "192.168.1.100",
                45679,
                "8.8.8.8",
                443,
                "ESTABLISHED",
                pid=os.getpid(),
            )
        ]

        with patch.object(
            monitor, "_get_current_connections", return_value=violation_conns
        ):
            with patch.object(monitor, "_is_our_process", return_value=True):
                await monitor._check_connections()

                # Should have recorded security event
                mock_tracker.record_event.assert_called_once()
                call_args = mock_tracker.record_event.call_args[0][0]
                assert call_args["details"]["violation_type"] == "network_attempt"

    @pytest.mark.asyncio
    async def test_process_termination(self):
        """Test process termination on violation."""
        monitor = NetworkMonitor(terminate_on_violation=True)

        # Mock os.kill
        with patch("os.kill") as mock_kill:
            # Test termination of other process
            await monitor._terminate_process(12345)

            # Should try SIGTERM first
            assert mock_kill.call_count >= 1
            assert mock_kill.call_args_list[0][0] == (12345, 15)  # SIGTERM

        # Test refusing to terminate self
        with patch("os.kill") as mock_kill:
            await monitor._terminate_process(monitor._our_pid)
            mock_kill.assert_not_called()

    @pytest.mark.asyncio
    async def test_violation_threshold(self):
        """Test that processes are terminated after threshold violations."""
        monitor = NetworkMonitor(terminate_on_violation=True)

        violation = NetworkConnection(
            "tcp", "192.168.1.100", 45679, "8.8.8.8", 443, "ESTABLISHED", pid=12345
        )

        # First two violations shouldn't terminate
        with patch.object(monitor, "_terminate_process") as mock_terminate:
            await monitor._handle_violations([violation])
            await monitor._handle_violations([violation])
            mock_terminate.assert_not_called()

            # Third violation should trigger termination
            await monitor._handle_violations([violation])
            mock_terminate.assert_called_once_with(12345)

    def test_get_violation_stats(self) -> None:
        """Test violation statistics."""
        monitor = NetworkMonitor()
        monitor._monitoring = True
        monitor._baseline_connections = {"conn1", "conn2"}
        monitor._violations_by_pid = {1234: 2, 5678: 1}

        stats = monitor.get_violation_stats()

        assert stats["monitoring_active"] is True
        assert stats["baseline_connections"] == 2
        assert stats["total_violations"] == 3
        assert stats["violations_by_pid"][1234] == 2

    @pytest.mark.asyncio
    async def test_create_network_monitor(self):
        """Test factory function."""
        with patch.object(NetworkMonitor, "start_monitoring") as mock_start:
            monitor = await create_network_monitor(check_interval=10)

            assert monitor.check_interval == 10
            mock_start.assert_called_once()

    @pytest.mark.asyncio
    async def test_monitor_loop_error_handling(self):
        """Test that monitor loop handles errors gracefully."""
        monitor = NetworkMonitor(check_interval=0.1)

        # Mock _check_connections to raise error
        with patch.object(
            monitor, "_check_connections", side_effect=Exception("Test error")
        ):
            monitor._monitoring = True

            # Run loop for a short time
            task = asyncio.create_task(monitor._monitor_loop())
            await asyncio.sleep(0.3)

            # Should still be running despite errors
            assert not task.done()

            # Stop monitoring
            monitor._monitoring = False
            await task

    def test_get_metrics(self) -> None:
        """Test metrics collection and retrieval."""
        monitor = NetworkMonitor()

        # Get initial metrics
        metrics = monitor.get_metrics()

        assert "raw_metrics" in metrics
        assert "summary" in metrics
        assert "violation_stats" in metrics

        # Check raw metrics structure
        raw = metrics["raw_metrics"]
        assert raw["monitoring_cycles"] == 0
        assert raw["violations_detected"] == 0
        assert raw["processes_terminated"] == 0

        # Test metrics after violations
        monitor.metrics_collector.record_violation()
        monitor.metrics_collector.record_violation()
        monitor.metrics_collector.record_process_termination()

        metrics = monitor.get_metrics()
        assert metrics["raw_metrics"]["violations_detected"] == 2
        assert metrics["raw_metrics"]["processes_terminated"] == 1
