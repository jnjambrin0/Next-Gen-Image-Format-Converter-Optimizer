"""
Simplified network monitoring for sandboxed environment.

Since all network access is blocked in sandbox, this monitor
simply verifies that no connections exist.
"""

import asyncio
import os
import subprocess
from datetime import datetime
from typing import Optional

import structlog

from app.core.constants import CONNECTION_CHECK_TIMEOUT, DEFAULT_MONITORING_INTERVAL
from app.core.monitoring.security_events import SecurityEventTracker
from app.core.security.parsers import check_network_isolation
from app.models.security_event import SecurityEventType, SecuritySeverity

logger = structlog.get_logger()


class NetworkConnection:
    """Represents a network connection for monitoring."""

    def __init__(self, protocol: str, local_addr: str, remote_addr: str, state: str):
        self.protocol = protocol
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.state = state
        self.timestamp = datetime.now()

    def is_localhost(self) -> bool:
        """Check if connection is to localhost."""
        localhost_ips = ["127.0.0.1", "::1", "localhost"]
        return any(ip in self.remote_addr for ip in localhost_ips)


class NetworkMonitor:
    """
    Simplified network monitor that verifies network isolation.

    In sandboxed environment, ANY network connection is a violation.
    """

    def __init__(
        self,
        security_tracker: Optional[SecurityEventTracker] = None,
        check_interval: float = DEFAULT_MONITORING_INTERVAL,
        enabled: bool = True,
    ):
        """Initialize network monitor."""
        self.security_tracker = security_tracker
        self.check_interval = check_interval
        self.enabled = enabled
        self._monitoring = False
        self._monitor_task = None
        self._last_check = None
        self._violation_count = 0

    async def start_monitoring(self) -> None:
        """Start monitoring for network violations."""
        if not self.enabled:
            logger.info("Network monitoring disabled")
            return

        if self._monitoring:
            logger.warning("Network monitoring already active")
            return

        self._monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Network monitoring started")

    async def stop_monitoring(self) -> None:
        """Stop network monitoring."""
        if not self._monitoring:
            return

        self._monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

        logger.info("Network monitoring stopped")

    async def check_now(self) -> dict:
        """Perform immediate network check."""
        return await self._check_network_isolation()

    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._monitoring:
            try:
                status = await self._check_network_isolation()

                if not status["isolated"]:
                    await self._handle_violation(status)

                await asyncio.sleep(self.check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in network monitor loop", error=str(e))
                await asyncio.sleep(self.check_interval)

    async def _check_network_isolation(self) -> dict:
        """Check if network is properly isolated."""
        try:
            # Use ss if available, otherwise netstat
            if os.path.exists("/usr/bin/ss"):
                cmd = ["ss", "-tunap"]
            else:
                cmd = ["netstat", "-tunap"]

            # Run command with timeout
            try:
                result = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
                    ),
                    timeout=CONNECTION_CHECK_TIMEOUT,
                )
                stdout, _ = await result.communicate()
                output = stdout.decode("utf-8", errors="ignore")

            except asyncio.TimeoutError:
                logger.warning("Network check command timed out")
                return {"isolated": True, "connection_count": 0, "status": "timeout"}

            # Check isolation status
            status = check_network_isolation(output)
            self._last_check = datetime.now()
            return status

        except Exception as e:
            logger.error("Failed to check network isolation", error=str(e))
            return {"isolated": True, "connection_count": 0, "status": "error"}

    async def _handle_violation(self, status: dict) -> None:
        """Handle network isolation violation."""
        self._violation_count += 1

        logger.error(
            "CRITICAL: Network isolation violated in sandbox",
            connection_count=status["connection_count"],
            violation_count=self._violation_count,
        )

        # Report to security tracker if available
        if self.security_tracker:
            await self.security_tracker.record_event(
                event_type=SecurityEventType.NETWORK_ACCESS_VIOLATION,
                severity=SecuritySeverity.CRITICAL,
                details={
                    "violation_type": "network_isolation_breach",
                    "connection_count": status["connection_count"],
                    "violation_count": self._violation_count,
                    "timestamp": (
                        self._last_check.isoformat() if self._last_check else None
                    ),
                },
            )

    def get_status(self) -> dict:
        """Get current monitor status."""
        return {
            "monitoring": self._monitoring,
            "enabled": self.enabled,
            "last_check": self._last_check.isoformat() if self._last_check else None,
            "violation_count": self._violation_count,
        }


def create_network_monitor(
    security_tracker: Optional[SecurityEventTracker] = None,
    check_interval: float = DEFAULT_MONITORING_INTERVAL,
    enabled: bool = True,
) -> NetworkMonitor:
    """Factory function to create a NetworkMonitor instance."""
    return NetworkMonitor(
        security_tracker=security_tracker,
        check_interval=check_interval,
        enabled=enabled,
    )
