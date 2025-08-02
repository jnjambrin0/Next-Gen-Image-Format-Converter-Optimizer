"""
Real-time network connection monitoring for security enforcement.
"""

import asyncio
import os
import signal
import subprocess
import time
import random
from datetime import datetime
from typing import Dict, List, Set, Optional, Any, Tuple
import structlog

from app.core.monitoring.security_events import SecurityEventTracker
from app.models.security_event import SecurityEventType, SecuritySeverity
from app.core.constants import (
    NETWORK_VIOLATION_THRESHOLD,
    PROCESS_TERMINATION_GRACE_PERIOD,
    DEFAULT_MONITORING_INTERVAL,
    MONITORING_JITTER_PERCENT,
    NETWORK_BASELINE_MAX_CONNECTIONS
)
from app.core.security.types import ConnectionInfo, ViolationStats
from app.core.security.metrics import SecurityMetricsCollector

logger = structlog.get_logger()


class NetworkConnection:
    """Represents a network connection."""
    
    def __init__(
        self,
        protocol: str,
        local_addr: str,
        local_port: int,
        remote_addr: str,
        remote_port: int,
        state: str,
        pid: Optional[int] = None,
        process_name: Optional[str] = None
    ):
        self.protocol = protocol
        self.local_addr = local_addr
        self.local_port = local_port
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.state = state
        self.pid = pid
        self.process_name = process_name
        self.detected_at = datetime.now()
    
    def is_localhost(self) -> bool:
        """Check if connection is to localhost."""
        localhost_addrs = ["127.0.0.1", "::1", "localhost"]
        return (
            self.remote_addr in localhost_addrs or
            self.local_addr in localhost_addrs
        )
    
    def to_dict(self) -> ConnectionInfo:
        """Convert to dictionary for logging (privacy-aware)."""
        return {
            "protocol": self.protocol,
            "is_localhost": self.is_localhost(),
            "state": self.state,
            "has_pid": self.pid is not None,
            "detected_at": self.detected_at.isoformat()
        }


class NetworkMonitor:
    """
    Monitor network connections in real-time for security violations.
    """
    
    def __init__(
        self,
        security_tracker: Optional[SecurityEventTracker] = None,
        check_interval: int = DEFAULT_MONITORING_INTERVAL,
        terminate_on_violation: bool = False
    ):
        """
        Initialize network monitor.
        
        Args:
            security_tracker: Optional security event tracker
            check_interval: Seconds between connection checks
            terminate_on_violation: Whether to terminate violating processes
        """
        self.security_tracker = security_tracker
        self.check_interval = check_interval
        self.terminate_on_violation = terminate_on_violation
        self._monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._baseline_connections: Set[str] = set()
        self._violations_by_pid: Dict[int, int] = {}
        self._our_pid = os.getpid()
        self.metrics_collector = SecurityMetricsCollector()
    
    async def __aenter__(self) -> 'NetworkMonitor':
        """Context manager entry - start monitoring."""
        await self.start_monitoring()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - stop monitoring."""
        await self.stop_monitoring()
    
    async def start_monitoring(self) -> None:
        """Start background network monitoring."""
        if self._monitoring:
            logger.warning("Network monitoring already active")
            return
        
        logger.info(
            "Starting network monitoring",
            interval=self.check_interval,
            terminate_on_violation=self.terminate_on_violation
        )
        
        # Establish baseline connections
        await self._establish_baseline()
        
        # Start monitoring task
        self._monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
    
    async def stop_monitoring(self) -> None:
        """Stop network monitoring."""
        if not self._monitoring:
            return
        
        logger.info("Stopping network monitoring")
        self._monitoring = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None
    
    async def _establish_baseline(self) -> None:
        """Establish baseline of allowed connections."""
        connections = await self._get_current_connections()
        
        for conn in connections:
            if conn.is_localhost() or conn.state == "LISTEN":
                # Allow localhost and listening sockets
                conn_id = self._get_connection_id(conn)
                self._baseline_connections.add(conn_id)
                
                # Limit baseline size to prevent memory issues
                if len(self._baseline_connections) >= NETWORK_BASELINE_MAX_CONNECTIONS:
                    logger.warning(
                        "Baseline connection limit reached",
                        limit=NETWORK_BASELINE_MAX_CONNECTIONS
                    )
                    break
        
        logger.info(
            "Network baseline established",
            allowed_connections=len(self._baseline_connections)
        )
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._monitoring:
            try:
                await self._check_connections()
                
                # Add jitter to prevent thundering herd
                jitter = random.uniform(0, self.check_interval * MONITORING_JITTER_PERCENT)
                sleep_time = self.check_interval + jitter
                
                await asyncio.sleep(sleep_time)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in network monitor loop: {e}")
                await asyncio.sleep(self.check_interval)
    
    async def _check_connections(self) -> None:
        """Check current connections for violations."""
        # Start monitoring cycle metrics
        self.metrics_collector.start_monitoring_cycle()
        
        connections = await self._get_current_connections()
        violations = []
        
        for conn in connections:
            conn_id = self._get_connection_id(conn)
            
            # Skip baseline connections
            if conn_id in self._baseline_connections:
                continue
            
            # Skip localhost connections
            if conn.is_localhost():
                continue
            
            # Skip listening sockets
            if conn.state == "LISTEN":
                continue
            
            # Check if it's our process or a child
            if conn.pid and self._is_our_process(conn.pid):
                violations.append(conn)
        
        # End monitoring cycle metrics
        self.metrics_collector.end_monitoring_cycle(len(connections))
        
        # Handle violations
        if violations:
            await self._handle_violations(violations)
    
    async def _get_current_connections(self) -> List[NetworkConnection]:
        """Get current network connections."""
        connections = []
        
        try:
            # Use ss if available, otherwise netstat
            if os.path.exists("/usr/bin/ss"):
                cmd = ["ss", "-tunap"]
            else:
                cmd = ["netstat", "-tunap"]
            
            # Run command
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )
            stdout, _ = await result.communicate()
            output = stdout.decode("utf-8", errors="ignore")
            
            # Parse output
            for line in output.split('\n')[1:]:  # Skip header
                conn = self._parse_connection_line(line)
                if conn:
                    connections.append(conn)
        
        except Exception as e:
            logger.error(f"Failed to get network connections: {e}")
        
        return connections
    
    def _parse_connection_line(self, line: str) -> Optional[NetworkConnection]:
        """Parse a connection line from ss/netstat output."""
        try:
            parts = line.split()
            if len(parts) < 5:
                return None
            
            # Parse based on tool output format
            if "tcp" in parts[0] or "udp" in parts[0]:
                protocol = parts[0]
                
                # Find the state column (LISTEN, ESTAB, etc.)
                state_idx = -1
                for i, part in enumerate(parts):
                    if part in ["LISTEN", "ESTAB", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"]:
                        state_idx = i
                        break
                
                if state_idx == -1:
                    return None
                
                state = parts[state_idx]
                
                # Parse addresses - find patterns with colons
                local = None
                remote = None
                
                # Look for address:port patterns in the entire line
                for i, part in enumerate(parts):
                    if ":" in part and i != state_idx and not part.startswith("users:"):
                        # Skip numeric values that might look like addresses
                        if "." in part or "::" in part or part.count(":") > 1:
                            if not local:
                                local = part
                            elif not remote:
                                remote = part
                                break
                
                if not local:
                    return None
                
                # Extract address and port
                local_addr, local_port = self._parse_address(local)
                remote_addr, remote_port = self._parse_address(remote if remote else "*")
                
                # Try to get PID and process name
                pid = None
                process_name = None
                for part in parts[6:]:
                    if "pid=" in part:
                        pid = int(part.split("=")[1].split(",")[0])
                    elif "/" in part and pid is None:
                        # Format: "1234/python"
                        pid_proc = part.split("/")
                        if pid_proc[0].isdigit():
                            pid = int(pid_proc[0])
                            process_name = pid_proc[1] if len(pid_proc) > 1 else None
                
                return NetworkConnection(
                    protocol=protocol,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    pid=pid,
                    process_name=process_name
                )
        
        except Exception:
            return None
        
        return None
    
    def _parse_address(self, addr_str: str) -> Tuple[str, int]:
        """Parse address string into IP and port."""
        if not addr_str or addr_str == "*":
            return "*", 0
        
        # Handle IPv6
        if "[" in addr_str:
            # Format: [::1]:8080
            addr = addr_str.split("]")[0].replace("[", "")
            port = int(addr_str.split("]:")[-1]) if "]:" in addr_str else 0
            return addr, port
        
        # Handle IPv4
        if ":" in addr_str:
            parts = addr_str.rsplit(":", 1)
            return parts[0], int(parts[1]) if parts[1].isdigit() else 0
        
        return addr_str, 0
    
    def _get_connection_id(self, conn: NetworkConnection) -> str:
        """Get unique identifier for a connection."""
        return f"{conn.protocol}:{conn.local_addr}:{conn.local_port}-{conn.remote_addr}:{conn.remote_port}"
    
    def _is_our_process(self, pid: int) -> bool:
        """Check if PID belongs to our process tree."""
        if pid == self._our_pid:
            return True
        
        try:
            # Check if it's a child process
            with open(f"/proc/{pid}/stat", "r") as f:
                stat = f.read().split()
                ppid = int(stat[3])  # Parent PID is 4th field
                return ppid == self._our_pid or self._is_our_process(ppid)
        except Exception:
            return False
    
    async def _handle_violations(self, violations: List[NetworkConnection]) -> None:
        """Handle detected network violations."""
        logger.warning(
            "Network violations detected",
            violation_count=len(violations),
            terminate_enabled=self.terminate_on_violation
        )
        
        for conn in violations:
            # Record violation in metrics
            self.metrics_collector.record_violation()
            
            # Log violation
            logger.warning(
                "Unauthorized network connection",
                connection=conn.to_dict()
            )
            
            # Record security event
            if self.security_tracker:
                await self.security_tracker.record_event({
                    "event_type": SecurityEventType.VIOLATION,
                    "severity": SecuritySeverity.CRITICAL,
                    "details": {
                        "violation_type": "network_attempt",
                        "protocol": conn.protocol,
                        "is_localhost": conn.is_localhost(),
                        "state": conn.state,
                        "has_pid": conn.pid is not None
                    }
                })
            
            # Track violations by PID
            if conn.pid:
                self._violations_by_pid[conn.pid] = (
                    self._violations_by_pid.get(conn.pid, 0) + 1
                )
                
                # Terminate if enabled and threshold reached
                if self.terminate_on_violation and self._violations_by_pid[conn.pid] >= NETWORK_VIOLATION_THRESHOLD:
                    await self._terminate_process(conn.pid)
    
    async def _terminate_process(self, pid: int) -> None:
        """Terminate a violating process."""
        if pid == self._our_pid:
            logger.error("Refusing to terminate self")
            return
        
        try:
            logger.warning(f"Terminating process for network violation", pid=pid)
            
            # First try SIGTERM
            os.kill(pid, signal.SIGTERM)
            
            # Give it time to exit gracefully
            await asyncio.sleep(PROCESS_TERMINATION_GRACE_PERIOD)
            
            # Check if still alive and force kill
            try:
                os.kill(pid, 0)  # Check if process exists
                os.kill(pid, signal.SIGKILL)
                logger.warning(f"Force killed process", pid=pid)
            except ProcessLookupError:
                pass  # Process already terminated
            
            # Record process termination in metrics
            self.metrics_collector.record_process_termination()
            
            # Record termination event
            if self.security_tracker:
                await self.security_tracker.record_event({
                    "event_type": SecurityEventType.VIOLATION,
                    "severity": SecuritySeverity.CRITICAL,
                    "details": {
                        "violation_type": "process_terminated",
                        "reason": "network_violation",
                        "pid": pid
                    }
                })
        
        except Exception as e:
            logger.error(f"Failed to terminate process {pid}: {e}")
    
    def get_violation_stats(self) -> ViolationStats:
        """Get current violation statistics."""
        return {
            "monitoring_active": self._monitoring,
            "baseline_connections": len(self._baseline_connections),
            "violations_by_pid": dict(self._violations_by_pid),
            "total_violations": sum(self._violations_by_pid.values()),
            "terminate_enabled": self.terminate_on_violation
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get monitoring metrics."""
        metrics = self.metrics_collector.get_metrics()
        summary = self.metrics_collector.get_summary()
        
        return {
            "raw_metrics": metrics,
            "summary": summary,
            "violation_stats": self.get_violation_stats()
        }


async def create_network_monitor(
    security_tracker: Optional[SecurityEventTracker] = None,
    check_interval: int = 5,
    terminate_on_violation: bool = False
) -> NetworkMonitor:
    """
    Factory function to create and start a network monitor.
    
    Args:
        security_tracker: Optional security event tracker
        check_interval: Seconds between checks
        terminate_on_violation: Whether to terminate violating processes
    
    Returns:
        Started NetworkMonitor instance
    """
    monitor = NetworkMonitor(
        security_tracker=security_tracker,
        check_interval=check_interval,
        terminate_on_violation=terminate_on_violation
    )
    await monitor.start_monitoring()
    return monitor