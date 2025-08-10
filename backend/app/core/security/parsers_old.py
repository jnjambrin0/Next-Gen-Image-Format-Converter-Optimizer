"""
Connection output parsers for network monitoring.

This module provides parsers for ss and netstat command outputs
to extract connection information in a structured format.
"""

import re
from typing import List, Protocol, Optional, Tuple, Dict
from datetime import datetime
import structlog

from app.core.security.types import ConnectionInfo
from app.core.constants import (
    MIN_CONNECTION_PARTS,
    CONNECTION_PID_PARSE_START_INDEX,
    LOCALHOST_VARIANTS,
)

logger = structlog.get_logger()


class NetworkConnection:
    """Represents a parsed network connection."""

    def __init__(
        self,
        protocol: str,
        local_addr: str,
        local_port: int,
        remote_addr: str,
        remote_port: int,
        state: str,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
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
        return (
            self.remote_addr in LOCALHOST_VARIANTS
            or self.local_addr in LOCALHOST_VARIANTS
        )

    def to_dict(self) -> ConnectionInfo:
        """Convert to dictionary for logging (privacy-aware)."""
        return {
            "protocol": self.protocol,
            "is_localhost": self.is_localhost(),
            "state": self.state,
            "has_pid": self.pid is not None,
            "detected_at": self.detected_at.isoformat(),
        }

    def get_connection_id(self) -> str:
        """Get unique identifier for this connection."""
        return f"{self.protocol}:{self.local_addr}:{self.local_port}-{self.remote_addr}:{self.remote_port}"


class ConnectionParser(Protocol):
    """Protocol for connection parsers."""

    def parse(self, output: str) -> List[NetworkConnection]:
        """Parse command output into list of connections."""
        ...


class SSParser:
    """Parser for ss command output."""

    def parse(self, output: str) -> List[NetworkConnection]:
        """
        Parse ss command output.

        Expected format:
        tcp    ESTAB      0      0      192.168.1.100:45678    93.184.216.34:443    users:(("firefox",pid=1234,fd=10))
        """
        connections = []

        for line in output.strip().split("\n")[1:]:  # Skip header
            conn = self._parse_line(line)
            if conn:
                connections.append(conn)

        return connections

    def _parse_line(self, line: str) -> Optional[NetworkConnection]:
        """Parse a single line of ss output."""
        try:
            parts = line.split()
            if len(parts) < MIN_CONNECTION_PARTS:
                return None

            # ss format: protocol state recv-q send-q local remote [users]
            protocol = parts[0].lower()
            if not protocol.startswith(("tcp", "udp")):
                return None

            state = parts[1]

            # Find local and remote addresses
            local_addr_port = None
            remote_addr_port = None

            # Look for address:port patterns
            for i in range(2, min(len(parts), 8)):
                part = parts[i]
                if ":" in part and self._is_address_port(part):
                    if not local_addr_port:
                        local_addr_port = part
                    elif not remote_addr_port:
                        remote_addr_port = part
                        break

            if not local_addr_port:
                return None

            # Parse addresses
            local_addr, local_port = self._parse_address(local_addr_port)
            remote_addr, remote_port = self._parse_address(
                remote_addr_port if remote_addr_port else "*:*"
            )

            # Extract PID and process name from users field
            pid = None
            process_name = None

            # Look for users:(("process",pid=123,fd=x))
            users_pattern = r'users:\(\("([^"]+)",pid=(\d+)'
            match = re.search(users_pattern, line)
            if match:
                process_name = match.group(1)
                pid = int(match.group(2))

            return NetworkConnection(
                protocol=protocol,
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                state=state,
                pid=pid,
                process_name=process_name,
            )

        except Exception as e:
            logger.debug(f"Failed to parse ss line: {line[:50]}... - {e}")
            return None

    def _is_address_port(self, addr_str: str) -> bool:
        """Check if string looks like address:port."""
        if ":" not in addr_str:
            return False

        # Must have either dots (IPv4) or multiple colons (IPv6) or be special
        return (
            "." in addr_str
            or addr_str.count(":") > 1
            or addr_str.startswith("[")
            or addr_str in ["*:*", "0.0.0.0:*", ":::*"]
        )

    def _parse_address(self, addr_str: str) -> Tuple[str, int]:
        """Parse address:port string."""
        if not addr_str or addr_str == "*:*":
            return "*", 0

        # Handle IPv6 format [::1]:8000
        if "[" in addr_str:
            addr = addr_str.split("]")[0].replace("[", "")
            port_str = addr_str.split("]:")[-1] if "]:" in addr_str else "0"
            port = int(port_str) if port_str.isdigit() else 0
            return addr, port

        # Handle IPv4 and simple format
        if ":" in addr_str:
            parts = addr_str.rsplit(":", 1)
            addr = parts[0]
            port = int(parts[1]) if parts[1].isdigit() else 0
            return addr, port

        return addr_str, 0


class NetstatParser:
    """Parser for netstat command output."""

    def parse(self, output: str) -> List[NetworkConnection]:
        """
        Parse netstat command output.

        Expected format:
        tcp        0      0 192.168.1.100:45678     93.184.216.34:443       ESTABLISHED 1234/firefox
        """
        connections = []

        for line in output.strip().split("\n")[1:]:  # Skip header
            conn = self._parse_line(line)
            if conn:
                connections.append(conn)

        return connections

    def _parse_line(self, line: str) -> Optional[NetworkConnection]:
        """Parse a single line of netstat output."""
        try:
            parts = line.split()
            if len(parts) < MIN_CONNECTION_PARTS:
                return None

            # netstat format: protocol recv-q send-q local remote state [pid/program]
            protocol = parts[0].lower()
            if not protocol.startswith(("tcp", "udp")):
                return None

            # Find state column
            state_idx = -1
            for i, part in enumerate(parts):
                if part in [
                    "LISTEN",
                    "ESTAB",
                    "ESTABLISHED",
                    "TIME_WAIT",
                    "CLOSE_WAIT",
                    "SYN_SENT",
                    "SYN_RECV",
                    "FIN_WAIT1",
                    "FIN_WAIT2",
                    "CLOSING",
                    "LAST_ACK",
                    "CLOSED",
                ]:
                    state_idx = i
                    break

            if state_idx == -1:
                # For UDP, there's no state
                if protocol.startswith("udp"):
                    state = "STATELESS"
                    state_idx = 5  # Typical position where state would be
                else:
                    return None
            else:
                state = parts[state_idx]

            # Local and remote are typically at positions 3 and 4
            local_addr_port = parts[3] if len(parts) > 3 else None
            remote_addr_port = parts[4] if len(parts) > 4 else None

            if not local_addr_port:
                return None

            # Parse addresses
            local_addr, local_port = self._parse_address(local_addr_port)
            remote_addr, remote_port = self._parse_address(
                remote_addr_port if remote_addr_port else "*:*"
            )

            # Extract PID and process name
            pid = None
            process_name = None

            # For UDP without state, PID/program is typically last field
            # For TCP with state, it's after the state field
            if protocol.startswith("udp") and state == "STATELESS":
                # Look in last column for UDP
                if len(parts) > 5:
                    pid_prog = parts[-1]
                    if "/" in pid_prog:
                        pid_str, process_name = pid_prog.split("/", 1)
                        if pid_str.isdigit():
                            pid = int(pid_str)
            else:
                # Look for PID/program after state for TCP
                if state_idx + 1 < len(parts):
                    pid_prog = parts[state_idx + 1]
                    if "/" in pid_prog:
                        pid_str, process_name = pid_prog.split("/", 1)
                        if pid_str.isdigit():
                            pid = int(pid_str)

            return NetworkConnection(
                protocol=protocol,
                local_addr=local_addr,
                local_port=local_port,
                remote_addr=remote_addr,
                remote_port=remote_port,
                state=state,
                pid=pid,
                process_name=process_name,
            )

        except Exception as e:
            logger.debug(f"Failed to parse netstat line: {line[:50]}... - {e}")
            return None

    def _parse_address(self, addr_str: str) -> Tuple[str, int]:
        """Parse address:port string."""
        if not addr_str or addr_str == "*:*":
            return "*", 0

        # Handle IPv6 format
        if addr_str.startswith("[") or "::" in addr_str:
            # Complex IPv6 parsing
            if "]:" in addr_str:
                addr = addr_str.split("]:")[0].replace("[", "")
                port = int(addr_str.split("]:")[1])
                return addr, port
            else:
                # Try to find last : that's part of port
                parts = addr_str.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    return parts[0], int(parts[1])
                return addr_str, 0

        # Handle IPv4
        if ":" in addr_str:
            parts = addr_str.rsplit(":", 1)
            addr = parts[0]
            port = int(parts[1]) if parts[1].isdigit() else 0
            return addr, port

        return addr_str, 0


def get_connection_parser(command: str) -> ConnectionParser:
    """
    Factory function to get appropriate parser for command.

    Args:
        command: Command name ('ss' or 'netstat')

    Returns:
        Appropriate parser instance
    """
    parsers: Dict[str, ConnectionParser] = {
        "ss": SSParser(),
        "netstat": NetstatParser(),
    }

    # Default to SSParser if unknown command
    return parsers.get(command.lower(), SSParser())


def parse_connections(output: str, command: str = "ss") -> List[NetworkConnection]:
    """
    Convenience function to parse connection output.

    Args:
        output: Command output to parse
        command: Command that generated output

    Returns:
        List of parsed connections
    """
    parser = get_connection_parser(command)
    return parser.parse(output)
