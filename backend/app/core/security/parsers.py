"""
Network connection parsers for security monitoring.
Stub implementation for testing.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Union


@dataclass
class NetworkConnection:
    """Represents a network connection."""

    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    timestamp: Optional[datetime] = None


class SSParser:
    """Parser for ss command output."""

    def parse(self, output: str) -> List[NetworkConnection]:
        """Parse ss output into NetworkConnection objects."""
        connections: List[NetworkConnection] = []

        # Skip header lines and parse each connection line
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("State") or line.startswith("Netid"):
                continue

            # Parse ss output format: State Recv-Q Send-Q Local Address:Port Peer Address:Port
            parts = line.split()
            if len(parts) >= 5:
                try:
                    state = parts[0]
                    local_addr_port = parts[3]
                    remote_addr_port = parts[4]

                    # Parse local address and port
                    local_addr, local_port = self._parse_address_port(local_addr_port)
                    remote_addr, remote_port = self._parse_address_port(
                        remote_addr_port
                    )

                    # Extract PID if available (usually in process column)
                    pid = None
                    process_name = None
                    if len(parts) > 5:
                        # Look for pid pattern in remaining parts
                        for part in parts[5:]:
                            if "pid=" in part:
                                pid_match = re.search(r"pid=([0-9]+)", part)
                                if pid_match:
                                    pid = int(pid_match.group(1))
                                # Extract process name if available
                                proc_match = re.search(r'users:\(\(("([^"]+)")', part)
                                if proc_match:
                                    process_name = proc_match.group(3)

                    connection = NetworkConnection(
                        local_address=local_addr,
                        local_port=local_port,
                        remote_address=remote_addr,
                        remote_port=remote_port,
                        state=state,
                        pid=pid,
                        process_name=process_name,
                        timestamp=datetime.now(),
                    )
                    connections.append(connection)
                except (ValueError, IndexError):
                    # Skip malformed lines
                    continue

        return connections

    def _parse_address_port(self, addr_port: str) -> tuple[str, int]:
        """Parse address:port string into address and port."""
        if addr_port == "*:*" or addr_port == "0.0.0.0:*":
            return "0.0.0.0", 0

        # Handle IPv6 addresses [addr]:port
        if addr_port.startswith("[") and "]:" in addr_port:
            addr, port_str = addr_port.rsplit(":", 1)
            addr = addr[1:-1]  # Remove brackets
        else:
            # IPv4 addr:port
            if ":" in addr_port:
                addr, port_str = addr_port.rsplit(":", 1)
            else:
                return addr_port, 0

        try:
            port = int(port_str) if port_str != "*" else 0
        except ValueError:
            port = 0

        return addr, port


class NetstatParser:
    """Parser for netstat command output."""

    def parse(self, output: str) -> List[NetworkConnection]:
        """Parse netstat output into NetworkConnection objects."""
        connections: List[NetworkConnection] = []

        # Skip header lines and parse each connection line
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or "Proto" in line or "Active" in line:
                continue

            # Parse netstat output format: Proto Recv-Q Send-Q Local Address Foreign Address State [PID/Program]
            parts = line.split()
            if len(parts) >= 6:
                try:
                    proto = parts[0]
                    local_addr_port = parts[3]
                    remote_addr_port = parts[4]
                    state = parts[5]

                    # Only process TCP connections
                    if not proto.startswith("tcp"):
                        continue

                    # Parse addresses and ports
                    local_addr, local_port = self._parse_address_port(local_addr_port)
                    remote_addr, remote_port = self._parse_address_port(
                        remote_addr_port
                    )

                    # Extract PID and process name if available
                    pid = None
                    process_name = None
                    if len(parts) > 6:
                        # PID/Program name format: "1234/python3"
                        pid_program = parts[6]
                        if "/" in pid_program:
                            try:
                                pid_str, process_name = pid_program.split("/", 1)
                                pid = int(pid_str) if pid_str != "-" else None
                            except (ValueError, IndexError):
                                pass

                    connection = NetworkConnection(
                        local_address=local_addr,
                        local_port=local_port,
                        remote_address=remote_addr,
                        remote_port=remote_port,
                        state=state,
                        pid=pid,
                        process_name=process_name,
                        timestamp=datetime.now(),
                    )
                    connections.append(connection)
                except (ValueError, IndexError):
                    # Skip malformed lines
                    continue

        return connections

    def _parse_address_port(self, addr_port: str) -> tuple[str, int]:
        """Parse address:port string into address and port."""
        if addr_port in ("0.0.0.0:*", "*:*"):
            return "0.0.0.0", 0

        # Handle IPv6 addresses [addr]:port
        if addr_port.startswith("[") and "]:" in addr_port:
            addr, port_str = addr_port.rsplit(":", 1)
            addr = addr[1:-1]  # Remove brackets
        else:
            # IPv4 addr:port format
            if ":" in addr_port:
                addr, port_str = addr_port.rsplit(":", 1)
            else:
                return addr_port, 0

        try:
            port = int(port_str) if port_str != "*" else 0
        except ValueError:
            port = 0

        return addr, port


def get_connection_parser(command: str) -> Union[SSParser, NetstatParser]:
    """Get appropriate parser for command."""
    if command == "ss":
        return SSParser()
    elif command == "netstat":
        return NetstatParser()
    else:
        # Default fallback
        return SSParser()


def parse_connections(output: str, command: str = "ss") -> List[NetworkConnection]:
    """Parse connection output using appropriate parser."""
    parser = get_connection_parser(command)
    return parser.parse(output)


def check_network_isolation() -> bool:
    """
    Check if network isolation is properly configured.

    Returns:
        True if network is isolated (no external connections),
        False otherwise.
    """
    try:
        import platform
        import subprocess

        # Use appropriate command based on OS
        if platform.system() == "Darwin":  # macOS
            cmd = ["netstat", "-an"]
        elif platform.system() == "Linux":
            cmd = ["ss", "-tuln"]
        else:  # Windows
            cmd = ["netstat", "-an"]

        # Run command to check network connections
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

        if result.returncode != 0:
            # Command failed, assume not isolated
            return False

        # Parse output to check for external connections
        lines = result.stdout.strip().split("\n")

        # Check for connections to external IPs
        for line in lines:
            # Skip headers and local connections
            if any(x in line.lower() for x in ["listen", "time_wait", "close_wait"]):
                continue

            # Check if connection is to external IP (not localhost/127.0.0.1)
            if "ESTABLISHED" in line:
                # Check if it's not a local connection
                if not any(
                    local in line
                    for local in ["127.0.0.1", "localhost", "::1", "[::1]"]
                ):
                    # External connection found
                    return False

        # No external connections found - network is isolated
        return True

    except Exception:
        # On error, assume network is not isolated (fail-safe)
        return False
