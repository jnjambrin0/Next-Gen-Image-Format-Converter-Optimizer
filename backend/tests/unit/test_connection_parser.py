"""
Unit tests for connection parser utility.
"""

from datetime import datetime

import pytest

from app.core.security.parsers import (
    NetstatParser,
    NetworkConnection,
    SSParser,
    get_connection_parser,
    parse_connections,
)


class TestNetworkConnection:
    """Test NetworkConnection class."""

    def test_connection_creation(self):
        """Test creating a network connection."""
        conn = NetworkConnection(
            protocol="tcp",
            local_addr="192.168.1.100",
            local_port=45678,
            remote_addr="93.184.216.34",
            remote_port=443,
            state="ESTABLISHED",
            pid=1234,
            process_name="firefox",
        )

        assert conn.protocol == "tcp"
        assert conn.local_addr == "192.168.1.100"
        assert conn.local_port == 45678
        assert conn.remote_addr == "93.184.216.34"
        assert conn.remote_port == 443
        assert conn.state == "ESTABLISHED"
        assert conn.pid == 1234
        assert conn.process_name == "firefox"
        assert isinstance(conn.detected_at, datetime)

    def test_is_localhost(self):
        """Test localhost detection."""
        # Localhost connection
        conn = NetworkConnection(
            protocol="tcp",
            local_addr="127.0.0.1",
            local_port=8000,
            remote_addr="127.0.0.1",
            remote_port=45678,
            state="ESTABLISHED",
        )
        assert conn.is_localhost()

        # IPv6 localhost
        conn = NetworkConnection(
            protocol="tcp",
            local_addr="::1",
            local_port=8000,
            remote_addr="::1",
            remote_port=45678,
            state="ESTABLISHED",
        )
        assert conn.is_localhost()

        # External connection
        conn = NetworkConnection(
            protocol="tcp",
            local_addr="192.168.1.100",
            local_port=45678,
            remote_addr="93.184.216.34",
            remote_port=443,
            state="ESTABLISHED",
        )
        assert not conn.is_localhost()

    def test_to_dict(self):
        """Test privacy-aware dictionary conversion."""
        conn = NetworkConnection(
            protocol="tcp",
            local_addr="192.168.1.100",
            local_port=45678,
            remote_addr="93.184.216.34",
            remote_port=443,
            state="ESTABLISHED",
            pid=1234,
            process_name="firefox",
        )

        data = conn.to_dict()
        assert data["protocol"] == "tcp"
        assert data["is_localhost"] is False
        assert data["state"] == "ESTABLISHED"
        assert data["has_pid"] is True
        assert "detected_at" in data

        # Should not contain actual addresses (privacy-aware)
        assert "local_addr" not in data
        assert "remote_addr" not in data
        assert "process_name" not in data

    def test_get_connection_id(self):
        """Test connection ID generation."""
        conn = NetworkConnection(
            protocol="tcp",
            local_addr="192.168.1.100",
            local_port=45678,
            remote_addr="93.184.216.34",
            remote_port=443,
            state="ESTABLISHED",
        )

        conn_id = conn.get_connection_id()
        assert conn_id == "tcp:192.168.1.100:45678-93.184.216.34:443"


class TestSSParser:
    """Test ss command output parser."""

    def test_parse_tcp_connections(self):
        """Test parsing TCP connections from ss output."""
        parser = SSParser()
        output = """Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
tcp    ESTAB      0      0      192.168.1.100:45678             93.184.216.34:443               users:(("firefox",pid=1234,fd=10))
tcp    LISTEN     0      128    0.0.0.0:8000                    0.0.0.0:*                       users:(("python",pid=5678,fd=3))
tcp    TIME-WAIT  0      0      192.168.1.100:45679             93.184.216.34:443"""

        connections = parser.parse(output)
        assert len(connections) == 3

        # Check first connection
        conn = connections[0]
        assert conn.protocol == "tcp"
        assert conn.local_addr == "192.168.1.100"
        assert conn.local_port == 45678
        assert conn.remote_addr == "93.184.216.34"
        assert conn.remote_port == 443
        assert conn.state == "ESTAB"
        assert conn.pid == 1234
        assert conn.process_name == "firefox"

        # Check listening socket
        conn = connections[1]
        assert conn.state == "LISTEN"
        assert conn.local_addr == "0.0.0.0"
        assert conn.local_port == 8000
        assert conn.process_name == "python"

        # Check connection without PID
        conn = connections[2]
        assert conn.state == "TIME-WAIT"
        assert conn.pid is None
        assert conn.process_name is None

    def test_parse_udp_connections(self):
        """Test parsing UDP connections from ss output."""
        parser = SSParser()
        output = """Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
udp    UNCONN     0      0      0.0.0.0:53                      0.0.0.0:*                       users:(("dnsmasq",pid=1111,fd=4))
udp    UNCONN     0      0      127.0.0.1:323                   0.0.0.0:*"""

        connections = parser.parse(output)
        assert len(connections) == 2

        conn = connections[0]
        assert conn.protocol == "udp"
        assert conn.state == "UNCONN"
        assert conn.local_port == 53
        assert conn.process_name == "dnsmasq"

    def test_parse_ipv6_connections(self):
        """Test parsing IPv6 connections."""
        parser = SSParser()
        output = """Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
tcp    ESTAB      0      0      [2001:db8::1]:45678             [2001:db8::2]:443               users:(("chrome",pid=9999,fd=15))
tcp    LISTEN     0      128    [::]:8000                       [::]:*                          users:(("node",pid=8888,fd=3))"""

        connections = parser.parse(output)
        assert len(connections) == 2

        conn = connections[0]
        assert conn.local_addr == "2001:db8::1"
        assert conn.remote_addr == "2001:db8::2"
        assert conn.process_name == "chrome"

        conn = connections[1]
        assert conn.local_addr == "::"
        assert conn.state == "LISTEN"

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        parser = SSParser()
        connections = parser.parse("")
        assert connections == []

    def test_parse_invalid_lines(self):
        """Test parsing with invalid lines."""
        parser = SSParser()
        output = """Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
invalid line
tcp    ESTAB      0      0      192.168.1.100:45678             93.184.216.34:443
another invalid line
not enough parts"""

        connections = parser.parse(output)
        # Should only parse the valid tcp line
        assert len(connections) == 1
        assert connections[0].local_port == 45678


class TestNetstatParser:
    """Test netstat command output parser."""

    def test_parse_tcp_connections(self):
        """Test parsing TCP connections from netstat output."""
        parser = NetstatParser()
        output = """Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.1.100:45678     93.184.216.34:443       ESTABLISHED 1234/firefox
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      5678/python
tcp        0      0 192.168.1.100:45679     93.184.216.34:443       TIME_WAIT   -"""

        connections = parser.parse(output)
        assert len(connections) == 3

        # Check first connection
        conn = connections[0]
        assert conn.protocol == "tcp"
        assert conn.local_addr == "192.168.1.100"
        assert conn.local_port == 45678
        assert conn.remote_addr == "93.184.216.34"
        assert conn.remote_port == 443
        assert conn.state == "ESTABLISHED"
        assert conn.pid == 1234
        assert conn.process_name == "firefox"

        # Check listening socket
        conn = connections[1]
        assert conn.state == "LISTEN"
        assert conn.local_addr == "0.0.0.0"
        assert conn.local_port == 8000
        assert conn.pid == 5678
        assert conn.process_name == "python"

        # Check connection without PID
        conn = connections[2]
        assert conn.state == "TIME_WAIT"
        assert conn.pid is None
        assert conn.process_name is None

    def test_parse_udp_connections(self):
        """Test parsing UDP connections from netstat output."""
        parser = NetstatParser()
        output = """Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
udp        0      0 0.0.0.0:53              0.0.0.0:*                           1111/dnsmasq
udp        0      0 127.0.0.1:323           0.0.0.0:*                           -"""

        connections = parser.parse(output)
        assert len(connections) == 2

        conn = connections[0]
        assert conn.protocol == "udp"
        assert conn.state == "STATELESS"  # UDP has no state in netstat
        assert conn.local_port == 53
        assert conn.pid == 1111
        assert conn.process_name == "dnsmasq"

        conn = connections[1]
        assert conn.state == "STATELESS"
        assert conn.pid is None

    def test_parse_ipv6_connections(self):
        """Test parsing IPv6 connections."""
        parser = NetstatParser()
        output = """Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp6       0      0 2001:db8::1:45678       2001:db8::2:443         ESTABLISHED 9999/chrome
tcp6       0      0 :::8000                 :::*                    LISTEN      8888/node"""

        connections = parser.parse(output)
        assert len(connections) == 2

        conn = connections[0]
        assert conn.protocol == "tcp6"
        assert conn.local_addr == "2001:db8::1"
        assert conn.local_port == 45678
        assert conn.remote_addr == "2001:db8::2"
        assert conn.remote_port == 443
        assert conn.process_name == "chrome"


class TestFactoryFunctions:
    """Test factory and convenience functions."""

    def test_get_connection_parser(self):
        """Test parser factory function."""
        # Get ss parser
        parser = get_connection_parser("ss")
        assert isinstance(parser, SSParser)

        # Get netstat parser
        parser = get_connection_parser("netstat")
        assert isinstance(parser, NetstatParser)

        # Unknown parser defaults to ss
        parser = get_connection_parser("unknown")
        assert isinstance(parser, SSParser)

        # Case insensitive
        parser = get_connection_parser("SS")
        assert isinstance(parser, SSParser)

    def test_parse_connections_convenience(self):
        """Test convenience parsing function."""
        ss_output = """Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
tcp    ESTAB      0      0      192.168.1.100:45678             93.184.216.34:443               users:(("firefox",pid=1234,fd=10))"""

        connections = parse_connections(ss_output, "ss")
        assert len(connections) == 1
        assert connections[0].process_name == "firefox"

        netstat_output = """Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.1.100:45678     93.184.216.34:443       ESTABLISHED 1234/firefox"""

        connections = parse_connections(netstat_output, "netstat")
        assert len(connections) == 1
        assert connections[0].process_name == "firefox"
