"""
Ultra-realistic network blocking tests.
Tests localhost-only enforcement, SSRF prevention, and network isolation.
"""

import pytest
import asyncio
import socket
import ssl
import urllib.parse
from unittest.mock import patch, MagicMock, AsyncMock
import aiohttp
import requests
from typing import List, Dict, Any
import subprocess
import platform

from app.core.security.sandbox import SecuritySandbox
from app.core.security.engine import SecurityEngine
from app.services.conversion_service import conversion_service
from app.models.conversion import ConversionRequest
from app.core.exceptions import SecurityError, NetworkError


class TestNetworkBlockingReal:
    """Test network blocking and isolation mechanisms."""

    @pytest.fixture
    def sandbox(self):
        """Create SecuritySandbox instance."""
        return SecuritySandbox(enable_network_blocking=True)

    @pytest.fixture
    def security_engine(self):
        """Create SecurityEngine instance."""
        return SecurityEngine()

    def create_ssrf_payloads(self) -> List[Dict[str, Any]]:
        """
        Create various SSRF (Server-Side Request Forgery) payloads.

        Real attack vectors from bug bounties and CTFs.
        """
        payloads = [
            # Direct IP access attempts
            {
                "type": "direct_ip",
                "url": "http://169.254.169.254/latest/meta-data/",  # AWS metadata
                "description": "AWS metadata endpoint",
            },
            {
                "type": "direct_ip",
                "url": "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
                "description": "GCP metadata endpoint",
            },
            # Localhost variations
            {
                "type": "localhost",
                "url": "http://127.0.0.1:8080/admin",
                "description": "Localhost admin panel",
            },
            {
                "type": "localhost",
                "url": "http://[::1]:3000/api/internal",
                "description": "IPv6 localhost",
            },
            {
                "type": "localhost",
                "url": "http://0.0.0.0:9000/debug",
                "description": "All interfaces",
            },
            # DNS rebinding attempts
            {
                "type": "dns_rebind",
                "url": "http://evil.rebind.network/attack",
                "description": "DNS rebinding attack",
            },
            # URL encoding bypass attempts
            {
                "type": "encoded",
                "url": "http://127.0.0.%31/admin",  # 127.0.0.1 with encoding
                "description": "URL encoded IP",
            },
            {
                "type": "encoded",
                "url": "http://0x7f000001/",  # 127.0.0.1 in hex
                "description": "Hex encoded IP",
            },
            {
                "type": "encoded",
                "url": "http://2130706433/",  # 127.0.0.1 as decimal
                "description": "Decimal IP",
            },
            # Protocol smuggling
            {
                "type": "protocol",
                "url": "file:///etc/passwd",
                "description": "File protocol",
            },
            {
                "type": "protocol",
                "url": "gopher://localhost:9000/_GET",
                "description": "Gopher protocol",
            },
            {
                "type": "protocol",
                "url": "dict://localhost:11211/stats",
                "description": "Dict protocol",
            },
            # Redirect chains
            {
                "type": "redirect",
                "url": "http://bit.ly/evil-redirect",  # Shortened URL
                "description": "URL shortener redirect",
            },
            # DNS tricks
            {
                "type": "dns_trick",
                "url": "http://localhost.evil.com/",
                "description": "Subdomain trick",
            },
            {
                "type": "dns_trick",
                "url": "http://127.0.0.1.nip.io/",
                "description": "nip.io DNS service",
            },
        ]

        return payloads

    @pytest.mark.security
    @pytest.mark.critical
    async def test_socket_blocking(self, sandbox):
        """
        Test that socket connections are blocked in sandbox.

        Critical for preventing network escape.
        """
        # Test various socket operations
        with sandbox:
            # TCP socket should be blocked
            with pytest.raises((OSError, SecurityError, AttributeError)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(("8.8.8.8", 53))

            # UDP socket should be blocked
            with pytest.raises((OSError, SecurityError, AttributeError)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(b"test", ("8.8.8.8", 53))

            # Raw socket should be blocked
            with pytest.raises(
                (OSError, SecurityError, AttributeError, PermissionError)
            ):
                sock = socket.socket(
                    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
                )

            # IPv6 should also be blocked
            with pytest.raises((OSError, SecurityError, AttributeError)):
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.connect(("::1", 80))

    @pytest.mark.security
    async def test_ssl_socket_blocking(self, sandbox):
        """
        Test that SSL/TLS connections are blocked.

        SSL uses socket internally and should be blocked.
        """
        with sandbox:
            # SSL wrap should fail
            with pytest.raises((OSError, SecurityError, TypeError, AttributeError)):
                context = ssl.create_default_context()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                wrapped = context.wrap_socket(sock, server_hostname="example.com")
                wrapped.connect(("example.com", 443))

    @pytest.mark.security
    async def test_http_library_blocking(self, sandbox):
        """
        Test that HTTP libraries are blocked.

        Tests urllib, requests, aiohttp blocking.
        """
        with sandbox:
            # urllib should be blocked
            import urllib.request

            with pytest.raises((OSError, SecurityError, URLError)):
                urllib.request.urlopen("http://example.com")

            # requests should be blocked
            with pytest.raises(
                (OSError, SecurityError, requests.exceptions.ConnectionError)
            ):
                requests.get("http://example.com")

            # aiohttp should be blocked
            with pytest.raises((OSError, SecurityError, aiohttp.ClientError)):
                async with aiohttp.ClientSession() as session:
                    await session.get("http://example.com")

    @pytest.mark.security
    @pytest.mark.critical
    async def test_ssrf_prevention(self, security_engine):
        """
        Test prevention of Server-Side Request Forgery attacks.

        Critical for preventing access to internal resources.
        """
        ssrf_payloads = self.create_ssrf_payloads()

        for payload in ssrf_payloads:
            url = payload["url"]

            # Test URL validation
            is_blocked = await security_engine.is_url_blocked(url)

            if "localhost" in url or "127.0.0" in url or "[::1]" in url:
                assert is_blocked, f"Failed to block localhost URL: {url}"

            if "169.254" in url or "metadata" in url.lower():
                assert is_blocked, f"Failed to block metadata URL: {url}"

            if url.startswith(("file://", "gopher://", "dict://")):
                assert is_blocked, f"Failed to block protocol: {url}"

    @pytest.mark.security
    async def test_dns_resolution_blocking(self, sandbox):
        """
        Test that DNS resolution is blocked.

        Prevents DNS-based attacks and data exfiltration.
        """
        with sandbox:
            # socket.gethostbyname should be blocked
            with pytest.raises((OSError, SecurityError, AttributeError)):
                socket.gethostbyname("example.com")

            # socket.getaddrinfo should be blocked
            with pytest.raises((OSError, SecurityError, AttributeError)):
                socket.getaddrinfo("example.com", 80)

            # socket.gethostbyaddr should be blocked
            with pytest.raises((OSError, SecurityError, AttributeError)):
                socket.gethostbyaddr("8.8.8.8")

    @pytest.mark.security
    async def test_subprocess_network_commands(self, sandbox):
        """
        Test that network commands are blocked in subprocess.

        Prevents command injection for network access.
        """
        blocked_commands = [
            ["curl", "http://example.com"],
            ["wget", "http://example.com"],
            ["nc", "8.8.8.8", "53"],
            ["telnet", "example.com", "80"],
            ["ssh", "user@example.com"],
            ["ping", "8.8.8.8"],
            ["nslookup", "example.com"],
            ["dig", "example.com"],
        ]

        with sandbox:
            for cmd in blocked_commands:
                # Command should be blocked
                with pytest.raises(
                    (OSError, SecurityError, subprocess.CalledProcessError)
                ):
                    result = subprocess.run(
                        cmd, capture_output=True, timeout=1, check=True
                    )

    @pytest.mark.security
    async def test_localhost_only_api(self):
        """
        Test that API only accepts localhost connections.

        Ensures API isn't exposed to network.
        """
        # Test various host bindings
        allowed_hosts = ["localhost", "127.0.0.1", "[::1]", "::1"]
        blocked_hosts = ["0.0.0.0", "192.168.1.1", "10.0.0.1", "example.com"]

        for host in allowed_hosts:
            # Should be allowed
            result = await security_engine.validate_api_host(host)
            assert result is True, f"Localhost host rejected: {host}"

        for host in blocked_hosts:
            # Should be blocked
            result = await security_engine.validate_api_host(host)
            assert result is False, f"Non-localhost host allowed: {host}"

    @pytest.mark.security
    async def test_image_with_embedded_urls(self, security_engine):
        """
        Test handling of images with embedded URLs.

        Prevents data exfiltration via image metadata.
        """
        # Create image with URL in metadata
        from PIL import Image
        import io

        img = Image.new("RGB", (100, 100), color="red")

        # Add EXIF with URL
        exif_data = img.getexif()
        exif_data[0x8298] = "http://evil.com/track"  # Copyright field

        # Save with EXIF
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", exif=exif_data)
        image_data = buffer.getvalue()

        # Check for embedded URLs
        scan_result = await security_engine.scan_for_urls(image_data)

        assert scan_result.get("has_urls", False), "Failed to detect embedded URL"
        assert "evil.com" in str(scan_result.get("urls", [])), "Failed to extract URL"

        # Conversion should strip URLs
        request = ConversionRequest(output_format="png", strip_metadata=True)

        result, output_data = await conversion_service.convert(
            image_data=image_data, request=request
        )

        # URL should be removed
        scan_after = await security_engine.scan_for_urls(output_data)
        assert not scan_after.get("has_urls", False), "URL not removed"

    @pytest.mark.security
    @pytest.mark.slow
    async def test_network_timeout_enforcement(self, sandbox):
        """
        Test that network timeouts are enforced.

        Prevents hanging on network operations.
        """
        with sandbox:
            # Even if network wasn't blocked, operations should timeout

            # Test with mock that simulates hang
            with patch("socket.socket") as mock_socket:
                mock_sock = MagicMock()
                mock_sock.connect = MagicMock(side_effect=lambda x: asyncio.sleep(10))
                mock_socket.return_value = mock_sock

                # Should timeout or be blocked
                with pytest.raises((OSError, SecurityError, asyncio.TimeoutError)):
                    await asyncio.wait_for(
                        asyncio.to_thread(mock_sock.connect, ("8.8.8.8", 53)),
                        timeout=1.0,
                    )

    @pytest.mark.security
    async def test_unix_socket_blocking(self, sandbox):
        """
        Test that Unix domain sockets are blocked.

        Prevents IPC-based escapes.
        """
        if platform.system() == "Windows":
            pytest.skip("Unix sockets not available on Windows")

        with sandbox:
            # Unix socket should be blocked
            with pytest.raises((OSError, SecurityError, AttributeError)):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect("/tmp/test.sock")

    @pytest.mark.security
    async def test_multicast_blocking(self, sandbox):
        """
        Test that multicast is blocked.

        Prevents broadcast attacks and discovery.
        """
        with sandbox:
            # Multicast socket should be blocked
            with pytest.raises((OSError, SecurityError, AttributeError)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("", 9999))

                # Join multicast group
                mreq = socket.inet_aton("224.0.0.1") + socket.inet_aton("0.0.0.0")
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    @pytest.mark.security
    @pytest.mark.critical
    async def test_network_namespace_isolation(self):
        """
        Test network namespace isolation (Linux only).

        Strongest form of network isolation.
        """
        if platform.system() != "Linux":
            pytest.skip("Network namespaces only available on Linux")

        if not os.geteuid() == 0:
            pytest.skip("Network namespace requires root")

        # Create isolated network namespace
        import subprocess

        # Create namespace
        result = subprocess.run(
            ["unshare", "--net", "ip", "addr"], capture_output=True, text=True
        )

        # Should only have loopback
        assert "lo" in result.stdout
        assert "eth" not in result.stdout
        assert "wlan" not in result.stdout

    @pytest.mark.security
    async def test_websocket_blocking(self, sandbox):
        """
        Test that WebSocket connections are blocked.

        WebSockets can be used for data exfiltration.
        """
        with sandbox:
            # WebSocket should be blocked
            import websockets

            with pytest.raises(
                (OSError, SecurityError, websockets.exceptions.WebSocketException)
            ):
                async with websockets.connect("ws://echo.websocket.org"):
                    pass

    @pytest.mark.security
    async def test_grpc_blocking(self, sandbox):
        """
        Test that gRPC connections are blocked.

        gRPC uses HTTP/2 and should be blocked.
        """
        with sandbox:
            try:
                import grpc

                # gRPC channel should fail
                with pytest.raises((OSError, SecurityError, grpc.RpcError)):
                    channel = grpc.insecure_channel("localhost:50051")
                    channel.close()

            except ImportError:
                # gRPC not installed, skip
                pass

    @pytest.mark.security
    async def test_proxy_environment_variables(self, sandbox):
        """
        Test that proxy environment variables are neutralized.

        Prevents proxy-based escapes.
        """
        import os

        # Set proxy variables
        os.environ["HTTP_PROXY"] = "http://evil-proxy.com:8080"
        os.environ["HTTPS_PROXY"] = "http://evil-proxy.com:8080"
        os.environ["http_proxy"] = "http://evil-proxy.com:8080"
        os.environ["https_proxy"] = "http://evil-proxy.com:8080"

        with sandbox:
            # Proxy should be disabled
            assert os.environ.get("HTTP_PROXY", "") in ["", "http://127.0.0.1:1"]
            assert os.environ.get("HTTPS_PROXY", "") in ["", "http://127.0.0.1:1"]

            # Requests should not use proxy
            with pytest.raises(
                (OSError, SecurityError, requests.exceptions.ConnectionError)
            ):
                requests.get("http://example.com")

    @pytest.mark.security
    async def test_network_blocking_persistence(self, sandbox):
        """
        Test that network blocking persists throughout conversion.

        Ensures blocking isn't bypassed during processing.
        """
        # Create test image
        from PIL import Image
        import io

        img = Image.new("RGB", (100, 100))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        image_data = buffer.getvalue()

        # Perform conversion with network monitoring
        network_attempts = []

        def network_monitor(*args, **kwargs):
            network_attempts.append(("socket_call", args, kwargs))
            raise OSError("Network access blocked")

        with patch("socket.socket", side_effect=network_monitor):
            request = ConversionRequest(output_format="jpeg", quality=80)

            result, output = await conversion_service.convert(
                image_data=image_data, request=request
            )

            # Conversion should succeed without network
            assert result.success

            # No network attempts should be made
            assert (
                len(network_attempts) == 0
            ), f"Network access attempted: {network_attempts}"
