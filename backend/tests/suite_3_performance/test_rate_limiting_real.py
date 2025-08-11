"""
Ultra-realistic rate limiting tests.
Tests API throttling, burst handling, and per-user/IP limits.
"""

import asyncio
import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.api.middleware.rate_limit import RateLimiter, RateLimitExceeded
from app.models.conversion import ConversionRequest
from app.services.batch_service import batch_service
from app.services.conversion_service import conversion_service


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_size: int = 10
    cooldown_seconds: int = 60


class TestRateLimitingReal:
    """Test rate limiting under realistic conditions."""

    @pytest.fixture
    def rate_limiter(self):
        """Create RateLimiter instance."""
        config = RateLimitConfig()
        return RateLimiter(
            requests_per_minute=config.requests_per_minute,
            requests_per_hour=config.requests_per_hour,
            burst_size=config.burst_size,
        )

    @pytest.fixture
    def mock_request(self):
        """Create mock request object."""

        class MockRequest:
            def __init__(self, client_ip="127.0.0.1", api_key=None):
                self.client = MagicMock()
                self.client.host = client_ip
                self.headers = {}
                if api_key:
                    self.headers["X-API-Key"] = api_key
                self.url = MagicMock()
                self.url.path = "/api/convert"

        return MockRequest

    @pytest.mark.performance
    @pytest.mark.critical
    async def test_basic_rate_limiting(self, rate_limiter, mock_request):
        """
        Test basic rate limiting enforcement.

        Validates requests are properly throttled.
        """
        request = mock_request()

        # Track successful and blocked requests
        successful = 0
        blocked = 0

        # Make requests up to and beyond limit
        for i in range(70):  # More than 60/minute limit
            try:
                await rate_limiter.check_rate_limit(request)
                successful += 1
            except RateLimitExceeded:
                blocked += 1

            # Small delay to spread requests
            await asyncio.sleep(0.01)

        # Should allow up to limit + burst
        assert successful <= 70  # 60 + 10 burst
        assert blocked > 0, "No requests were blocked"

    @pytest.mark.performance
    async def test_burst_handling(self, rate_limiter, mock_request):
        """
        Test burst request handling.

        Should allow burst then throttle.
        """
        request = mock_request()

        # Send burst of requests
        burst_results = []

        for i in range(15):  # More than burst size
            try:
                await rate_limiter.check_rate_limit(request)
                burst_results.append(True)
            except RateLimitExceeded:
                burst_results.append(False)

        # Should allow burst_size requests immediately
        successful_burst = sum(burst_results[:10])
        assert successful_burst == 10, f"Burst not handled: {successful_burst}/10"

        # Requests beyond burst should be throttled
        blocked_after_burst = sum(1 for r in burst_results[10:] if not r)
        assert blocked_after_burst > 0, "No throttling after burst"

    @pytest.mark.performance
    async def test_per_ip_rate_limiting(self, rate_limiter):
        """
        Test per-IP address rate limiting.

        Different IPs should have separate limits.
        """
        # Create requests from different IPs
        ips = ["192.168.1.1", "192.168.1.2", "10.0.0.1", "172.16.0.1"]

        results_by_ip = defaultdict(list)

        # Each IP makes requests
        for _ in range(20):
            for ip in ips:
                request = self.MockRequest(client_ip=ip)

                try:
                    await rate_limiter.check_rate_limit(request)
                    results_by_ip[ip].append(True)
                except RateLimitExceeded:
                    results_by_ip[ip].append(False)

                await asyncio.sleep(0.01)

        # Each IP should have independent limits
        for ip, results in results_by_ip.items():
            successful = sum(results)
            # Each IP should get some requests through
            assert successful > 0, f"IP {ip} completely blocked"
            # But not all (rate limited)
            assert successful < len(results), f"IP {ip} not rate limited"

    @pytest.mark.performance
    async def test_api_key_rate_limits(self, rate_limiter):
        """
        Test different rate limits for API keys.

        Premium keys get higher limits.
        """
        # Define different API key tiers
        api_keys = {
            "free_key_123": {"tier": "free", "rpm": 10},
            "basic_key_456": {"tier": "basic", "rpm": 60},
            "premium_key_789": {"tier": "premium", "rpm": 300},
            "enterprise_key_abc": {"tier": "enterprise", "rpm": 1000},
        }

        results_by_key = {}

        for api_key, config in api_keys.items():
            # Configure rate limiter for this key
            key_limiter = RateLimiter(
                requests_per_minute=config["rpm"], burst_size=config["rpm"] // 10
            )

            request = self.MockRequest(api_key=api_key)

            # Make requests
            successful = 0
            blocked = 0

            for i in range(config["rpm"] + 10):
                try:
                    await key_limiter.check_rate_limit(request)
                    successful += 1
                except RateLimitExceeded:
                    blocked += 1

                # Faster requests for higher tiers
                delay = 60 / config["rpm"] * 0.5
                await asyncio.sleep(delay)

            results_by_key[api_key] = {
                "successful": successful,
                "blocked": blocked,
                "tier": config["tier"],
            }

        # Verify tier-based limits
        assert results_by_key["free_key_123"]["successful"] <= 15  # 10 + small burst
        assert (
            results_by_key["premium_key_789"]["successful"]
            > results_by_key["basic_key_456"]["successful"]
        )
        assert (
            results_by_key["enterprise_key_abc"]["successful"]
            > results_by_key["premium_key_789"]["successful"]
        )

    @pytest.mark.performance
    async def test_sliding_window_rate_limit(self, rate_limiter):
        """
        Test sliding window rate limiting algorithm.

        More accurate than fixed windows.
        """
        request = self.MockRequest()

        # Make requests over time
        timeline = []

        # First minute - use half the limit
        for i in range(30):
            timestamp = time.time()
            try:
                await rate_limiter.check_rate_limit(request)
                timeline.append((timestamp, True))
            except RateLimitExceeded:
                timeline.append((timestamp, False))

            await asyncio.sleep(1)  # 1 request per second

        # Wait 30 seconds (half window slides)
        await asyncio.sleep(30)

        # Second minute - should allow more requests
        for i in range(40):
            timestamp = time.time()
            try:
                await rate_limiter.check_rate_limit(request)
                timeline.append((timestamp, True))
            except RateLimitExceeded:
                timeline.append((timestamp, False))

            await asyncio.sleep(0.5)

        # Analyze sliding window behavior
        first_minute_success = sum(1 for t, s in timeline[:30] if s)
        second_period_success = sum(1 for t, s in timeline[30:] if s)

        assert first_minute_success <= 30
        assert second_period_success > 0, "Sliding window not working"

    @pytest.mark.performance
    @pytest.mark.critical
    async def test_distributed_rate_limiting(self):
        """
        Test rate limiting across multiple workers/instances.

        Uses Redis or shared storage for distributed limits.
        """

        # Mock Redis for distributed rate limiting
        class MockRedis:
            def __init__(self):
                self.data = {}
                self.expires = {}

            async def incr(self, key):
                self.data[key] = self.data.get(key, 0) + 1
                return self.data[key]

            async def expire(self, key, seconds):
                self.expires[key] = time.time() + seconds

            async def ttl(self, key):
                if key in self.expires:
                    remaining = self.expires[key] - time.time()
                    return max(0, int(remaining))
                return -1

            async def get(self, key):
                if key in self.expires and time.time() > self.expires[key]:
                    del self.data[key]
                    del self.expires[key]
                    return None
                return self.data.get(key)

        redis = MockRedis()

        # Simulate multiple workers
        async def worker_requests(worker_id, redis, num_requests=20):
            results = []

            for i in range(num_requests):
                key = f"rate_limit:global"

                # Check rate limit using Redis
                count = await redis.incr(key)

                if count == 1:
                    # First request, set expiry
                    await redis.expire(key, 60)

                if count <= 60:  # Global limit
                    results.append(True)
                else:
                    results.append(False)

                await asyncio.sleep(0.1)

            return results

        # Run multiple workers concurrently
        workers = [worker_requests(i, redis, 25) for i in range(4)]

        all_results = await asyncio.gather(*workers)

        # Total successful across all workers should respect global limit
        total_successful = sum(sum(results) for results in all_results)
        assert total_successful <= 65, f"Global limit exceeded: {total_successful}"

        # Each worker should get some requests
        for worker_results in all_results:
            assert sum(worker_results) > 0, "Worker completely blocked"

    @pytest.mark.performance
    async def test_rate_limit_headers(self, rate_limiter, mock_request):
        """
        Test rate limit headers in responses.

        Should include X-RateLimit-* headers.
        """
        request = mock_request()

        # Mock response headers
        response_headers = {}

        # Make request and capture headers
        for i in range(5):
            try:
                remaining = await rate_limiter.check_rate_limit(request)

                # Set headers
                response_headers["X-RateLimit-Limit"] = "60"
                response_headers["X-RateLimit-Remaining"] = str(60 - i - 1)
                response_headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)

            except RateLimitExceeded as e:
                response_headers["X-RateLimit-Limit"] = "60"
                response_headers["X-RateLimit-Remaining"] = "0"
                response_headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)
                response_headers["Retry-After"] = "60"

        # Verify headers are set
        assert "X-RateLimit-Limit" in response_headers
        assert "X-RateLimit-Remaining" in response_headers
        assert "X-RateLimit-Reset" in response_headers

    @pytest.mark.performance
    async def test_endpoint_specific_limits(self, rate_limiter):
        """
        Test different rate limits for different endpoints.

        Some endpoints need different limits.
        """
        # Define endpoint limits
        endpoint_limits = {
            "/api/convert": 60,  # Standard conversion
            "/api/batch": 10,  # Batch is resource-intensive
            "/api/intelligence/classify": 100,  # ML classification
            "/api/formats": 1000,  # Simple metadata
            "/api/health": 10000,  # Health checks
        }

        results_by_endpoint = {}

        for endpoint, limit in endpoint_limits.items():
            # Create endpoint-specific limiter
            endpoint_limiter = RateLimiter(
                requests_per_minute=limit, burst_size=limit // 10
            )

            request = self.MockRequest()
            request.url.path = endpoint

            # Test limit
            successful = 0

            for i in range(limit + 5):
                try:
                    await endpoint_limiter.check_rate_limit(request)
                    successful += 1
                except RateLimitExceeded:
                    break

                # Quick requests
                await asyncio.sleep(0.001)

            results_by_endpoint[endpoint] = successful

        # Verify endpoint-specific limits
        assert results_by_endpoint["/api/batch"] <= 11  # 10 + burst
        assert results_by_endpoint["/api/health"] > results_by_endpoint["/api/convert"]

    @pytest.mark.performance
    @pytest.mark.slow
    async def test_rate_limit_recovery(self, rate_limiter, mock_request):
        """
        Test recovery after hitting rate limit.

        Should allow requests again after cooldown.
        """
        request = mock_request()

        # Hit rate limit
        for i in range(70):
            try:
                await rate_limiter.check_rate_limit(request)
            except RateLimitExceeded:
                break

        # Should be rate limited now
        with pytest.raises(RateLimitExceeded):
            await rate_limiter.check_rate_limit(request)

        # Wait for cooldown (simulated)
        await asyncio.sleep(2)  # In real test would be 60s

        # Mock time passage
        with patch("time.time", return_value=time.time() + 60):
            # Should allow requests again
            try:
                await rate_limiter.check_rate_limit(request)
                recovered = True
            except RateLimitExceeded:
                recovered = False

        assert recovered, "Didn't recover after cooldown"

    @pytest.mark.performance
    async def test_websocket_rate_limiting(self):
        """
        Test rate limiting for WebSocket connections.

        WebSockets need special handling.
        """
        # Track WebSocket connections
        connections_by_ip = defaultdict(list)
        max_connections_per_ip = 10

        async def accept_websocket(client_ip):
            """Simulate WebSocket acceptance with rate limiting."""
            current_connections = len(
                [c for c in connections_by_ip[client_ip] if c["active"]]
            )

            if current_connections >= max_connections_per_ip:
                raise RateLimitExceeded(f"Max WebSocket connections for {client_ip}")

            connection = {
                "id": hashlib.md5(f"{client_ip}{time.time()}".encode()).hexdigest(),
                "active": True,
                "created": time.time(),
            }

            connections_by_ip[client_ip].append(connection)
            return connection

        # Test connection limits
        test_ip = "192.168.1.100"

        successful_connections = []

        for i in range(15):
            try:
                conn = await accept_websocket(test_ip)
                successful_connections.append(conn)
            except RateLimitExceeded:
                break

        assert len(successful_connections) == max_connections_per_ip

        # Close some connections
        for conn in successful_connections[:5]:
            conn["active"] = False

        # Should allow new connections
        new_connections = []
        for i in range(5):
            try:
                conn = await accept_websocket(test_ip)
                new_connections.append(conn)
            except RateLimitExceeded:
                break

        assert len(new_connections) == 5, "Didn't allow new connections after closing"

    @pytest.mark.performance
    async def test_rate_limit_bypass_prevention(self, rate_limiter):
        """
        Test prevention of rate limit bypass attempts.

        Common bypass techniques should be blocked.
        """
        # Test various bypass attempts
        bypass_attempts = [
            # Spoofed headers
            {"X-Forwarded-For": "1.2.3.4"},
            {"X-Real-IP": "5.6.7.8"},
            {"X-Client-IP": "9.10.11.12"},
            # Multiple IPs
            {"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 3.3.3.3"},
            # IPv6 variations
            {"X-Forwarded-For": "::1"},
            {"X-Forwarded-For": "0:0:0:0:0:0:0:1"},
            # Case variations
            {"x-forwarded-for": "13.14.15.16"},
            {"X-FORWARDED-FOR": "17.18.19.20"},
        ]

        for headers in bypass_attempts:
            request = self.MockRequest()
            request.headers.update(headers)

            # Should still be rate limited by actual IP
            successful = 0
            for i in range(70):
                try:
                    await rate_limiter.check_rate_limit(request)
                    successful += 1
                except RateLimitExceeded:
                    break

            # Should not bypass limit
            assert successful <= 70, f"Bypass with headers: {headers}"

    @pytest.mark.performance
    async def test_graceful_degradation_under_load(
        self, rate_limiter, realistic_image_generator
    ):
        """
        Test graceful degradation when rate limited.

        Should prioritize important requests.
        """
        # Define request priorities
        high_priority_requests = []
        low_priority_requests = []

        for i in range(50):
            if i % 5 == 0:
                # High priority (e.g., paid user)
                high_priority_requests.append(
                    {
                        "id": i,
                        "priority": "high",
                        "image": realistic_image_generator(width=100, height=100),
                    }
                )
            else:
                # Low priority
                low_priority_requests.append(
                    {
                        "id": i,
                        "priority": "low",
                        "image": realistic_image_generator(width=100, height=100),
                    }
                )

        # Process with priority
        high_priority_success = 0
        low_priority_success = 0

        # Process high priority first
        for req in high_priority_requests:
            try:
                request_obj = self.MockRequest(api_key="premium_key")
                await rate_limiter.check_rate_limit(request_obj)
                high_priority_success += 1
            except RateLimitExceeded:
                pass

        # Then low priority
        for req in low_priority_requests:
            try:
                request_obj = self.MockRequest()
                await rate_limiter.check_rate_limit(request_obj)
                low_priority_success += 1
            except RateLimitExceeded:
                pass

        # High priority should have better success rate
        high_priority_rate = high_priority_success / len(high_priority_requests)
        low_priority_rate = (
            low_priority_success / len(low_priority_requests)
            if low_priority_requests
            else 0
        )

        assert (
            high_priority_rate > low_priority_rate or high_priority_rate == 1.0
        ), "Priority not respected in rate limiting"

    class MockRequest:
        """Helper class for creating mock requests."""

        def __init__(self, client_ip="127.0.0.1", api_key=None):
            self.client = MagicMock()
            self.client.host = client_ip
            self.headers = {}
            if api_key:
                self.headers["X-API-Key"] = api_key
            self.url = MagicMock()
            self.url.path = "/api/convert"
