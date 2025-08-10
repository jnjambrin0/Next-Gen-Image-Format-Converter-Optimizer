"""
Token bucket rate limiter for security events and API requests.
"""

import time
from threading import Lock
from typing import Any, Dict, Optional, Tuple

from app.core.constants import (RATE_LIMIT_BURST_SIZE,
                                RATE_LIMIT_EVENTS_PER_HOUR,
                                RATE_LIMIT_EVENTS_PER_MINUTE,
                                RATE_LIMIT_HOUR_BURST_DIVISOR,
                                RATE_LIMIT_TOKEN_REFILL_AMOUNT)
from app.core.security.types import RateLimitConfig


class TokenBucket:
    """Token bucket implementation for rate limiting."""

    def __init__(self, rate: float, capacity: int) -> None:
        """
        Initialize token bucket.

        Args:
            rate: Tokens per second to add
            capacity: Maximum tokens in bucket
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_update = time.time()
        self.lock = Lock()

    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from bucket.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were available, False otherwise
        """
        with self.lock:
            # Refill bucket based on time elapsed
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now

            # Try to consume tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_available_tokens(self) -> int:
        """Get number of available tokens."""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            return int(min(self.capacity, self.tokens + elapsed * self.rate))


class SecurityEventRateLimiter:
    """Rate limiter for security events."""

    def __init__(self, config: Optional[RateLimitConfig] = None) -> None:
        """
        Initialize rate limiter.

        Args:
            config: Rate limit configuration
        """
        if config is None:
            # Default configuration
            config = {
                "max_events_per_minute": int(RATE_LIMIT_EVENTS_PER_MINUTE),
                "max_events_per_hour": int(RATE_LIMIT_EVENTS_PER_HOUR),
                "burst_size": int(RATE_LIMIT_BURST_SIZE),
                "enabled": True,
            }

        self.config = config
        self.enabled = config["enabled"]

        # Create token buckets for different time windows
        self.minute_bucket = TokenBucket(
            rate=config["max_events_per_minute"] / 60.0,  # tokens per second
            capacity=config["burst_size"],
        )

        self.hour_bucket = TokenBucket(
            rate=config["max_events_per_hour"] / 3600.0,  # tokens per second
            capacity=int(
                config["max_events_per_hour"] // RATE_LIMIT_HOUR_BURST_DIVISOR
            ),  # 10% burst capacity
        )

        # Track rate limit violations
        self.violations_count = 0
        self.last_violation_time = None
        self.lock = Lock()

    def should_allow_event(self, event_type: Optional[str] = None) -> bool:
        """
        Check if event should be allowed based on rate limits.

        Args:
            event_type: Type of event (for future per-type limiting)

        Returns:
            True if event should be allowed, False if rate limited
        """
        if not self.enabled:
            return True

        # Check both minute and hour buckets
        minute_ok = self.minute_bucket.consume()
        hour_ok = self.hour_bucket.consume()

        # Both must have capacity
        allowed = minute_ok and hour_ok

        # If rate limited, restore tokens and track violation
        if not allowed:
            if minute_ok:
                # Restore minute token if hour limit hit
                self.minute_bucket.tokens += RATE_LIMIT_TOKEN_REFILL_AMOUNT

            with self.lock:
                self.violations_count += 1
                self.last_violation_time = time.time()

        return allowed

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        with self.lock:
            return {
                "enabled": self.enabled,
                "violations_count": self.violations_count,
                "last_violation_time": self.last_violation_time,
                "minute_tokens_available": self.minute_bucket.get_available_tokens(),
                "hour_tokens_available": self.hour_bucket.get_available_tokens(),
                "config": self.config,
            }

    def reset_violations(self) -> None:
        """Reset violation counter."""
        with self.lock:
            self.violations_count = 0
            self.last_violation_time = None

    def get_rate_limit_headers(self) -> Dict[str, str]:
        """Get rate limit headers for HTTP responses.

        Returns:
            Dictionary of rate limit headers
        """
        minute_available = self.minute_bucket.get_available_tokens()
        hour_available = self.hour_bucket.get_available_tokens()

        # Use minute bucket for headers (standard practice)
        limit = self.config["max_events_per_minute"]
        remaining = max(0, minute_available)
        reset_time = int(time.time() + 60)  # Reset in 60 seconds

        return {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_time),
            "X-RateLimit-Window": "60",  # 60 seconds
        }


class ApiRateLimiter:
    """Rate limiter for API requests with per-key support."""

    def __init__(self) -> None:
        """Initialize API rate limiter."""
        self.limiters: Dict[str, SecurityEventRateLimiter] = {}
        self.default_limiter = SecurityEventRateLimiter()
        self.lock = Lock()

    def get_limiter_for_key(
        self, api_key_id: Optional[str], custom_limit: Optional[int] = None
    ) -> SecurityEventRateLimiter:
        """Get rate limiter for a specific API key.

        Args:
            api_key_id: API key ID (None for unauthenticated requests)
            custom_limit: Custom rate limit override per minute

        Returns:
            Rate limiter instance
        """
        if not api_key_id:
            return self.default_limiter

        with self.lock:
            if api_key_id not in self.limiters:
                # Create custom config if needed
                config = None
                if custom_limit:
                    config = {
                        "max_events_per_minute": custom_limit,
                        "max_events_per_hour": custom_limit * 60,  # Scale hourly limit
                        "burst_size": min(custom_limit, RATE_LIMIT_BURST_SIZE),
                        "enabled": True,
                    }

                self.limiters[api_key_id] = SecurityEventRateLimiter(config)

            return self.limiters[api_key_id]

    def check_rate_limit(
        self, api_key_id: Optional[str] = None, custom_limit: Optional[int] = None
    ) -> Tuple[bool, Dict[str, str]]:
        """Check rate limit and return headers.

        Args:
            api_key_id: API key ID (None for unauthenticated requests)
            custom_limit: Custom rate limit override per minute

        Returns:
            Tuple of (allowed, headers)
        """
        limiter = self.get_limiter_for_key(api_key_id, custom_limit)
        allowed = limiter.should_allow_event("api_request")
        headers = limiter.get_rate_limit_headers()

        return allowed, headers

    def get_stats(self, api_key_id: Optional[str] = None) -> Dict[str, Any]:
        """Get rate limiter statistics.

        Args:
            api_key_id: API key ID (None for default limiter)

        Returns:
            Statistics dictionary
        """
        if not api_key_id:
            return self.default_limiter.get_stats()

        with self.lock:
            if api_key_id in self.limiters:
                return self.limiters[api_key_id].get_stats()
            else:
                # Return empty stats for non-existent key
                return {
                    "enabled": True,
                    "violations_count": 0,
                    "last_violation_time": None,
                    "minute_tokens_available": 0,
                    "hour_tokens_available": 0,
                    "config": {},
                }

    def cleanup_unused_limiters(self, active_key_ids: set[str]) -> int:
        """Clean up rate limiters for unused API keys.

        Args:
            active_key_ids: Set[Any] of currently active API key IDs

        Returns:
            Number of limiters cleaned up
        """
        with self.lock:
            to_remove = []
            for key_id in self.limiters:
                if key_id not in active_key_ids:
                    to_remove.append(key_id)

            for key_id in to_remove:
                del self.limiters[key_id]

            return len(to_remove)


# Global API rate limiter instance
api_rate_limiter = ApiRateLimiter()
