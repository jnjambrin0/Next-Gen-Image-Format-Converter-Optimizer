"""
Token bucket rate limiter for security events.
"""

import time
from typing import Dict, Optional
from threading import Lock

from app.core.security.types import RateLimitConfig
from app.core.constants import (
    RATE_LIMIT_EVENTS_PER_MINUTE,
    RATE_LIMIT_EVENTS_PER_HOUR,
    RATE_LIMIT_BURST_SIZE,
    RATE_LIMIT_HOUR_BURST_DIVISOR,
    RATE_LIMIT_TOKEN_REFILL_AMOUNT
)


class TokenBucket:
    """Token bucket implementation for rate limiting."""
    
    def __init__(self, rate: float, capacity: int):
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
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Initialize rate limiter.
        
        Args:
            config: Rate limit configuration
        """
        if config is None:
            # Default configuration
            config = {
                "max_events_per_minute": RATE_LIMIT_EVENTS_PER_MINUTE,
                "max_events_per_hour": RATE_LIMIT_EVENTS_PER_HOUR,
                "burst_size": RATE_LIMIT_BURST_SIZE,
                "enabled": True
            }
        
        self.config = config
        self.enabled = config["enabled"]
        
        # Create token buckets for different time windows
        self.minute_bucket = TokenBucket(
            rate=config["max_events_per_minute"] / 60.0,  # tokens per second
            capacity=config["burst_size"]
        )
        
        self.hour_bucket = TokenBucket(
            rate=config["max_events_per_hour"] / 3600.0,  # tokens per second
            capacity=config["max_events_per_hour"] // RATE_LIMIT_HOUR_BURST_DIVISOR  # 10% burst capacity
        )
        
        # Track rate limit violations
        self.violations_count = 0
        self.last_violation_time = None
        self.lock = Lock()
    
    def should_allow_event(self, event_type: str = None) -> bool:
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
    
    def get_stats(self) -> Dict[str, any]:
        """Get rate limiter statistics."""
        with self.lock:
            return {
                "enabled": self.enabled,
                "violations_count": self.violations_count,
                "last_violation_time": self.last_violation_time,
                "minute_tokens_available": self.minute_bucket.get_available_tokens(),
                "hour_tokens_available": self.hour_bucket.get_available_tokens(),
                "config": self.config
            }
    
    def reset_violations(self) -> None:
        """Reset violation counter."""
        with self.lock:
            self.violations_count = 0
            self.last_violation_time = None