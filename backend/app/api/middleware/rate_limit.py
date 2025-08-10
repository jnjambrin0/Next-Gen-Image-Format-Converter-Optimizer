"""
Rate limiting middleware for API endpoints.
Stub implementation for testing.
"""

from typing import Dict, Optional
import time
import asyncio
from datetime import datetime, timedelta


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    pass


class RateLimiter:
    """Rate limiter for API endpoints."""
    
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = {}
        self._lock = asyncio.Lock()
        
    async def check_rate_limit(self, identifier: str) -> bool:
        """Check if identifier has exceeded rate limit."""
        async with self._lock:
            now = time.time()
            
            # Clean old requests
            if identifier in self.requests:
                self.requests[identifier] = [
                    req_time for req_time in self.requests[identifier]
                    if now - req_time < self.window_seconds
                ]
            else:
                self.requests[identifier] = []
            
            # Check limit
            if len(self.requests[identifier]) >= self.max_requests:
                raise RateLimitExceeded(f"Rate limit exceeded for {identifier}")
            
            # Add current request
            self.requests[identifier].append(now)
            return True
            
    async def reset(self, identifier: Optional[str] = None) -> None:
        """Reset rate limit for identifier or all."""
        async with self._lock:
            if identifier:
                self.requests.pop(identifier, None)
            else:
                self.requests.clear()
                
    def get_remaining_requests(self, identifier: str) -> int:
        """Get remaining requests for identifier."""
        now = time.time()
        if identifier not in self.requests:
            return self.max_requests
            
        active_requests = [
            req_time for req_time in self.requests[identifier]
            if now - req_time < self.window_seconds
        ]
        return max(0, self.max_requests - len(active_requests))
        
    def get_reset_time(self, identifier: str) -> Optional[datetime]:
        """Get when rate limit resets for identifier."""
        if identifier not in self.requests or not self.requests[identifier]:
            return None
            
        oldest_request = min(self.requests[identifier])
        reset_time = datetime.fromtimestamp(oldest_request + self.window_seconds)
        return reset_time