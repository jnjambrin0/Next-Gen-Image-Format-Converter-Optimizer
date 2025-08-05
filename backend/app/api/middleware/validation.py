"""Request validation middleware for enhanced API security."""

import time
import asyncio
from typing import Dict, Optional, Set
from collections import defaultdict, deque

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
import structlog

from app.config import settings

logger = structlog.get_logger()


class RequestValidator:
    """Enhanced request validation with rate limiting and size controls."""
    
    def __init__(self):
        # Use maxlen to automatically limit deque size and prevent unbounded growth
        self.request_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.blocked_ips: Dict[str, float] = {}  # IP -> block expiry timestamp
        self.last_cleanup = time.time()
        self._cleanup_lock = asyncio.Lock()
        
        # Configuration - use settings directly (they now exist)
        self.max_requests_per_minute = settings.max_requests_per_minute
        self.max_requests_per_hour = settings.max_requests_per_hour
        self.max_body_size = settings.max_request_body_size
        self.request_timeout = settings.request_timeout
        
    async def _cleanup_old_requests(self):
        """Clean up old request tracking data and expired IP blocks."""
        async with self._cleanup_lock:
            current_time = time.time()
            
            # Only cleanup every 5 minutes
            if current_time - self.last_cleanup < 300:
                return
                
            cutoff_time = current_time - 3600  # 1 hour ago
            
            # Clean up old requests
            empty_ips = []
            for ip, requests in list(self.request_counts.items()):
                # Remove requests older than 1 hour
                while requests and requests[0] < cutoff_time:
                    requests.popleft()
                
                # Mark empty entries for removal
                if not requests:
                    empty_ips.append(ip)
            
            # Remove empty IP entries to prevent memory leak
            for ip in empty_ips:
                del self.request_counts[ip]
            
            # Clean up expired IP blocks
            expired_blocks = [ip for ip, expiry in self.blocked_ips.items() if expiry < current_time]
            for ip in expired_blocks:
                del self.blocked_ips[ip]
                
            self.last_cleanup = current_time
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request."""
        # Check for forwarded headers (common in reverse proxy setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
            
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
            
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"
    
    def _is_rate_limited(self, client_ip: str) -> tuple[bool, str]:
        """Check if client IP is rate limited."""
        current_time = time.time()
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            if self.blocked_ips[client_ip] > current_time:
                remaining_time = int(self.blocked_ips[client_ip] - current_time)
                return True, f"IP temporarily blocked due to excessive requests. Try again in {remaining_time} seconds"
            else:
                # Block has expired, remove it
                del self.blocked_ips[client_ip]
        
        requests = self.request_counts[client_ip]
        
        # Count requests in last minute
        minute_ago = current_time - 60
        minute_requests = sum(1 for req_time in requests if req_time > minute_ago)
        
        if minute_requests >= self.max_requests_per_minute:
            # Block IP for 5 minutes
            self.blocked_ips[client_ip] = current_time + 300
            return True, f"Rate limit exceeded: {minute_requests} requests per minute (max: {self.max_requests_per_minute})"
        
        # Count requests in last hour
        hour_ago = current_time - 3600
        hour_requests = sum(1 for req_time in requests if req_time > hour_ago)
        
        if hour_requests >= self.max_requests_per_hour:
            # Block IP for 1 hour
            self.blocked_ips[client_ip] = current_time + 3600
            return True, f"Hourly rate limit exceeded: {hour_requests} requests per hour (max: {self.max_requests_per_hour})"
        
        return False, ""
    
    # Remove _unblock_ip_later method - no longer needed with timestamp-based blocking
    
    def _validate_request_size(self, request: Request) -> tuple[bool, str]:
        """Validate request body size."""
        content_length = request.headers.get("content-length")
        
        if content_length:
            try:
                size = int(content_length)
                if size > self.max_body_size:
                    return False, f"Request body too large: {size} bytes (max: {self.max_body_size})"
            except ValueError:
                return False, "Invalid Content-Length header"
                
        return True, ""
    
    def _validate_content_type(self, request: Request) -> tuple[bool, str]:
        """Validate content type for relevant endpoints."""
        if request.method == "POST":
            content_type = request.headers.get("content-type", "")
            
            # File upload endpoints should use multipart/form-data
            if any(path in request.url.path for path in ["/convert", "/detect-format", "/recommend-format", "/batch"]):
                if not content_type.startswith("multipart/form-data"):
                    return False, "File upload endpoints require multipart/form-data content type"
            
            # JSON endpoints should use application/json
            elif any(path in request.url.path for path in ["/presets", "/intelligence", "/optimize"]):
                if content_type.startswith("multipart/form-data"):
                    # Skip validation for mixed endpoints that can accept both
                    pass
                elif content_type and not content_type.startswith("application/json"):
                    return False, "JSON endpoints require application/json content type"
        
        return True, ""
    
    def _validate_headers(self, request: Request) -> tuple[bool, str]:
        """Validate request headers."""
        # Check for required headers
        if request.method == "POST":
            # File uploads should have content-length
            if any(path in request.url.path for path in ["/convert", "/detect-format", "/recommend-format", "/batch"]):
                if not request.headers.get("content-length"):
                    return False, "Content-Length header required for file uploads"
        
        # Validate custom headers if present
        correlation_id = request.headers.get("X-Correlation-ID")
        if correlation_id and len(correlation_id) > 100:
            return False, "X-Correlation-ID header too long (max: 100 characters)"
        
        # Validate Accept-Version header
        accept_version = request.headers.get("Accept-Version")
        if accept_version and accept_version not in ["v1"]:
            return False, f"Unsupported API version: {accept_version}"
        
        return True, ""
    
    async def validate_request(self, request: Request) -> Optional[Response]:
        """Perform comprehensive request validation."""
        try:
            # Cleanup old tracking data periodically
            await self._cleanup_old_requests()
            
            # Get client IP
            client_ip = self._get_client_ip(request)
            
            # Check rate limiting
            is_limited, limit_message = self._is_rate_limited(client_ip)
            if is_limited:
                logger.warning(
                    "Request rate limited",
                    client_ip=client_ip,
                    path=request.url.path,
                    message=limit_message
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error_code": "VAL429",
                        "message": limit_message,
                        "correlation_id": getattr(request.state, 'correlation_id', 'unknown'),
                        "retry_after": 60,  # seconds
                    }
                )
            
            # Record this request
            current_time = time.time()
            self.request_counts[client_ip].append(current_time)
            
            # Validate request size
            size_valid, size_message = self._validate_request_size(request)
            if not size_valid:
                logger.warning(
                    "Request size validation failed",
                    client_ip=client_ip,
                    path=request.url.path,
                    message=size_message
                )
                return JSONResponse(
                    status_code=413,
                    content={
                        "error_code": "VAL413",
                        "message": size_message,
                        "correlation_id": getattr(request.state, 'correlation_id', 'unknown'),
                    }
                )
            
            # Validate content type
            content_valid, content_message = self._validate_content_type(request)
            if not content_valid:
                logger.warning(
                    "Content type validation failed",
                    client_ip=client_ip,
                    path=request.url.path,
                    message=content_message
                )
                return JSONResponse(
                    status_code=415,
                    content={
                        "error_code": "VAL415",
                        "message": content_message,
                        "correlation_id": getattr(request.state, 'correlation_id', 'unknown'),
                    }
                )
            
            # Validate headers
            headers_valid, headers_message = self._validate_headers(request)
            if not headers_valid:
                logger.warning(
                    "Header validation failed",
                    client_ip=client_ip,
                    path=request.url.path,
                    message=headers_message
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error_code": "VAL400",
                        "message": headers_message,
                        "correlation_id": getattr(request.state, 'correlation_id', 'unknown'),
                    }
                )
            
            # All validations passed
            return None
            
        except Exception as e:
            logger.exception(
                "Unexpected error in request validation",
                error=str(e),
                client_ip=client_ip if 'client_ip' in locals() else 'unknown',
                path=request.url.path
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error_code": "VAL500",
                    "message": "Internal validation error",
                    "correlation_id": getattr(request.state, 'correlation_id', 'unknown'),
                }
            )


# Global validator instance
request_validator = RequestValidator()


async def validation_middleware(request: Request, call_next):
    """FastAPI middleware for request validation."""
    
    # Skip validation for certain endpoints
    skip_paths = ["/api/docs", "/api/redoc", "/api/openapi.json", "/health"]
    if any(request.url.path.startswith(path) for path in skip_paths):
        return await call_next(request)
    
    # Perform validation
    validation_response = await request_validator.validate_request(request)
    if validation_response:
        return validation_response
    
    # Set request start time for timeout tracking
    request.state.start_time = time.time()
    
    # Continue with request processing
    try:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Add rate limiting headers
        client_ip = request_validator._get_client_ip(request)
        current_time = time.time()
        minute_ago = current_time - 60
        requests = request_validator.request_counts[client_ip]
        minute_requests = sum(1 for req_time in requests if req_time > minute_ago)
        
        response.headers["X-RateLimit-Limit"] = str(request_validator.max_requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(max(0, request_validator.max_requests_per_minute - minute_requests))
        response.headers["X-RateLimit-Reset"] = str(int(current_time + 60))
        
        return response
        
    except Exception as e:
        # Check if request timed out
        if hasattr(request.state, 'start_time'):
            elapsed = time.time() - request.state.start_time
            if elapsed > request_validator.request_timeout:
                logger.error(
                    "Request timeout",
                    path=request.url.path,
                    elapsed_time=elapsed,
                    timeout_limit=request_validator.request_timeout
                )
                return JSONResponse(
                    status_code=408,
                    content={
                        "error_code": "VAL408",
                        "message": f"Request timeout after {elapsed:.1f} seconds",
                        "correlation_id": getattr(request.state, 'correlation_id', 'unknown'),
                    }
                )
        
        # Re-raise the exception to be handled by other middleware
        raise