"""Request validation middleware for enhanced API security."""

import asyncio
import time
from collections import defaultdict, deque
from typing import Dict, Optional

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from app.config import settings
from app.core.security.rate_limiter import api_rate_limiter

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
            expired_blocks = [
                ip for ip, expiry in self.blocked_ips.items() if expiry < current_time
            ]
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

    def _is_rate_limited(
        self, client_ip: str, request: Request
    ) -> tuple[bool, str, dict]:
        """Check if client IP is rate limited using enhanced API rate limiter.

        Args:
            client_ip: Client IP address
            request: FastAPI request object

        Returns:
            Tuple of (is_limited, message, headers)
        """
        # Get API key info from request state (set by auth middleware)
        api_key_record = getattr(request.state, "api_key", None)
        api_key_id = api_key_record.id if api_key_record else None
        custom_limit = api_key_record.rate_limit_override if api_key_record else None

        # Use enhanced API rate limiter
        allowed, headers = api_rate_limiter.check_rate_limit(api_key_id, custom_limit)

        if not allowed:
            # Determine which limit was hit based on headers
            remaining = int(headers.get("X-RateLimit-Remaining", "0"))
            limit = int(headers.get("X-RateLimit-Limit", "60"))

            if api_key_record:
                message = f"API key rate limit exceeded: {limit - remaining}/{limit} requests per minute"
            else:
                message = f"Rate limit exceeded: {limit - remaining}/{limit} requests per minute"

            return True, message, headers

        return False, "", headers

    # Remove _unblock_ip_later method - no longer needed with timestamp-based blocking

    def _validate_request_size(self, request: Request) -> tuple[bool, str]:
        """Validate request body size."""
        content_length = request.headers.get("content-length")

        if content_length:
            try:
                size = int(content_length)
                if size > self.max_body_size:
                    return (
                        False,
                        f"Request body too large: {size} bytes (max: {self.max_body_size})",
                    )
            except ValueError:
                return False, "Invalid Content-Length header"

        return True, ""

    def _validate_content_type(self, request: Request) -> tuple[bool, str]:
        """Validate content type for relevant endpoints."""
        if request.method == "POST":
            content_type = request.headers.get("content-type", "")

            # File upload endpoints should use multipart/form-data
            if any(
                path in request.url.path
                for path in [
                    "/convert",
                    "/detect-format",
                    "/recommend-format",
                    "/batch",
                ]
            ):
                if not content_type.startswith("multipart/form-data"):
                    return (
                        False,
                        "File upload endpoints require multipart/form-data content type",
                    )

            # JSON endpoints should use application/json
            elif any(
                path in request.url.path
                for path in ["/presets", "/intelligence", "/optimize"]
            ):
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
            if any(
                path in request.url.path
                for path in [
                    "/convert",
                    "/detect-format",
                    "/recommend-format",
                    "/batch",
                ]
            ):
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

            # Check rate limiting with enhanced API rate limiter
            is_limited, limit_message, rate_limit_headers = self._is_rate_limited(
                client_ip, request
            )
            if is_limited:
                logger.warning(
                    "Request rate limited",
                    client_ip=client_ip,
                    path=request.url.path,
                    message=limit_message,
                    api_key_authenticated=hasattr(request.state, "authenticated")
                    and request.state.authenticated,
                )

                # Create response with rate limit headers
                response = JSONResponse(
                    status_code=429,
                    content={
                        "error_code": "VAL429",
                        "message": limit_message,
                        "correlation_id": getattr(
                            request.state, "correlation_id", "unknown"
                        ),
                        "retry_after": 60,  # seconds
                    },
                )

                # Add rate limit headers
                for header, value in rate_limit_headers.items():
                    response.headers[header] = value

                return response

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
                    message=size_message,
                )
                return JSONResponse(
                    status_code=413,
                    content={
                        "error_code": "VAL413",
                        "message": size_message,
                        "correlation_id": getattr(
                            request.state, "correlation_id", "unknown"
                        ),
                    },
                )

            # Validate content type
            content_valid, content_message = self._validate_content_type(request)
            if not content_valid:
                logger.warning(
                    "Content type validation failed",
                    client_ip=client_ip,
                    path=request.url.path,
                    message=content_message,
                )
                return JSONResponse(
                    status_code=415,
                    content={
                        "error_code": "VAL415",
                        "message": content_message,
                        "correlation_id": getattr(
                            request.state, "correlation_id", "unknown"
                        ),
                    },
                )

            # Validate headers
            headers_valid, headers_message = self._validate_headers(request)
            if not headers_valid:
                logger.warning(
                    "Header validation failed",
                    client_ip=client_ip,
                    path=request.url.path,
                    message=headers_message,
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error_code": "VAL400",
                        "message": headers_message,
                        "correlation_id": getattr(
                            request.state, "correlation_id", "unknown"
                        ),
                    },
                )

            # All validations passed
            return None

        except Exception as e:
            logger.exception(
                "Unexpected error in request validation",
                error=str(e),
                client_ip=client_ip if "client_ip" in locals() else "unknown",
                path=request.url.path,
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error_code": "VAL500",
                    "message": "Internal validation error",
                    "correlation_id": getattr(
                        request.state, "correlation_id", "unknown"
                    ),
                },
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
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        # Add rate limiting headers using enhanced API rate limiter
        api_key_record = getattr(request.state, "api_key", None)
        api_key_id = api_key_record.id if api_key_record else None
        custom_limit = api_key_record.rate_limit_override if api_key_record else None

        # Get current rate limit headers
        _, rate_limit_headers = api_rate_limiter.check_rate_limit(
            api_key_id, custom_limit
        )

        # Add rate limit headers to response
        for header, value in rate_limit_headers.items():
            response.headers[header] = value

        return response

    except Exception:
        # Check if request timed out
        if hasattr(request.state, "start_time"):
            elapsed = time.time() - request.state.start_time
            if elapsed > request_validator.request_timeout:
                logger.error(
                    "Request timeout",
                    path=request.url.path,
                    elapsed_time=elapsed,
                    timeout_limit=request_validator.request_timeout,
                )
                return JSONResponse(
                    status_code=408,
                    content={
                        "error_code": "VAL408",
                        "message": f"Request timeout after {elapsed:.1f} seconds",
                        "correlation_id": getattr(
                            request.state, "correlation_id", "unknown"
                        ),
                    },
                )

        # Re-raise the exception to be handled by other middleware
        raise
