"""Authentication middleware for optional API key support."""

from typing import Optional

from fastapi import HTTPException, Request, status
from fastapi.security.utils import get_authorization_scheme_param

from app.models.database import ApiKey
from app.services.api_key_service import api_key_service
from app.utils.logging import get_logger

logger = get_logger(__name__)


class OptionalAPIKeyAuth:
    """Optional API key authentication dependency."""

    def __init__(self, auto_error: bool = False):
        """Initialize optional API key authentication.

        Args:
            auto_error: Whether to automatically raise errors for invalid keys
        """
        self.auto_error = auto_error
        self.logger = get_logger(__name__)

    async def __call__(self, request: Request) -> Optional[ApiKey]:
        """Extract and verify API key from request.

        Args:
            request: FastAPI request object

        Returns:
            ApiKey record if valid key provided, None if no key or invalid

        Raises:
            HTTPException: If auto_error=True and authentication fails
        """
        # Check if we should bypass authentication for certain endpoints
        if self._should_bypass_auth(request):
            return None

        # Check for whitelisted local processes
        if self._is_whitelisted_request(request):
            self.logger.debug("Request whitelisted, bypassing authentication")
            return None

        # Extract API key from request
        api_key = self._extract_api_key(request)

        if not api_key:
            # No API key provided - this is OK for optional auth
            return None

        # Verify the API key
        try:
            api_key_record = api_key_service.verify_api_key(api_key)
        except Exception as e:
            self.logger.warning(
                "API key verification failed",
                error=str(e),
                client_ip=self._get_client_ip(request),
            )
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={
                        "error_code": "AUTH500",
                        "message": "Authentication service error",
                    },
                )
            return None

        if not api_key_record:
            # Invalid or expired API key
            self.logger.warning(
                "Invalid or expired API key used",
                client_ip=self._get_client_ip(request),
                path=request.url.path,
            )
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={
                        "error_code": "AUTH401",
                        "message": "Invalid or expired API key",
                    },
                )
            return None

        # Valid API key
        self.logger.debug(
            "API key authenticated",
            key_id=api_key_record.id,
            client_ip=self._get_client_ip(request),
        )

        # Store API key info in request state for later use
        request.state.api_key = api_key_record
        request.state.authenticated = True

        return api_key_record

    def _extract_api_key(self, request: Request) -> Optional[str]:
        """Extract API key from request headers.

        Args:
            request: FastAPI request object

        Returns:
            API key string if found, None otherwise
        """
        # Check Authorization header (Bearer token)
        authorization = request.headers.get("Authorization")
        if authorization:
            scheme, param = get_authorization_scheme_param(authorization)
            if scheme.lower() == "bearer":
                return param

        # Check X-API-Key header
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return api_key.strip()

        # Check query parameter (less secure, but sometimes needed)
        api_key = request.query_params.get("api_key")
        if api_key:
            self.logger.warning(
                "API key provided in query parameter (insecure)",
                client_ip=self._get_client_ip(request),
                path=request.url.path,
            )
            return api_key.strip()

        return None

    def _should_bypass_auth(self, request: Request) -> bool:
        """Check if authentication should be bypassed for this request.

        Args:
            request: FastAPI request object

        Returns:
            True if authentication should be bypassed
        """
        # Always bypass for health endpoints
        health_paths = ["/health", "/api/health", "/api/v1/health"]
        if request.url.path in health_paths:
            return True

        # Bypass for documentation endpoints
        doc_paths = [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/docs",
            "/api/redoc",
            "/api/openapi.json",
        ]
        if any(request.url.path.startswith(path) for path in doc_paths):
            return True

        # Bypass for static files
        if request.url.path.startswith("/static/"):
            return True

        return False

    def _is_whitelisted_request(self, request: Request) -> bool:
        """Check if request is from a whitelisted source.

        Args:
            request: FastAPI request object

        Returns:
            True if request should be whitelisted
        """
        client_ip = self._get_client_ip(request)

        # Whitelist localhost/127.0.0.1 for local development
        localhost_ips = ["127.0.0.1", "::1", "localhost"]
        if client_ip in localhost_ips:
            return True

        # Check for specific user agents that indicate local tools
        user_agent = request.headers.get("User-Agent", "").lower()
        local_agents = ["curl", "wget", "httpie", "postman", "insomnia"]
        if any(agent in user_agent for agent in local_agents):
            self.logger.debug(
                "Request from local tool, considering for whitelist",
                user_agent=user_agent,
                client_ip=client_ip,
            )
            # Only whitelist if also from localhost
            return client_ip in localhost_ips

        return False

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request.

        Args:
            request: FastAPI request object

        Returns:
            Client IP address
        """
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"


class RequiredAPIKeyAuth(OptionalAPIKeyAuth):
    """Required API key authentication dependency."""

    def __init__(self):
        """Initialize required API key authentication."""
        super().__init__(auto_error=True)


# Global instances for dependency injection
optional_api_key_auth = OptionalAPIKeyAuth(auto_error=False)
required_api_key_auth = RequiredAPIKeyAuth()


def get_current_api_key(api_key: Optional[ApiKey] = None) -> Optional[ApiKey]:
    """Dependency to get current API key from request.

    This is a convenience function that can be used in route handlers.

    Args:
        api_key: API key from authentication dependency

    Returns:
        Current API key or None
    """
    return api_key


def require_api_key(api_key: ApiKey = None) -> ApiKey:
    """Dependency that requires a valid API key.

    Args:
        api_key: API key from authentication dependency

    Returns:
        Valid API key

    Raises:
        HTTPException: If no valid API key provided
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error_code": "AUTH401", "message": "Valid API key required"},
        )
    return api_key


# Utility functions for checking authentication in middleware
def is_authenticated(request: Request) -> bool:
    """Check if request is authenticated.

    Args:
        request: FastAPI request object

    Returns:
        True if request has valid authentication
    """
    return getattr(request.state, "authenticated", False)


def get_api_key_from_request(request: Request) -> Optional[ApiKey]:
    """Get API key from request state.

    Args:
        request: FastAPI request object

    Returns:
        API key if available, None otherwise
    """
    return getattr(request.state, "api_key", None)


async def auth_middleware(request: Request, call_next):
    """Middleware to handle authentication for all requests.

    This middleware runs the optional authentication on all requests
    and stores the result in request state for later use.

    Args:
        request: FastAPI request object
        call_next: Next middleware/handler in chain

    Returns:
        Response from next handler
    """
    # Run optional authentication
    try:
        await optional_api_key_auth(request)
        # API key info is already stored in request.state by the auth dependency
    except Exception as e:
        logger.warning(
            "Authentication middleware error",
            error=str(e),
            path=request.url.path,
            client_ip=optional_api_key_auth._get_client_ip(request),
        )
        # Don't fail the request - continue without authentication
        request.state.authenticated = False
        request.state.api_key = None

    # Continue with request processing
    response = await call_next(request)

    return response
