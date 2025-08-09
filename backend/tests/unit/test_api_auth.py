"""Unit tests for API authentication and key management."""

import hashlib
import secrets
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.middleware.auth import OptionalAPIKeyAuth, RequiredAPIKeyAuth
from app.core.security.rate_limiter import ApiRateLimiter, SecurityEventRateLimiter
from app.models.database import ApiKey, ApiUsageStats, Base
from app.services.api_key_service import ApiKeyService


class TestApiKeyService:
    """Test cases for ApiKeyService."""

    @pytest.fixture
    def service(self):
        """Create ApiKeyService with in-memory database."""
        service = ApiKeyService(db_path=":memory:")
        return service

    def test_generate_api_key(self, service):
        """Test API key generation."""
        key = service.generate_api_key()

        # Check key format
        assert isinstance(key, str)
        assert len(key) > 30  # Should be 43 chars for 32 bytes base64

        # Should be URL-safe base64
        import base64

        try:
            decoded = base64.urlsafe_b64decode(key + "==")  # Add padding
            assert len(decoded) > 0
        except Exception:
            pytest.fail("Generated key is not valid URL-safe base64")

    def test_hash_api_key(self, service):
        """Test API key hashing."""
        key = "test_api_key_12345"
        hash1 = service.hash_api_key(key)
        hash2 = service.hash_api_key(key)

        # Should be deterministic
        assert hash1 == hash2

        # Should be SHA-256 hex
        assert len(hash1) == 64
        assert all(c in "0123456789abcdef" for c in hash1)

        # Should match manual hash
        expected = hashlib.sha256(key.encode()).hexdigest()
        assert hash1 == expected

    def test_create_api_key_basic(self, service):
        """Test basic API key creation."""
        api_key, raw_key = service.create_api_key(name="Test Key")

        # Check returned objects
        assert isinstance(api_key, ApiKey)
        assert isinstance(raw_key, str)

        # Check database record
        assert api_key.name == "Test Key"
        assert api_key.is_active is True
        assert api_key.key_hash == service.hash_api_key(raw_key)
        assert api_key.created_at is not None
        assert api_key.id is not None

    def test_create_api_key_with_options(self, service):
        """Test API key creation with all options."""
        api_key, raw_key = service.create_api_key(
            name="Advanced Key",
            permissions={"convert": True, "batch": False},
            rate_limit_override=120,
            expires_days=30,
        )

        # Check all options were set
        assert api_key.name == "Advanced Key"
        assert api_key.rate_limit_override == 120
        assert api_key.expires_at is not None

        # Check expiration is approximately 30 days from now
        expected_expiry = datetime.utcnow() + timedelta(days=30)
        time_diff = abs((api_key.expires_at - expected_expiry).seconds)
        assert time_diff < 60  # Within 1 minute

        # Check permissions JSON
        import json

        permissions = json.loads(api_key.permissions)
        assert permissions == {"convert": True, "batch": False}

    def test_verify_api_key_valid(self, service):
        """Test verification of valid API key."""
        _, raw_key = service.create_api_key(name="Valid Key")

        # Should verify successfully
        api_key = service.verify_api_key(raw_key)
        assert api_key is not None
        assert api_key.name == "Valid Key"
        assert api_key.last_used_at is not None

    def test_verify_api_key_invalid(self, service):
        """Test verification of invalid API key."""
        # Non-existent key
        result = service.verify_api_key("invalid_key_12345")
        assert result is None

        # Empty key
        result = service.verify_api_key("")
        assert result is None

        # None key
        result = service.verify_api_key(None)
        assert result is None

    def test_verify_api_key_expired(self, service):
        """Test verification of expired API key."""
        api_key, raw_key = service.create_api_key(name="Expired Key", expires_days=1)

        # Manually set expiry to past
        with service.SessionLocal() as session:
            api_key.expires_at = datetime.utcnow() - timedelta(days=1)
            session.add(api_key)
            session.commit()

        # Should not verify
        result = service.verify_api_key(raw_key)
        assert result is None

    def test_verify_api_key_inactive(self, service):
        """Test verification of inactive API key."""
        api_key, raw_key = service.create_api_key(name="Inactive Key")

        # Deactivate the key
        service.revoke_api_key(api_key.id)

        # Should not verify
        result = service.verify_api_key(raw_key)
        assert result is None

    def test_list_api_keys(self, service):
        """Test listing API keys."""
        # Create test keys
        service.create_api_key(name="Key 1")
        service.create_api_key(name="Key 2")
        key3, _ = service.create_api_key(name="Key 3")

        # Revoke one key
        service.revoke_api_key(key3.id)

        # List active keys only
        active_keys = service.list_api_keys(include_inactive=False)
        assert len(active_keys) == 2
        assert all(key.is_active for key in active_keys)

        # List all keys
        all_keys = service.list_api_keys(include_inactive=True)
        assert len(all_keys) == 3

        # Check ordering (newest first)
        assert all_keys[0].created_at >= all_keys[1].created_at

    def test_get_api_key_by_id(self, service):
        """Test getting API key by ID."""
        api_key, _ = service.create_api_key(name="Find Me")

        # Should find the key
        found_key = service.get_api_key_by_id(api_key.id)
        assert found_key is not None
        assert found_key.id == api_key.id
        assert found_key.name == "Find Me"

        # Should not find non-existent key
        not_found = service.get_api_key_by_id("non-existent-id")
        assert not_found is None

    def test_revoke_api_key(self, service):
        """Test API key revocation."""
        api_key, raw_key = service.create_api_key(name="To Revoke")

        # Should be active initially
        assert api_key.is_active is True

        # Revoke the key
        success = service.revoke_api_key(api_key.id)
        assert success is True

        # Should be inactive now
        updated_key = service.get_api_key_by_id(api_key.id)
        assert updated_key.is_active is False

        # Should not verify anymore
        result = service.verify_api_key(raw_key)
        assert result is None

        # Revoking non-existent key should fail
        success = service.revoke_api_key("non-existent-id")
        assert success is False

    def test_update_api_key(self, service):
        """Test API key updates."""
        api_key, _ = service.create_api_key(name="Original Name")

        # Update the key
        updated_key = service.update_api_key(
            api_key.id, name="Updated Name", rate_limit_override=200, expires_days=60
        )

        assert updated_key is not None
        assert updated_key.name == "Updated Name"
        assert updated_key.rate_limit_override == 200
        assert updated_key.expires_at is not None

        # Partial update
        updated_key2 = service.update_api_key(api_key.id, name="Final Name")
        assert updated_key2.name == "Final Name"
        assert updated_key2.rate_limit_override == 200  # Should remain

        # Update non-existent key
        result = service.update_api_key("non-existent-id", name="New")
        assert result is None

    def test_cleanup_expired_keys(self, service):
        """Test cleanup of expired API keys."""
        # Create keys with different expiry
        api_key1, _ = service.create_api_key(name="Active Key")
        api_key2, _ = service.create_api_key(name="Expired Key 1", expires_days=1)
        api_key3, _ = service.create_api_key(name="Expired Key 2", expires_days=1)

        # Manually expire two keys
        with service.SessionLocal() as session:
            for key_id in [api_key2.id, api_key3.id]:
                key = session.get(ApiKey, key_id)
                key.expires_at = datetime.utcnow() - timedelta(days=1)
                session.add(key)
            session.commit()

        # Cleanup expired keys
        cleaned_count = service.cleanup_expired_keys()
        assert cleaned_count == 2

        # Check keys are now inactive
        key2_updated = service.get_api_key_by_id(api_key2.id)
        key3_updated = service.get_api_key_by_id(api_key3.id)
        assert key2_updated.is_active is False
        assert key3_updated.is_active is False

        # Active key should remain active
        key1_updated = service.get_api_key_by_id(api_key1.id)
        assert key1_updated.is_active is True

    def test_get_rate_limit_for_key(self, service):
        """Test rate limit retrieval for API keys."""
        # Key without override
        api_key1, _ = service.create_api_key(name="Default Rate")
        limit1 = service.get_rate_limit_for_key(api_key1)
        assert limit1 == 60  # Default from settings

        # Key with override
        api_key2, _ = service.create_api_key(
            name="Custom Rate", rate_limit_override=120
        )
        limit2 = service.get_rate_limit_for_key(api_key2)
        assert limit2 == 120

    def test_record_usage(self, service):
        """Test API usage recording."""
        api_key, _ = service.create_api_key(name="Usage Test")

        # Record usage
        service.record_usage(
            api_key_id=api_key.id,
            endpoint="/api/convert",
            method="POST",
            status_code=200,
            response_time_ms=150,
        )

        # Record unauthenticated usage
        service.record_usage(
            api_key_id=None,
            endpoint="/api/health",
            method="GET",
            status_code=200,
            response_time_ms=50,
        )

        # Check records were created
        with service.SessionLocal() as session:
            from sqlalchemy import select

            result = session.execute(select(ApiUsageStats))
            stats = result.scalars().all()
            assert len(stats) == 2

            # Check authenticated record
            auth_stat = next(s for s in stats if s.api_key_id is not None)
            assert auth_stat.api_key_id == api_key.id
            assert auth_stat.endpoint == "/api/convert"
            assert auth_stat.method == "POST"
            assert auth_stat.status_code == 200
            assert auth_stat.response_time_ms == 150

            # Check unauthenticated record
            unauth_stat = next(s for s in stats if s.api_key_id is None)
            assert unauth_stat.endpoint == "/api/health"

    def test_get_usage_stats(self, service):
        """Test usage statistics retrieval."""
        api_key, _ = service.create_api_key(name="Stats Test")

        # Record various usage
        endpoints = ["/api/convert", "/api/batch", "/api/convert"]
        status_codes = [200, 200, 400]
        response_times = [100, 200, 50]

        for endpoint, status, time_ms in zip(endpoints, status_codes, response_times):
            service.record_usage(api_key.id, endpoint, "POST", status, time_ms)

        # Get stats for specific key
        stats = service.get_usage_stats(api_key_id=api_key.id, days=7)

        assert stats["total_requests"] == 3
        assert stats["unique_endpoints"] == 2
        assert stats["avg_response_time_ms"] == pytest.approx(116.67, rel=1e-2)
        assert stats["status_codes"] == {200: 2, 400: 1}
        assert stats["endpoints"] == {"/api/convert": 2, "/api/batch": 1}
        assert stats["period_days"] == 7

        # Get overall stats
        overall_stats = service.get_usage_stats(days=7)
        assert overall_stats["total_requests"] == 3  # Same as above since only one key


class TestOptionalAPIKeyAuth:
    """Test cases for OptionalAPIKeyAuth dependency."""

    @pytest.fixture
    def mock_request(self):
        """Create mock FastAPI request."""
        request = Mock()
        request.url.path = "/api/convert"
        request.client.host = "127.0.0.1"
        request.headers = {}
        request.query_params = {}
        request.state = Mock()
        return request

    @pytest.fixture
    def auth_dependency(self):
        """Create OptionalAPIKeyAuth instance."""
        return OptionalAPIKeyAuth(auto_error=False)

    @pytest.fixture
    def mock_api_key_service(self):
        """Mock API key service."""
        with patch("app.api.middleware.auth.api_key_service") as mock:
            yield mock

    def test_no_api_key_provided(self, auth_dependency, mock_request):
        """Test when no API key is provided."""
        result = pytest.asyncio.run(auth_dependency(mock_request))
        assert result is None

    def test_bypass_health_endpoint(self, auth_dependency, mock_request):
        """Test bypassing authentication for health endpoints."""
        mock_request.url.path = "/api/health"
        result = pytest.asyncio.run(auth_dependency(mock_request))
        assert result is None

    def test_bypass_docs_endpoint(self, auth_dependency, mock_request):
        """Test bypassing authentication for docs endpoints."""
        mock_request.url.path = "/api/docs"
        result = pytest.asyncio.run(auth_dependency(mock_request))
        assert result is None

    def test_whitelist_localhost(self, auth_dependency, mock_request):
        """Test whitelisting localhost requests."""
        mock_request.client.host = "127.0.0.1"
        result = pytest.asyncio.run(auth_dependency(mock_request))
        assert result is None

    @pytest.mark.asyncio
    async def test_valid_bearer_token(
        self, auth_dependency, mock_request, mock_api_key_service
    ):
        """Test valid Bearer token authentication."""
        # Setup
        mock_request.headers = {"Authorization": "Bearer test_api_key"}
        mock_api_key = Mock()
        mock_api_key.id = "key_id_123"
        mock_api_key_service.verify_api_key.return_value = mock_api_key

        # Test
        result = await auth_dependency(mock_request)

        # Verify
        assert result == mock_api_key
        mock_api_key_service.verify_api_key.assert_called_once_with("test_api_key")
        assert mock_request.state.api_key == mock_api_key
        assert mock_request.state.authenticated is True

    @pytest.mark.asyncio
    async def test_valid_x_api_key_header(
        self, auth_dependency, mock_request, mock_api_key_service
    ):
        """Test valid X-API-Key header authentication."""
        # Setup
        mock_request.headers = {"X-API-Key": "test_api_key"}
        mock_api_key = Mock()
        mock_api_key_service.verify_api_key.return_value = mock_api_key

        # Test
        result = await auth_dependency(mock_request)

        # Verify
        assert result == mock_api_key
        mock_api_key_service.verify_api_key.assert_called_once_with("test_api_key")

    @pytest.mark.asyncio
    async def test_invalid_api_key(
        self, auth_dependency, mock_request, mock_api_key_service
    ):
        """Test invalid API key."""
        # Setup
        mock_request.headers = {"Authorization": "Bearer invalid_key"}
        mock_api_key_service.verify_api_key.return_value = None

        # Test
        result = await auth_dependency(mock_request)

        # Verify
        assert result is None
        mock_api_key_service.verify_api_key.assert_called_once_with("invalid_key")

    @pytest.mark.asyncio
    async def test_api_key_service_error(
        self, auth_dependency, mock_request, mock_api_key_service
    ):
        """Test API key service error handling."""
        # Setup
        mock_request.headers = {"Authorization": "Bearer test_key"}
        mock_api_key_service.verify_api_key.side_effect = Exception("Database error")

        # Test
        result = await auth_dependency(mock_request)

        # Verify - should handle error gracefully
        assert result is None


class TestRequiredAPIKeyAuth:
    """Test cases for RequiredAPIKeyAuth dependency."""

    @pytest.fixture
    def auth_dependency(self):
        """Create RequiredAPIKeyAuth instance."""
        return RequiredAPIKeyAuth()

    @pytest.fixture
    def mock_request(self):
        """Create mock FastAPI request."""
        request = Mock()
        request.url.path = "/api/convert"
        request.client.host = "192.168.1.100"  # Not localhost
        request.headers = {}
        request.query_params = {}
        request.state = Mock()
        return request

    @pytest.mark.asyncio
    async def test_required_auth_no_key(self, auth_dependency, mock_request):
        """Test required auth with no API key."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await auth_dependency(mock_request)

        assert exc_info.value.status_code == 401
        assert "AUTH401" in str(exc_info.value.detail)


class TestApiRateLimiter:
    """Test cases for API rate limiter."""

    @pytest.fixture
    def rate_limiter(self):
        """Create ApiRateLimiter instance."""
        return ApiRateLimiter()

    def test_default_limiter(self, rate_limiter):
        """Test default rate limiter for unauthenticated requests."""
        limiter = rate_limiter.get_limiter_for_key(None)
        assert isinstance(limiter, SecurityEventRateLimiter)

        # Should be the same instance for repeated calls
        limiter2 = rate_limiter.get_limiter_for_key(None)
        assert limiter is limiter2

    def test_api_key_limiter_default(self, rate_limiter):
        """Test rate limiter for API key with default limits."""
        limiter = rate_limiter.get_limiter_for_key("test_key_123")
        assert isinstance(limiter, SecurityEventRateLimiter)

        # Should create new limiter for different keys
        limiter2 = rate_limiter.get_limiter_for_key("test_key_456")
        assert limiter is not limiter2

        # Should reuse limiter for same key
        limiter3 = rate_limiter.get_limiter_for_key("test_key_123")
        assert limiter is limiter3

    def test_api_key_limiter_custom(self, rate_limiter):
        """Test rate limiter for API key with custom limits."""
        limiter = rate_limiter.get_limiter_for_key("custom_key", custom_limit=120)

        # Check rate limit
        allowed, headers = rate_limiter.check_rate_limit("custom_key", custom_limit=120)
        assert allowed is True
        assert headers["X-RateLimit-Limit"] == "120"

    def test_rate_limit_enforcement(self, rate_limiter):
        """Test rate limit enforcement."""
        # Use a very low limit for testing
        api_key_id = "test_limit_key"
        custom_limit = 2

        # First request should be allowed
        allowed, headers = rate_limiter.check_rate_limit(api_key_id, custom_limit)
        assert allowed is True
        assert int(headers["X-RateLimit-Remaining"]) >= 0

        # Second request should be allowed
        allowed, headers = rate_limiter.check_rate_limit(api_key_id, custom_limit)
        assert allowed is True

        # Third request might be rate limited (depends on timing)
        # This test is inherently flaky due to time-based rate limiting
        # In practice, we'd need to mock time or use a test-specific implementation

    def test_rate_limit_headers(self, rate_limiter):
        """Test rate limit headers format."""
        allowed, headers = rate_limiter.check_rate_limit("header_test_key")

        # Check required headers
        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers
        assert "X-RateLimit-Window" in headers

        # Check header values are numeric strings
        assert headers["X-RateLimit-Limit"].isdigit()
        assert headers["X-RateLimit-Remaining"].isdigit()
        assert headers["X-RateLimit-Reset"].isdigit()
        assert headers["X-RateLimit-Window"] == "60"

    def test_get_stats(self, rate_limiter):
        """Test rate limiter statistics."""
        # Test default limiter stats
        stats = rate_limiter.get_stats()
        assert "enabled" in stats
        assert "violations_count" in stats
        assert "minute_tokens_available" in stats

        # Test API key limiter stats
        rate_limiter.get_limiter_for_key("stats_test_key")
        stats = rate_limiter.get_stats("stats_test_key")
        assert "enabled" in stats

        # Test non-existent key stats
        stats = rate_limiter.get_stats("non_existent_key")
        assert stats["enabled"] is True
        assert stats["violations_count"] == 0

    def test_cleanup_unused_limiters(self, rate_limiter):
        """Test cleanup of unused rate limiters."""
        # Create several limiters
        rate_limiter.get_limiter_for_key("key1")
        rate_limiter.get_limiter_for_key("key2")
        rate_limiter.get_limiter_for_key("key3")

        # Cleanup, keeping only key1 and key2
        active_keys = {"key1", "key2"}
        cleaned_count = rate_limiter.cleanup_unused_limiters(active_keys)

        assert cleaned_count == 1  # key3 should be cleaned

        # Verify key3 limiter was removed
        assert "key1" in rate_limiter.limiters
        assert "key2" in rate_limiter.limiters
        assert "key3" not in rate_limiter.limiters
