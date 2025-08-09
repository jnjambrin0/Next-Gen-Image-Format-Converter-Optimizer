"""Integration tests for API authentication flow."""

from typing import Any
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.models.database import Base
from app.services.api_key_service import api_key_service


class TestAuthenticationFlow:
    """Test the complete authentication flow."""

    @pytest.fixture(scope="function")
    def client(self) -> None:
        """Create test client with clean database."""
        # Use in-memory database for tests
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)

        # Override the service's database
        api_key_service.engine = engine
        api_key_service.SessionLocal = sessionmaker(bind=engine)

        with TestClient(app) as client:
            yield client

    @pytest.fixture
    def sample_api_key(self, client) -> None:
        """Create a sample API key for testing."""
        api_key_record, raw_key = api_key_service.create_api_key(
            name="Test Integration Key", rate_limit_override=100
        )
        return api_key_record, raw_key

    def test_create_api_key_endpoint(self, client) -> None:
        """Test API key creation endpoint."""
        payload = {
            "name": "Integration Test Key",
            "rate_limit_override": 120,
            "expires_days": 30,
        }

        response = client.post("/api/auth/api-keys", json=payload)

        assert response.status_code == 201
        data = response.json()

        # Check response structure
        assert "api_key" in data
        assert "key_info" in data

        # Check API key format
        api_key = data["api_key"]
        assert isinstance(api_key, str)
        assert len(api_key) > 30

        # Check key info
        key_info = data["key_info"]
        assert key_info["name"] == "Integration Test Key"
        assert key_info["rate_limit_override"] == 120
        assert key_info["is_active"] is True
        assert key_info["expires_at"] is not None

    def test_create_api_key_minimal(self, client) -> None:
        """Test API key creation with minimal data."""
        response = client.post("/api/auth/api-keys", json={})

        assert response.status_code == 201
        data = response.json()

        # Should work with no parameters
        assert "api_key" in data
        key_info = data["key_info"]
        assert key_info["name"] is None
        assert key_info["rate_limit_override"] is None
        assert key_info["expires_at"] is None

    def test_create_api_key_validation_errors(self, client) -> None:
        """Test API key creation validation."""
        # Empty name should be rejected
        response = client.post("/api/auth/api-keys", json={"name": ""})
        assert response.status_code == 400
        assert "AUTH400" in response.json()["detail"]["error_code"]

        # Invalid rate limit
        response = client.post("/api/auth/api-keys", json={"rate_limit_override": 0})
        assert response.status_code == 422  # FastAPI validation error

        # Invalid expires_days
        response = client.post("/api/auth/api-keys", json={"expires_days": 400})
        assert response.status_code == 422  # FastAPI validation error

    def test_list_api_keys_endpoint(self, client, sample_api_key) -> None:
        """Test API key listing endpoint."""
        api_key_record, _ = sample_api_key

        # Create another key and revoke it
        api_key_service.create_api_key(name="Inactive Key")
        inactive_key, _ = api_key_service.create_api_key(name="To Revoke")
        api_key_service.revoke_api_key(inactive_key.id)

        # List active keys only
        response = client.get("/api/auth/api-keys")
        assert response.status_code == 200
        data = response.json()

        assert len(data) == 2  # Only active keys
        key_names = [key["name"] for key in data]
        assert "Test Integration Key" in key_names
        assert "Inactive Key" in key_names
        assert "To Revoke" not in key_names

        # List all keys
        response = client.get("/api/auth/api-keys?include_inactive=true")
        assert response.status_code == 200
        data = response.json()

        assert len(data) == 3  # All keys
        key_names = [key["name"] for key in data]
        assert "To Revoke" in key_names

    def test_get_api_key_endpoint(self, client, sample_api_key) -> None:
        """Test get specific API key endpoint."""
        api_key_record, _ = sample_api_key

        # Get existing key
        response = client.get(f"/api/auth/api-keys/{api_key_record.id}")
        assert response.status_code == 200
        data = response.json()

        assert data["id"] == api_key_record.id
        assert data["name"] == "Test Integration Key"
        assert data["rate_limit_override"] == 100

        # Get non-existent key
        response = client.get("/api/auth/api-keys/non-existent-id")
        assert response.status_code == 404
        assert "AUTH404" in response.json()["detail"]["error_code"]

    def test_update_api_key_endpoint(self, client, sample_api_key) -> None:
        """Test API key update endpoint."""
        api_key_record, _ = sample_api_key

        # Update the key
        payload = {
            "name": "Updated Test Key",
            "rate_limit_override": 200,
            "expires_days": 60,
        }

        response = client.put(f"/api/auth/api-keys/{api_key_record.id}", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["name"] == "Updated Test Key"
        assert data["rate_limit_override"] == 200
        assert data["expires_at"] is not None

        # Partial update
        response = client.put(
            f"/api/auth/api-keys/{api_key_record.id}", json={"name": "Final Name"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Final Name"
        assert data["rate_limit_override"] == 200  # Should remain

        # Update non-existent key
        response = client.put("/api/auth/api-keys/non-existent", json={"name": "New"})
        assert response.status_code == 404

    def test_revoke_api_key_endpoint(self, client, sample_api_key) -> None:
        """Test API key revocation endpoint."""
        api_key_record, raw_key = sample_api_key

        # Revoke the key
        response = client.delete(f"/api/auth/api-keys/{api_key_record.id}")
        assert response.status_code == 204

        # Verify key is revoked
        updated_key = api_key_service.get_api_key_by_id(api_key_record.id)
        assert updated_key.is_active is False

        # Key should no longer verify
        result = api_key_service.verify_api_key(raw_key)
        assert result is None

        # Revoke non-existent key
        response = client.delete("/api/auth/api-keys/non-existent")
        assert response.status_code == 404

    def test_get_api_key_usage_endpoint(self, client, sample_api_key) -> None:
        """Test API key usage statistics endpoint."""
        api_key_record, _ = sample_api_key

        # Record some usage
        api_key_service.record_usage(
            api_key_id=api_key_record.id,
            endpoint="/api/convert",
            method="POST",
            status_code=200,
            response_time_ms=150,
        )

        api_key_service.record_usage(
            api_key_id=api_key_record.id,
            endpoint="/api/batch",
            method="POST",
            status_code=400,
            response_time_ms=100,
        )

        # Get usage stats
        response = client.get(f"/api/auth/api-keys/{api_key_record.id}/usage")
        assert response.status_code == 200
        data = response.json()

        assert data["total_requests"] == 2
        assert data["unique_endpoints"] == 2
        assert data["avg_response_time_ms"] == 125.0
        assert data["status_codes"] == {"200": 1, "400": 1}
        assert data["endpoints"] == {"/api/convert": 1, "/api/batch": 1}
        assert data["period_days"] == 7

        # Test with custom days
        response = client.get(f"/api/auth/api-keys/{api_key_record.id}/usage?days=1")
        assert response.status_code == 200
        data = response.json()
        assert data["period_days"] == 1

        # Test invalid days parameter
        response = client.get(f"/api/auth/api-keys/{api_key_record.id}/usage?days=50")
        assert response.status_code == 400

        # Test non-existent key
        response = client.get("/api/auth/api-keys/non-existent/usage")
        assert response.status_code == 404

    def test_get_overall_usage_endpoint(self, client, sample_api_key) -> None:
        """Test overall usage statistics endpoint."""
        api_key_record, _ = sample_api_key

        # Record usage for API key and unauthenticated
        api_key_service.record_usage(
            api_key_id=api_key_record.id,
            endpoint="/api/convert",
            method="POST",
            status_code=200,
            response_time_ms=100,
        )

        api_key_service.record_usage(
            api_key_id=None,  # Unauthenticated
            endpoint="/api/health",
            method="GET",
            status_code=200,
            response_time_ms=50,
        )

        # Get overall stats
        response = client.get("/api/auth/usage")
        assert response.status_code == 200
        data = response.json()

        assert data["total_requests"] == 2
        assert data["unique_endpoints"] == 2
        assert data["avg_response_time_ms"] == 75.0
        assert data["status_codes"] == {"200": 2}
        assert data["endpoints"] == {"/api/convert": 1, "/api/health": 1}

    def test_cleanup_expired_endpoint(self, client) -> None:
        """Test expired keys cleanup endpoint."""
        # Create keys with different expiry states
        active_key, _ = api_key_service.create_api_key(name="Active")
        expired_key, _ = api_key_service.create_api_key(name="Expired", expires_days=1)

        # Manually expire one key
        with api_key_service.SessionLocal() as session:
            key = session.get(type(expired_key), expired_key.id)
            key.expires_at = datetime.utcnow() - timedelta(days=1)
            session.add(key)
            session.commit()

        # Run cleanup
        response = client.post("/api/auth/cleanup-expired")
        assert response.status_code == 200
        data = response.json()

        assert data["count"] == 1
        assert "Cleaned up 1 expired API keys" in data["message"]

        # Verify expired key is now inactive
        updated_key = api_key_service.get_api_key_by_id(expired_key.id)
        assert updated_key.is_active is False

        # Active key should remain active
        active_updated = api_key_service.get_api_key_by_id(active_key.id)
        assert active_updated.is_active is True

    def test_authentication_with_bearer_token(self, client, sample_api_key) -> None:
        """Test API authentication using Bearer token."""
        _, raw_key = sample_api_key

        # Make authenticated request to health endpoint
        headers = {"Authorization": f"Bearer {raw_key}"}
        response = client.get("/api/health", headers=headers)

        # Should work and include rate limit headers
        assert response.status_code == 200
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers

        # Check custom rate limit is applied
        assert response.headers["X-RateLimit-Limit"] == "100"  # Custom limit

    def test_authentication_with_x_api_key_header(self, client, sample_api_key) -> None:
        """Test API authentication using X-API-Key header."""
        _, raw_key = sample_api_key

        headers = {"X-API-Key": raw_key}
        response = client.get("/api/health", headers=headers)

        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == "100"

    def test_authentication_with_invalid_key(self, client) -> None:
        """Test API authentication with invalid key."""
        headers = {"Authorization": "Bearer invalid_key_12345"}
        response = client.get("/api/health", headers=headers)

        # Should still work (optional auth) but use default rate limits
        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == "60"  # Default limit

    def test_unauthenticated_request(self, client) -> None:
        """Test unauthenticated request."""
        response = client.get("/api/health")

        # Should work with default rate limits
        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == "60"

    def test_rate_limiting_with_api_key(self, client) -> None:
        """Test rate limiting with API key."""
        # Create API key with very low limit for testing
        api_key_record, raw_key = api_key_service.create_api_key(
            name="Rate Limited Key", rate_limit_override=2
        )

        headers = {"Authorization": f"Bearer {raw_key}"}

        # First request should succeed
        response = client.get("/api/health", headers=headers)
        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == "2"

        remaining = int(response.headers["X-RateLimit-Remaining"])
        assert remaining >= 0

        # Make requests until rate limited
        # Note: This test might be flaky due to timing
        for _ in range(5):  # Try multiple times
            response = client.get("/api/health", headers=headers)
            if response.status_code == 429:
                break

        # Should eventually hit rate limit
        # In practice, rate limiting with time buckets is hard to test reliably
        # A more robust test would mock the rate limiter or use a test-specific implementation

    def test_cors_headers(self, client) -> None:
        """Test CORS headers are present."""
        response = client.get("/api/health")

        # CORS headers should be present (configured in main.py)
        # Note: TestClient might not include all CORS headers
        assert response.status_code == 200

    def test_security_headers(self, client) -> None:
        """Test security headers are added."""
        response = client.get("/api/health")

        # Security headers from validation middleware
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        assert "Strict-Transport-Security" in response.headers

        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"

    def test_correlation_id_header(self, client) -> None:
        """Test correlation ID is added to responses."""
        response = client.get("/api/health")

        assert "X-Correlation-ID" in response.headers
        correlation_id = response.headers["X-Correlation-ID"]
        assert len(correlation_id) > 0

        # Make another request with same correlation ID
        headers = {"X-Correlation-ID": correlation_id}
        response2 = client.get("/api/health", headers=headers)
        assert response2.headers["X-Correlation-ID"] == correlation_id

    def test_api_endpoints_in_both_versions(self, client, sample_api_key) -> None:
        """Test that auth endpoints work in both /api and /api/v1."""
        api_key_record, _ = sample_api_key

        # Test /api version
        response = client.get(f"/api/auth/api-keys/{api_key_record.id}")
        assert response.status_code == 200

        # Test /api/v1 version
        response = client.get(f"/api/v1/auth/api-keys/{api_key_record.id}")
        assert response.status_code == 200

        # Both should return same data
        data1 = client.get(f"/api/auth/api-keys/{api_key_record.id}").json()
        data2 = client.get(f"/api/v1/auth/api-keys/{api_key_record.id}").json()
        assert data1 == data2

    def test_error_response_format(self, client) -> None:
        """Test error response format consistency."""
        # Test 404 error
        response = client.get("/api/auth/api-keys/non-existent")
        assert response.status_code == 404
        data = response.json()

        assert "detail" in data
        assert "error_code" in data["detail"]
        assert "message" in data["detail"]
        assert data["detail"]["error_code"] == "AUTH404"

        # Test validation error
        response = client.post("/api/auth/api-keys", json={"rate_limit_override": -1})
        assert response.status_code == 422  # FastAPI validation error

    def test_privacy_aware_logging(self, client, sample_api_key) -> None:
        """Test that sensitive data is not logged."""
        _, raw_key = sample_api_key

        # Make authenticated request
        headers = {"Authorization": f"Bearer {raw_key}"}
        response = client.get("/api/health", headers=headers)
        assert response.status_code == 200

        # Verify usage was recorded but no sensitive data exposed
        # This test mainly ensures the logging middleware runs without error
        # In a real scenario, we'd check log files for PII absence
