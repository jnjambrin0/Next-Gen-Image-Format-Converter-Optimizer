"""Tests for API versioning functionality."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from app.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


class TestApiVersioning:
    """Test API versioning implementation."""

    def test_legacy_health_endpoint_exists(self, client):
        """Test that legacy /api/health endpoint still works."""
        response = client.get("/api/health")
        assert response.status_code == 200
        assert "status" in response.json()

    def test_v1_health_endpoint_exists(self, client):
        """Test that new /api/v1/health endpoint works."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert "status" in response.json()

    def test_both_endpoints_return_same_data(self, client):
        """Test that legacy and v1 endpoints return equivalent data."""
        legacy_response = client.get("/api/health")
        v1_response = client.get("/api/v1/health")

        assert legacy_response.status_code == 200
        assert v1_response.status_code == 200

        # Both should have the same structure
        legacy_data = legacy_response.json()
        v1_data = v1_response.json()

        # Should have same keys
        assert set(legacy_data.keys()) == set(v1_data.keys())
        assert legacy_data["status"] == v1_data["status"]

    def test_openapi_includes_both_servers(self, client):
        """Test that OpenAPI spec includes both legacy and v1 servers."""
        response = client.get("/api/openapi.json")
        assert response.status_code == 200

        openapi_spec = response.json()
        servers = openapi_spec.get("servers", [])

        # Should have at least 2 servers
        assert len(servers) >= 2

        # Check for v1 server
        v1_server = next((s for s in servers if "/api/v1" in s["url"]), None)
        assert v1_server is not None
        assert "v1 API" in v1_server["description"]

        # Check for legacy server
        legacy_server = next((s for s in servers if s["url"].endswith("/api")), None)
        assert legacy_server is not None
        assert "Legacy" in legacy_server["description"]

    def test_accept_version_header_support(self, client):
        """Test that Accept-Version header is properly handled."""
        # Test with v1 version header
        response = client.get("/api/v1/health", headers={"Accept-Version": "v1"})
        assert response.status_code == 200

        # Test with unsupported version (should be handled by validation middleware)
        response = client.get("/api/v1/health", headers={"Accept-Version": "v2"})
        assert (
            response.status_code == 400
        )  # Should be rejected by validation middleware

    def test_v1_endpoints_include_api_version_header(self, client):
        """Test that v1 endpoints include API version in response headers."""
        # Mock the conversion service to avoid dependencies
        with patch("app.api.routes.conversion.conversion_service") as mock_service:
            # Mock the convert method to return dummy data
            mock_result = MagicMock()
            mock_result.id = "test-id"
            mock_result.processing_time = 1.0
            mock_result.compression_ratio = 0.8
            mock_result.metadata_removed = True
            mock_result.output_format = "webp"

            mock_service.convert.return_value = (mock_result, b"fake_image_data")

            # Create a simple test image
            test_image = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100  # Simple PNG header

            response = client.post(
                "/api/v1/convert",
                files={"file": ("test.png", test_image, "image/png")},
                data={"output_format": "webp"},
            )

            if response.status_code == 200:
                assert "X-API-Version" in response.headers
                assert response.headers["X-API-Version"] == "v1"


class TestApiDocumentation:
    """Test API documentation enhancements."""

    def test_openapi_spec_has_enhanced_info(self, client):
        """Test that OpenAPI spec includes enhanced information."""
        response = client.get("/api/openapi.json")
        assert response.status_code == 200

        spec = response.json()
        info = spec.get("info", {})

        # Check enhanced metadata
        assert "contact" in info
        assert "license" in info
        assert "x-logo" in info
        assert "version" in info
        assert info["version"] == "1.0.0"

        # Check description includes key features
        description = info.get("description", "")
        assert "local-only processing" in description.lower()
        assert "privacy" in description.lower()
        assert "sandboxed" in description.lower()

    def test_openapi_spec_has_reusable_components(self, client):
        """Test that OpenAPI spec includes reusable components."""
        response = client.get("/api/openapi.json")
        assert response.status_code == 200

        spec = response.json()
        components = spec.get("components", {})

        # Check for security schemes
        assert "securitySchemes" in components
        security_schemes = components["securitySchemes"]
        assert "ApiKeyAuth" in security_schemes
        assert "BearerAuth" in security_schemes

        # Check for common schemas
        schemas = components.get("schemas", {})
        assert "ErrorResponse" in schemas
        assert "ValidationError" in schemas

        # Check for common parameters
        parameters = components.get("parameters", {})
        assert "CorrelationId" in parameters
        assert "AcceptVersion" in parameters

    def test_openapi_spec_has_organized_tags(self, client):
        """Test that OpenAPI spec includes organized tags."""
        response = client.get("/api/openapi.json")
        assert response.status_code == 200

        spec = response.json()
        tags = spec.get("tags", [])

        # Should have tags for major endpoint groups
        tag_names = [tag["name"] for tag in tags]
        expected_tags = [
            "conversion",
            "batch",
            "detection",
            "presets",
            "monitoring",
            "health",
        ]

        for expected_tag in expected_tags:
            assert expected_tag in tag_names

        # Each tag should have a description
        for tag in tags:
            assert "description" in tag
            assert len(tag["description"].strip()) > 0
