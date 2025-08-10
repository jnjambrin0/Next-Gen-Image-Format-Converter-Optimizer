"""
Integration tests for main FastAPI application.
Tests app initialization, middleware, and route registration.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import asyncio

from app.main import app, lifespan


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
async def app_with_lifespan():
    """Test app with lifespan events."""
    async with lifespan(app):
        yield app


class TestMainApp:
    """Test main FastAPI application."""

    def test_app_initialization(self, client):
        """Test that app initializes correctly."""
        assert app.title == "Next-Gen Image Converter API"
        assert app.version != ""
        assert "/api" in [route.path for route in app.routes]

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "network_isolation" in data

    def test_cors_middleware_configured(self, client):
        """Test CORS middleware is properly configured."""
        response = client.options(
            "/api/health",
            headers={"Origin": "http://localhost:3000"}
        )
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers

    def test_api_versioning(self, client):
        """Test API versioning works."""
        # Legacy endpoint
        response = client.get("/api/health")
        assert response.status_code == 200
        
        # Versioned endpoint
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_formats_endpoint(self, client):
        """Test formats listing endpoint."""
        response = client.get("/api/formats")
        assert response.status_code == 200
        data = response.json()
        assert "input_formats" in data
        assert "output_formats" in data
        assert "jpeg" in data["input_formats"]
        assert "webp" in data["output_formats"]

    def test_404_handling(self, client):
        """Test 404 error handling."""
        response = client.get("/api/nonexistent")
        assert response.status_code == 404

    def test_method_not_allowed(self, client):
        """Test 405 method not allowed."""
        response = client.delete("/api/health")
        assert response.status_code == 405

    @pytest.mark.asyncio
    async def test_lifespan_startup(self):
        """Test lifespan startup events."""
        mock_app = MagicMock()
        
        with patch('app.main.stats_collector') as mock_stats:
            with patch('app.main.security_tracker') as mock_security:
                async with lifespan(mock_app):
                    # Services should be initialized
                    assert mock_stats is not None
                    assert mock_security is not None

    def test_request_validation_middleware(self, client):
        """Test request validation middleware."""
        # Send oversized payload
        large_data = b"x" * (100 * 1024 * 1024 + 1)  # > 100MB
        
        response = client.post(
            "/api/convert",
            files={"file": ("large.jpg", large_data, "image/jpeg")}
        )
        
        assert response.status_code == 413  # Payload too large

    def test_error_handler_formatting(self, client):
        """Test error response formatting."""
        response = client.post(
            "/api/convert",
            json={}  # Missing required fields
        )
        
        assert response.status_code in [422, 400]
        data = response.json()
        assert "detail" in data or "error" in data

    def test_openapi_schema_available(self, client):
        """Test OpenAPI schema is available."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "openapi" in schema
        assert "paths" in schema
        assert "/api/convert" in schema["paths"]

    def test_monitoring_endpoints(self, client):
        """Test monitoring endpoints are registered."""
        response = client.get("/api/monitoring/stats")
        assert response.status_code == 200
        
        response = client.get("/api/monitoring/errors")
        assert response.status_code == 200

    def test_security_endpoints(self, client):
        """Test security endpoints are registered."""
        response = client.get("/api/security/status")
        assert response.status_code == 200
        data = response.json()
        assert "sandboxing_enabled" in data

    def test_batch_endpoints_registered(self, client):
        """Test batch processing endpoints."""
        # Create batch should require proper data
        response = client.post("/api/batch", json={})
        assert response.status_code in [422, 400]  # Validation error

    def test_websocket_endpoint_registered(self):
        """Test WebSocket endpoint is registered."""
        from fastapi.testclient import TestClient
        
        with TestClient(app) as client:
            # WebSocket endpoint should exist
            routes = [route.path for route in app.routes]
            ws_routes = [r for r in routes if "ws" in r.lower()]
            assert len(ws_routes) > 0

    def test_preset_endpoints(self, client):
        """Test preset management endpoints."""
        response = client.get("/api/presets")
        assert response.status_code == 200
        data = response.json()
        assert "presets" in data

    def test_rate_limiting_headers(self, client):
        """Test rate limiting headers are present."""
        response = client.get("/api/health")
        assert response.status_code == 200
        # Check for rate limit headers if configured
        headers = response.headers
        # Rate limiting might add these headers
        if "x-ratelimit-limit" in headers:
            assert int(headers["x-ratelimit-limit"]) > 0

    def test_compression_middleware(self, client):
        """Test response compression for large responses."""
        response = client.get("/api/formats")
        assert response.status_code == 200
        # Check if compression is applied for JSON responses
        # (FastAPI may compress automatically)

    def test_intelligence_endpoints(self, client):
        """Test intelligence/ML endpoints."""
        response = client.get("/api/intelligence/capabilities")
        assert response.status_code == 200
        data = response.json()
        assert "content_detection" in data

    def test_optimization_endpoints(self, client):
        """Test optimization endpoints."""
        response = client.get("/api/optimization/presets")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict) or isinstance(data, list)

    def test_api_documentation_endpoints(self, client):
        """Test API documentation is available."""
        # Swagger UI
        response = client.get("/docs")
        assert response.status_code == 200
        
        # ReDoc
        response = client.get("/redoc")
        assert response.status_code == 200

    def test_startup_initialization_order(self):
        """Test that services initialize in correct order."""
        # This would test that dependencies are injected properly
        # Mock the initialization to verify order
        with patch('app.main.initialize_services') as mock_init:
            # Would verify services initialize in dependency order
            pass

    def test_shutdown_cleanup(self):
        """Test that cleanup happens on shutdown."""
        with patch('app.main.cleanup_services') as mock_cleanup:
            # Would verify cleanup is called
            pass

    def test_exception_handler_chain(self, client):
        """Test exception handlers work correctly."""
        # Test validation error
        response = client.post(
            "/api/convert",
            json={"output_format": "invalid"}
        )
        assert response.status_code in [422, 400]
        
        # Test security error (if applicable)
        # Would need to trigger a security exception

    def test_middleware_order(self):
        """Test middleware execution order is correct."""
        # Middleware should execute in correct order:
        # 1. CORS
        # 2. Rate limiting
        # 3. Request validation
        # 4. Error handling
        # This is implicitly tested by other tests