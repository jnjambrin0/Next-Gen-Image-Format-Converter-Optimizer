import pytest
from fastapi.testclient import TestClient
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from app.main import app


class TestHealthEndpoint:
    """Test health check endpoint functionality."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_health_endpoint_success(self, client):
        """Test successful health check."""
        response = client.get("/api/health")

        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_health_endpoint_headers(self, client):
        """Test health endpoint response headers."""
        response = client.get("/api/health")

        # Check correlation ID header
        assert "x-correlation-id" in response.headers
        assert len(response.headers["x-correlation-id"]) > 0

        # Check content type
        assert response.headers["content-type"] == "application/json"

    def test_health_endpoint_methods(self, client):
        """Test that only GET method is allowed."""
        # Test POST - should fail
        response = client.post("/api/health")
        assert response.status_code == 405

        # Test PUT - should fail
        response = client.put("/api/health")
        assert response.status_code == 405

        # Test DELETE - should fail
        response = client.delete("/api/health")
        assert response.status_code == 405

        # Test GET - should succeed
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_health_endpoint_with_query_params(self, client):
        """Test health endpoint ignores query parameters."""
        response = client.get("/api/health?test=123&foo=bar")

        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_health_endpoint_cors(self, client):
        """Test CORS headers on health endpoint."""
        response = client.get(
            "/api/health", headers={"Origin": "http://localhost:5173"}
        )

        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers

    def test_health_endpoint_logging(self, client, caplog):
        """Test that health endpoint requests are logged."""
        import logging

        with caplog.at_level(logging.INFO):
            response = client.get("/api/health")

            assert response.status_code == 200

            # Note: Structured logging might format differently
            # Just check that some logging occurred
            assert len(caplog.records) > 0

    def test_health_endpoint_performance(self, client):
        """Test health endpoint response time."""
        import time

        start_time = time.time()
        response = client.get("/api/health")
        end_time = time.time()

        assert response.status_code == 200

        # Health check should be fast (under 100ms)
        response_time = (end_time - start_time) * 1000
        assert response_time < 100
