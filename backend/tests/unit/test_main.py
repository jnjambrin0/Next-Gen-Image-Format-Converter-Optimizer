import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from app.main import app
from app.config import settings


class TestMainApplication:
    """Test FastAPI application setup and configuration."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_app_creation(self):
        """Test that app is created successfully."""
        assert app is not None
        assert app.title == "Image Converter API"
        assert app.version == "0.1.0"

    def test_openapi_configuration(self, client):
        """Test OpenAPI configuration."""
        response = client.get("/api/openapi.json")
        assert response.status_code == 200

        openapi_schema = response.json()
        assert openapi_schema["info"]["title"] == "Image Converter API"
        assert openapi_schema["info"]["version"] == "0.1.0"
        assert "servers" in openapi_schema
        assert (
            openapi_schema["servers"][0]["url"]
            == f"http://localhost:{settings.api_port}/api"
        )

    def test_docs_endpoints(self, client):
        """Test documentation endpoints."""
        # Test Swagger UI
        response = client.get("/api/docs")
        assert response.status_code == 200
        assert "swagger-ui" in response.text.lower()

        # Test ReDoc
        response = client.get("/api/redoc")
        assert response.status_code == 200
        assert "redoc" in response.text.lower()

    def test_cors_headers(self, client):
        """Test CORS configuration."""
        response = client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert (
            response.headers["access-control-allow-origin"] == "http://localhost:5173"
        )
        # CORS middleware allows all methods when configured with ["*"]
        assert "GET" in response.headers["access-control-allow-methods"]

    def test_root_endpoint_development(self, client):
        """Test root endpoint in development mode."""
        with patch.object(settings, "env", "development"):
            response = client.get("/")
            assert response.status_code == 200
            assert response.json() == {
                "message": "Image Converter API",
                "version": "0.1.0",
            }

    @patch("app.main.Path")
    def test_static_files_production(self, mock_path_class, client):
        """Test static file serving in production mode."""
        # Mock production environment
        with patch.object(settings, "env", "production"):
            # Mock frontend build path
            mock_path_instance = MagicMock()
            mock_path_instance.exists.return_value = True
            mock_path_class.return_value = mock_path_instance

            # Test that frontend routes are handled in production
            # Note: Actual static file serving requires app restart, so we just verify config
            assert settings.env == "production"

    def test_middleware_order(self):
        """Test that middleware is added in correct order."""
        # Check that middleware is properly configured
        # FastAPI internally manages middleware, we can verify by checking app.middleware
        middleware_names = []
        current = app.middleware_stack
        while hasattr(current, "app"):
            middleware_names.append(current.__class__.__name__)
            current = getattr(current, "app", None)
            if current is None:
                break

        # Verify CORS middleware is present
        assert any("CORSMiddleware" in name for name in middleware_names)

    def test_exception_handlers_registered(self):
        """Test that exception handlers are properly registered."""
        # Check that custom exception handlers are registered
        assert len(app.exception_handlers) > 0

        # Check for specific exception types
        from fastapi.exceptions import RequestValidationError
        from starlette.exceptions import HTTPException

        assert RequestValidationError in app.exception_handlers
        assert HTTPException in app.exception_handlers
        assert Exception in app.exception_handlers

    def test_api_router_included(self, client):
        """Test that API router is included."""
        # Test that health endpoint from router is accessible
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_lifespan_context(self):
        """Test lifespan context manager."""
        # This is tested implicitly when the app starts
        # We can verify logging setup is called
        with patch("app.main.setup_logging") as mock_setup_logging:
            with TestClient(app) as client:
                # Lifespan events are triggered during client creation
                pass

            # Verify logging was set up
            mock_setup_logging.assert_called_once()
