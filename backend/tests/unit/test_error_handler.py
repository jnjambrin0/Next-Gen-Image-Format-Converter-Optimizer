import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from unittest.mock import patch, Mock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from app.main import app
from app.core.exceptions import (
    ConversionError,
    ValidationError,
    SecurityError,
    ResourceLimitError,
    FormatNotSupportedError,
    ProcessingTimeoutError,
)
from app.api.middleware.error_handler import handle_exception


class TestErrorHandling:
    """Test error handling middleware and exception handlers."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_404_not_found(self, client):
        """Test 404 error handling."""
        response = client.get("/api/nonexistent")

        assert response.status_code == 404
        assert "x-correlation-id" in response.headers

        data = response.json()
        assert "correlation_id" in data
        assert "error" in data
        assert data["error"]["code"] == "HTTP404"
        assert data["error"]["type"] == "HTTPException"

    @pytest.mark.asyncio
    async def test_conversion_error_handling(self):
        """Test custom ConversionError handling."""
        error = ConversionError("Test conversion failed", {"format": "unknown"})
        correlation_id = "test-correlation-123"

        response = await handle_exception(error, correlation_id)
        data = response.body.decode()

        import json

        response_data = json.loads(data)

        assert response.status_code == 422
        assert response_data["correlation_id"] == correlation_id
        assert response_data["error"]["code"] == "CONV001"
        assert response_data["error"]["type"] == "ConversionError"
        assert response_data["error"]["message"] == "Test conversion failed"
        assert response_data["error"]["details"]["format"] == "unknown"

    @pytest.mark.asyncio
    async def test_security_error_handling(self):
        """Test SecurityError handling."""
        error = SecurityError("Access denied", {"reason": "invalid_token"})
        correlation_id = "test-correlation-456"

        response = await handle_exception(error, correlation_id)
        data = response.body.decode()

        import json

        response_data = json.loads(data)

        assert response.status_code == 403
        assert response_data["error"]["code"] == "CONV003"
        assert response_data["error"]["type"] == "SecurityError"
        assert response_data["error"]["message"] == "Access denied"

    @pytest.mark.asyncio
    async def test_resource_limit_error_handling(self):
        """Test ResourceLimitError handling."""
        error = ResourceLimitError("File too large", {"size": 200000000})
        correlation_id = "test-correlation-789"

        response = await handle_exception(error, correlation_id)
        data = response.body.decode()

        import json

        response_data = json.loads(data)

        assert response.status_code == 413
        assert response_data["error"]["code"] == "CONV004"
        assert response_data["error"]["type"] == "ResourceLimitError"

    @pytest.mark.asyncio
    async def test_format_not_supported_error_handling(self):
        """Test FormatNotSupportedError handling."""
        error = FormatNotSupportedError("Format not supported", {"format": "xyz"})
        correlation_id = "test-correlation-101"

        response = await handle_exception(error, correlation_id)
        data = response.body.decode()

        import json

        response_data = json.loads(data)

        assert response.status_code == 415
        assert response_data["error"]["code"] == "CONV005"
        assert response_data["error"]["type"] == "FormatNotSupportedError"

    @pytest.mark.asyncio
    async def test_processing_timeout_error_handling(self):
        """Test ProcessingTimeoutError handling."""
        error = ProcessingTimeoutError("Processing timed out", {"duration": 301})
        correlation_id = "test-correlation-102"

        response = await handle_exception(error, correlation_id)
        data = response.body.decode()

        import json

        response_data = json.loads(data)

        assert response.status_code == 408
        assert response_data["error"]["code"] == "CONV006"
        assert response_data["error"]["type"] == "ProcessingTimeoutError"

    @pytest.mark.asyncio
    async def test_generic_exception_handling(self):
        """Test generic exception handling."""
        error = Exception("Something went wrong")
        correlation_id = "test-correlation-103"

        response = await handle_exception(error, correlation_id)
        data = response.body.decode()

        import json

        response_data = json.loads(data)

        assert response.status_code == 500
        assert response_data["error"]["code"] == "CONV999"
        assert response_data["error"]["type"] == "InternalServerError"
        assert response_data["error"]["message"] == "An unexpected error occurred"

    @pytest.mark.asyncio
    async def test_http_exception_handling(self):
        """Test HTTP exception handling."""
        from starlette.exceptions import HTTPException as StarletteHTTPException

        error = StarletteHTTPException(status_code=400, detail="Bad request")
        correlation_id = "test-correlation-104"

        response = await handle_exception(error, correlation_id)
        data = response.body.decode()

        import json

        response_data = json.loads(data)

        assert response.status_code == 400
        assert response_data["error"]["code"] == "HTTP400"
        assert response_data["error"]["type"] == "HTTPException"
        assert response_data["error"]["message"] == "Bad request"

    def test_correlation_id_propagation(self, client):
        """Test correlation ID is consistent across error response."""
        response = client.get("/api/nonexistent")

        header_correlation_id = response.headers.get("x-correlation-id")
        body_correlation_id = response.json().get("correlation_id")

        assert header_correlation_id is not None
        assert body_correlation_id is not None
        assert header_correlation_id == body_correlation_id

    def test_error_response_structure(self, client):
        """Test error response has consistent structure."""
        response = client.get("/api/nonexistent")

        data = response.json()

        # Check required fields
        assert "correlation_id" in data
        assert "error" in data

        error = data["error"]
        assert "message" in error
        assert "code" in error
        assert "type" in error

        # Details field may or may not be present
        if "details" in error:
            assert isinstance(error["details"], dict)

    def test_validation_error_structure(self, client):
        """Test validation error response structure."""
        # Send malformed JSON
        response = client.post(
            "/api/health",
            data="invalid json",
            headers={"Content-Type": "application/json"},
        )

        # Should get 422 for invalid JSON
        assert response.status_code in [
            405,
            422,
        ]  # 405 if method not allowed, 422 if validation fails
        assert "x-correlation-id" in response.headers
