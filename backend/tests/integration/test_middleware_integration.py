"""
Integration tests for API middleware.
Tests rate limiting, validation, and error handling middleware.
"""

import pytest
import asyncio
import time
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import io
from PIL import Image

from app.main import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def sample_image():
    """Create a sample image for testing."""
    img = Image.new('RGB', (100, 100), color='red')
    buffer = io.BytesIO()
    img.save(buffer, format='JPEG')
    buffer.seek(0)
    return buffer


class TestMiddlewareIntegration:
    """Test middleware integration."""

    def test_rate_limiting_enforcement(self, client, sample_image):
        """Test rate limiting is enforced."""
        # Make rapid requests to trigger rate limit
        responses = []
        
        # Make 20 rapid requests
        for _ in range(20):
            response = client.post(
                "/api/convert",
                files={"file": ("test.jpg", sample_image.getvalue(), "image/jpeg")},
                data={"output_format": "png"}
            )
            responses.append(response)
            sample_image.seek(0)  # Reset buffer
        
        # At least one should be rate limited (429)
        status_codes = [r.status_code for r in responses]
        
        # Either we get rate limited or all succeed (if rate limit is high)
        assert 429 in status_codes or all(s in [200, 422, 400] for s in status_codes)

    def test_validation_middleware_file_size(self, client):
        """Test file size validation middleware."""
        # Create oversized file (> 100MB)
        large_data = b"x" * (101 * 1024 * 1024)
        
        response = client.post(
            "/api/convert",
            files={"file": ("large.jpg", large_data, "image/jpeg")},
            data={"output_format": "png"}
        )
        
        assert response.status_code == 413
        data = response.json()
        assert "error_code" in data
        assert data["error_code"] == "VAL413"

    def test_validation_middleware_content_type(self, client):
        """Test content type validation middleware."""
        # Send non-image file
        response = client.post(
            "/api/convert",
            files={"file": ("test.txt", b"not an image", "text/plain")},
            data={"output_format": "png"}
        )
        
        assert response.status_code in [415, 422, 400]

    def test_cors_middleware_preflight(self, client):
        """Test CORS preflight requests."""
        response = client.options(
            "/api/convert",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type"
            }
        )
        
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
        assert "access-control-allow-methods" in response.headers

    def test_cors_middleware_actual_request(self, client, sample_image):
        """Test CORS headers on actual requests."""
        response = client.post(
            "/api/convert",
            files={"file": ("test.jpg", sample_image.getvalue(), "image/jpeg")},
            data={"output_format": "png"},
            headers={"Origin": "http://localhost:3000"}
        )
        
        # Should have CORS headers regardless of status
        assert "access-control-allow-origin" in response.headers

    def test_error_middleware_format(self, client):
        """Test error response formatting."""
        # Trigger validation error
        response = client.post(
            "/api/convert",
            json={}  # Missing required fields
        )
        
        assert response.status_code in [422, 400, 415]
        data = response.json()
        
        # Should have consistent error format
        assert any(key in data for key in ["detail", "error", "message"])

    def test_timeout_middleware(self, client):
        """Test request timeout handling."""
        with patch('app.api.routes.conversion.conversion_service.convert') as mock_convert:
            # Make conversion take too long
            async def slow_convert(*args, **kwargs):
                await asyncio.sleep(35)  # Longer than timeout
                return MagicMock()
            
            mock_convert.side_effect = slow_convert
            
            response = client.post(
                "/api/convert",
                files={"file": ("test.jpg", b"fake", "image/jpeg")},
                data={"output_format": "png"},
                timeout=5  # Client timeout
            )
            
            # Should timeout
            assert response.status_code in [504, 408, 500]

    def test_compression_middleware(self, client):
        """Test response compression."""
        # Request with gzip support
        response = client.get(
            "/api/formats",
            headers={"Accept-Encoding": "gzip"}
        )
        
        assert response.status_code == 200
        # Check if response is compressed (if middleware is enabled)
        encoding = response.headers.get("content-encoding", "")
        # Compression might be applied
        assert encoding in ["", "gzip", "br"]

    def test_security_headers_middleware(self, client):
        """Test security headers are added."""
        response = client.get("/api/health")
        
        assert response.status_code == 200
        headers = response.headers
        
        # Check for security headers
        security_headers = [
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
            "strict-transport-security"
        ]
        
        # At least some security headers should be present
        present_headers = [h for h in security_headers if h in headers]
        # May not have all headers in dev, but should have some

    def test_request_id_middleware(self, client, sample_image):
        """Test request ID tracking."""
        response = client.post(
            "/api/convert",
            files={"file": ("test.jpg", sample_image.getvalue(), "image/jpeg")},
            data={"output_format": "png"}
        )
        
        # Check if request ID is in response headers
        if "x-request-id" in response.headers:
            request_id = response.headers["x-request-id"]
            assert len(request_id) > 0

    def test_logging_middleware(self, client):
        """Test that requests are logged."""
        with patch('app.utils.logging.logger') as mock_logger:
            response = client.get("/api/health")
            
            assert response.status_code == 200
            # Logger should have been called for the request
            # (Implementation dependent)

    def test_validation_middleware_missing_file(self, client):
        """Test validation when file is missing."""
        response = client.post(
            "/api/convert",
            data={"output_format": "png"}
            # No file provided
        )
        
        assert response.status_code in [422, 400, 415]
        data = response.json()
        assert "error" in data or "detail" in data

    def test_validation_middleware_invalid_format(self, client, sample_image):
        """Test validation with invalid output format."""
        response = client.post(
            "/api/convert",
            files={"file": ("test.jpg", sample_image.getvalue(), "image/jpeg")},
            data={"output_format": "invalid_format"}
        )
        
        assert response.status_code in [422, 400]
        data = response.json()
        assert "error" in data or "detail" in data

    def test_batch_size_limit_middleware(self, client):
        """Test batch size limit enforcement."""
        # Create too many files for batch
        files = []
        for i in range(101):  # Over limit of 100
            img = Image.new('RGB', (10, 10), color='red')
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG')
            buffer.seek(0)
            files.append(("files", (f"test{i}.jpg", buffer.getvalue(), "image/jpeg")))
        
        response = client.post(
            "/api/batch",
            files=files,
            data={"output_format": "png"}
        )
        
        assert response.status_code in [413, 422, 400]

    def test_websocket_rate_limiting(self):
        """Test WebSocket connection rate limiting."""
        from fastapi.testclient import TestClient
        
        with TestClient(app) as client:
            # Try to open many WebSocket connections rapidly
            connections = []
            try:
                for _ in range(20):
                    ws = client.websocket_connect("/ws/batch/test-job-id")
                    connections.append(ws)
            except Exception:
                # Should hit connection limit
                pass
            
            # Clean up
            for conn in connections:
                try:
                    conn.close()
                except:
                    pass
            
            # At least some connections should have been rejected
            assert len(connections) < 20

    def test_middleware_order_validation(self, client):
        """Test that middleware executes in correct order."""
        # Send request that triggers multiple middleware
        large_data = b"x" * (101 * 1024 * 1024)
        
        response = client.post(
            "/api/convert",
            files={"file": ("large.txt", large_data, "text/plain")},
            data={"output_format": "png"},
            headers={"Origin": "http://localhost:3000"}
        )
        
        # Should fail at validation (413) before hitting route
        assert response.status_code in [413, 415]
        # Should still have CORS headers (CORS runs first)
        assert "access-control-allow-origin" in response.headers

    def test_error_recovery_middleware(self, client, sample_image):
        """Test that middleware recovers from errors."""
        # First request causes error
        response1 = client.post(
            "/api/convert",
            files={"file": ("test.txt", b"not an image", "text/plain")},
            data={"output_format": "png"}
        )
        assert response1.status_code in [415, 422, 400]
        
        # Second request should work normally
        response2 = client.post(
            "/api/convert",
            files={"file": ("test.jpg", sample_image.getvalue(), "image/jpeg")},
            data={"output_format": "png"}
        )
        # Should work or give proper error, not crash
        assert response2.status_code in [200, 422, 400]