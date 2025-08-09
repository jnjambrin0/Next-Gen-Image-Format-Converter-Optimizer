"""Integration tests for API endpoints."""

import io
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app

# Fixtures are automatically discovered by pytest from conftest.py


class TestAPIEndpoints:
    """Integration tests for Image Converter API endpoints."""

    @pytest.fixture
    def client(self) -> None:
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def auth_headers(self) -> None:
        """Mock authentication headers if needed."""
        return {"X-API-Key": "test-key"}

    def test_health_check(self, client) -> None:
        """Test health check endpoint."""
        # Act
        response = client.get("/api/health")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "uptime" in data

    def test_convert_single_image_success(self, client, sample_image_path) -> None:
        """Test successful single image conversion."""
        # Arrange
        with open(sample_image_path, "rb") as f:
            files = {"file": ("test.jpg", f, "image/jpeg")}
            data = {"output_format": "webp", "quality": "85"}

            # Act
            response = client.post("/api/convert", files=files, data=data)

        # Assert
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/webp"
        assert "content-disposition" in response.headers
        assert "X-Conversion-Id" in response.headers
        assert "X-Processing-Time" in response.headers
        assert "X-Compression-Ratio" in response.headers
        assert len(response.content) > 0

    @pytest.mark.skip(reason="Resize feature not implemented in this story")
    def test_convert_with_resize(self, client, sample_image_path) -> None:
        """Test image conversion with resizing."""

    def test_convert_invalid_format(self, client, sample_image_path) -> None:
        """Test conversion with invalid output format."""
        # Arrange
        with open(sample_image_path, "rb") as f:
            files = {"file": ("test.jpg", f, "image/jpeg")}
            data = {"output_format": "invalid_format", "quality": "85"}

            # Act
            response = client.post("/api/convert", files=files, data=data)

        # Assert
        assert response.status_code == 422  # FastAPI validation error

    def test_convert_file_too_large(self, client) -> None:
        """Test rejection of files exceeding size limit."""
        # Arrange
        # Create a mock large file (51MB, exceeds 50MB limit)
        large_data = b"x" * (51 * 1024 * 1024)
        files = {"file": ("large.jpg", io.BytesIO(large_data), "image/jpeg")}
        data = {"output_format": "webp"}

        # Act
        response = client.post("/api/convert", files=files, data=data)

        # Assert
        assert response.status_code == 413
        error = response.json()
        assert error["detail"]["error_code"] == "CONV202"
        assert "exceeds maximum" in error["detail"]["message"]

    @pytest.mark.skip(reason="Batch conversion not implemented in this story")
    def test_batch_conversion(self, client, all_test_images) -> None:
        """Test batch image conversion."""

    @pytest.mark.skip(reason="Formats endpoint not implemented in this story")
    def test_get_supported_formats(self, client) -> None:
        """Test endpoint returning supported formats."""

    @pytest.mark.skip(reason="Content detection not implemented in this story")
    def test_content_detection(self, client, all_test_images) -> None:
        """Test ML-based content detection endpoint."""

    @pytest.mark.skip(reason="Presets not implemented in this story")
    def test_preset_operations(self, client) -> None:
        """Test preset CRUD operations."""

    @pytest.mark.skip(reason="Download endpoint not implemented in this story")
    def test_download_converted_file(self, client, sample_image_path) -> None:
        """Test downloading converted files."""

    @pytest.mark.skip(reason="WebSocket not implemented in this story")
    def test_websocket_progress(self, client, sample_image_path) -> None:
        """Test WebSocket progress updates for conversion."""

    @pytest.mark.skip(reason="Rate limiting not implemented in this story")
    def test_rate_limiting(self, client, sample_image_path) -> None:
        """Test API rate limiting."""

    def test_cors_headers(self, client) -> None:
        """Test CORS headers are properly set."""
        # Act
        response = client.options(
            "/api/convert",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )

        # Assert
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
        assert (
            response.headers["access-control-allow-origin"] == "http://localhost:5173"
        )

    def test_error_handling_corrupted_file(self, client) -> None:
        """Test API handling of corrupted files."""
        # Arrange
        corrupted_data = b"Not a real image file"
        files = {"file": ("corrupted.jpg", io.BytesIO(corrupted_data), "image/jpeg")}
        data = {"output_format": "webp"}

        # Act
        response = client.post("/api/convert", files=files, data=data)

        # Assert
        assert response.status_code in [415, 422, 500]  # Could be various errors
        error = response.json()
        assert "error_code" in error["detail"]

    def test_concurrent_requests(self, client, sample_image_path) -> None:
        """Test handling of concurrent conversion requests."""
        # Arrange
        with open(sample_image_path, "rb") as f:
            image_data = f.read()

        # Make multiple requests
        responses = []
        for _ in range(5):
            files = {"file": ("test.jpg", io.BytesIO(image_data), "image/jpeg")}
            data = {"output_format": "webp", "quality": "85"}
            response = client.post("/api/convert", files=files, data=data)
            responses.append(response)

        # Assert all succeeded
        for response in responses:
            assert response.status_code == 200
            assert response.headers["content-type"] == "image/webp"
            assert len(response.content) > 0
