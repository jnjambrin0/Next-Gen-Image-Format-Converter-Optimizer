"""Integration tests for API endpoints."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
import io
import json
import asyncio
from pathlib import Path

# TODO: Uncomment when app is properly implemented
# from app.main import app

# Fixtures are automatically discovered by pytest from conftest.py


class TestAPIEndpoints:
    """Integration tests for Image Converter API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        # TODO: Uncomment when app is implemented
        # return TestClient(app)

        # Mock client for now
        mock_client = Mock()
        mock_client.get = Mock(
            return_value=Mock(status_code=200, json=lambda: {"status": "healthy"})
        )
        mock_client.post = Mock(
            return_value=Mock(status_code=200, json=lambda: {"status": "success"})
        )
        return mock_client

    @pytest.fixture
    def auth_headers(self):
        """Mock authentication headers if needed."""
        return {"X-API-Key": "test-key"}

    def test_health_check(self, client):
        """Test health check endpoint."""
        # TODO: Enable when API is implemented
        pytest.skip("Waiting for API implementation")

        # Act
        response = client.get("/api/health")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "uptime" in data

    def test_convert_single_image_success(self, client, sample_image_path):
        """Test successful single image conversion."""
        # Arrange
        with open(sample_image_path, "rb") as f:
            files = {"file": ("test.jpg", f, "image/jpeg")}
            data = {"output_format": "webp", "quality": "85", "strip_metadata": "true"}

            # Act
            response = client.post("/api/convert", files=files, data=data)

        # Assert
        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "success"
        assert result["output_format"] == "webp"
        assert "download_url" in result
        assert result["compression_ratio"] > 0

    def test_convert_with_resize(self, client, sample_image_path):
        """Test image conversion with resizing."""
        # Arrange
        with open(sample_image_path, "rb") as f:
            files = {"file": ("test.jpg", f, "image/jpeg")}
            data = {
                "output_format": "jpeg",
                "quality": "90",
                "resize_width": "800",
                "resize_height": "600",
                "resize_fit": "cover",
            }

            # Act
            response = client.post("/api/convert", files=files, data=data)

        # Assert
        assert response.status_code == 200
        result = response.json()
        assert result["dimensions"]["output"]["width"] == 800
        assert result["dimensions"]["output"]["height"] == 600

    def test_convert_invalid_format(self, client, sample_image_path):
        """Test conversion with invalid output format."""
        # Arrange
        with open(sample_image_path, "rb") as f:
            files = {"file": ("test.jpg", f, "image/jpeg")}
            data = {"output_format": "invalid_format", "quality": "85"}

            # Act
            response = client.post("/api/convert", files=files, data=data)

        # Assert
        assert response.status_code == 400
        error = response.json()
        assert error["error_code"] == "INVALID_FORMAT"
        assert "Unsupported" in error["message"]

    def test_convert_file_too_large(self, client):
        """Test rejection of files exceeding size limit."""
        # Arrange
        # Create a mock large file
        large_data = b"x" * (101 * 1024 * 1024)  # 101 MB
        files = {"file": ("large.jpg", io.BytesIO(large_data), "image/jpeg")}
        data = {"output_format": "webp"}

        # Act
        response = client.post("/api/convert", files=files, data=data)

        # Assert
        assert response.status_code == 413
        error = response.json()
        assert error["error_code"] == "FILE_TOO_LARGE"

    def test_batch_conversion(self, client, all_test_images):
        """Test batch image conversion."""
        # Arrange
        files = []
        for name, info in list(all_test_images.items())[:3]:
            with open(info["path"], "rb") as f:
                files.append(
                    (
                        "files",
                        (f"{name}.{info['format'].lower()}", f.read(), "image/jpeg"),
                    )
                )

        data = {"output_format": "webp", "quality": "85", "parallel": "true"}

        # Act
        response = client.post("/api/batch", files=files, data=data)

        # Assert
        assert response.status_code == 200
        result = response.json()
        assert result["total_files"] == 3
        assert "batch_id" in result
        assert result["status"] in ["completed", "processing"]

    def test_get_supported_formats(self, client):
        """Test endpoint returning supported formats."""
        # Act
        response = client.get("/api/formats")

        # Assert
        assert response.status_code == 200
        formats = response.json()
        assert "input_formats" in formats
        assert "output_formats" in formats
        assert "jpeg" in formats["input_formats"]
        assert "webp" in formats["output_formats"]

    def test_content_detection(self, client, all_test_images):
        """Test ML-based content detection endpoint."""
        # Arrange
        photo_path = all_test_images["sample_photo"]["path"]
        with open(photo_path, "rb") as f:
            files = {"file": ("photo.jpg", f, "image/jpeg")}

            # Act
            response = client.post("/api/detect", files=files)

        # Assert
        assert response.status_code == 200
        result = response.json()
        assert result["content_type"] in [
            "photograph",
            "screenshot",
            "illustration",
            "document",
        ]
        assert result["confidence"] > 0
        assert "optimization_suggestions" in result

    def test_preset_operations(self, client):
        """Test preset CRUD operations."""
        # Create preset
        preset_data = {
            "name": "My Web Images",
            "output_format": "webp",
            "quality": 88,
            "resize": {"max_width": 1200, "maintain_aspect_ratio": True},
        }

        # Create
        create_response = client.post("/api/presets", json=preset_data)
        assert create_response.status_code == 201
        preset = create_response.json()
        preset_id = preset["id"]

        # Get
        get_response = client.get(f"/api/presets/{preset_id}")
        assert get_response.status_code == 200
        assert get_response.json()["name"] == "My Web Images"

        # List
        list_response = client.get("/api/presets")
        assert list_response.status_code == 200
        assert len(list_response.json()) > 0

        # Update
        update_data = {"quality": 90}
        update_response = client.patch(f"/api/presets/{preset_id}", json=update_data)
        assert update_response.status_code == 200
        assert update_response.json()["quality"] == 90

        # Delete
        delete_response = client.delete(f"/api/presets/{preset_id}")
        assert delete_response.status_code == 204

    def test_download_converted_file(self, client, sample_image_path):
        """Test downloading converted files."""
        # First convert an image
        with open(sample_image_path, "rb") as f:
            files = {"file": ("test.jpg", f, "image/jpeg")}
            data = {"output_format": "webp"}

            convert_response = client.post("/api/convert", files=files, data=data)
            assert convert_response.status_code == 200

            file_id = convert_response.json()["file_id"]

        # Download the converted file
        download_response = client.get(f"/api/download/{file_id}")
        assert download_response.status_code == 200
        assert download_response.headers["content-type"] == "image/webp"
        assert len(download_response.content) > 0

    def test_websocket_progress(self, client, sample_image_path):
        """Test WebSocket progress updates for conversion."""
        with client.websocket_connect("/ws") as websocket:
            # Send conversion request via WebSocket
            with open(sample_image_path, "rb") as f:
                image_data = f.read()

            request = {
                "action": "convert",
                "data": {
                    "image": image_data.hex(),  # Send as hex string
                    "output_format": "avif",
                    "quality": 85,
                },
            }

            websocket.send_json(request)

            # Receive progress updates
            messages = []
            while True:
                message = websocket.receive_json()
                messages.append(message)

                if message["type"] == "complete" or message["type"] == "error":
                    break

            # Assert we got progress updates
            assert any(msg["type"] == "progress" for msg in messages)
            assert messages[-1]["type"] == "complete"

    def test_rate_limiting(self, client, sample_image_path):
        """Test API rate limiting."""
        # Arrange
        with open(sample_image_path, "rb") as f:
            image_data = f.read()

        # Make many requests quickly
        responses = []
        for _ in range(70):  # Exceed 60/minute limit
            files = {"file": ("test.jpg", io.BytesIO(image_data), "image/jpeg")}
            data = {"output_format": "webp"}
            response = client.post("/api/convert", files=files, data=data)
            responses.append(response.status_code)

        # Assert rate limit is enforced
        assert 429 in responses  # Too Many Requests

    def test_cors_headers(self, client):
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

    def test_error_handling_corrupted_file(self, client):
        """Test API handling of corrupted files."""
        # Arrange
        corrupted_data = b"Not a real image file"
        files = {"file": ("corrupted.jpg", io.BytesIO(corrupted_data), "image/jpeg")}
        data = {"output_format": "webp"}

        # Act
        response = client.post("/api/convert", files=files, data=data)

        # Assert
        assert response.status_code == 422
        error = response.json()
        assert error["error_code"] == "CORRUPTED_FILE"

    def test_concurrent_requests(self, client, sample_image_path):
        """Test handling of concurrent conversion requests."""
        # Arrange
        with open(sample_image_path, "rb") as f:
            image_data = f.read()

        async def make_request():
            files = {"file": ("test.jpg", io.BytesIO(image_data), "image/jpeg")}
            data = {"output_format": "webp", "quality": "85"}
            return client.post("/api/convert", files=files, data=data)

        # Act - Make 10 concurrent requests
        loop = asyncio.new_event_loop()
        tasks = [loop.run_in_executor(None, make_request) for _ in range(10)]
        responses = loop.run_until_complete(asyncio.gather(*tasks))

        # Assert all succeeded
        assert all(r.status_code == 200 for r in responses)
        assert len(set(r.json()["file_id"] for r in responses)) == 10  # All unique
