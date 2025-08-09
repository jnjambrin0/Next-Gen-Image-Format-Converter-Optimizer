"""Integration tests for optimization API endpoints."""

from typing import Any
import io

import pytest
from fastapi import status
from httpx import AsyncClient
from PIL import Image

from app.main import app


class TestOptimizationAPI:
    """Test cases for optimization API endpoints."""

    @pytest.fixture
    def test_image(self) -> None:
        """Create a test image file."""
        img = Image.new("RGB", (200, 200), color="red")
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=90)
        buffer.seek(0)
        return buffer

    @pytest.fixture
    def test_image_with_alpha(self) -> None:
        """Create a test image with alpha channel."""
        img = Image.new("RGBA", (200, 200), color=(255, 0, 0, 128))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return buffer

    @pytest.mark.asyncio
    async def test_optimize_advanced_basic(self, test_image):
        """Test basic advanced optimization."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/optimize/advanced",
                files={"file": ("test.jpg", test_image, "image/jpeg")},
                data={
                    "output_format": "webp",
                    "optimization_mode": "balanced",
                    "base_quality": 85,
                },
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["output_format"] == "webp"
            assert data["optimization_mode"] == "balanced"

    @pytest.mark.asyncio
    async def test_optimize_advanced_multipass(self, test_image):
        """Test multi-pass optimization."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/optimize/advanced",
                files={"file": ("test.jpg", test_image, "image/jpeg")},
                data={
                    "output_format": "jpeg",
                    "optimization_mode": "size",
                    "multi_pass": True,
                    "target_size_kb": 50,
                    "min_quality": 40,
                    "max_quality": 95,
                },
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["total_passes"] > 0
            assert "passes" in data

    @pytest.mark.asyncio
    async def test_optimize_advanced_perceptual_metrics(self, test_image):
        """Test perceptual metrics calculation."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/optimize/advanced",
                files={"file": ("test.jpg", test_image, "image/jpeg")},
                data={
                    "output_format": "webp",
                    "perceptual_metrics": True,
                    "base_quality": 80,
                },
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert "quality_metrics" in data
            assert "ssim_score" in data["quality_metrics"]
            assert "psnr_value" in data["quality_metrics"]

    @pytest.mark.asyncio
    async def test_optimize_advanced_lossless(self, test_image):
        """Test lossless compression."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/optimize/advanced",
                files={"file": ("test.jpg", test_image, "image/jpeg")},
                data={"output_format": "png", "lossless": True},
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True

    @pytest.mark.asyncio
    async def test_optimize_advanced_encoding_options(self, test_image):
        """Test advanced encoding options."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/optimize/advanced",
                files={"file": ("test.jpg", test_image, "image/jpeg")},
                data={
                    "output_format": "jpeg",
                    "progressive": True,
                    "chroma_subsampling": "420",
                },
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert "encoding_options_applied" in data

    @pytest.mark.asyncio
    async def test_optimize_advanced_alpha_channel(self, test_image_with_alpha):
        """Test alpha channel optimization."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/optimize/advanced",
                files={"file": ("test.png", test_image_with_alpha, "image/png")},
                data={"output_format": "webp", "alpha_quality": 80},
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert "alpha_info" in data

    @pytest.mark.asyncio
    async def test_optimize_download(self, test_image):
        """Test optimization with direct download."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/optimize/advanced/download",
                files={"file": ("test.jpg", test_image, "image/jpeg")},
                data={"output_format": "webp", "base_quality": 85},
            )

            assert response.status_code == status.HTTP_200_OK
            assert response.headers["content-type"].startswith("image/")
            assert "content-disposition" in response.headers
            assert len(response.content) > 0

    @pytest.mark.asyncio
    async def test_analyze_optimization_potential(self, test_image_with_alpha):
        """Test optimization potential analysis."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.post(
                "/api/optimize/analyze",
                files={"file": ("test.png", test_image_with_alpha, "image/png")},
                data={"output_format": "webp"},
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "alpha_analysis" in data
            assert "compression_potential" in data
            assert "recommendations" in data

    @pytest.mark.asyncio
    async def test_get_format_capabilities(self):
        """Test getting format capabilities."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/api/optimize/capabilities/jpeg")

            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["format"] == "jpeg"
            assert "encoding_options" in data
            assert "supports_progressive" in data

            # Test unsupported format
            response = await client.get("/api/optimize/capabilities/invalid")
            assert response.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_optimize_invalid_input(self):
        """Test optimization with invalid input."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # Missing file
            response = await client.post(
                "/api/optimize/advanced", data={"output_format": "webp"}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Invalid file
            response = await client.post(
                "/api/optimize/advanced",
                files={"file": ("test.txt", b"not an image", "text/plain")},
                data={"output_format": "webp"},
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.asyncio
    async def test_optimization_progress_sse(self):
        """Test SSE progress updates (basic connectivity test)."""
        import uuid

        conversion_id = uuid.uuid4()

        async with AsyncClient(app=app, base_url="http://test") as client:
            # Just test that the endpoint exists and responds
            response = await client.get(
                f"/api/optimize/progress/{conversion_id}",
                headers={"Accept": "text/event-stream"},
            )
            # SSE endpoints return 200 and stream data
            assert response.status_code == status.HTTP_200_OK
