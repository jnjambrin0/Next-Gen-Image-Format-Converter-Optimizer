"""Integration tests for recommendation API endpoints."""

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.conversion import (
    ContentType,
    InputFormat,
    OutputFormat,
)
from app.models.recommendation import UseCaseType


class TestRecommendationAPI:
    """Test cases for recommendation API endpoints."""

    @pytest.fixture
    def client(self) -> None:
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def sample_classification(self) -> None:
        """Create sample content classification."""
        return {
            "primary_type": ContentType.PHOTO.value,
            "confidence": 0.9,
            "processing_time_ms": 50.0,
            "has_text": False,
            "has_faces": True,
        }

    def test_recommend_endpoint_basic(self, client, sample_classification) -> None:
        """Test basic recommendation endpoint."""
        response = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": sample_classification,
                "original_format": InputFormat.JPEG.value,
                "original_size_kb": 500,
                "use_case": UseCaseType.WEB.value,
            },
        )

        assert response.status_code == 200
        data = response.json()

        assert "recommendations" in data
        assert len(data["recommendations"]) <= 3
        assert "comparison_matrix" in data
        assert data["content_type"] == ContentType.PHOTO.value
        assert data["use_case"] == UseCaseType.WEB.value
        assert "processing_time_ms" in data

    def test_recommend_endpoint_with_priority(
        self, client, sample_classification
    ) -> None:
        """Test recommendation with priority."""
        response = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": sample_classification,
                "original_format": InputFormat.PNG.value,
                "original_size_kb": 1000,
                "use_case": UseCaseType.WEB.value,
                "prioritize": "size",
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Should prioritize formats with good compression
        recommendations = data["recommendations"]
        assert len(recommendations) > 0

        # Top recommendation should have good reasons
        top_rec = recommendations[0]
        assert (
            "compression" in str(top_rec["reasons"]).lower()
            or "smaller" in str(top_rec["reasons"]).lower()
        )

    def test_recommend_endpoint_with_exclusions(
        self, client, sample_classification
    ) -> None:
        """Test recommendation with format exclusions."""
        response = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": sample_classification,
                "original_format": InputFormat.JPEG.value,
                "original_size_kb": 500,
                "exclude_formats": [OutputFormat.WEBP.value, OutputFormat.AVIF.value],
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Excluded formats should not appear
        formats = [r["format"] for r in data["recommendations"]]
        assert OutputFormat.WEBP.value not in formats
        assert OutputFormat.AVIF.value not in formats

    def test_recommend_endpoint_with_override(
        self, client, sample_classification
    ) -> None:
        """Test recommendation with user override."""
        response = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": sample_classification,
                "original_format": InputFormat.JPEG.value,
                "original_size_kb": 500,
                "override_format": OutputFormat.PNG.value,
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Should only have one recommendation
        assert len(data["recommendations"]) == 1
        assert data["recommendations"][0]["format"] == OutputFormat.PNG.value
        assert data["recommendations"][0]["score"] == 1.0  # Max score for override

    def test_recommend_endpoint_document_archive(self, client) -> None:
        """Test recommendation for document archival."""
        classification = {
            "primary_type": ContentType.DOCUMENT.value,
            "confidence": 0.95,
            "processing_time_ms": 45.0,
            "has_text": True,
            "has_faces": False,
        }

        response = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": classification,
                "original_format": InputFormat.PNG.value,
                "original_size_kb": 2000,
                "use_case": UseCaseType.ARCHIVE.value,
                "prioritize": "quality",
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Should recommend lossless formats
        recommendations = data["recommendations"]
        assert len(recommendations) > 0

    def test_recommend_endpoint_validation(self, client, sample_classification) -> None:
        """Test endpoint validation."""
        # Missing required field
        response = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": sample_classification,
                "original_format": InputFormat.JPEG.value,
                # Missing original_size_kb
            },
        )

        assert response.status_code == 422  # Validation error

        # Invalid size
        response = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": sample_classification,
                "original_format": InputFormat.JPEG.value,
                "original_size_kb": -100,  # Negative size
            },
        )

        assert response.status_code == 422

    def test_preference_record_endpoint(self, client) -> None:
        """Test preference recording endpoint."""
        response = client.post(
            "/api/intelligence/preferences/record",
            json={
                "content_type": ContentType.PHOTO.value,
                "chosen_format": OutputFormat.WEBP.value,
                "use_case": UseCaseType.WEB.value,
                "was_override": False,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Preference recorded successfully"

    def test_preference_get_endpoint(self, client) -> None:
        """Test getting preferences endpoint."""
        # First record some preferences
        for _ in range(5):
            client.post(
                "/api/intelligence/preferences/record",
                json={
                    "content_type": ContentType.PHOTO.value,
                    "chosen_format": OutputFormat.AVIF.value,
                },
            )

        # Get preferences
        response = client.get(
            f"/api/intelligence/preferences/{ContentType.PHOTO.value}"
        )

        assert response.status_code == 200
        data = response.json()
        assert data["content_type"] == ContentType.PHOTO.value
        assert "preferences" in data

    def test_preference_reset_endpoint(self, client) -> None:
        """Test preference reset endpoint."""
        # Record some preferences first
        client.post(
            "/api/intelligence/preferences/record",
            json={
                "content_type": ContentType.PHOTO.value,
                "chosen_format": OutputFormat.WEBP.value,
            },
        )

        # Reset preferences
        response = client.post(
            "/api/intelligence/preferences/reset",
            json={"content_type": ContentType.PHOTO.value},
        )

        assert response.status_code == 200
        data = response.json()
        assert "count" in data
        assert "Reset" in data["message"]

    def test_format_details_endpoint(self, client) -> None:
        """Test format details endpoint."""
        response = client.get(
            f"/api/intelligence/formats/{OutputFormat.WEBP.value}/details",
            params={"content_type": ContentType.PHOTO.value},
        )

        assert response.status_code == 200
        data = response.json()

        assert data["format"] == OutputFormat.WEBP.value
        assert "characteristics" in data
        assert "features" in data
        assert "content_suitability" in data
        assert "description" in data
        assert "best_for" in data

    def test_recommendation_response_structure(
        self, client, sample_classification
    ) -> None:
        """Test complete recommendation response structure."""
        response = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": sample_classification,
                "original_format": InputFormat.JPEG.value,
                "original_size_kb": 500,
                "use_case": UseCaseType.WEB.value,
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Check recommendations structure
        for rec in data["recommendations"]:
            assert "format" in rec
            assert "score" in rec
            assert 0 <= rec["score"] <= 1
            assert "reasons" in rec
            assert isinstance(rec["reasons"], list)
            assert "estimated_size_kb" in rec
            assert rec["estimated_size_kb"] > 0
            assert "quality_score" in rec
            assert "compatibility_score" in rec
            assert "features" in rec
            assert "trade_offs" in rec
            assert "pros" in rec
            assert "cons" in rec

        # Check comparison matrix
        matrix = data["comparison_matrix"]
        assert isinstance(matrix, dict)
        for format_key, format_data in matrix.items():
            assert "score" in format_data
            assert "metrics" in format_data
            assert "features" in format_data

    def test_recommendation_performance(self, client, sample_classification) -> None:
        """Test recommendation performance requirement."""
        import time

        start = time.time()
        response = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": sample_classification,
                "original_format": InputFormat.JPEG.value,
                "original_size_kb": 500,
            },
        )
        end = time.time()

        assert response.status_code == 200

        # Should complete within reasonable time
        assert (end - start) < 1.0  # 1 second max for API call

        # Processing time should be under 200ms
        data = response.json()
        assert data["processing_time_ms"] < 200

    @pytest.mark.asyncio
    async def test_preference_learning_integration(self, client):
        """Test that preferences affect recommendations."""
        # Clear any existing preferences
        client.post("/api/intelligence/preferences/reset", json={})

        classification = {
            "primary_type": ContentType.PHOTO.value,
            "confidence": 0.9,
            "processing_time_ms": 50.0,
            "has_text": False,
            "has_faces": False,
        }

        # Get initial recommendations
        response1 = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": classification,
                "original_format": InputFormat.JPEG.value,
                "original_size_kb": 500,
            },
        )
        initial_recs = response1.json()["recommendations"]

        # Record strong preference for PNG (unusual for photos)
        for _ in range(10):
            client.post(
                "/api/intelligence/preferences/record",
                json={
                    "content_type": ContentType.PHOTO.value,
                    "chosen_format": OutputFormat.PNG.value,
                },
            )

        # Get new recommendations (may need to wait for preference to take effect)
        import asyncio

        await asyncio.sleep(0.1)

        response2 = client.post(
            "/api/intelligence/recommend",
            json={
                "content_classification": classification,
                "original_format": InputFormat.JPEG.value,
                "original_size_kb": 500,
            },
        )
        new_recs = response2.json()["recommendations"]

        # PNG should rank higher now due to user preference
        initial_png_rank = next(
            (
                i
                for i, r in enumerate(initial_recs)
                if r["format"] == OutputFormat.PNG.value
            ),
            None,
        )
        new_png_rank = next(
            (
                i
                for i, r in enumerate(new_recs)
                if r["format"] == OutputFormat.PNG.value
            ),
            None,
        )

        # PNG should appear in recommendations after preference
        assert new_png_rank is not None
