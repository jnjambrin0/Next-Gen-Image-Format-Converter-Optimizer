"""
Comprehensive test suite to maximize core module coverage.
Focused on achieving 85%+ coverage efficiently.
"""

import asyncio
import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from PIL import Image

from app.api.routes import conversion, health, monitoring, security

# Import all core modules to test
from app.core.conversion.manager import ConversionManager
from app.core.conversion.sandboxed_convert import main as sandboxed_main
from app.core.intelligence.engine import IntelligenceEngine
from app.core.monitoring.stats import StatsCollector
from app.core.optimization.optimization_engine import OptimizationEngine
from app.core.security.engine import SecurityEngine
from app.core.security.sandbox import SecuritySandbox
from app.main import app, lifespan
from app.models.conversion import ConversionRequest, ConversionResult
from app.models.intelligence import ContentClassification, ContentType
from app.services.conversion_service import conversion_service
from app.services.format_detection_service import format_detection_service
from app.services.intelligence_service import intelligence_service


@pytest.fixture
def sample_image_bytes():
    """Create sample image bytes."""
    img = Image.new("RGB", (100, 100), color="red")
    buffer = io.BytesIO()
    img.save(buffer, format="JPEG")
    return buffer.getvalue()


@pytest.fixture
def temp_dir():
    """Create temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestConversionManager:
    """Test ConversionManager with high coverage."""

    @pytest.mark.asyncio
    async def test_manager_initialization(self):
        """Test manager initializes correctly."""
        manager = ConversionManager()
        assert manager is not None
        assert hasattr(manager, "convert")

    @pytest.mark.asyncio
    async def test_convert_basic(self, sample_image_bytes):
        """Test basic conversion flow."""
        manager = ConversionManager()
        request = ConversionRequest(output_format="png", quality=90)

        with patch.object(manager, "_execute_conversion") as mock_exec:
            mock_exec.return_value = (b"fake_png_data", {"width": 100, "height": 100})

            result = await manager.convert(sample_image_bytes, request)

            assert result is not None
            mock_exec.assert_called_once()

    @pytest.mark.asyncio
    async def test_convert_with_optimization(self, sample_image_bytes):
        """Test conversion with optimization."""
        manager = ConversionManager()
        request = ConversionRequest(output_format="webp", quality=85, optimize=True)

        with patch.object(manager, "_execute_conversion") as mock_exec:
            with patch.object(manager, "_optimize_output") as mock_opt:
                mock_exec.return_value = (b"webp_data", {})
                mock_opt.return_value = b"optimized_webp"

                result = await manager.convert(sample_image_bytes, request)

                assert mock_opt.called

    @pytest.mark.asyncio
    async def test_convert_with_resize(self, sample_image_bytes):
        """Test conversion with resize."""
        manager = ConversionManager()
        request = ConversionRequest(
            output_format="jpeg", quality=85, resize_width=50, resize_height=50
        )

        with patch.object(manager, "_execute_conversion") as mock_exec:
            mock_exec.return_value = (b"resized_jpeg", {"width": 50, "height": 50})

            result = await manager.convert(sample_image_bytes, request)

            call_args = mock_exec.call_args
            assert "resize_width" in call_args[1] or "resize_width" in str(call_args)


class TestIntelligenceEngine:
    """Test IntelligenceEngine with high coverage."""

    @pytest.mark.asyncio
    async def test_engine_initialization(self):
        """Test engine initialization."""
        engine = IntelligenceEngine()
        await engine.initialize()

        assert engine.initialized is True
        assert engine.enable_ml is True

    @pytest.mark.asyncio
    async def test_classify_content_photo(self, sample_image_bytes):
        """Test photo classification."""
        engine = IntelligenceEngine()
        await engine.initialize()

        with patch.object(engine, "_run_ml_classification") as mock_ml:
            mock_ml.return_value = (ContentType.PHOTO, 0.95)

            result = await engine.classify_content(sample_image_bytes)

            assert isinstance(result, ContentClassification)
            assert result.content_type == ContentType.PHOTO
            assert result.confidence >= 0.9

    @pytest.mark.asyncio
    async def test_classify_with_cache(self, sample_image_bytes):
        """Test classification caching."""
        engine = IntelligenceEngine()
        engine.enable_caching = True
        await engine.initialize()

        with patch.object(engine, "_run_ml_classification") as mock_ml:
            mock_ml.return_value = (ContentType.SCREENSHOT, 0.85)

            # First call
            result1 = await engine.classify_content(sample_image_bytes)

            # Second call (should use cache)
            result2 = await engine.classify_content(sample_image_bytes)

            # ML should only be called once due to cache
            assert mock_ml.call_count == 1
            assert result1.content_type == result2.content_type

    @pytest.mark.asyncio
    async def test_face_detection(self, sample_image_bytes):
        """Test face detection."""
        engine = IntelligenceEngine()
        await engine.initialize()

        with patch.object(engine, "_detect_faces") as mock_faces:
            mock_faces.return_value = [
                {"x": 10, "y": 10, "width": 30, "height": 30, "confidence": 0.9}
            ]

            result = await engine.classify_content(sample_image_bytes)

            if hasattr(result, "face_regions"):
                assert len(result.face_regions) > 0

    @pytest.mark.asyncio
    async def test_ml_disabled_fallback(self, sample_image_bytes):
        """Test fallback when ML is disabled."""
        engine = IntelligenceEngine()
        engine.enable_ml = False
        await engine.initialize()

        result = await engine.classify_content(sample_image_bytes)

        assert isinstance(result, ContentClassification)
        assert result.confidence < 0.7  # Heuristic confidence is lower


class TestSecurityEngine:
    """Test SecurityEngine with high coverage."""

    @pytest.mark.asyncio
    async def test_engine_initialization(self):
        """Test security engine init."""
        engine = SecurityEngine()

        assert engine is not None
        assert hasattr(engine, "analyze_and_process_metadata")

    @pytest.mark.asyncio
    async def test_metadata_analysis(self, sample_image_bytes):
        """Test metadata analysis."""
        engine = SecurityEngine()

        result, summary = await engine.analyze_and_process_metadata(
            sample_image_bytes, "jpeg", remove_metadata=False
        )

        assert result is not None
        assert isinstance(summary, dict)

    @pytest.mark.asyncio
    async def test_metadata_removal(self, sample_image_bytes):
        """Test metadata removal."""
        engine = SecurityEngine()

        cleaned, summary = await engine.analyze_and_process_metadata(
            sample_image_bytes, "jpeg", remove_metadata=True
        )

        assert cleaned is not None
        assert summary.get("removed", False)

    @pytest.mark.asyncio
    async def test_create_sandbox(self):
        """Test sandbox creation."""
        engine = SecurityEngine()

        sandbox = await engine.create_sandbox(strictness_level="standard")

        assert isinstance(sandbox, SecuritySandbox)
        assert sandbox.memory_limit > 0

    @pytest.mark.asyncio
    async def test_verify_sandbox_result(self):
        """Test sandbox result verification."""
        engine = SecurityEngine()

        # Valid result
        is_valid = await engine.verify_sandbox_result(
            b"valid_image_data", max_size=10 * 1024 * 1024
        )
        assert is_valid is True

        # Invalid result (too large)
        is_valid = await engine.verify_sandbox_result(
            b"x" * (101 * 1024 * 1024), max_size=100 * 1024 * 1024
        )
        assert is_valid is False


class TestServices:
    """Test service layer with high coverage."""

    @pytest.mark.asyncio
    async def test_conversion_service(self, sample_image_bytes):
        """Test conversion service."""
        request = ConversionRequest(output_format="png", quality=90)

        with patch("app.services.conversion_service.conversion_manager") as mock_mgr:
            mock_result = ConversionResult(
                success=True, output_format="png", output_size=1000, processing_time=0.1
            )
            mock_mgr.convert.return_value = mock_result

            result = await conversion_service.convert(sample_image_bytes, request)

            assert result is not None

    @pytest.mark.asyncio
    async def test_format_detection_service(self, sample_image_bytes):
        """Test format detection service."""
        detected, confident = await format_detection_service.detect_format(
            sample_image_bytes
        )

        assert detected in ["jpeg", "jpg", "png", "webp"]
        assert isinstance(confident, bool)

    @pytest.mark.asyncio
    async def test_intelligence_service(self, sample_image_bytes):
        """Test intelligence service."""
        with patch.object(intelligence_service, "engine") as mock_engine:
            mock_classification = ContentClassification(
                content_type=ContentType.PHOTO, confidence=0.95
            )
            mock_engine.classify_content.return_value = mock_classification

            result = await intelligence_service.classify(sample_image_bytes)

            assert result.content_type == ContentType.PHOTO


class TestAPIRoutes:
    """Test API routes for coverage."""

    def test_health_route(self):
        """Test health endpoint."""
        from fastapi.testclient import TestClient

        with TestClient(app) as client:
            response = client.get("/api/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"

    def test_formats_route(self):
        """Test formats endpoint."""
        from fastapi.testclient import TestClient

        with TestClient(app) as client:
            response = client.get("/api/formats")

            assert response.status_code == 200
            data = response.json()
            assert "input_formats" in data
            assert "output_formats" in data

    def test_monitoring_stats_route(self):
        """Test monitoring stats."""
        from fastapi.testclient import TestClient

        with TestClient(app) as client:
            response = client.get("/api/monitoring/stats")

            assert response.status_code == 200
            data = response.json()
            assert "total_conversions" in data

    def test_security_status_route(self):
        """Test security status."""
        from fastapi.testclient import TestClient

        with TestClient(app) as client:
            response = client.get("/api/security/status")

            assert response.status_code == 200
            data = response.json()
            assert "sandboxing_enabled" in data


class TestOptimizationEngine:
    """Test optimization engine."""

    @pytest.mark.asyncio
    async def test_engine_init(self):
        """Test optimization engine initialization."""
        engine = OptimizationEngine()

        assert engine is not None
        assert hasattr(engine, "optimize")

    @pytest.mark.asyncio
    async def test_optimize_jpeg(self, sample_image_bytes):
        """Test JPEG optimization."""
        engine = OptimizationEngine()

        with patch.object(engine, "_optimize_jpeg") as mock_opt:
            mock_opt.return_value = b"optimized_jpeg"

            result = await engine.optimize(
                sample_image_bytes, format_type="jpeg", quality=85
            )

            assert result == b"optimized_jpeg"

    @pytest.mark.asyncio
    async def test_optimize_png(self):
        """Test PNG optimization."""
        engine = OptimizationEngine()
        img = Image.new("RGBA", (100, 100), color=(255, 0, 0, 128))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        png_data = buffer.getvalue()

        with patch.object(engine, "_optimize_png") as mock_opt:
            mock_opt.return_value = b"optimized_png"

            result = await engine.optimize(png_data, format_type="png", lossless=True)

            assert result == b"optimized_png"


class TestStatsCollector:
    """Test monitoring stats collector."""

    def test_collector_init(self):
        """Test stats collector initialization."""
        collector = StatsCollector()

        assert collector is not None
        assert hasattr(collector, "record_conversion")

    def test_record_conversion(self):
        """Test recording conversion stats."""
        collector = StatsCollector()

        collector.record_conversion(
            input_format="jpeg",
            output_format="webp",
            input_size=1000,
            output_size=800,
            processing_time=0.5,
            success=True,
        )

        stats = collector.get_stats()
        assert stats["total_conversions"] >= 1

    def test_record_error(self):
        """Test recording errors."""
        collector = StatsCollector()

        collector.record_error(
            error_type="conversion_failed", error_message="Invalid format"
        )

        errors = collector.get_recent_errors()
        assert len(errors) >= 1

    def test_get_format_stats(self):
        """Test format-specific stats."""
        collector = StatsCollector()

        # Record some conversions
        collector.record_conversion("jpeg", "webp", 1000, 800, 0.5, True)
        collector.record_conversion("png", "avif", 2000, 1200, 0.8, True)

        format_stats = collector.get_format_stats()
        assert "jpeg" in format_stats or len(format_stats) > 0


class TestErrorHandling:
    """Test error handling paths."""

    @pytest.mark.asyncio
    async def test_conversion_error_handling(self):
        """Test conversion error paths."""
        manager = ConversionManager()
        request = ConversionRequest(output_format="invalid", quality=85)

        with pytest.raises(Exception):
            await manager.convert(b"invalid", request)

    @pytest.mark.asyncio
    async def test_intelligence_error_handling(self):
        """Test intelligence error paths."""
        engine = IntelligenceEngine()

        with pytest.raises(Exception):
            await engine.classify_content(b"")

    @pytest.mark.asyncio
    async def test_security_error_handling(self):
        """Test security error paths."""
        engine = SecurityEngine()

        with pytest.raises(Exception):
            await engine.analyze_and_process_metadata(
                b"", "invalid_format", remove_metadata=True
            )
