"""Pytest fixtures for image converter tests."""

import io
import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
from PIL import Image


@pytest.fixture
def test_images_dir():
    """Path to test images directory."""
    return Path(__file__).parent / "fixtures" / "images"


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test outputs."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    # Cleanup after test
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_image_path(test_images_dir):
    """Path to sample photo with EXIF data."""
    return test_images_dir / "sample_photo.jpg"


@pytest.fixture
def sample_image_bytes(sample_image_path):
    """Sample image as bytes."""
    with open(sample_image_path, "rb") as f:
        return f.read()


@pytest.fixture
def all_test_images(test_images_dir):
    """Dictionary of all test images with metadata."""
    return {
        "sample_photo": {
            "path": test_images_dir / "sample_photo.jpg",
            "format": "JPEG",
            "has_exif": True,
            "has_gps": True,
            "dimensions": (1920, 1080),
            "content_type": "photo",
        },
        "portrait_photo": {
            "path": test_images_dir / "portrait_photo.jpg",
            "format": "JPEG",
            "has_exif": True,
            "has_gps": True,
            "dimensions": (1080, 1920),
            "content_type": "photo",
        },
        "screenshot": {
            "path": test_images_dir / "screenshot.png",
            "format": "PNG",
            "has_exif": False,
            "has_gps": False,
            "dimensions": (1440, 900),
            "content_type": "screenshot",
        },
        "document_scan": {
            "path": test_images_dir / "document_scan.png",
            "format": "PNG",
            "has_exif": False,
            "has_gps": False,
            "dimensions": (2480, 3508),
            "content_type": "document",
        },
        "illustration": {
            "path": test_images_dir / "illustration.png",
            "format": "PNG",
            "has_exif": False,
            "has_gps": False,
            "dimensions": (800, 800),
            "content_type": "illustration",
            "has_transparency": True,
        },
        "animated_gif": {
            "path": test_images_dir / "animated.gif",
            "format": "GIF",
            "has_exif": False,
            "has_gps": False,
            "dimensions": (500, 500),
            "content_type": "illustration",
            "is_animated": True,
            "frame_count": 3,
        },
        "large_photo": {
            "path": test_images_dir / "large_photo.jpg",
            "format": "JPEG",
            "has_exif": False,
            "has_gps": False,
            "dimensions": (4000, 3000),
            "content_type": "photo",
            "size_category": "large",
        },
        "tiny_icon": {
            "path": test_images_dir / "tiny_icon.png",
            "format": "PNG",
            "has_exif": False,
            "has_gps": False,
            "dimensions": (16, 16),
            "content_type": "illustration",
            "size_category": "tiny",
            "has_transparency": True,
        },
    }


@pytest.fixture
def corrupted_image_path(test_images_dir):
    """Path to corrupted image for error testing."""
    return test_images_dir / "corrupted.jpg"


@pytest.fixture
def empty_image_path(test_images_dir):
    """Path to empty file for validation testing."""
    return test_images_dir / "empty.png"


@pytest.fixture
def mock_conversion_request():
    """Sample conversion request data."""
    return {
        "output_format": "webp",
        "quality": 85,
        "resize": {"width": 1200, "height": None, "maintain_aspect_ratio": True},
        "strip_metadata": True,
        "optimize": True,
    }


@pytest.fixture
def mock_batch_request():
    """Sample batch conversion request."""
    return {
        "files": ["photo1.jpg", "photo2.png", "document.pdf"],
        "output_format": "avif",
        "quality": 80,
        "parallel": True,
        "preset": "web_optimized",
    }


@pytest.fixture
def conversion_presets():
    """Sample conversion presets."""
    return {
        "web_optimized": {
            "name": "Web Optimized",
            "description": "Optimized for web delivery",
            "output_format": "webp",
            "quality": 85,
            "resize": {"max_width": 1920, "max_height": 1080},
            "strip_metadata": True,
            "optimize": True,
        },
        "thumbnail": {
            "name": "Thumbnail",
            "description": "Small thumbnail images",
            "output_format": "jpeg",
            "quality": 75,
            "resize": {"width": 150, "height": 150, "crop": "center"},
            "strip_metadata": True,
        },
        "archive": {
            "name": "Archive Quality",
            "description": "High quality for archival",
            "output_format": "png",
            "quality": 100,
            "strip_metadata": False,
            "optimize": False,
        },
        "social_media": {
            "name": "Social Media",
            "description": "Optimized for social platforms",
            "output_format": "jpeg",
            "quality": 90,
            "resize": {"width": 1200, "height": 630, "crop": "smart"},
            "strip_metadata": True,
        },
    }


@pytest.fixture
def mock_file_upload():
    """Create a mock file upload object."""

    def _create_upload(filename: str, content: bytes, content_type: str = "image/jpeg"):
        return {
            "filename": filename,
            "content": content,
            "content_type": content_type,
            "size": len(content),
        }

    return _create_upload


@pytest.fixture
def image_generator():
    """Generate test images on the fly."""

    def _generate(
        width: int = 100,
        height: int = 100,
        format: str = "PNG",
        color: Tuple[int, int, int] = (255, 0, 0),
    ) -> bytes:
        img = Image.new("RGB", (width, height), color=color)
        buffer = io.BytesIO()
        img.save(buffer, format=format)
        return buffer.getvalue()

    return _generate


@pytest.fixture
def mock_image_metadata():
    """Sample image metadata response."""
    return {
        "format": "JPEG",
        "width": 1920,
        "height": 1080,
        "color_mode": "RGB",
        "file_size": 245678,
        "has_transparency": False,
        "has_animation": False,
        "exif": {
            "Make": "Canon",
            "Model": "EOS 5D Mark IV",
            "DateTime": "2025:07:31 12:34:56",
            "ExposureTime": "1/125",
            "FNumber": "f/2.8",
            "ISO": 200,
        },
        "gps": {"latitude": 37.7749, "longitude": -122.4194, "altitude": 10.0},
    }


@pytest.fixture
def expected_api_responses():
    """Expected API response structures."""
    return {
        "conversion_success": {
            "status": "success",
            "file_id": "abc123",
            "output_format": "webp",
            "output_size": 123456,
            "compression_ratio": 0.65,
            "processing_time": 1.23,
            "download_url": "/api/download/abc123",
        },
        "conversion_error": {
            "status": "error",
            "error_code": "INVALID_FORMAT",
            "message": "Unsupported input format",
            "details": "The file format 'xyz' is not supported",
        },
        "batch_progress": {
            "batch_id": "batch_123",
            "total_files": 10,
            "completed": 7,
            "failed": 1,
            "in_progress": 2,
            "results": [],
        },
    }


@pytest.fixture
def performance_test_config():
    """Configuration for performance tests."""
    return {
        "small_image": {"size": (640, 480), "max_time": 0.5},
        "medium_image": {"size": (1920, 1080), "max_time": 1.0},
        "large_image": {"size": (4000, 3000), "max_time": 2.0},
        "batch_size": 10,
        "parallel_workers": 4,
    }


@pytest.fixture
def security_test_payloads():
    """Security test payloads."""
    return {
        "path_traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\system.ini"],
        "command_injection": ["; ls -la", "| whoami", "&& rm -rf /"],
        "xxe_payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "zip_bomb_size": 1024 * 1024 * 100,  # 100MB when decompressed
        "malicious_exif": {
            "UserComment": '<script>alert("XSS")</script>',
            "Copyright": "'; DROP TABLE images; --",
        },
    }


@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Automatically cleanup any temporary files after each test."""
    yield
    # Cleanup code here if needed
    temp_patterns = ["/tmp/image-converter-test-*", "/tmp/pytest-*"]
    for pattern in temp_patterns:
        for path in Path("/tmp").glob(pattern.split("/")[-1]):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            elif path.is_file():
                path.unlink(missing_ok=True)


@pytest.fixture
def mock_ml_model_response():
    """Mock response from ML content detection model."""
    return {
        "content_type": "photograph",
        "confidence": 0.95,
        "features": {
            "has_faces": True,
            "has_text": False,
            "is_screenshot": False,
            "is_document": False,
            "dominant_colors": ["#4A90E2", "#F5A623", "#7ED321"],
        },
        "suggested_formats": ["webp", "avif"],
        "optimization_hints": {
            "can_reduce_quality": True,
            "suggested_quality": 85,
            "can_resize": True,
            "suggested_max_dimension": 2048,
        },
    }
