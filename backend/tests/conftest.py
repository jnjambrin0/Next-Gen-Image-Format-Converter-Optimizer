"""Pytest fixtures for image converter tests."""

import asyncio
import io
import json
import os
import shutil
import socket
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from PIL import Image

# Set test environment variables BEFORE any imports
os.environ["IMAGE_CONVERTER_ENABLE_SANDBOXING"] = "false"
os.environ["TESTING"] = "true"
os.environ["IMAGE_CONVERTER_SANDBOX_STRICTNESS"] = "standard"

# Note: Some tests may timeout due to service initialization
# If this happens, consider mocking heavy services in individual test files


# Ensure proper event loop handling for async tests
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Initialize services fixture for tests
@pytest.fixture
def initialized_services():
    """Mock services for testing."""
    from app.services.conversion_service import conversion_service

    return {
        "conversion_service": conversion_service,
        "intelligence_service": MagicMock(),
        "batch_service": MagicMock(),
    }


# Mock format handler dependencies that may not be available in CI
@pytest.fixture(autouse=True)
def mock_format_dependencies():
    """Mock optional format handler dependencies for consistent testing."""
    with patch.dict(
        "sys.modules",
        {
            "pillow_avif": MagicMock(),
            "pillow_heif": MagicMock(),
            "jxl": MagicMock(),
            "jxllib": MagicMock(),
            "opencv-python": MagicMock(),
            "cv2": MagicMock(),
        },
    ):
        # Mock AVIF availability
        with patch("app.core.conversion.formats.avif_handler.AVIF_AVAILABLE", True):
            with patch("app.core.conversion.formats.heif_handler.HEIF_AVAILABLE", True):
                with patch(
                    "app.core.conversion.formats.jxl_handler.JXL_AVAILABLE", True
                ):
                    yield


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


@pytest.fixture
def realistic_image_generator():
    """Generate realistic test images with proper content."""
    import numpy as np

    try:
        import piexif
    except ImportError:
        piexif = None

    def _generate_realistic(
        width: int = 1920,
        height: int = 1080,
        content_type: str = "photo",
        has_metadata: bool = True,
        format: str = "JPEG",
    ) -> bytes:
        # Create realistic content based on type
        if content_type == "photo":
            # Simulate photo with gradient and noise (vectorized for performance)
            # Generate noise arrays once instead of per-pixel
            noise_r = np.random.randint(-20, 21, (height, width))
            noise_g = np.random.randint(-20, 21, (height, width))
            noise_b = np.random.randint(-20, 21, (height, width))

            # Generate gradient arrays
            x_gradient = np.linspace(0, 255, width).astype(int)
            y_gradient = np.linspace(0, 255, height).astype(int)

            # Create RGB channels using broadcasting
            r_channel = np.clip(x_gradient[np.newaxis, :] + noise_r, 0, 255)
            g_channel = np.clip(y_gradient[:, np.newaxis] + noise_g, 0, 255)
            b_channel = np.clip(
                (
                    (x_gradient[np.newaxis, :] + y_gradient[:, np.newaxis])
                    * 128
                    // (width + height)
                )
                + noise_b,
                0,
                255,
            )

            # Stack into RGB array and convert to image
            rgb_array = np.stack([r_channel, g_channel, b_channel], axis=2).astype(
                np.uint8
            )
            img = Image.fromarray(rgb_array)

        elif content_type == "screenshot":
            # Simulate screenshot with UI elements (vectorized)
            screenshot_array = np.full(
                (height, width, 3), 245, dtype=np.uint8
            )  # Background
            # Add toolbar efficiently
            screenshot_array[:60, :] = [230, 230, 230]  # Toolbar area
            img = Image.fromarray(screenshot_array)

        elif content_type == "document":
            # Simulate document with text lines (vectorized)
            doc_array = np.full(
                (height, width, 3), 255, dtype=np.uint8
            )  # White background
            # Add text lines efficiently
            for y in range(100, height - 100, 30):
                # Create text pattern: 10 black pixels, 5 white pixels
                text_pattern = np.tile([0] * 10 + [255] * 5, (width - 200) // 15 + 1)[
                    : width - 200
                ]
                doc_array[y : y + 2, 100 : 100 + len(text_pattern)] = text_pattern[
                    :, np.newaxis
                ]
            img = Image.fromarray(doc_array)

        else:  # illustration
            # Geometric patterns (vectorized)
            # Create base RGBA array
            illus_array = np.full(
                (height, width, 4), [255, 255, 255, 0], dtype=np.uint8
            )

            # Generate geometric pattern using meshgrid
            y_coords, x_coords = np.meshgrid(
                np.arange(height), np.arange(width), indexing="ij"
            )

            # Create checkerboard pattern
            block_size = 50
            x_blocks = x_coords // block_size
            y_blocks = y_coords // block_size
            mask = (
                ((x_blocks + y_blocks) % 2 == 0)
                & (x_coords % block_size < 40)
                & (y_coords % block_size < 40)
            )

            # Apply colors where mask is True
            illus_array[mask, 0] = (x_coords[mask] * 255 // width).astype(np.uint8)  # R
            illus_array[mask, 1] = (y_coords[mask] * 255 // height).astype(
                np.uint8
            )  # G
            illus_array[mask, 2] = 128  # B
            illus_array[mask, 3] = 200  # A

            img = Image.fromarray(illus_array, "RGBA")

        # Add metadata if requested
        buffer = io.BytesIO()
        exif_bytes = b""

        if has_metadata and format in ["JPEG", "JPG"] and piexif:
            exif_dict = {
                "0th": {
                    piexif.ImageIFD.Make: b"TestCamera",
                    piexif.ImageIFD.Model: b"TestModel X1",
                    piexif.ImageIFD.DateTime: b"2025:01:15 14:30:00",
                },
                "GPS": {
                    piexif.GPSIFD.GPSLatitude: ((37, 1), (46, 1), (30, 1)),
                    piexif.GPSIFD.GPSLongitude: ((122, 1), (25, 1), (0, 1)),
                },
            }
            exif_bytes = piexif.dump(exif_dict)

        if exif_bytes:
            img.save(buffer, format=format, quality=95, exif=exif_bytes)
        else:
            img.save(
                buffer, format=format, quality=95 if format in ["JPEG", "JPG"] else None
            )

        return buffer.getvalue()

    return _generate_realistic


@pytest.fixture
def create_malicious_image():
    """Create various types of malicious images for security testing."""

    def _create_malicious(attack_type: str) -> bytes:
        if attack_type == "zip_bomb":
            # PNG with fake huge dimensions
            png_header = b"\x89PNG\r\n\x1a\n"
            # IHDR chunk claiming 65535x65535 size
            import struct

            ihdr_data = struct.pack(">II", 65535, 65535) + b"\x08\x02\x00\x00\x00"
            ihdr_crc = struct.pack(">I", 0)
            ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc
            idat_chunk = struct.pack(">I", 0) + b"IDAT" + struct.pack(">I", 0)
            iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0)
            return png_header + ihdr_chunk + idat_chunk + iend_chunk

        elif attack_type == "polyglot":
            # File that's both valid JPEG and contains embedded code
            jpeg_header = (
                b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            )
            payload = b'<script>alert("XSS")</script>'
            jpeg_data = (
                jpeg_header
                + b"\xff\xfe"
                + struct.pack(">H", len(payload) + 2)
                + payload
            )
            jpeg_data += b"\xff\xd9"  # End of JPEG
            return jpeg_data

        elif attack_type == "infinite_loop":
            # GIF with circular frame references
            gif_header = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00"
            gif_data = gif_header + b"\x21\xff\x0bNETSCAPE2.0\x03\x01\xff\xff\x00"
            gif_data += b"\x21\xf9\x04\x00\x00\x00\x00\x00"  # Graphics control
            gif_data += b"\x2c" + struct.pack("<HHHH", 0, 0, 1, 1) + b"\x00"
            gif_data += b"\x02\x02\x44\x01\x00"  # Image data
            gif_data += b"\x3b"  # Trailer
            return gif_data

        elif attack_type == "buffer_overflow":
            # TIFF with oversized tag
            import struct

            tiff_header = b"II*\x00" + struct.pack("<I", 8)  # Little-endian TIFF
            # IFD with malicious tag
            ifd = struct.pack("<H", 1)  # 1 entry
            # Tag with huge count
            ifd += struct.pack(
                "<HHII", 256, 1, 0xFFFFFFFF, 0
            )  # ImageWidth with huge count
            ifd += struct.pack("<I", 0)  # Next IFD offset
            return tiff_header + ifd

        else:  # corrupted
            # Partially valid JPEG that becomes corrupted
            jpeg_start = (
                b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            )
            corrupted_data = b"\xff\xff" * 100 + b"CORRUPTED" * 50
            return jpeg_start + corrupted_data + b"\xff\xd9"

    return _create_malicious


@pytest.fixture
def simulate_network_conditions():
    """Simulate various network conditions for testing."""
    import asyncio

    class NetworkSimulator:
        def __init__(self):
            self.latency = 0
            self.packet_loss = 0
            self.bandwidth_limit = float("inf")

        async def slow_network(self, latency_ms: int = 100):
            """Simulate slow network with latency."""
            self.latency = latency_ms / 1000
            await asyncio.sleep(self.latency)

        async def unreliable_network(self, loss_rate: float = 0.1):
            """Simulate packet loss."""
            import random

            if random.random() < loss_rate:
                raise ConnectionError("Simulated packet loss")

        async def limited_bandwidth(self, bytes_per_sec: int):
            """Simulate bandwidth limitation."""
            self.bandwidth_limit = bytes_per_sec

    return NetworkSimulator()


@pytest.fixture
def batch_test_files():
    """Generate a batch of diverse test files."""

    def _generate_batch(count: int = 100) -> List[Dict[str, Any]]:
        files = []
        categories = ["photo", "screenshot", "document", "illustration"]
        formats = ["jpeg", "png", "gif", "bmp", "tiff"]

        for i in range(count):
            category = categories[i % len(categories)]
            format_idx = i % len(formats)

            # Vary dimensions
            if category == "photo":
                width = 1920 + (i * 100) % 2000
                height = 1080 + (i * 100) % 1500
            elif category == "screenshot":
                width = 1366 + (i * 50) % 500
                height = 768 + (i * 50) % 300
            elif category == "document":
                width = 2480
                height = 3508
            else:  # illustration
                width = 500 + (i * 100) % 1000
                height = 500 + (i * 100) % 1000

            files.append(
                {
                    "index": i,
                    "filename": f"test_{category}_{i:04d}.{formats[format_idx]}",
                    "category": category,
                    "format": formats[format_idx],
                    "width": width,
                    "height": height,
                    "has_metadata": i % 3 == 0,  # Every 3rd file has metadata
                    "size_estimate": width * height * 3 // 10,  # Rough estimate
                }
            )

        return files

    return _generate_batch


@pytest.fixture
def websocket_test_client():
    """Create a WebSocket test client."""
    import json

    import websockets

    class WebSocketTestClient:
        def __init__(self):
            self.connection = None
            self.messages = []

        async def connect(self, url: str, token: str = None):
            """Connect to WebSocket endpoint."""
            if token:
                url = f"{url}?token={token}"
            self.connection = await websockets.connect(url)

        async def send_json(self, data: Dict):
            """Send JSON message."""
            if self.connection:
                await self.connection.send(json.dumps(data))

        async def receive_json(self) -> Dict:
            """Receive and parse JSON message."""
            if self.connection:
                message = await self.connection.recv()
                data = json.loads(message)
                self.messages.append(data)
                return data

        async def close(self):
            """Close connection."""
            if self.connection:
                await self.connection.close()

    return WebSocketTestClient()


@pytest.fixture
def memory_monitor():
    """Monitor memory usage during tests."""
    import time

    import psutil

    class MemoryMonitor:
        def __init__(self):
            self.process = psutil.Process()
            self.initial_memory = None
            self.peak_memory = 0
            self.samples = []

        def start(self):
            """Start monitoring."""
            self.initial_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            self.peak_memory = self.initial_memory
            self.samples = [(0, self.initial_memory)]

        def sample(self):
            """Take a memory sample."""
            current = self.process.memory_info().rss / 1024 / 1024
            elapsed = time.time() if self.samples else 0
            self.samples.append((elapsed, current))
            self.peak_memory = max(self.peak_memory, current)
            return current

        def get_growth(self) -> float:
            """Get memory growth since start."""
            if not self.initial_memory:
                return 0
            current = self.process.memory_info().rss / 1024 / 1024
            return current - self.initial_memory

        def assert_stable(self, max_growth_mb: float = 100):
            """Assert memory growth is within limits."""
            growth = self.get_growth()
            assert (
                growth < max_growth_mb
            ), f"Memory grew by {growth:.2f}MB (limit: {max_growth_mb}MB)"

    return MemoryMonitor()


# Test markers for categorizing tests
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "security: security-related tests")
    config.addinivalue_line("markers", "performance: performance tests")
    config.addinivalue_line("markers", "integration: integration tests")
    config.addinivalue_line("markers", "critical: critical functionality tests")
    config.addinivalue_line("markers", "network: tests requiring network")
    config.addinivalue_line("markers", "ml: machine learning tests")
