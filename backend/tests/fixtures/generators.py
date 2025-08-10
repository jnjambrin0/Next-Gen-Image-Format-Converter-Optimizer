"""Test data generators for dynamic test data creation."""

import io
import json
import random
import string
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import piexif
from PIL import Image, ImageDraw, ImageFilter


class ImageGenerator:
    """Generate test images with specific characteristics."""

    @staticmethod
    def create_test_image(
        width: int = 800,
        height: int = 600,
        format: str = "JPEG",
        color_mode: str = "RGB",
        content_type: str = "photo",
        add_metadata: bool = False,
        quality: int = 85,
    ) -> bytes:
        """Generate a test image with specified parameters."""
        # Create base image
        if color_mode == "RGBA":
            img = Image.new(color_mode, (width, height), (255, 255, 255, 0))
        else:
            img = Image.new(color_mode, (width, height), (255, 255, 255))

        draw = ImageDraw.Draw(img)

        # Generate content based on type
        if content_type == "photo":
            ImageGenerator._draw_photo_content(draw, width, height)
        elif content_type == "screenshot":
            ImageGenerator._draw_screenshot_content(draw, width, height)
        elif content_type == "document":
            ImageGenerator._draw_document_content(draw, width, height)
        elif content_type == "illustration":
            ImageGenerator._draw_illustration_content(draw, width, height)

        # Add metadata if requested
        exif_bytes = None
        if add_metadata and format in ["JPEG", "JPG"]:
            exif_bytes = ImageGenerator._create_exif_data()

        # Convert to bytes
        output = io.BytesIO()
        save_kwargs = {"format": format, "quality": quality}
        if exif_bytes:
            save_kwargs["exif"] = exif_bytes

        img.save(output, **save_kwargs)
        return output.getvalue()

    @staticmethod
    def _draw_photo_content(draw: ImageDraw.Draw, width: int, height: int):
        """Draw photo-like content."""
        # Create gradient background
        for y in range(height):
            r = int(200 + (y / height) * 55)
            g = int(150 + (y / height) * 105)
            b = int(100 + (y / height) * 155)
            draw.rectangle([(0, y), (width, y + 1)], fill=(r, g, b))

        # Add some shapes to simulate objects
        for _ in range(5):
            x = random.randint(0, width)
            y = random.randint(0, height)
            r = random.randint(50, 150)
            color = (
                random.randint(50, 200),
                random.randint(50, 200),
                random.randint(50, 200),
            )
            draw.ellipse([(x - r, y - r), (x + r, y + r)], fill=color)

    @staticmethod
    def _draw_screenshot_content(draw: ImageDraw.Draw, width: int, height: int):
        """Draw screenshot-like content."""
        # Window chrome
        draw.rectangle([(0, 0), (width, 30)], fill=(60, 60, 60))
        # Window controls
        for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            draw.ellipse([(10 + i * 20, 10), (20 + i * 20, 20)], fill=color)

        # Content area
        draw.rectangle([(0, 30), (width, height)], fill=(245, 245, 245))

        # Simulate UI elements
        for i in range(3):
            y = 50 + i * 100
            draw.rectangle(
                [(20, y), (width - 20, y + 60)],
                fill=(255, 255, 255),
                outline=(200, 200, 200),
            )
            draw.rectangle([(30, y + 10), (100, y + 30)], fill=(100, 150, 255))

    @staticmethod
    def _draw_document_content(draw: ImageDraw.Draw, width: int, height: int):
        """Draw document-like content."""
        # White background
        draw.rectangle([(0, 0), (width, height)], fill=(255, 255, 255))

        # Text lines
        line_height = 20
        margin = 50
        y = margin

        while y < height - margin:
            line_width = random.randint(int(width * 0.6), width - 2 * margin)
            draw.rectangle(
                [(margin, y), (margin + line_width, y + 10)], fill=(30, 30, 30)
            )
            y += line_height

            # Paragraph break
            if random.random() > 0.8:
                y += line_height

    @staticmethod
    def _draw_illustration_content(draw: ImageDraw.Draw, width: int, height: int):
        """Draw illustration-like content."""
        # Colorful abstract shapes
        for _ in range(10):
            shape_type = random.choice(["circle", "rectangle", "polygon"])
            x = random.randint(0, width)
            y = random.randint(0, height)
            size = random.randint(30, 100)
            color = (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                (
                    random.randint(100, 255)
                    if hasattr(draw, "_image") and draw._image.mode == "RGBA"
                    else 255
                ),
            )

            if shape_type == "circle":
                draw.ellipse([(x - size, y - size), (x + size, y + size)], fill=color)
            elif shape_type == "rectangle":
                draw.rectangle([(x - size, y - size), (x + size, y + size)], fill=color)
            else:
                points = [
                    (x + random.randint(-size, size), y + random.randint(-size, size))
                    for _ in range(3)
                ]
                draw.polygon(points, fill=color)

    @staticmethod
    def _create_exif_data() -> bytes:
        """Create sample EXIF data."""
        exif_dict = {
            "0th": {
                piexif.ImageIFD.Make: b"TestCamera",
                piexif.ImageIFD.Model: b"Model X",
                piexif.ImageIFD.DateTime: datetime.now()
                .strftime("%Y:%m:%d %H:%M:%S")
                .encode(),
                piexif.ImageIFD.Software: b"TestSoftware 1.0",
            },
            "Exif": {
                piexif.ExifIFD.DateTimeOriginal: datetime.now()
                .strftime("%Y:%m:%d %H:%M:%S")
                .encode(),
                piexif.ExifIFD.ExposureTime: (1, 100),
                piexif.ExifIFD.FNumber: (18, 10),
                piexif.ExifIFD.ISOSpeedRatings: 400,
                piexif.ExifIFD.FocalLength: (35, 1),
            },
            "GPS": {
                piexif.GPSIFD.GPSLatitudeRef: b"N",
                piexif.GPSIFD.GPSLatitude: ((40, 1), (45, 1), (0, 1)),
                piexif.GPSIFD.GPSLongitudeRef: b"W",
                piexif.GPSIFD.GPSLongitude: ((73, 1), (59, 1), (0, 1)),
            },
        }
        return piexif.dump(exif_dict)

    @staticmethod
    def create_animated_gif(
        width: int = 200, height: int = 200, frames: int = 5, duration: int = 200
    ) -> bytes:
        """Create an animated GIF."""
        images = []

        for frame in range(frames):
            img = Image.new("RGB", (width, height), (255, 255, 255))
            draw = ImageDraw.Draw(img)

            # Draw moving circle
            angle = (frame / frames) * 2 * np.pi
            x = width // 2 + int(width * 0.3 * np.cos(angle))
            y = height // 2 + int(height * 0.3 * np.sin(angle))

            draw.ellipse([(x - 20, y - 20), (x + 20, y + 20)], fill=(255, 100, 100))

            images.append(img)

        output = io.BytesIO()
        images[0].save(
            output,
            format="GIF",
            save_all=True,
            append_images=images[1:],
            duration=duration,
            loop=0,
        )
        return output.getvalue()

    @staticmethod
    def create_corrupted_image() -> bytes:
        """Create a corrupted image file."""
        # Start with valid image data
        img = Image.new("RGB", (100, 100), (255, 0, 0))
        output = io.BytesIO()
        img.save(output, format="JPEG")
        data = output.getvalue()

        # Corrupt by truncating
        return data[: len(data) // 2]

    @staticmethod
    def create_edge_case_image(case_type: str) -> bytes:
        """Create images for specific edge cases."""
        if case_type == "massive":
            # Create a very large image (but not too large for tests)
            return ImageGenerator.create_test_image(8000, 6000)
        elif case_type == "tiny":
            # Create a 1x1 pixel image
            return ImageGenerator.create_test_image(1, 1)
        elif case_type == "extreme_ratio":
            # Create image with extreme aspect ratio
            return ImageGenerator.create_test_image(10000, 10)
        elif case_type == "transparent":
            # Create fully transparent image
            img = Image.new("RGBA", (100, 100), (0, 0, 0, 0))
            output = io.BytesIO()
            img.save(output, format="PNG")
            return output.getvalue()
        elif case_type == "cmyk":
            # Create CMYK image
            img = Image.new("CMYK", (100, 100), (100, 0, 100, 0))
            output = io.BytesIO()
            img.save(output, format="JPEG")
            return output.getvalue()
        else:
            raise ValueError(f"Unknown edge case type: {case_type}")


class RequestDataGenerator:
    """Generate test request data."""

    @staticmethod
    def create_conversion_request(**kwargs) -> Dict[str, Any]:
        """Create a conversion request with optional overrides."""
        default = {
            "file_id": RequestDataGenerator._generate_id(),
            "output_format": random.choice(["webp", "avif", "jpeg", "png"]),
            "quality": random.randint(70, 95),
            "resize": {
                "width": random.choice([None, 800, 1200, 1920]),
                "height": random.choice([None, 600, 900, 1080]),
                "maintain_aspect_ratio": True,
                "fit": random.choice(["contain", "cover", "fill", "inside", "outside"]),
            },
            "strip_metadata": random.choice([True, False]),
            "optimize": True,
            "advanced": {
                "compression_level": random.randint(1, 9),
                "chroma_subsampling": random.choice(["4:4:4", "4:2:2", "4:2:0"]),
                "progressive": random.choice([True, False]),
            },
        }

        # Apply overrides
        for key, value in kwargs.items():
            if (
                key in default
                and isinstance(default[key], dict)
                and isinstance(value, dict)
            ):
                default[key].update(value)
            else:
                default[key] = value

        return default

    @staticmethod
    def create_batch_request(file_count: int = 5, **kwargs) -> Dict[str, Any]:
        """Create a batch conversion request."""
        files = [
            f"image_{i}.{random.choice(['jpg', 'png', 'gif', 'bmp'])}"
            for i in range(file_count)
        ]

        default = {
            "batch_id": RequestDataGenerator._generate_id("batch"),
            "files": files,
            "output_format": random.choice(["webp", "avif"]),
            "quality": 85,
            "parallel": True,
            "max_workers": 4,
            "continue_on_error": True,
            "notification_webhook": None,
        }

        default.update(kwargs)
        return default

    @staticmethod
    def create_preset(**kwargs) -> Dict[str, Any]:
        """Create a conversion preset."""
        preset_types = ["web", "thumbnail", "social", "print", "archive"]
        preset_type = kwargs.get("type", random.choice(preset_types))

        presets = {
            "web": {
                "name": "Web Optimized",
                "output_format": "webp",
                "quality": 85,
                "resize": {"max_width": 1920, "max_height": 1080},
                "strip_metadata": True,
            },
            "thumbnail": {
                "name": "Thumbnail",
                "output_format": "jpeg",
                "quality": 75,
                "resize": {"width": 200, "height": 200, "fit": "cover"},
                "strip_metadata": True,
            },
            "social": {
                "name": "Social Media",
                "output_format": "jpeg",
                "quality": 90,
                "resize": {"width": 1200, "height": 630, "fit": "cover"},
                "strip_metadata": True,
            },
            "print": {
                "name": "Print Quality",
                "output_format": "tiff",
                "quality": 100,
                "strip_metadata": False,
                "dpi": 300,
            },
            "archive": {
                "name": "Archive",
                "output_format": "png",
                "quality": 100,
                "strip_metadata": False,
                "optimize": False,
            },
        }

        preset = presets.get(preset_type, presets["web"]).copy()
        preset["id"] = RequestDataGenerator._generate_id("preset")
        preset["created_at"] = datetime.now().isoformat()
        preset.update(kwargs)

        return preset

    @staticmethod
    def _generate_id(prefix: str = "file") -> str:
        """Generate a random ID."""
        random_part = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=8)
        )
        return f"{prefix}_{random_part}"


class ResponseDataGenerator:
    """Generate test response data."""

    @staticmethod
    def create_success_response(**kwargs) -> Dict[str, Any]:
        """Create a successful conversion response."""
        default = {
            "status": "success",
            "file_id": RequestDataGenerator._generate_id(),
            "original_format": "jpeg",
            "output_format": "webp",
            "original_size": random.randint(100000, 5000000),
            "output_size": random.randint(50000, 2500000),
            "compression_ratio": round(random.uniform(0.3, 0.9), 2),
            "processing_time": round(random.uniform(0.1, 2.0), 3),
            "dimensions": {
                "original": {"width": 1920, "height": 1080},
                "output": {"width": 1920, "height": 1080},
            },
            "download_url": f"/api/download/{RequestDataGenerator._generate_id()}",
            "expires_at": (datetime.now() + timedelta(hours=24)).isoformat(),
        }

        default.update(kwargs)
        return default

    @staticmethod
    def create_error_response(error_type: str = "generic", **kwargs) -> Dict[str, Any]:
        """Create an error response."""
        errors = {
            "invalid_format": {
                "error_code": "INVALID_FORMAT",
                "message": "Unsupported file format",
                "details": "The uploaded file format is not supported",
            },
            "file_too_large": {
                "error_code": "FILE_TOO_LARGE",
                "message": "File size exceeds limit",
                "details": "Maximum file size is 100MB",
            },
            "corrupted": {
                "error_code": "CORRUPTED_FILE",
                "message": "File appears to be corrupted",
                "details": "Unable to read image data",
            },
            "timeout": {
                "error_code": "PROCESSING_TIMEOUT",
                "message": "Processing timeout",
                "details": "Image processing took too long",
            },
            "generic": {
                "error_code": "INTERNAL_ERROR",
                "message": "An error occurred",
                "details": "Please try again later",
            },
        }

        response = {"status": "error", "timestamp": datetime.now().isoformat()}
        response.update(errors.get(error_type, errors["generic"]))
        response.update(kwargs)

        return response

    @staticmethod
    def create_batch_response(total: int = 10, **kwargs) -> Dict[str, Any]:
        """Create a batch processing response."""
        completed = kwargs.get("completed", random.randint(0, total))
        failed = kwargs.get("failed", random.randint(0, total - completed))
        in_progress = total - completed - failed

        results = []
        for i in range(completed):
            results.append(
                {
                    "file": f"image_{i}.jpg",
                    "status": "success",
                    "output_size": random.randint(50000, 500000),
                }
            )

        for i in range(completed, completed + failed):
            results.append(
                {
                    "file": f"image_{i}.jpg",
                    "status": "error",
                    "error": "Processing failed",
                }
            )

        return {
            "batch_id": RequestDataGenerator._generate_id("batch"),
            "status": "in_progress" if in_progress > 0 else "completed",
            "total_files": total,
            "completed": completed,
            "failed": failed,
            "in_progress": in_progress,
            "results": results,
            "started_at": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "updated_at": datetime.now().isoformat(),
        }


class SecurityTestGenerator:
    """Generate security test payloads."""

    @staticmethod
    def create_malicious_filename() -> List[str]:
        """Generate potentially malicious filenames."""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "image.jpg\x00.exe",
            "image.jpg; rm -rf /",
            "image.php.jpg",
            "image.jsp.jpg",
            "../../uploads/shell.php",
            "image.jpg%00.php",
            "image.jpg%20.php",
            "con.jpg",  # Windows reserved name
            "aux.png",  # Windows reserved name
            "nul.gif",  # Windows reserved name
            "a" * 300 + ".jpg",  # Very long filename
            ".htaccess",
            "web.config",
        ]

    @staticmethod
    def create_malicious_metadata() -> Dict[str, Any]:
        """Create potentially malicious metadata."""
        return {
            "xss_attempts": {
                "UserComment": '<script>alert("XSS")</script>',
                "Copyright": "<img src=x onerror=alert(1)>",
                "Artist": "javascript:alert(document.cookie)",
            },
            "sql_injection": {
                "Make": "Canon'; DROP TABLE images; --",
                "Model": "' OR '1'='1",
                "Software": "1; DELETE FROM users WHERE 1=1; --",
            },
            "command_injection": {
                "DateTime": "; cat /etc/passwd",
                "Artist": "| whoami",
                "Copyright": "&& rm -rf /",
            },
            "xxe_injection": {
                "UserComment": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            },
        }

    @staticmethod
    def create_resource_exhaustion_payload() -> Dict[str, Any]:
        """Create payloads designed to exhaust resources."""
        return {
            "massive_dimensions": {"width": 50000, "height": 50000},
            "excessive_quality": {"quality": 100, "compression_level": 0},
            "complex_resize": {
                "resize_operations": [
                    {"width": 10000, "height": 10000},
                    {"rotate": 45},
                    {"blur": 100},
                    {"sharpen": 100},
                ]
                * 100
            },
            "batch_bomb": {
                "files": ["image.jpg"] * 10000,
                "parallel": True,
                "max_workers": 1000,
            },
        }
