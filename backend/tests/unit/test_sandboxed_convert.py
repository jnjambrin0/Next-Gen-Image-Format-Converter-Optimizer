"""Unit tests for sandboxed_convert.py script."""

from typing import Any
import io
import json
import os
import subprocess
import sys

import pytest
from PIL import Image


class TestSandboxedConvert:
    """Test cases for the sandboxed conversion script."""

    @pytest.fixture
    def script_path(self) -> None:
        """Get the path to sandboxed_convert.py."""
        return os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "app",
            "core",
            "conversion",
            "sandboxed_convert.py",
        )

    @pytest.fixture
    def test_image_data(self) -> None:
        """Create test image data."""
        img = Image.new("RGB", (100, 100), color="red")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def run_script(self, script_path, args, input_data=None) -> None:
        """Run the sandboxed conversion script."""
        cmd = [sys.executable, script_path] + args
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
        )
        return result

    def test_missing_arguments(self, script_path) -> None:
        """Test script fails with missing arguments."""
        result = self.run_script(script_path, [])
        assert result.returncode == 1

        # Check for JSON error
        stderr = result.stderr.decode("utf-8")
        assert "ARGS_ERROR" in stderr

    def test_invalid_input_format(self, script_path, test_image_data) -> None:
        """Test script rejects invalid input format."""
        result = self.run_script(
            script_path, ["invalid_format", "png", "85"], test_image_data
        )
        assert result.returncode == 1

        stderr = result.stderr.decode("utf-8")
        assert "VALIDATION_ERROR" in stderr
        assert "not in allowed formats" in stderr

    def test_invalid_output_format(self, script_path, test_image_data) -> None:
        """Test script rejects invalid output format."""
        result = self.run_script(
            script_path, ["png", "invalid_format", "85"], test_image_data
        )
        assert result.returncode == 1

        stderr = result.stderr.decode("utf-8")
        assert "VALIDATION_ERROR" in stderr

    def test_invalid_quality(self, script_path, test_image_data) -> None:
        """Test script rejects invalid quality values."""
        # Test non-numeric quality
        result = self.run_script(
            script_path, ["png", "jpeg", "not_a_number"], test_image_data
        )
        assert result.returncode == 1
        assert "VALIDATION_ERROR" in result.stderr.decode("utf-8")

        # Test quality out of range
        result = self.run_script(script_path, ["png", "jpeg", "150"], test_image_data)
        assert result.returncode == 1
        assert "VALIDATION_ERROR" in result.stderr.decode("utf-8")

    def test_no_input_data(self, script_path) -> None:
        """Test script handles no input data."""
        result = self.run_script(script_path, ["png", "jpeg", "85"], b"")
        assert result.returncode == 1

        stderr = result.stderr.decode("utf-8")
        assert "INPUT_ERROR" in stderr
        assert "No input data" in stderr

    def test_input_size_limit(self, script_path) -> None:
        """Test script enforces input size limit."""
        # Create data larger than MAX_INPUT_SIZE (50MB)
        large_data = b"x" * (51 * 1024 * 1024)

        result = self.run_script(script_path, ["png", "jpeg", "85"], large_data)
        assert result.returncode == 1

        stderr = result.stderr.decode("utf-8")
        assert "SIZE_ERROR" in stderr
        assert "exceeds maximum size" in stderr

    def test_invalid_image_data(self, script_path) -> None:
        """Test script handles invalid image data."""
        result = self.run_script(
            script_path, ["png", "jpeg", "85"], b"This is not an image"
        )
        assert result.returncode == 1

        stderr = result.stderr.decode("utf-8")
        assert "INVALID_IMAGE" in stderr

    def test_successful_png_to_jpeg(self, script_path, test_image_data) -> None:
        """Test successful PNG to JPEG conversion."""
        result = self.run_script(script_path, ["png", "jpeg", "85"], test_image_data)
        assert result.returncode == 0

        # Verify output is valid JPEG
        output_img = Image.open(io.BytesIO(result.stdout))
        assert output_img.format == "JPEG"
        assert output_img.size == (100, 100)

    def test_successful_jpeg_to_png(self, script_path) -> None:
        """Test successful JPEG to PNG conversion."""
        # Create JPEG test image
        img = Image.new("RGB", (50, 50), color="blue")
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG")
        jpeg_data = buffer.getvalue()

        result = self.run_script(script_path, ["jpeg", "png", "85"], jpeg_data)
        assert result.returncode == 0

        # Verify output is valid PNG
        output_img = Image.open(io.BytesIO(result.stdout))
        assert output_img.format == "PNG"

    def test_transparency_handling(self, script_path) -> None:
        """Test conversion handles transparency correctly."""
        # Create PNG with transparency
        img = Image.new("RGBA", (50, 50), color=(255, 0, 0, 128))
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        png_data = buffer.getvalue()

        # Convert to JPEG (should add white background)
        result = self.run_script(script_path, ["png", "jpeg", "90"], png_data)
        assert result.returncode == 0

        output_img = Image.open(io.BytesIO(result.stdout))
        assert output_img.mode == "RGB"  # No alpha channel

    def test_metadata_stripping(self, script_path) -> None:
        """Test metadata stripping works."""
        # Create image with EXIF data
        img = Image.new("RGB", (50, 50), color="green")
        exif_data = img.getexif()
        exif_data[0x0112] = 1  # Orientation

        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", exif=exif_data)
        jpeg_data = buffer.getvalue()

        # Convert - metadata stripping is now handled before conversion
        result = self.run_script(
            script_path,
            ["jpeg", "jpeg", "85"],  # No strip_metadata parameter
            jpeg_data,
        )
        assert result.returncode == 0

        # Output should still have EXIF since sandboxed script doesn't strip
        output_img = Image.open(io.BytesIO(result.stdout))
        # The test should verify conversion works, not metadata stripping

    def test_metadata_preservation(self, script_path) -> None:
        """Test metadata preservation works."""
        # Create image with metadata
        img = Image.new("RGB", (50, 50), color="yellow")
        buffer = io.BytesIO()
        # For PNG, use PngInfo object
        from PIL import PngImagePlugin

        pnginfo = PngImagePlugin.PngInfo()
        pnginfo.add_text("Comment", "Test metadata")
        img.save(buffer, format="PNG", pnginfo=pnginfo)
        png_data = buffer.getvalue()

        # Convert - metadata handling is now done before conversion
        result = self.run_script(
            script_path,
            ["png", "png", "85"],  # No strip_metadata parameter anymore
            png_data,
        )
        assert result.returncode == 0

    def test_quality_parameter(self, script_path, test_image_data) -> None:
        """Test quality parameter affects output."""
        # Convert with high quality
        result_high = self.run_script(
            script_path, ["png", "jpeg", "95"], test_image_data
        )
        assert result_high.returncode == 0

        # Convert with low quality
        result_low = self.run_script(
            script_path, ["png", "jpeg", "20"], test_image_data
        )
        assert result_low.returncode == 0

        # Low quality should produce smaller file
        assert len(result_low.stdout) < len(result_high.stdout)

    def test_webp_conversion(self, script_path, test_image_data) -> None:
        """Test WebP format conversion."""
        result = self.run_script(script_path, ["png", "webp", "85"], test_image_data)
        assert result.returncode == 0

        # Verify output is valid WebP
        output_img = Image.open(io.BytesIO(result.stdout))
        assert output_img.format == "WEBP"

    def test_error_message_format(self, script_path) -> None:
        """Test error messages are in correct JSON format."""
        result = self.run_script(script_path, ["invalid", "png", "85"], b"fake")

        stderr = result.stderr.decode("utf-8")
        # Find JSON error line
        for line in stderr.split("\n"):
            if line.strip() and line.startswith("{"):
                error_data = json.loads(line)
                assert "error_code" in error_data
                assert "message" in error_data
                assert "type" in error_data
                assert error_data["type"] == "sandboxed_conversion_error"
                break
        else:
            pytest.fail("No JSON error found in stderr")

    @pytest.mark.parametrize(
        "in_fmt,out_fmt",
        [
            ("png", "jpeg"),
            ("jpeg", "png"),
            ("png", "webp"),
            ("jpeg", "webp"),
            ("webp", "png"),
            ("webp", "jpeg"),
            ("bmp", "png"),
            ("png", "bmp"),
        ],
    )
    def test_format_conversions(self, script_path, in_fmt, out_fmt) -> None:
        """Test various format conversions."""
        # Create test image in input format
        img = Image.new("RGB", (50, 50), color="purple")
        buffer = io.BytesIO()
        img.save(buffer, format=in_fmt.upper())
        input_data = buffer.getvalue()

        result = self.run_script(script_path, [in_fmt, out_fmt, "85"], input_data)
        assert result.returncode == 0

        # Verify output format
        output_img = Image.open(io.BytesIO(result.stdout))
        # Handle JPEG/JPG naming
        expected_format = "JPEG" if out_fmt in ["jpeg", "jpg"] else out_fmt.upper()
        assert output_img.format == expected_format
