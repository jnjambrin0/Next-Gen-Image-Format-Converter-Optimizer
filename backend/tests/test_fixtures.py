"""Test that all fixtures work correctly."""

import json
from pathlib import Path

import pytest
from PIL import Image


def test_test_images_dir_exists(test_images_dir):
    """Test that test images directory exists."""
    assert test_images_dir.exists()
    assert test_images_dir.is_dir()
    assert (test_images_dir / "sample_photo.jpg").exists()


def test_sample_image_path_exists(sample_image_path):
    """Test sample image path fixture."""
    assert sample_image_path.exists()
    assert sample_image_path.suffix == ".jpg"


def test_sample_image_bytes(sample_image_bytes):
    """Test sample image bytes fixture."""
    assert len(sample_image_bytes) > 0
    # Verify it's a valid image
    import io

    img = Image.open(io.BytesIO(sample_image_bytes))
    assert img.format == "JPEG"


def test_all_test_images(all_test_images):
    """Test all test images fixture."""
    assert len(all_test_images) > 0
    assert "sample_photo" in all_test_images

    for name, info in all_test_images.items():
        assert "path" in info
        assert "format" in info
        assert "dimensions" in info
        assert info["path"].exists(), f"{name} image not found at {info['path']}"


def test_temp_dir_fixture(temp_dir):
    """Test temporary directory fixture."""
    assert temp_dir.exists()
    assert temp_dir.is_dir()

    # Test we can write to it
    test_file = temp_dir / "test.txt"
    test_file.write_text("test")
    assert test_file.exists()


def test_mock_conversion_request(mock_conversion_request):
    """Test mock conversion request fixture."""
    assert "output_format" in mock_conversion_request
    assert "quality" in mock_conversion_request
    assert mock_conversion_request["quality"] == 85


def test_conversion_presets(conversion_presets):
    """Test conversion presets fixture."""
    assert len(conversion_presets) > 0
    assert "web_optimized" in conversion_presets

    web_preset = conversion_presets["web_optimized"]
    assert "quality" in web_preset
    assert "output_format" in web_preset


def test_image_generator(image_generator):
    """Test image generator fixture."""
    # Generate a test image
    img_data = image_generator(width=200, height=150, format="PNG")
    assert len(img_data) > 0

    # Verify it's valid
    import io

    img = Image.open(io.BytesIO(img_data))
    assert img.size == (200, 150)
    assert img.format == "PNG"


def test_expected_api_responses(expected_api_responses):
    """Test expected API responses fixture."""
    assert "conversion_success" in expected_api_responses
    assert "conversion_error" in expected_api_responses

    success = expected_api_responses["conversion_success"]
    assert success["status"] == "success"
    assert "download_url" in success


def test_json_data_files():
    """Test that JSON data files are valid."""
    data_dir = Path(__file__).parent / "fixtures" / "data"

    json_files = [
        "conversion_requests.json",
        "image_metadata.json",
        "presets.json",
        "error_responses.json",
    ]

    for json_file in json_files:
        file_path = data_dir / json_file
        assert file_path.exists(), f"{json_file} not found"

        # Verify it's valid JSON
        with open(file_path) as f:
            data = json.load(f)
            assert data is not None


def test_generated_images_are_valid(test_images_dir):
    """Test all generated test images are valid."""
    image_files = [
        "sample_photo.jpg",
        "portrait_photo.jpg",
        "screenshot.png",
        "document_scan.png",
        "illustration.png",
        "animated.gif",
        "large_photo.jpg",
        "tiny_icon.png",
        "corrupted.jpg",  # This one is intentionally corrupted
        "empty.png",  # This one is intentionally empty
    ]

    for img_file in image_files:
        img_path = test_images_dir / img_file
        assert img_path.exists(), f"{img_file} not found"

        # Skip validation for intentionally broken files
        if img_file in ["corrupted.jpg", "empty.png"]:
            continue

        # Verify it's a valid image
        img = Image.open(img_path)
        assert img.size[0] > 0 and img.size[1] > 0
