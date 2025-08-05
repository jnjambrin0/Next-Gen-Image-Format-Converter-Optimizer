"""Integration tests for preset system with conversion pipeline."""

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
import tempfile
import os

from app.main import app
from app.services.preset_service import preset_service
from app.services.conversion_service import conversion_service


@pytest.fixture
def client():
    """Create test client with proper lifespan handling."""
    with TestClient(app) as test_client:
        yield test_client


@pytest_asyncio.fixture
async def test_preset():
    """Create a test preset."""
    from app.models.schemas import PresetCreate, PresetSettings
    
    preset_data = PresetCreate(
        name="Test Conversion Preset",
        description="Preset for testing conversion",
        settings=PresetSettings(
            output_format="webp",
            quality=70,
            optimization_mode="file_size",
            preserve_metadata=False
        )
    )
    
    preset = await preset_service.create_preset(preset_data)
    yield preset
    
    # Cleanup
    await preset_service.delete_preset(preset.id)


def create_test_image():
    """Create a simple test PNG image."""
    # Create a 100x100 red square
    from PIL import Image
    import io
    
    img = Image.new('RGB', (100, 100), color='red')
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    return img_buffer.read()


class TestPresetConversion:
    """Test preset integration with conversion pipeline."""
    
    def test_convert_with_preset(self, client, test_preset):
        """Test image conversion using a preset."""
        # Create test image
        image_data = create_test_image()
        
        # Convert with preset
        response = client.post(
            "/api/convert",
            files={"file": ("test.png", image_data, "image/png")},
            data={
                "preset_id": test_preset.id,
                # These should be overridden by preset
                "output_format": "jpeg",
                "quality": 95
            }
        )
        
        assert response.status_code == 200
        
        # Check response headers
        assert response.headers["content-type"] == "image/webp"  # Preset format
        
        # Verify the result uses preset settings
        result_data = response.content
        assert len(result_data) > 0
        
        # The file should be smaller due to quality 70 vs 95
        assert len(result_data) < len(image_data)
    
    def test_convert_with_preset_override(self, client, test_preset):
        """Test conversion with preset but override some settings."""
        image_data = create_test_image()
        
        # Convert with preset but override quality
        response = client.post(
            "/api/convert",
            files={"file": ("test.png", image_data, "image/png")},
            data={
                "preset_id": test_preset.id,
                "output_format": "jpeg",  # This will be overridden by preset
                "quality": 50  # Override preset quality of 70
            }
        )
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/webp"  # Still uses preset format
        
        # File should be even smaller with quality 50
        result_data = response.content
        assert len(result_data) > 0
    
    def test_convert_with_invalid_preset(self, client):
        """Test conversion with non-existent preset ID."""
        image_data = create_test_image()
        
        # Try to convert with invalid preset
        response = client.post(
            "/api/convert",
            files={"file": ("test.png", image_data, "image/png")},
            data={
                "preset_id": "non-existent-preset-id",
                "output_format": "jpeg",
                "quality": 85
            }
        )
        
        # Should still work but use provided settings instead
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/jpeg"
    
    def test_batch_convert_with_preset(self, client, test_preset):
        """Test batch conversion using a preset."""
        # Create multiple test images
        images = []
        for i in range(3):
            img_data = create_test_image()
            images.append(("files", (f"test{i}.png", img_data, "image/png")))
        
        # Create batch job with preset
        response = client.post(
            "/api/batch",
            files=images,
            data={
                "preset_id": test_preset.id,
                "output_format": "jpeg"  # This will be overridden by preset
            }
        )
        
        assert response.status_code == 202
        job_data = response.json()
        assert "job_id" in job_data
        
        # Check job status
        job_id = job_data["job_id"]
        status_response = client.get(f"/api/batch/{job_id}/status")
        assert status_response.status_code == 200
        
        status_data = status_response.json()
        # BatchStatusResponse doesn't include settings, so we can't check them here
        # The preset is applied during conversion
    
    def test_builtin_preset_conversion(self, client):
        """Test conversion using a built-in preset."""
        image_data = create_test_image()
        
        # Get list of presets to find built-in Web Optimized
        presets_response = client.get("/api/presets")
        presets = presets_response.json()["presets"]
        web_preset = next(p for p in presets if p["name"] == "Web Optimized" and p["is_builtin"])
        
        # Convert with built-in preset
        response = client.post(
            "/api/convert",
            files={"file": ("test.png", image_data, "image/png")},
            data={
                "preset_id": web_preset["id"],
                "output_format": "jpeg"  # This will be overridden by preset
            }
        )
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/webp"
        
        # Web Optimized preset uses quality 85 and file_size optimization
        result_data = response.content
        assert len(result_data) > 0