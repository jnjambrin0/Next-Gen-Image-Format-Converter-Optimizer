#!/usr/bin/env python3
"""Test script to verify new format conversions work."""

from PIL import Image
import io
import sys
import os

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.conversion.formats.bmp_handler import BmpHandler
from app.core.conversion.formats.tiff_handler import TiffHandler  
from app.core.conversion.formats.gif_handler import GifHandler
from app.core.conversion.formats.heif_handler import HeifHandler
from app.models.conversion import ConversionSettings

print("Testing new format handlers...")

# Test BMP Handler
print("\n=== Testing BMP Handler ===")
try:
    bmp_handler = BmpHandler()
    
    # Create a test BMP image
    img = Image.new('RGB', (100, 100), color='blue')
    buffer = io.BytesIO()
    img.save(buffer, format='BMP')
    bmp_data = buffer.getvalue()
    
    # Test validation
    assert bmp_handler.validate_image(bmp_data), "BMP validation failed"
    print("✓ BMP validation passed")
    
    # Test loading
    loaded_img = bmp_handler.load_image(bmp_data)
    assert loaded_img.size == (100, 100), "BMP loading failed"
    print("✓ BMP loading passed")
    
    # Test saving
    output_buffer = io.BytesIO()
    settings = ConversionSettings()
    bmp_handler.save_image(loaded_img, output_buffer, settings)
    assert len(output_buffer.getvalue()) > 0, "BMP saving failed"
    print("✓ BMP saving passed")
    
except Exception as e:
    print(f"✗ BMP handler error: {e}")

# Test TIFF Handler
print("\n=== Testing TIFF Handler ===")
try:
    tiff_handler = TiffHandler()
    
    # Create a test TIFF image
    img = Image.new('RGB', (150, 150), color='green')
    buffer = io.BytesIO()
    img.save(buffer, format='TIFF')
    tiff_data = buffer.getvalue()
    
    # Test validation
    assert tiff_handler.validate_image(tiff_data), "TIFF validation failed"
    print("✓ TIFF validation passed")
    
    # Test loading
    loaded_img = tiff_handler.load_image(tiff_data)
    assert loaded_img.size == (150, 150), "TIFF loading failed"
    print("✓ TIFF loading passed")
    
    # Test saving
    output_buffer = io.BytesIO()
    settings = ConversionSettings(optimize=True)
    tiff_handler.save_image(loaded_img, output_buffer, settings)
    assert len(output_buffer.getvalue()) > 0, "TIFF saving failed"
    print("✓ TIFF saving passed")
    
except Exception as e:
    print(f"✗ TIFF handler error: {e}")

# Test GIF Handler
print("\n=== Testing GIF Handler ===")
try:
    gif_handler = GifHandler()
    
    # Create a test GIF image
    img = Image.new('P', (80, 80))
    img.putpalette([i//3 for i in range(768)])
    buffer = io.BytesIO()
    img.save(buffer, format='GIF')
    gif_data = buffer.getvalue()
    
    # Test validation
    assert gif_handler.validate_image(gif_data), "GIF validation failed"
    print("✓ GIF validation passed")
    
    # Test loading
    loaded_img = gif_handler.load_image(gif_data)
    assert loaded_img.size == (80, 80), "GIF loading failed"
    print("✓ GIF loading passed")
    
    # Test saving
    output_buffer = io.BytesIO()
    settings = ConversionSettings()
    gif_handler.save_image(loaded_img, output_buffer, settings)
    assert len(output_buffer.getvalue()) > 0, "GIF saving failed"
    print("✓ GIF saving passed")
    
except Exception as e:
    print(f"✗ GIF handler error: {e}")

# Test HEIF Handler
print("\n=== Testing HEIF Handler ===")
try:
    heif_handler = HeifHandler()
    print("✓ HEIF handler initialized (pillow-heif available)")
except Exception as e:
    print(f"✗ HEIF handler not available: {e}")

# Test format detection
print("\n=== Testing Format Detection ===")
from app.core.conversion.image_processor import ImageProcessor

processor = ImageProcessor()

# Test BMP detection
test_cases = [
    (b"BM" + b"\x00" * 100, "bmp", "BMP magic bytes"),
    (b"GIF89a" + b"\x00" * 100, "gif", "GIF magic bytes"),
    (b"II*\x00" + b"\x00" * 100, "tiff", "TIFF little-endian"),
    (b"MM\x00*" + b"\x00" * 100, "tiff", "TIFF big-endian"),
]

for data, expected_format, description in test_cases:
    try:
        detected = processor.detect_format(data)
        assert detected == expected_format, f"Expected {expected_format}, got {detected}"
        print(f"✓ {description} detected correctly as {expected_format}")
    except Exception as e:
        print(f"✗ {description} detection failed: {e}")

print("\n=== All tests completed ===")