#!/usr/bin/env python3
"""Test script to verify image conversion works."""

import requests
import base64
from PIL import Image
import io
import sys

# Test different format conversions
test_cases = [
    ('PNG', 'WEBP', 'png', 'webp'),
    ('JPEG', 'PNG', 'jpeg', 'png'),
    ('PNG', 'JPEG', 'png', 'jpeg'),
    ('WEBP', 'PNG', 'webp', 'png'),
    # New format tests
    ('BMP', 'PNG', 'bmp', 'png'),
    ('TIFF', 'JPEG', 'tiff', 'jpeg'),
    ('GIF', 'PNG', 'gif', 'png'),
    ('BMP', 'WEBP', 'bmp', 'webp'),
    ('TIFF', 'WEBP', 'tiff', 'webp'),
    ('GIF', 'WEBP', 'gif', 'webp'),
    ('WEBP', 'BMP', 'webp', 'bmp'),
    ('PNG', 'TIFF', 'png', 'tiff'),
    ('JPEG', 'GIF', 'jpeg', 'gif'),
]

if len(sys.argv) > 1:
    # Filter test cases if argument provided
    test_cases = [(a, b, c, d) for a, b, c, d in test_cases if sys.argv[1] in [c, d]]

for input_format, output_format, input_ext, output_ext in test_cases:
    print(f"\n=== Testing {input_format} to {output_format} ===")
    
    # Create a small test image
    img = Image.new('RGB', (100, 100), color='red')
    img_buffer = io.BytesIO()
    img.save(img_buffer, format=input_format)
    img_data = img_buffer.getvalue()

    # Prepare the request
    url = "http://localhost:8080/api/convert"
    files = {
        'file': (f'test.{input_ext}', img_data, f'image/{input_ext}')
    }
    data = {
        'output_format': output_ext,
        'quality': '85'
    }

    # Send the request
    response = requests.post(url, files=files, data=data)

    print(f"Status code: {response.status_code}")

    if response.status_code == 200:
        print("✓ Conversion successful!")
        print(f"  Output size: {len(response.content)} bytes")
        
        # Verify it's a valid image
        try:
            output_img = Image.open(io.BytesIO(response.content))
            print(f"  Output format verified: {output_img.format}")
            print(f"  Output dimensions: {output_img.size}")
        except Exception as e:
            print(f"✗ Error verifying output: {e}")
    else:
        print(f"✗ Conversion failed: {response.text}")