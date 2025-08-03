#!/usr/bin/env python3
"""Test HEIC validation when misdetected as PNG."""

import asyncio
import sys
sys.path.insert(0, '.')

from app.services.conversion_service import ConversionService
from unittest.mock import patch


async def test_heic_png_misdetection():
    """Test HEIC file validation when MIME detection returns PNG."""
    print("Testing HEIC validation when misdetected as PNG...\n")
    
    service = ConversionService()
    
    # Proper HEIC file structure
    heic_data = b'\x00\x00\x00\x20' + b'ftyp' + b'heic' + b'\x00' * 100
    
    # Mock magic.from_buffer to return 'image/png' (simulating misdetection)
    with patch('app.services.conversion_service.magic') as mock_magic:
        mock_magic.from_buffer.return_value = 'image/png'
        
        result = await service.validate_image(heic_data, "heic")
        print(f"HEIC file misdetected as PNG: {'✓ PASS' if result else '✗ FAIL'}")
        
        # Verify our special case was triggered
        if result:
            print("✅ Special case handling for misdetected HEIC files is working!")
        else:
            print("❌ HEIC validation failed when misdetected as PNG")


if __name__ == "__main__":
    asyncio.run(test_heic_png_misdetection())