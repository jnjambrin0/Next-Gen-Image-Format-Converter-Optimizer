"""Helper functions for format conversion tests."""

from PIL import Image
import io
from typing import Optional, Tuple


def create_test_image_for_format(format: str, width: int = 100, height: int = 100) -> bytes:
    """
    Create a test image suitable for the given format.
    
    Handles format-specific requirements like:
    - RGB conversion for formats that don't support RGBA
    - Proper mode selection for each format
    """
    # Determine the appropriate mode for the format
    if format.lower() in ['jpeg', 'jpg', 'bmp']:
        mode = 'RGB'  # These formats don't support transparency
    elif format.lower() in ['gif']:
        mode = 'P'  # GIF uses palette mode
    else:
        mode = 'RGBA'  # PNG, WebP, AVIF support transparency
    
    # Create the image
    if mode == 'P':
        # For palette mode, create RGB first then convert
        img = Image.new('RGB', (width, height), color=(255, 0, 0))
        img = img.convert('P')
    else:
        img = Image.new(mode, (width, height), color=(255, 0, 0, 255) if mode == 'RGBA' else (255, 0, 0))
    
    # Save to bytes
    buffer = io.BytesIO()
    
    # Handle format-specific save parameters
    save_kwargs = {'format': format.upper()}
    if format.lower() in ['jpeg', 'jpg']:
        save_kwargs['quality'] = 95
    elif format.lower() == 'png':
        save_kwargs['compress_level'] = 6
    elif format.lower() == 'webp':
        save_kwargs['quality'] = 90
        save_kwargs['method'] = 6
    
    try:
        img.save(buffer, **save_kwargs)
    except Exception:
        # Fallback to basic save
        img.save(buffer, format=format.upper())
    
    return buffer.getvalue()


def prepare_image_for_conversion(image_data: bytes, target_format: str) -> bytes:
    """
    Prepare an image for conversion to target format.
    
    Handles special cases like:
    - HEIC to AVIF requiring RGB intermediate
    - GIF animations
    - Format-specific color mode requirements
    """
    try:
        img = Image.open(io.BytesIO(image_data))
        
        # Handle format-specific requirements
        if target_format.lower() in ['jpeg', 'jpg', 'bmp']:
            # Convert to RGB for formats that don't support transparency
            if img.mode in ('RGBA', 'LA', 'P'):
                # Handle transparency by compositing on white background
                if img.mode == 'RGBA' or 'transparency' in img.info:
                    background = Image.new('RGB', img.size, (255, 255, 255))
                    if img.mode == 'P':
                        img = img.convert('RGBA')
                    background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                    img = background
                else:
                    img = img.convert('RGB')
        
        elif target_format.lower() in ['avif', 'heif', 'heic']:
            # These formats work best with RGB
            if img.mode not in ('RGB', 'RGBA'):
                img = img.convert('RGB')
        
        # Save prepared image
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')  # Use PNG as intermediate format
        return buffer.getvalue()
        
    except Exception:
        # Return original if preparation fails
        return image_data


def validate_conversion_result(
    original_data: bytes, 
    converted_data: bytes,
    input_format: str,
    output_format: str
) -> Tuple[bool, Optional[str]]:
    """
    Validate that a conversion was successful.
    
    Returns:
        Tuple of (success, error_message)
    """
    if not converted_data:
        return False, "Conversion resulted in empty data"
    
    if len(converted_data) < 100:  # Suspicious if too small
        return False, f"Converted data suspiciously small: {len(converted_data)} bytes"
    
    try:
        # Try to open the converted image
        img = Image.open(io.BytesIO(converted_data))
        
        # Verify it can be loaded
        img.load()
        
        # Check dimensions are reasonable
        if img.width == 0 or img.height == 0:
            return False, "Converted image has zero dimensions"
        
        # Special validations for specific formats
        if output_format.lower() in ['jpeg', 'jpg'] and img.mode not in ['RGB', 'L']:
            return False, f"JPEG image has unexpected mode: {img.mode}"
        
        return True, None
        
    except Exception as e:
        return False, f"Failed to validate converted image: {str(e)}"


def get_format_capabilities(format: str) -> dict:
    """Get capabilities of a specific image format."""
    capabilities = {
        'jpeg': {
            'supports_transparency': False,
            'supports_animation': False,
            'max_colors': 16777216,
            'modes': ['RGB', 'L'],
            'lossy': True
        },
        'png': {
            'supports_transparency': True,
            'supports_animation': False,
            'max_colors': 16777216,
            'modes': ['RGB', 'RGBA', 'L', 'LA', 'P'],
            'lossy': False
        },
        'webp': {
            'supports_transparency': True,
            'supports_animation': True,
            'max_colors': 16777216,
            'modes': ['RGB', 'RGBA'],
            'lossy': True  # Can be lossless too
        },
        'gif': {
            'supports_transparency': True,
            'supports_animation': True,
            'max_colors': 256,
            'modes': ['P', 'L'],
            'lossy': False  # But limited colors
        },
        'avif': {
            'supports_transparency': True,
            'supports_animation': True,
            'max_colors': 16777216,
            'modes': ['RGB', 'RGBA'],
            'lossy': True
        },
        'heif': {
            'supports_transparency': True,
            'supports_animation': False,
            'max_colors': 16777216,
            'modes': ['RGB', 'RGBA'],
            'lossy': True
        },
        'bmp': {
            'supports_transparency': False,
            'supports_animation': False,
            'max_colors': 16777216,
            'modes': ['RGB', 'L', 'P'],
            'lossy': False
        },
        'tiff': {
            'supports_transparency': True,
            'supports_animation': False,
            'max_colors': 16777216,
            'modes': ['RGB', 'RGBA', 'L', 'LA'],
            'lossy': False
        }
    }
    
    format_lower = format.lower()
    if format_lower == 'jpg':
        format_lower = 'jpeg'
    elif format_lower == 'heic':
        format_lower = 'heif'
    
    return capabilities.get(format_lower, {
        'supports_transparency': False,
        'supports_animation': False,
        'max_colors': 16777216,
        'modes': ['RGB'],
        'lossy': False
    })