"""
Input Validation Utilities
Validation helpers for CLI inputs
"""

from pathlib import Path
from typing import List, Optional


# Supported image extensions
SUPPORTED_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.webp', '.avif', '.heif', '.heic',
    '.bmp', '.tiff', '.tif', '.gif', '.jxl', '.jp2', '.j2k'
}


def validate_input_file(path: Path) -> bool:
    """Validate that a file is a supported image"""
    if not path.exists():
        return False
    
    if not path.is_file():
        return False
    
    # Check extension
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        return False
    
    # Check file size (basic sanity check)
    if path.stat().st_size == 0:
        return False
    
    if path.stat().st_size > 100 * 1024 * 1024:  # 100MB limit
        return False
    
    return True


def validate_output_path(path: Path) -> bool:
    """Validate output path is writable"""
    # Check parent directory exists and is writable
    parent = path.parent
    if not parent.exists():
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            return False
    
    # Check if we can write to the directory
    if not parent.is_dir():
        return False
    
    # Check if file exists and is writable
    if path.exists() and not path.is_file():
        return False
    
    return True


def validate_format(format_str: str) -> bool:
    """Validate output format"""
    valid_formats = {
        'jpeg', 'jpg', 'png', 'webp', 'avif', 'heif', 'heic',
        'bmp', 'tiff', 'tif', 'gif', 'jxl', 'webp2'
    }
    return format_str.lower() in valid_formats


def validate_quality(quality: int) -> bool:
    """Validate quality value"""
    return 1 <= quality <= 100


def validate_dimensions(width: Optional[int], height: Optional[int]) -> bool:
    """Validate image dimensions"""
    if width is not None:
        if width <= 0 or width > 50000:
            return False
    
    if height is not None:
        if height <= 0 or height > 50000:
            return False
    
    return True


def find_images_in_directory(directory: Path, recursive: bool = False) -> List[Path]:
    """Find all supported images in a directory"""
    images = []
    
    if recursive:
        pattern = "**/*"
    else:
        pattern = "*"
    
    for file_path in directory.glob(pattern):
        if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
            images.append(file_path)
    
    return images


def estimate_output_size(input_size: int, format: str, quality: Optional[int] = None) -> int:
    """Estimate output file size based on format and quality"""
    # Rough estimates based on format
    compression_ratios = {
        'jpeg': 0.15 if quality and quality < 85 else 0.25,
        'jpg': 0.15 if quality and quality < 85 else 0.25,
        'png': 0.7,  # PNG is lossless but compressed
        'webp': 0.12 if quality and quality < 85 else 0.20,
        'avif': 0.08 if quality and quality < 85 else 0.15,
        'heif': 0.10 if quality and quality < 85 else 0.18,
        'heic': 0.10 if quality and quality < 85 else 0.18,
        'bmp': 1.0,  # Uncompressed
        'tiff': 0.8,
        'tif': 0.8,
        'gif': 0.4,
        'jxl': 0.07 if quality and quality < 85 else 0.12,
        'webp2': 0.06 if quality and quality < 85 else 0.10,
    }
    
    ratio = compression_ratios.get(format.lower(), 0.5)
    return int(input_size * ratio)