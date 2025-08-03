#!/usr/bin/env python3
"""Quick analysis of test images to understand their properties."""

from PIL import Image
import numpy as np
from pathlib import Path

def analyze_image(img_path):
    """Analyze image properties."""
    img = Image.open(img_path)
    print(f"\n{img_path.name}:")
    print(f"  Size: {img.size}")
    print(f"  Mode: {img.mode}")
    
    # Convert to array for analysis
    if img.mode != 'RGB':
        img_rgb = img.convert('RGB')
    else:
        img_rgb = img
    
    img_array = np.array(img_rgb)
    
    # Basic statistics
    print(f"  Shape: {img_array.shape}")
    print(f"  Mean color: {img_array.mean(axis=(0,1)).astype(int)}")
    print(f"  Std dev: {img_array.std():.1f}")
    
    # For grayscale analysis
    gray = img.convert('L')
    gray_array = np.array(gray)
    
    # Look for high contrast regions (text)
    gradient_y = np.abs(np.diff(gray_array, axis=0))
    gradient_x = np.abs(np.diff(gray_array, axis=1))
    
    print(f"  Max gradient Y: {gradient_y.max()}")
    print(f"  Max gradient X: {gradient_x.max()}")
    print(f"  Mean gradient: {(gradient_y.mean() + gradient_x.mean())/2:.1f}")
    
    # Projection profiles for text detection
    h_proj = np.mean(gray_array, axis=1)
    v_proj = np.mean(gray_array, axis=0)
    
    # Find variations in projection
    h_diff = np.abs(np.diff(h_proj))
    v_diff = np.abs(np.diff(v_proj))
    
    print(f"  H projection variations: {h_diff.max():.1f} (mean: {h_diff.mean():.1f})")
    print(f"  V projection variations: {v_diff.max():.1f} (mean: {v_diff.mean():.1f})")
    
    # Look for skin-like colors (for face detection)
    # Simple HSV-based skin detection
    from PIL import ImageOps
    # Check middle region for skin tones
    h, w = img_array.shape[:2]
    center_region = img_array[h//3:2*h//3, w//3:2*w//3]
    
    # Basic skin color check (R > G > B)
    skin_like = np.logical_and(
        center_region[:,:,0] > center_region[:,:,1],
        center_region[:,:,1] > center_region[:,:,2]
    )
    skin_ratio = np.sum(skin_like) / skin_like.size
    print(f"  Skin-like pixels in center: {skin_ratio*100:.1f}%")

# Analyze test images
fixtures_path = Path("tests/fixtures/intelligence")

print("=== Face Images ===")
for img_file in (fixtures_path / "faces").glob("*"):
    if img_file.suffix.lower() in ['.jpg', '.jpeg', '.png']:
        analyze_image(img_file)

print("\n=== Text Images ===")
for img_file in (fixtures_path / "text").glob("*"):
    if img_file.suffix.lower() in ['.jpg', '.jpeg', '.png']:
        analyze_image(img_file)

print("\n=== Edge Cases ===")
edge_path = fixtures_path / "edge_cases"
if edge_path.exists():
    for img_file in edge_path.glob("*"):
        if img_file.suffix.lower() in ['.jpg', '.jpeg', '.png']:
            analyze_image(img_file)