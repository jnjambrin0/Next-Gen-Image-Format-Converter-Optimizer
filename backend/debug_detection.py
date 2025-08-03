#!/usr/bin/env python3
"""Debug face and text detection on test images."""

from PIL import Image, ImageDraw
import sys
from pathlib import Path

# Add backend to path
sys.path.append(str(Path(__file__).parent))

from app.core.intelligence.face_detector import FaceDetector
from app.core.intelligence.text_detector import TextDetector

def visualize_detections(image_path, output_path, detector_type="face"):
    """Visualize detections on image."""
    img = Image.open(image_path)
    
    if detector_type == "face":
        detector = FaceDetector()
        regions = detector.detect(img)
        color = "red"
    else:
        detector = TextDetector()
        regions = detector.detect(img)
        color = "blue"
    
    # Create drawing context
    draw = ImageDraw.Draw(img)
    
    print(f"\nDetected {len(regions)} {detector_type} regions in {image_path.name}:")
    for i, region in enumerate(regions):
        print(f"  Region {i}: x={region.x}, y={region.y}, w={region.width}, h={region.height}, conf={region.confidence:.3f}")
        
        # Draw rectangle
        x1, y1 = region.x, region.y
        x2, y2 = region.x + region.width, region.y + region.height
        draw.rectangle([x1, y1, x2, y2], outline=color, width=3)
        
        # Draw confidence
        draw.text((x1, y1-20), f"{region.confidence:.2f}", fill=color)
    
    # Save output
    img.save(output_path)
    print(f"Saved visualization to {output_path}")

# Test on various images
fixtures_path = Path("tests/fixtures/intelligence")

# Face detection
print("=== FACE DETECTION ===")
face_images = [
    fixtures_path / "faces" / "portrait.jpg",
    fixtures_path / "faces" / "woman-face.png",
]

for img_path in face_images:
    if img_path.exists():
        output_path = img_path.parent / f"debug_{img_path.stem}_faces.png"
        visualize_detections(img_path, output_path, "face")

# Text detection
print("\n=== TEXT DETECTION ===")
text_images = [
    fixtures_path / "text" / "document.JPG",
    fixtures_path / "text" / "text-code.JPG",
]

for img_path in text_images:
    if img_path.exists():
        # Create smaller preview for huge images
        img = Image.open(img_path)
        if img.width > 2000:
            scale = 1000 / img.width
            new_size = (int(img.width * scale), int(img.height * scale))
            img = img.resize(new_size, Image.Resampling.LANCZOS)
            preview_path = img_path.parent / f"preview_{img_path.stem}.jpg"
            img.save(preview_path)
            output_path = img_path.parent / f"debug_{img_path.stem}_text.png"
            visualize_detections(preview_path, output_path, "text")
        else:
            output_path = img_path.parent / f"debug_{img_path.stem}_text.png"
            visualize_detections(img_path, output_path, "text")