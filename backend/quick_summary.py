#!/usr/bin/env python3
"""Quick summary of detection performance on all images."""

from PIL import Image
import sys
from pathlib import Path
import time

sys.path.append(str(Path(__file__).parent))

from app.core.intelligence.face_detector import FaceDetector
from app.core.intelligence.text_detector import TextDetector

# Initialize detectors
face_detector = FaceDetector()
text_detector = TextDetector()

fixtures_path = Path("tests/fixtures/intelligence")

test_cases = [
    # Faces
    ("faces/portrait.jpg", "face", 1),
    ("faces/woman-face.png", "face", 1),
    ("faces/8-guys-playing-chess.JPG", "face", 8),
    ("faces/couple-eating.JPG", "face", 2),
    
    # Text
    ("text/document.JPG", "text", 10),
    ("text/text-code.JPG", "text", 20),
    ("text/mesages.JPG", "text", 5),
    
    # Mixed
    ("edge_cases/portrait-with-text.png", "both", None),
    ("edge_cases/group-mixed-text.JPG", "both", None),
    
    # Negative
    ("random/building.JPG", "none", 0),
    ("random/3-dogs.JPG", "face", 3),  # Might detect dog faces
]

print("Image Analysis Summary")
print("=" * 70)
print(f"{'Image':<35} {'Type':<8} {'Expected':<8} {'Faces':<8} {'Text':<8} {'Time':<8}")
print("-" * 70)

for img_path, expected_type, expected_count in test_cases:
    full_path = fixtures_path / img_path
    if not full_path.exists():
        print(f"{img_path:<35} NOT FOUND")
        continue
    
    try:
        img = Image.open(full_path)
        
        # Face detection
        start = time.time()
        faces = face_detector.detect(img)
        face_time = time.time() - start
        
        # Text detection (skip for very large images)
        if img.width * img.height < 5_000_000:  # Skip if > 5MP
            start = time.time()
            texts = text_detector.detect(img)
            text_time = time.time() - start
        else:
            texts = []
            text_time = 0
        
        total_time = face_time + text_time
        
        # Format output
        exp_str = str(expected_count) if expected_count is not None else "-"
        
        print(f"{img_path:<35} {expected_type:<8} {exp_str:<8} {len(faces):<8} {len(texts):<8} {total_time:<8.2f}s")
        
        # Check if results match expectations
        if expected_type == "face" and expected_count is not None:
            if abs(len(faces) - expected_count) > 2:
                print(f"  ⚠️  Expected ~{expected_count} faces, got {len(faces)}")
        
    except Exception as e:
        print(f"{img_path:<35} ERROR: {str(e)[:30]}")

print("-" * 70)
print("\nDetection thresholds: Face confidence >= 0.3, Text regions > 50 pixels")