#!/usr/bin/env python3
"""Comprehensive debug visualization for all test images."""

from PIL import Image, ImageDraw, ImageFont
import sys
from pathlib import Path
import time

# Add backend to path
sys.path.append(str(Path(__file__).parent))

from app.core.intelligence.face_detector import FaceDetector
from app.core.intelligence.text_detector import TextDetector

def visualize_detections(image_path, output_dir, detectors):
    """Visualize all detections on image."""
    img = Image.open(image_path)
    draw = ImageDraw.Draw(img)
    
    results = {}
    
    # Face detection
    if 'face' in detectors:
        start = time.time()
        faces = detectors['face'].detect(img)
        face_time = time.time() - start
        results['faces'] = {'count': len(faces), 'time': face_time}
        
        # Draw face boxes in red
        for i, face in enumerate(faces):
            x1, y1 = face.x, face.y
            x2, y2 = face.x + face.width, face.y + face.height
            draw.rectangle([x1, y1, x2, y2], outline='red', width=3)
            draw.text((x1, y1-20), f"F{i}: {face.confidence:.2f}", fill='red')
    
    # Text detection
    if 'text' in detectors:
        start = time.time()
        texts = detectors['text'].detect(img)
        text_time = time.time() - start
        results['texts'] = {'count': len(texts), 'time': text_time}
        
        # Draw text boxes in blue
        for i, text in enumerate(texts[:20]):  # Limit to 20 for clarity
            x1, y1 = text.x, text.y
            x2, y2 = text.x + text.width, text.y + text.height
            draw.rectangle([x1, y1, x2, y2], outline='blue', width=2)
    
    # Save output
    output_path = output_dir / f"{image_path.stem}_debug.jpg"
    # Resize if too large
    if img.width > 1500:
        scale = 1500 / img.width
        new_size = (int(img.width * scale), int(img.height * scale))
        img = img.resize(new_size, Image.Resampling.LANCZOS)
    
    img.save(output_path, quality=85)
    
    return results, output_path

# Initialize detectors
face_detector = FaceDetector()
text_detector = TextDetector()
detectors = {'face': face_detector, 'text': text_detector}

# Process all test images
fixtures_path = Path("tests/fixtures/intelligence")
output_dir = Path("debug_output")
output_dir.mkdir(exist_ok=True)

categories = {
    'faces': {
        'images': ['portrait.jpg', 'woman-face.png', '8-guys-playing-chess.JPG', 
                   'couple-eating.JPG', 'poeple-eating.JPG'],
        'detectors': ['face']
    },
    'text': {
        'images': ['document.JPG', 'text-code.JPG', 'mesages.JPG', 'train-ticket.PNG'],
        'detectors': ['text']
    },
    'edge_cases': {
        'images': ['portrait-with-text.png', 'text-with-woman-small-photo.PNG', 
                   'group-mixed-text.JPG'],
        'detectors': ['face', 'text']
    },
    'random': {
        'images': ['3-dogs.JPG', 'building.JPG', 'mini-burgers.JPG', 'plant-with-dog-and-light.JPG'],
        'detectors': ['face', 'text']
    }
}

print("=== COMPREHENSIVE DETECTION ANALYSIS ===\n")

for category, config in categories.items():
    print(f"\n{category.upper()}:")
    print("-" * 50)
    
    category_path = fixtures_path / category
    
    for img_name in config['images']:
        img_path = category_path / img_name
        if not img_path.exists():
            print(f"  {img_name}: NOT FOUND")
            continue
        
        # Get detectors for this category
        active_detectors = {k: detectors[k] for k in config['detectors']}
        
        try:
            results, output_path = visualize_detections(img_path, output_dir, active_detectors)
            
            print(f"\n  {img_name}:")
            for detector_type, result in results.items():
                print(f"    {detector_type}: {result['count']} detected in {result['time']:.2f}s")
            print(f"    Output: {output_path}")
            
        except Exception as e:
            print(f"  {img_name}: ERROR - {e}")

print(f"\n\nAll visualizations saved to: {output_dir.absolute()}")