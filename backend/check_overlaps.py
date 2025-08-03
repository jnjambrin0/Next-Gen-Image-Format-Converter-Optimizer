#!/usr/bin/env python3
"""Check overlap between detected face regions."""

faces = [
    {"x": 282, "y": 144, "w": 50, "h": 50},
    {"x": 302, "y": 112, "w": 50, "h": 50},
    {"x": 301, "y": 188, "w": 53, "h": 53}
]

def calculate_iou(box1, box2):
    """Calculate IoU between two boxes."""
    x1, y1, w1, h1 = box1["x"], box1["y"], box1["w"], box1["h"]
    x2, y2, w2, h2 = box2["x"], box2["y"], box2["w"], box2["h"]
    
    # Calculate intersection
    xi1 = max(x1, x2)
    yi1 = max(y1, y2)
    xi2 = min(x1 + w1, x2 + w2)
    yi2 = min(y1 + h1, y2 + h2)
    
    if xi2 <= xi1 or yi2 <= yi1:
        return 0.0
    
    intersection = (xi2 - xi1) * (yi2 - yi1)
    
    # Calculate union
    area1 = w1 * h1
    area2 = w2 * h2
    union = area1 + area2 - intersection
    
    return intersection / union if union > 0 else 0.0

# Check overlaps
for i in range(len(faces)):
    for j in range(i+1, len(faces)):
        iou = calculate_iou(faces[i], faces[j])
        print(f"Face {i} vs Face {j}: IoU = {iou:.3f}")
        
# Check distances between centers
for i in range(len(faces)):
    for j in range(i+1, len(faces)):
        c1x = faces[i]["x"] + faces[i]["w"] / 2
        c1y = faces[i]["y"] + faces[i]["h"] / 2
        c2x = faces[j]["x"] + faces[j]["w"] / 2
        c2y = faces[j]["y"] + faces[j]["h"] / 2
        
        dist = ((c2x - c1x)**2 + (c2y - c1y)**2)**0.5
        print(f"Face {i} vs Face {j}: Center distance = {dist:.1f}")