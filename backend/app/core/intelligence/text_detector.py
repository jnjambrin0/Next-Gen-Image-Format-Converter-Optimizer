"""Text detection module for document and screenshot analysis."""

import numpy as np
from PIL import Image
from typing import List, Optional, Tuple, Dict, Any
import logging
import time

from app.models.conversion import BoundingBox

logger = logging.getLogger(__name__)


class TextDetector:
    """Text detection using lightweight DBNet-style approach."""
    
    def __init__(self, model_session: Optional[Any] = None) -> None:
        """Initialize text detector.
        
        Args:
            model_session: ONNX Runtime session for text detection model
        """
        self.model_session = model_session
        self.input_size = (736, 736)  # Must be multiple of 32
        self.threshold = 0.3  # Binary map threshold
        self.min_area = 100  # Minimum text region area
        
    def detect(self, image: Image.Image) -> List[BoundingBox]:
        """Detect text regions in image.
        
        Args:
            image: PIL Image to process
            
        Returns:
            List of BoundingBox objects for text regions
        """
        start_time = time.time()
        
        try:
            if self.model_session:
                # ML-based detection
                return self._detect_with_model(image)
            else:
                # Fallback heuristic detection
                return self._detect_with_heuristics(image)
                
        except Exception as e:
            logger.warning(f"Text detection failed: {e}")
            return []
        finally:
            # Log processing time
            processing_time = (time.time() - start_time) * 1000
            logger.debug(f"Text detection took {processing_time:.1f}ms")
    
    def _detect_with_model(self, image: Image.Image) -> List[BoundingBox]:
        """Detect text using ML model (DBNet-style)."""
        # Preprocess image
        preprocessed, scale_factor, padding = self._preprocess_for_model(image)
        
        # Run inference
        outputs = self.model_session.run(
            None,
            {self.model_session.get_inputs()[0].name: preprocessed}
        )
        
        # Get probability map
        prob_map = outputs[0][0, 0]  # Shape: [H, W]
        
        # Threshold to binary map
        binary_map = (prob_map > self.threshold).astype(np.uint8)
        
        # Find text regions
        regions = self._extract_text_regions(binary_map)
        
        # Convert to original coordinates
        bounding_boxes = []
        for region in regions:
            x, y, w, h, confidence = region
            
            # Adjust for padding and scaling
            x = int((x - padding[0]) / scale_factor)
            y = int((y - padding[1]) / scale_factor)
            w = int(w / scale_factor)
            h = int(h / scale_factor)
            
            # Ensure within bounds
            x = max(0, x)
            y = max(0, y)
            w = min(w, image.width - x)
            h = min(h, image.height - y)
            
            if w > 10 and h > 10:  # Minimum size
                bounding_boxes.append(BoundingBox(
                    x=x,
                    y=y,
                    width=w,
                    height=h,
                    confidence=confidence
                ))
        
        return bounding_boxes[:50]  # Limit to 50 text regions
    
    def _detect_with_heuristics(self, image: Image.Image) -> List[BoundingBox]:
        """Fallback text detection using morphological operations."""
        # Resize for faster processing if image is too large
        max_dim = 1200
        if image.width > max_dim or image.height > max_dim:
            scale = max_dim / max(image.width, image.height)
            new_size = (int(image.width * scale), int(image.height * scale))
            processed_image = image.resize(new_size, Image.Resampling.LANCZOS)
            scale_factor = 1 / scale
        else:
            processed_image = image
            scale_factor = 1.0
        
        # Convert to grayscale
        if processed_image.mode != 'L':
            gray = processed_image.convert('L')
        else:
            gray = processed_image
        
        gray_array = np.array(gray)
        h, w = gray_array.shape
        
        # Multi-scale text detection - reduce scales for performance
        all_regions = []
        scales = [1.0] if h < 1000 else [0.7]  # Single scale for performance
        
        for scale in scales:
            if scale != 1.0:
                scaled_h, scaled_w = int(h * scale), int(w * scale)
                scaled_gray = np.array(Image.fromarray(gray_array).resize((scaled_w, scaled_h), Image.Resampling.LANCZOS))
            else:
                scaled_gray = gray_array
                scaled_h, scaled_w = h, w
            
            # Apply Otsu's thresholding
            threshold = self._otsu_threshold(scaled_gray)
            binary = (scaled_gray < threshold).astype(np.uint8) * 255
            
            # Morphological operations to connect text components
            # Stronger horizontal kernel for text lines
            kernel_h = np.ones((1, max(30, scaled_w // 30)), dtype=np.uint8)
            # Vertical kernel for connecting broken characters
            kernel_v = np.ones((max(5, scaled_h // 150), 1), dtype=np.uint8)
            
            # Apply morphological closing
            closed = self._morphological_close(binary, kernel_h)
            closed = self._morphological_close(closed, kernel_v)
            
            # Find connected components
            regions = self._find_text_components(closed, scale / scale_factor)
            all_regions.extend(regions)
        
        # Merge overlapping regions from different scales
        merged_regions = self._merge_overlapping_regions(all_regions)
        
        return merged_regions[:30]  # Limit regions
        
    def _otsu_threshold(self, gray_array: np.ndarray) -> int:
        """Calculate Otsu's threshold for binarization."""
        # Calculate histogram
        hist, _ = np.histogram(gray_array.flatten(), bins=256, range=[0, 256])
        hist = hist.astype(float)
        
        # Total number of pixels
        total = gray_array.size
        current_max, threshold = 0, 0
        sum_total = 0
        
        for i in range(256):
            sum_total += i * hist[i]
        
        sum_bg, weight_bg = 0, 0
        
        for i in range(256):
            weight_bg += hist[i]
            if weight_bg == 0:
                continue
            
            weight_fg = total - weight_bg
            if weight_fg == 0:
                break
            
            sum_bg += i * hist[i]
            mean_bg = sum_bg / weight_bg
            mean_fg = (sum_total - sum_bg) / weight_fg
            
            # Calculate between-class variance
            var_between = weight_bg * weight_fg * (mean_bg - mean_fg) ** 2
            
            if var_between > current_max:
                current_max = var_between
                threshold = i
        
        return int(threshold)
    
    def _morphological_close(self, binary: np.ndarray, kernel: np.ndarray) -> np.ndarray:
        """Apply morphological closing (dilation followed by erosion)."""
        # Simple dilation
        dilated = self._dilate(binary, kernel)
        # Simple erosion
        closed = self._erode(dilated, kernel)
        return closed
    
    def _dilate(self, binary: np.ndarray, kernel: np.ndarray) -> np.ndarray:
        """Simple binary dilation."""
        h, w = binary.shape
        kh, kw = kernel.shape
        
        # Pad the binary image
        pad_h, pad_w = kh // 2, kw // 2
        padded = np.pad(binary, ((pad_h, pad_h), (pad_w, pad_w)), mode='constant', constant_values=0)
        
        result = np.zeros_like(binary)
        
        # Apply dilation using vectorized operations for speed
        if kh == 1:  # Horizontal kernel - optimize
            for x in range(w):
                col_window = padded[:, x:x+kw]
                result[:, x] = np.where(np.any(col_window > 0, axis=1), 255, 0)
        elif kw == 1:  # Vertical kernel - optimize
            for y in range(h):
                row_window = padded[y:y+kh, :]
                result[y, :] = np.where(np.any(row_window > 0, axis=0), 255, 0)
        else:  # General case
            for y in range(h):
                for x in range(w):
                    window = padded[y:y+kh, x:x+kw]
                    if np.any(window[kernel > 0] > 0):
                        result[y, x] = 255
        
        return result
    
    def _erode(self, binary: np.ndarray, kernel: np.ndarray) -> np.ndarray:
        """Simple binary erosion."""
        h, w = binary.shape
        kh, kw = kernel.shape
        
        # Pad the binary image
        pad_h, pad_w = kh // 2, kw // 2
        padded = np.pad(binary, ((pad_h, pad_h), (pad_w, pad_w)), mode='constant', constant_values=0)
        
        result = np.zeros_like(binary)
        
        # Apply erosion
        for y in range(h):
            for x in range(w):
                # Extract window from padded image
                window = padded[y:y+kh, x:x+kw]
                # All pixels under the kernel must be on for output to be on
                if np.all(window[kernel > 0] > 0):
                    result[y, x] = 255
        
        return result
    
    def _find_text_components(self, binary: np.ndarray, scale_back: float) -> List[BoundingBox]:
        """Find connected components that could be text."""
        h, w = binary.shape
        visited = np.zeros_like(binary, dtype=bool)
        components = []
        
        for y in range(h):
            for x in range(w):
                if binary[y, x] > 0 and not visited[y, x]:
                    # BFS to find connected component
                    component = self._bfs_component(binary, visited, y, x)
                    
                    if len(component) > 50:  # Minimum size
                        # Calculate bounding box
                        ys = [p[0] for p in component]
                        xs = [p[1] for p in component]
                        
                        min_y, max_y = min(ys), max(ys)
                        min_x, max_x = min(xs), max(xs)
                        
                        width = max_x - min_x
                        height = max_y - min_y
                        
                        # Filter by aspect ratio and size
                        aspect_ratio = width / height if height > 0 else 0
                        
                        if 0.5 < aspect_ratio < 50 and width > 20 and height > 5:
                            # Calculate density as confidence
                            area = width * height
                            density = len(component) / area if area > 0 else 0
                            
                            components.append(BoundingBox(
                                x=int(min_x * scale_back),
                                y=int(min_y * scale_back),
                                width=int(width * scale_back),
                                height=int(height * scale_back),
                                confidence=min(0.9, density)
                            ))
        
        return components
    
    def _bfs_component(self, binary: np.ndarray, visited: np.ndarray, 
                      start_y: int, start_x: int) -> List[Tuple[int, int]]:
        """BFS to find connected component."""
        h, w = binary.shape
        queue = [(start_y, start_x)]
        visited[start_y, start_x] = True
        component = []
        
        while queue:
            y, x = queue.pop(0)
            component.append((y, x))
            
            # Check 8-connected neighbors
            for dy in [-1, 0, 1]:
                for dx in [-1, 0, 1]:
                    if dy == 0 and dx == 0:
                        continue
                    
                    ny, nx = y + dy, x + dx
                    
                    if (0 <= ny < h and 0 <= nx < w and 
                        binary[ny, nx] > 0 and not visited[ny, nx]):
                        visited[ny, nx] = True
                        queue.append((ny, nx))
        
        return component
    
    def _preprocess_for_model(self, image: Image.Image) -> Tuple[np.ndarray, float, Tuple[int, int]]:
        """Preprocess image for DBNet model.
        
        Returns:
            Tuple of (preprocessed_array, scale_factor, (pad_x, pad_y))
        """
        # Convert to RGB
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Calculate scale to fit in target size
        w, h = image.size
        target_w, target_h = self.input_size
        
        scale = min(target_w / w, target_h / h)
        new_w = int(w * scale)
        new_h = int(h * scale)
        
        # Ensure dimensions are multiples of 32
        new_w = (new_w // 32) * 32
        new_h = (new_h // 32) * 32
        
        # Resize image
        resized = image.resize((new_w, new_h), Image.Resampling.LANCZOS)
        
        # Create padded image
        padded = Image.new('RGB', self.input_size, (0, 0, 0))
        pad_x = (target_w - new_w) // 2
        pad_y = (target_h - new_h) // 2
        padded.paste(resized, (pad_x, pad_y))
        
        # Convert to array and normalize
        img_array = np.array(padded).astype(np.float32)
        img_array = img_array / 255.0
        
        # Transpose to CHW format
        img_array = np.transpose(img_array, (2, 0, 1))
        
        # Add batch dimension
        img_array = np.expand_dims(img_array, axis=0)
        
        return img_array, scale, (pad_x, pad_y)
    
    def _extract_text_regions(self, binary_map: np.ndarray) -> List[Tuple[int, int, int, int, float]]:
        """Extract text regions from binary map.
        
        Returns:
            List of (x, y, width, height, confidence) tuples
        """
        # Simple connected component analysis
        regions = []
        visited = np.zeros_like(binary_map, dtype=bool)
        
        def flood_fill(start_y: int, start_x: int) -> List[Tuple[int, int]]:
            """Simple flood fill to find connected region."""
            stack = [(start_y, start_x)]
            points = []
            
            while stack:
                y, x = stack.pop()
                
                if y < 0 or y >= binary_map.shape[0] or x < 0 or x >= binary_map.shape[1]:
                    continue
                    
                if visited[y, x] or binary_map[y, x] == 0:
                    continue
                
                visited[y, x] = True
                points.append((y, x))
                
                # Add neighbors
                for dy, dx in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
                    stack.append((y + dy, x + dx))
            
            return points
        
        # Find all connected components
        for y in range(binary_map.shape[0]):
            for x in range(binary_map.shape[1]):
                if binary_map[y, x] == 1 and not visited[y, x]:
                    points = flood_fill(y, x)
                    
                    if len(points) > self.min_area:
                        # Calculate bounding box
                        ys = [p[0] for p in points]
                        xs = [p[1] for p in points]
                        
                        min_y, max_y = min(ys), max(ys)
                        min_x, max_x = min(xs), max(xs)
                        
                        # Calculate confidence based on density
                        area = (max_y - min_y) * (max_x - min_x)
                        density = len(points) / area if area > 0 else 0
                        confidence = min(1.0, density)
                        
                        regions.append((
                            min_x,
                            min_y,
                            max_x - min_x,
                            max_y - min_y,
                            confidence
                        ))
        
        return regions
    
    def _merge_overlapping_regions(self, regions: List[BoundingBox]) -> List[BoundingBox]:
        """Merge overlapping text regions."""
        if not regions:
            return []
        
        # Sort by y-coordinate
        sorted_regions = sorted(regions, key=lambda r: r.y)
        merged = []
        
        current = sorted_regions[0]
        
        for region in sorted_regions[1:]:
            # Check if regions overlap or are very close
            vertical_overlap = (
                current.y <= region.y <= current.y + current.height or
                region.y <= current.y <= region.y + region.height
            )
            
            horizontal_overlap = (
                current.x <= region.x <= current.x + current.width or
                region.x <= current.x <= region.x + region.width
            )
            
            # Also merge if regions are on same line and close
            same_line = abs(current.y - region.y) < 10
            close_horizontally = abs(current.x + current.width - region.x) < 50
            
            if (vertical_overlap and horizontal_overlap) or (same_line and close_horizontally):
                # Merge regions
                min_x = min(current.x, region.x)
                min_y = min(current.y, region.y)
                max_x = max(current.x + current.width, region.x + region.width)
                max_y = max(current.y + current.height, region.y + region.height)
                
                current = BoundingBox(
                    x=min_x,
                    y=min_y,
                    width=max_x - min_x,
                    height=max_y - min_y,
                    confidence=max(current.confidence, region.confidence)
                )
            else:
                merged.append(current)
                current = region
        
        merged.append(current)
        return merged
    
    def calculate_text_density(self, image: Image.Image, regions: List[BoundingBox]) -> float:
        """Calculate text density score for the image.
        
        Args:
            image: Original image
            regions: Detected text regions
            
        Returns:
            Text density score (0.0 to 1.0)
        """
        if not regions:
            return 0.0
        
        # Calculate total area covered by text
        text_area = sum(region.width * region.height for region in regions)
        image_area = image.width * image.height
        
        # Normalize by image area
        density = text_area / image_area if image_area > 0 else 0.0
        
        # Apply sigmoid to get nice 0-1 range
        # density of 0.3 (30% coverage) maps to ~0.7
        return 1.0 / (1.0 + np.exp(-10 * (density - 0.3)))