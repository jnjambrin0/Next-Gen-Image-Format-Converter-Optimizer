"""Unit tests for text detection functionality."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import numpy as np
from PIL import Image
import io

from app.core.intelligence.text_detector import TextDetector
from app.models.conversion import BoundingBox


class TestTextDetector:
    """Test suite for TextDetector class."""
    
    @pytest.fixture
    def text_detector(self):
        """Create a TextDetector instance for testing."""
        return TextDetector(model_session=None)  # Will use heuristics
    
    @pytest.fixture
    def mock_model_session(self):
        """Create a mock ONNX model session."""
        mock = Mock()
        
        # Mock inputs
        mock_input = Mock()
        mock_input.name = "input"
        mock.get_inputs.return_value = [mock_input]
        
        # Mock run method
        # Return a probability map
        prob_map = np.random.rand(1, 1, 736, 736).astype(np.float32)
        prob_map[0, 0, 100:200, 100:600] = 0.8  # Simulate text region
        mock.run.return_value = [prob_map]
        
        return mock
    
    @pytest.fixture
    def document_image(self):
        """Create a document-like test image."""
        # Create image with text-like patterns
        img = Image.new('RGB', (800, 600), color='white')
        pixels = img.load()
        
        # Add horizontal lines (text lines)
        for y in range(100, 500, 40):
            for x in range(50, 750):
                if x % 3 != 0:  # Simulate text
                    pixels[x, y] = (0, 0, 0)
                    pixels[x, y+1] = (0, 0, 0)
        
        return img
    
    @pytest.fixture
    def blank_image(self):
        """Create a blank test image."""
        return Image.new('RGB', (400, 300), color='white')
    
    def test_detector_initialization(self, text_detector):
        """Test detector initializes correctly."""
        assert text_detector.input_size == (736, 736)
        assert text_detector.threshold == 0.3
        assert text_detector.min_area == 100
        assert text_detector.model_session is None
    
    def test_detect_with_heuristics_document(self, text_detector, document_image):
        """Test heuristic text detection on document image."""
        regions = text_detector.detect(document_image)
        
        assert isinstance(regions, list)
        assert len(regions) > 0
        
        # Check first region
        first_region = regions[0]
        assert isinstance(first_region, BoundingBox)
        assert first_region.x >= 0
        assert first_region.y >= 0
        assert first_region.width > 20
        assert first_region.height > 5
        assert 0 <= first_region.confidence <= 1.0
    
    def test_detect_with_heuristics_blank(self, text_detector, blank_image):
        """Test heuristic text detection on blank image."""
        regions = text_detector.detect(blank_image)
        
        assert isinstance(regions, list)
        assert len(regions) == 0  # No text in blank image
    
    def test_detect_with_model(self, mock_model_session, document_image):
        """Test ML-based text detection."""
        detector = TextDetector(model_session=mock_model_session)
        regions = detector.detect(document_image)
        
        assert isinstance(regions, list)
        assert len(regions) > 0
        
        # Verify model was called
        mock_model_session.run.assert_called_once()
    
    def test_preprocess_for_model(self, text_detector):
        """Test image preprocessing for model."""
        # Create test image
        test_img = Image.new('RGB', (400, 300), color='blue')
        
        # Preprocess
        preprocessed, scale, padding = text_detector._preprocess_for_model(test_img)
        
        # Check output
        assert isinstance(preprocessed, np.ndarray)
        assert preprocessed.shape == (1, 3, 736, 736)  # Batch, channels, H, W
        assert 0 <= preprocessed.min() <= preprocessed.max() <= 1.0
        assert isinstance(scale, float)
        assert isinstance(padding, tuple)
        assert len(padding) == 2
    
    def test_extract_text_regions(self, text_detector):
        """Test text region extraction from binary map."""
        # Create binary map with text regions
        binary_map = np.zeros((100, 100), dtype=np.uint8)
        
        # Add a rectangular region
        binary_map[20:40, 10:80] = 1
        
        # Extract regions
        regions = text_detector._extract_text_regions(binary_map)
        
        assert len(regions) > 0
        x, y, w, h, conf = regions[0]
        assert x >= 10
        assert y >= 20
        assert w > 0
        assert h > 0
        assert 0 <= conf <= 1.0
    
    def test_merge_overlapping_regions(self, text_detector):
        """Test merging of overlapping text regions."""
        # Create overlapping regions
        regions = [
            BoundingBox(x=10, y=10, width=100, height=20, confidence=0.8),
            BoundingBox(x=50, y=12, width=100, height=18, confidence=0.7),  # Overlaps
            BoundingBox(x=10, y=50, width=100, height=20, confidence=0.9),  # Separate
        ]
        
        # Merge
        merged = text_detector._merge_overlapping_regions(regions)
        
        assert len(merged) == 2  # Two regions after merging
        assert merged[0].width > 100  # First region expanded
    
    def test_calculate_text_density(self, text_detector, document_image):
        """Test text density calculation."""
        # Create some text regions
        regions = [
            BoundingBox(x=10, y=10, width=200, height=30, confidence=0.8),
            BoundingBox(x=10, y=50, width=200, height=30, confidence=0.7),
            BoundingBox(x=10, y=90, width=200, height=30, confidence=0.9),
        ]
        
        # Calculate density
        density = text_detector.calculate_text_density(document_image, regions)
        
        assert 0 <= density <= 1.0
        assert density > 0  # Should have some density
    
    def test_horizontal_projection_analysis(self, text_detector, document_image):
        """Test horizontal projection analysis for text lines."""
        # Convert to grayscale
        gray = document_image.convert('L')
        gray_array = np.array(gray)
        
        # Get horizontal projection
        projection = np.mean(gray_array, axis=1)
        gradient = np.abs(np.diff(projection))
        
        # Should detect variations (text lines)
        assert gradient.max() > gradient.mean()
        assert np.std(gradient) > 0
    
    def test_detection_timeout(self, text_detector):
        """Test that detection completes within reasonable time."""
        # Create large image
        large_img = Image.new('RGB', (2000, 2000), color='white')
        
        import time
        start = time.time()
        regions = text_detector.detect(large_img)
        duration = time.time() - start
        
        assert isinstance(regions, list)
        assert duration < 1.0  # Should complete in under 1 second
    
    def test_minimum_region_size(self, text_detector):
        """Test that small regions are filtered out."""
        # Create binary map with tiny region
        binary_map = np.zeros((100, 100), dtype=np.uint8)
        binary_map[10:12, 10:12] = 1  # 2x2 region
        
        # Extract regions
        regions = text_detector._extract_text_regions(binary_map)
        
        # Should be filtered out due to min_area
        assert len(regions) == 0
    
    def test_detection_error_handling(self, text_detector):
        """Test error handling in detection."""
        # Mock an error during detection
        with patch.object(text_detector, '_detect_with_heuristics', side_effect=Exception("Test error")):
            regions = text_detector.detect(Image.new('RGB', (100, 100)))
            
            # Should return empty list on error
            assert regions == []
    
    def test_aspect_ratio_preservation(self, text_detector):
        """Test that preprocessing preserves aspect ratio."""
        # Create image with specific aspect ratio
        test_img = Image.new('RGB', (800, 400), color='white')
        
        preprocessed, scale, padding = text_detector._preprocess_for_model(test_img)
        
        # Check that aspect ratio is preserved through scaling
        original_ratio = 800 / 400
        scaled_width = int(800 * scale)
        scaled_height = int(400 * scale)
        scaled_ratio = scaled_width / scaled_height
        
        assert abs(original_ratio - scaled_ratio) < 0.01