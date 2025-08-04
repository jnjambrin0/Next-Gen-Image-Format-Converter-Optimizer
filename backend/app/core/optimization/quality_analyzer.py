"""Quality analyzer with real SSIM/PSNR calculations without scikit-image."""

import asyncio
import io
import hashlib
from typing import Optional, Dict, Any, Tuple
from functools import lru_cache
import numpy as np
from PIL import Image

from app.core.constants import IMAGE_MAX_PIXELS
from app.core.security.errors_simplified import create_file_error
from app.core.security.memory import secure_clear
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Constants for SSIM calculation
SSIM_K1 = 0.01
SSIM_K2 = 0.03
SSIM_L = 255  # Dynamic range for 8-bit images
SSIM_C1 = (SSIM_K1 * SSIM_L) ** 2
SSIM_C2 = (SSIM_K2 * SSIM_L) ** 2
SSIM_WINDOW_SIZE = 11

# Constants for processing
MAX_PROCESS_SIZE = 2048  # Maximum dimension for quality analysis
CACHE_MAX_SIZE = 100


class QualityAnalyzer:
    """Analyzes image quality metrics including SSIM and PSNR."""
    
    def __init__(self, enable_caching: bool = True):
        """Initialize the quality analyzer.
        
        Args:
            enable_caching: Whether to enable result caching
        """
        self.enable_caching = enable_caching
        self._cache = {}  # Simple cache, cleared periodically
        self._cache_keys = []  # Track insertion order for LRU
        self._analysis_semaphore = asyncio.Semaphore(5)
        
    async def calculate_metrics(
        self,
        original_data: bytes,
        optimized_data: bytes,
        calculate_ssim: bool = True,
        calculate_psnr: bool = True,
    ) -> Dict[str, float]:
        """Calculate quality metrics between original and optimized images.
        
        Args:
            original_data: Original image data
            optimized_data: Optimized image data
            calculate_ssim: Whether to calculate SSIM
            calculate_psnr: Whether to calculate PSNR
            
        Returns:
            Dictionary with metrics (ssim_score, psnr_value)
        """
        # Input validation
        if not isinstance(original_data, bytes):
            raise create_file_error("invalid_input_type")
        if not isinstance(optimized_data, bytes):
            raise create_file_error("invalid_input_type")
        if len(original_data) == 0:
            raise create_file_error("empty_input")
        if len(optimized_data) == 0:
            raise create_file_error("empty_input")
        if len(original_data) > IMAGE_MAX_PIXELS * 4:
            raise create_file_error("input_too_large")
        if len(optimized_data) > IMAGE_MAX_PIXELS * 4:
            raise create_file_error("input_too_large")
            
        # Check cache
        cache_key = self._get_cache_key(original_data, optimized_data)
        if self.enable_caching and cache_key in self._cache:
            logger.debug("Quality metrics cache hit")
            return self._cache[cache_key].copy()
            
        # Use semaphore for concurrent control
        async with self._analysis_semaphore:
            try:
                # Load images
                original_img = Image.open(io.BytesIO(original_data))
                optimized_img = Image.open(io.BytesIO(optimized_data))
                
                # Convert to RGB if needed (SSIM/PSNR work on RGB)
                if original_img.mode != 'RGB':
                    original_img = original_img.convert('RGB')
                if optimized_img.mode != 'RGB':
                    optimized_img = optimized_img.convert('RGB')
                
                # Resize if dimensions don't match
                if original_img.size != optimized_img.size:
                    # Resize optimized to match original
                    optimized_img = optimized_img.resize(original_img.size, Image.Resampling.LANCZOS)
                
                # Downsample if too large
                width, height = original_img.size
                if width > MAX_PROCESS_SIZE or height > MAX_PROCESS_SIZE:
                    scale = min(MAX_PROCESS_SIZE / width, MAX_PROCESS_SIZE / height)
                    new_width = int(width * scale)
                    new_height = int(height * scale)
                    original_img = original_img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                    optimized_img = optimized_img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                    logger.debug(f"Downsampled images from {width}x{height} to {new_width}x{new_height}")
                
                # Convert to numpy arrays
                original_array = np.array(original_img, dtype=np.float64)
                optimized_array = np.array(optimized_img, dtype=np.float64)
                
                result = {}
                
                # Calculate SSIM
                if calculate_ssim:
                    ssim_score = await self._calculate_ssim(original_array, optimized_array)
                    result['ssim_score'] = float(ssim_score)
                
                # Calculate PSNR
                if calculate_psnr:
                    psnr_value = await self._calculate_psnr(original_array, optimized_array)
                    result['psnr_value'] = float(psnr_value)
                
                # Cache result
                if self.enable_caching:
                    self._add_to_cache(cache_key, result)
                
                # Clear arrays - numpy arrays need special handling
                if isinstance(original_array, np.ndarray):
                    original_array.fill(0)
                if isinstance(optimized_array, np.ndarray):
                    optimized_array.fill(0)
                
                return result
                
            except Exception as e:
                logger.error(f"Quality analysis failed: {str(e)}")
                raise create_file_error("quality_analysis_failed")
    
    async def _calculate_ssim(self, img1: np.ndarray, img2: np.ndarray) -> float:
        """Calculate Structural Similarity Index (SSIM).
        
        Args:
            img1: First image array
            img2: Second image array
            
        Returns:
            SSIM score between 0 and 1
        """
        # Calculate SSIM for each channel and average
        if len(img1.shape) == 3:
            ssims = []
            for i in range(img1.shape[2]):
                channel_ssim = self._ssim_channel(img1[:,:,i], img2[:,:,i])
                ssims.append(channel_ssim)
            return np.mean(ssims)
        else:
            return self._ssim_channel(img1, img2)
    
    def _ssim_channel(self, img1: np.ndarray, img2: np.ndarray) -> float:
        """Calculate SSIM for a single channel.
        
        Uses a simplified version of SSIM with uniform window.
        """
        # Create uniform window
        window = np.ones((SSIM_WINDOW_SIZE, SSIM_WINDOW_SIZE)) / (SSIM_WINDOW_SIZE ** 2)
        
        # Calculate local means
        mu1 = self._convolve2d(img1, window)
        mu2 = self._convolve2d(img2, window)
        
        # Calculate local variances and covariance
        mu1_sq = mu1 ** 2
        mu2_sq = mu2 ** 2
        mu1_mu2 = mu1 * mu2
        
        sigma1_sq = self._convolve2d(img1 ** 2, window) - mu1_sq
        sigma2_sq = self._convolve2d(img2 ** 2, window) - mu2_sq
        sigma12 = self._convolve2d(img1 * img2, window) - mu1_mu2
        
        # Calculate SSIM
        numerator = (2 * mu1_mu2 + SSIM_C1) * (2 * sigma12 + SSIM_C2)
        denominator = (mu1_sq + mu2_sq + SSIM_C1) * (sigma1_sq + sigma2_sq + SSIM_C2)
        
        ssim_map = numerator / denominator
        
        # Return mean SSIM
        return np.mean(ssim_map)
    
    def _convolve2d(self, img: np.ndarray, kernel: np.ndarray) -> np.ndarray:
        """Simple 2D convolution using uniform filter.
        
        This is a simplified version that uses scipy-like uniform filtering.
        """
        # Get dimensions
        img_height, img_width = img.shape
        kernel_height, kernel_width = kernel.shape
        
        # Pad image
        pad_h = kernel_height // 2
        pad_w = kernel_width // 2
        padded = np.pad(img, ((pad_h, pad_h), (pad_w, pad_w)), mode='edge')
        
        # Create output array
        output = np.zeros_like(img)
        
        # Perform convolution
        for i in range(img_height):
            for j in range(img_width):
                window = padded[i:i+kernel_height, j:j+kernel_width]
                output[i, j] = np.sum(window * kernel)
        
        return output
    
    async def _calculate_psnr(self, img1: np.ndarray, img2: np.ndarray) -> float:
        """Calculate Peak Signal-to-Noise Ratio (PSNR).
        
        Args:
            img1: First image array
            img2: Second image array
            
        Returns:
            PSNR value in dB
        """
        # Calculate MSE
        mse = np.mean((img1 - img2) ** 2)
        
        # Avoid log(0)
        if mse == 0:
            return 100.0  # Identical images
        
        # Calculate PSNR
        max_pixel = 255.0
        psnr = 20 * np.log10(max_pixel) - 10 * np.log10(mse)
        
        return float(psnr)
    
    async def calculate_file_size_reduction(
        self,
        original_size: int,
        optimized_size: int
    ) -> float:
        """Calculate file size reduction percentage.
        
        Args:
            original_size: Original file size in bytes
            optimized_size: Optimized file size in bytes
            
        Returns:
            Reduction percentage (0-100)
        """
        if original_size == 0:
            return 0.0
            
        reduction = ((original_size - optimized_size) / original_size) * 100
        return max(0.0, min(100.0, reduction))
    
    def get_visual_quality_rating(self, ssim_score: float) -> str:
        """Get visual quality rating based on SSIM score.
        
        Args:
            ssim_score: SSIM score (0-1)
            
        Returns:
            Quality rating: 'high', 'medium', or 'low'
        """
        if ssim_score >= 0.95:
            return "high"
        elif ssim_score >= 0.85:
            return "medium"
        else:
            return "low"
    
    def _get_cache_key(self, original_data: bytes, optimized_data: bytes) -> str:
        """Generate cache key from image data."""
        hasher = hashlib.sha256()
        hasher.update(original_data[:1024])  # Use first 1KB for performance
        hasher.update(b'|')
        hasher.update(optimized_data[:1024])
        return hasher.hexdigest()
    
    def _add_to_cache(self, key: str, value: Dict[str, float]) -> None:
        """Add result to cache with LRU eviction."""
        if key not in self._cache:
            self._cache_keys.append(key)
            
        self._cache[key] = value.copy()
        
        # Evict oldest if cache too large
        while len(self._cache_keys) > CACHE_MAX_SIZE:
            oldest_key = self._cache_keys.pop(0)
            if oldest_key in self._cache:
                del self._cache[oldest_key]
    
    async def clear_cache(self) -> None:
        """Clear the metrics cache."""
        self._cache.clear()
        self._cache_keys.clear()
        logger.debug("Quality metrics cache cleared")