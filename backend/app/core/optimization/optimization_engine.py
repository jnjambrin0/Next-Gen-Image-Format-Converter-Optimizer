"""Multi-pass optimization engine for finding optimal quality/size ratio."""

import asyncio
import time
from typing import Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from enum import Enum

from app.core.constants import INTELLIGENCE_TIMEOUT_MS
from app.core.security.errors_simplified import create_file_error
from app.core.security.memory import secure_clear
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Constants
MAX_OPTIMIZATION_PASSES = 10
DEFAULT_MIN_QUALITY = 40
DEFAULT_MAX_QUALITY = 95
SIZE_TOLERANCE_PERCENT = 5
MAX_CONCURRENT_OPTIMIZATIONS = 5
OPTIMIZATION_TIMEOUT = 30  # seconds


class OptimizationMode(Enum):
    """Optimization mode strategies."""
    BALANCED = "balanced"
    SIZE = "size"
    QUALITY = "quality"
    PERCEPTUAL = "perceptual"


@dataclass
class OptimizationPass:
    """Represents a single optimization pass."""
    pass_number: int
    quality: int
    file_size: int
    ssim_score: Optional[float] = None
    psnr_value: Optional[float] = None
    processing_time: float = 0.0


@dataclass
class OptimizationResult:
    """Result of multi-pass optimization."""
    final_quality: int
    final_size: int
    total_passes: int
    passes: list[OptimizationPass]
    converged: bool
    total_time: float


class OptimizationEngine:
    """Multi-pass optimization engine using binary search."""
    
    def __init__(
        self,
        quality_analyzer: Optional[Any] = None,
        max_passes: int = MAX_OPTIMIZATION_PASSES,
        size_tolerance_percent: float = SIZE_TOLERANCE_PERCENT,
    ):
        """Initialize the optimization engine.
        
        Args:
            quality_analyzer: QualityAnalyzer instance for metrics
            max_passes: Maximum optimization passes
            size_tolerance_percent: Size tolerance percentage
        """
        self.quality_analyzer = quality_analyzer
        self.max_passes = max_passes
        self.size_tolerance_percent = size_tolerance_percent
        self._optimization_semaphore = asyncio.Semaphore(MAX_CONCURRENT_OPTIMIZATIONS)
        
    async def optimize(
        self,
        image_data: bytes,
        output_format: str,
        target_size_kb: Optional[int],
        mode: OptimizationMode,
        conversion_func: Callable,
        original_data: Optional[bytes] = None,
        min_quality: int = DEFAULT_MIN_QUALITY,
        max_quality: int = DEFAULT_MAX_QUALITY,
        **kwargs
    ) -> Tuple[bytes, OptimizationResult]:
        """Perform multi-pass optimization.
        
        Args:
            image_data: Input image data
            output_format: Target format
            target_size_kb: Target file size in KB (optional)
            mode: Optimization mode
            conversion_func: Async function to convert image
            original_data: Original image for quality comparison
            min_quality: Minimum quality bound
            max_quality: Maximum quality bound
            **kwargs: Additional conversion parameters
            
        Returns:
            Tuple of (optimized_data, optimization_result)
        """
        # Input validation
        if not isinstance(image_data, bytes):
            raise create_file_error("invalid_input_type")
        if len(image_data) == 0:
            raise create_file_error("empty_input")
            
        # Use semaphore for concurrency control
        async with self._optimization_semaphore:
            start_time = time.time()
            
            try:
                # Set timeout for optimization
                result = await asyncio.wait_for(
                    self._optimize_internal(
                        image_data, output_format, target_size_kb, mode,
                        conversion_func, original_data, min_quality, max_quality,
                        **kwargs
                    ),
                    timeout=OPTIMIZATION_TIMEOUT
                )
                return result
                
            except asyncio.TimeoutError:
                logger.error("Optimization timeout exceeded")
                raise create_file_error("optimization_timeout")
            except Exception as e:
                logger.error(f"Optimization failed: {str(e)}")
                raise create_file_error("optimization_failed")
    
    async def _optimize_internal(
        self,
        image_data: bytes,
        output_format: str,
        target_size_kb: Optional[int],
        mode: OptimizationMode,
        conversion_func: Callable,
        original_data: Optional[bytes],
        min_quality: int,
        max_quality: int,
        **kwargs
    ) -> Tuple[bytes, OptimizationResult]:
        """Internal optimization implementation."""
        passes = []
        converged = False
        
        # Binary search bounds
        low_quality = min_quality
        high_quality = max_quality
        best_data = None
        best_quality = None
        
        # Target size in bytes
        target_size = target_size_kb * 1024 if target_size_kb else None
        
        for pass_num in range(1, self.max_passes + 1):
            pass_start = time.time()
            
            # Calculate quality for this pass
            if mode == OptimizationMode.SIZE and target_size:
                # Binary search for target size
                current_quality = (low_quality + high_quality) // 2
            elif mode == OptimizationMode.QUALITY:
                # Start high and reduce if needed
                current_quality = max_quality - (pass_num - 1) * 5
            elif mode == OptimizationMode.PERCEPTUAL and self.quality_analyzer:
                # Adaptive based on perceptual metrics
                current_quality = await self._calculate_perceptual_quality(
                    passes, low_quality, high_quality
                )
            else:
                # Balanced mode - middle ground
                current_quality = (low_quality + high_quality) // 2
            
            # Ensure quality is within bounds
            current_quality = max(min_quality, min(max_quality, current_quality))
            
            # Convert with current quality
            optimized_data = await conversion_func(
                image_data,
                output_format,
                quality=current_quality,
                **kwargs
            )
            
            file_size = len(optimized_data)
            
            # Calculate metrics if analyzer available and original provided
            ssim_score = None
            psnr_value = None
            if self.quality_analyzer and original_data and mode == OptimizationMode.PERCEPTUAL:
                metrics = await self.quality_analyzer.calculate_metrics(
                    original_data or image_data,
                    optimized_data,
                    calculate_ssim=True,
                    calculate_psnr=True
                )
                ssim_score = metrics.get('ssim_score')
                psnr_value = metrics.get('psnr_value')
            
            # Record pass
            pass_time = time.time() - pass_start
            passes.append(OptimizationPass(
                pass_number=pass_num,
                quality=current_quality,
                file_size=file_size,
                ssim_score=ssim_score,
                psnr_value=psnr_value,
                processing_time=pass_time
            ))
            
            # Update best result
            if best_data is None or self._is_better_result(
                mode, file_size, target_size, ssim_score, best_quality, current_quality
            ):
                best_data = optimized_data
                best_quality = current_quality
            
            # Check convergence for binary search
            if target_size and mode == OptimizationMode.SIZE:
                size_diff_percent = abs(file_size - target_size) / target_size * 100
                
                if size_diff_percent <= self.size_tolerance_percent:
                    converged = True
                    break
                elif file_size > target_size:
                    # File too large, reduce quality
                    high_quality = current_quality - 1
                else:
                    # File too small, increase quality
                    low_quality = current_quality + 1
                
                # Check if search space exhausted
                if low_quality > high_quality:
                    converged = True
                    break
            
            # For other modes, check if quality metrics are good enough
            elif mode == OptimizationMode.PERCEPTUAL and ssim_score:
                if ssim_score >= 0.95:  # High quality achieved
                    converged = True
                    break
        
        # Create result
        total_time = sum(p.processing_time for p in passes)
        result = OptimizationResult(
            final_quality=best_quality,
            final_size=len(best_data),
            total_passes=len(passes),
            passes=passes,
            converged=converged,
            total_time=total_time
        )
        
        return best_data, result
    
    def _is_better_result(
        self,
        mode: OptimizationMode,
        file_size: int,
        target_size: Optional[int],
        ssim_score: Optional[float],
        best_quality: Optional[int],
        current_quality: int
    ) -> bool:
        """Determine if current result is better than best so far."""
        if best_quality is None:
            return True
            
        if mode == OptimizationMode.SIZE and target_size:
            # Closer to target size is better
            current_diff = abs(file_size - target_size)
            # We don't have best_size stored, so assume current is better
            # if quality is reasonable
            return current_quality >= DEFAULT_MIN_QUALITY
            
        elif mode == OptimizationMode.QUALITY:
            # Higher quality is better
            return current_quality > best_quality
            
        elif mode == OptimizationMode.PERCEPTUAL and ssim_score:
            # Higher SSIM is better
            return ssim_score > 0.9
            
        else:
            # Balanced - prefer middle quality
            return abs(current_quality - 70) < abs(best_quality - 70)
    
    async def _calculate_perceptual_quality(
        self,
        passes: list[OptimizationPass],
        low_quality: int,
        high_quality: int
    ) -> int:
        """Calculate quality based on perceptual metrics from previous passes."""
        if not passes:
            return (low_quality + high_quality) // 2
            
        # Find pass with best SSIM/size ratio
        best_ratio = 0
        best_quality = (low_quality + high_quality) // 2
        
        for pass_data in passes:
            if pass_data.ssim_score:
                # Favor high SSIM with reasonable size
                ratio = pass_data.ssim_score / (pass_data.file_size / 1024 / 1024)  # Per MB
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_quality = pass_data.quality
        
        # Adjust search bounds based on results
        if passes[-1].ssim_score and passes[-1].ssim_score < 0.85:
            # Quality too low, search higher
            return min(high_quality, passes[-1].quality + 10)
        elif passes[-1].ssim_score and passes[-1].ssim_score > 0.98:
            # Quality unnecessarily high, search lower
            return max(low_quality, passes[-1].quality - 10)
        else:
            # Continue binary search
            return (low_quality + high_quality) // 2