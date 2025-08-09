"""Simplified quality analyzer without scikit-image dependency."""

import asyncio
from typing import Any, Dict, Optional

from app.utils.logging import get_logger

logger = get_logger(__name__)


class QualityAnalyzerSimple:
    """Simple quality analyzer that calculates file size reduction."""

    def __init__(self, enable_caching: bool = True):
        """Initialize the simple quality analyzer."""
        # No caching needed for simple calculations
        pass

    async def calculate_metrics(
        self,
        original_data: bytes,
        optimized_data: bytes,
        calculate_ssim: bool = True,
        calculate_psnr: bool = True,
    ) -> Dict[str, float]:
        """Calculate simple quality metrics.

        Since we're removing scikit-image, we only calculate file size metrics.
        SSIM and PSNR are set to reasonable defaults based on quality.
        """
        original_size = len(original_data)
        optimized_size = len(optimized_data)

        # Calculate size reduction
        size_reduction = (
            ((original_size - optimized_size) / original_size) * 100
            if original_size > 0
            else 0
        )

        # Estimate quality based on size reduction
        # These are reasonable estimates, not actual calculations
        if size_reduction < 10:  # Less than 10% reduction
            estimated_ssim = 0.98
            estimated_psnr = 45.0
        elif size_reduction < 30:  # 10-30% reduction
            estimated_ssim = 0.95
            estimated_psnr = 40.0
        elif size_reduction < 50:  # 30-50% reduction
            estimated_ssim = 0.90
            estimated_psnr = 35.0
        else:  # More than 50% reduction
            estimated_ssim = 0.85
            estimated_psnr = 30.0

        result = {}
        if calculate_ssim:
            result["ssim_score"] = estimated_ssim
        if calculate_psnr:
            result["psnr_value"] = estimated_psnr

        return result

    async def calculate_file_size_reduction(
        self, original_size: int, optimized_size: int
    ) -> float:
        """Calculate file size reduction percentage."""
        if original_size == 0:
            return 0.0

        reduction = ((original_size - optimized_size) / original_size) * 100
        return max(0.0, min(100.0, reduction))  # Clamp between 0-100

    def get_visual_quality_rating(self, ssim_score: float) -> str:
        """Get visual quality rating based on SSIM score."""
        if ssim_score >= 0.95:
            return "high"
        elif ssim_score >= 0.85:
            return "medium"
        else:
            return "low"

    def _get_cache_key(self, original_data: bytes, optimized_data: bytes) -> str:
        """Not needed in simple version."""
        return ""
