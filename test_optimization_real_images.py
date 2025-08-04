#!/usr/bin/env python3
"""Test optimization with real images from backend/images_sample."""

import asyncio
import sys
import os
import io
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app.services.optimization_service import optimization_service
from app.services.conversion_service import conversion_service
from app.models.optimization import OptimizationRequest, OptimizationMode
from app.core.monitoring.stats import StatsCollector

async def test_with_real_images():
    """Test optimization functionality with real images."""
    print("Testing Optimization with Real Images")
    print("=" * 50)
    
    # Initialize services minimally
    # Don't set stats_collector - let it be None
    # Create a simple conversion function
    async def simple_convert(image_data, output_format, quality=85, **kwargs):
        # Simple conversion using PIL
        img = Image.open(io.BytesIO(image_data))
        output = io.BytesIO()
        
        # Apply kwargs if needed
        save_kwargs = {"format": output_format.upper(), "quality": quality}
        save_kwargs.update(kwargs)
        
        img.save(output, **save_kwargs)
        return output.getvalue()
    
    optimization_service.conversion_func = simple_convert
    
    # Find a real test image
    test_image_path = "backend/images_sample/jpg/routine.jpg"
    
    if not os.path.exists(test_image_path):
        print(f"❌ Test image not found: {test_image_path}")
        return False
    
    # Read test image
    with open(test_image_path, 'rb') as f:
        image_data = f.read()
    
    print(f"✓ Loaded test image: {test_image_path}")
    print(f"  Size: {len(image_data):,} bytes")
    
    # Test 1: Basic optimization without SSIM/PSNR
    print("\nTest 1: Basic optimization (no metrics)")
    
    request = OptimizationRequest(
        output_format="webp",
        optimization_mode=OptimizationMode.BALANCED,
        perceptual_metrics=False,  # Skip SSIM/PSNR
        base_quality=85
    )
    
    try:
        response = await optimization_service.optimize_image(
            image_data,
            request,
            "jpeg"
        )
        
        if response.success:
            print(f"  ✓ Optimization successful")
            print(f"    Original size: {response.original_size:,} bytes")
            print(f"    Optimized size: {response.optimized_size:,} bytes")
            print(f"    Reduction: {(1 - response.optimized_size/response.original_size)*100:.1f}%")
        else:
            print(f"  ❌ Optimization failed: {response.error_message}")
            
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    
    # Test 2: With perceptual metrics (will use scikit-image)
    print("\nTest 2: With perceptual metrics (SSIM/PSNR)")
    
    request_with_metrics = OptimizationRequest(
        output_format="jpeg",
        optimization_mode=OptimizationMode.BALANCED,
        perceptual_metrics=True,  # Calculate SSIM/PSNR
        base_quality=90
    )
    
    try:
        response = await optimization_service.optimize_image(
            image_data,
            request_with_metrics,
            "jpeg"
        )
        
        if response.success:
            print(f"  ✓ Optimization successful")
            print(f"    Size reduction: {(1 - response.optimized_size/response.original_size)*100:.1f}%")
            if response.quality_metrics:
                print(f"    SSIM: {response.quality_metrics.ssim_score:.4f}")
                print(f"    PSNR: {response.quality_metrics.psnr_value:.2f} dB")
                print(f"    Visual quality: {response.quality_metrics.visual_quality}")
        else:
            print(f"  ❌ Optimization failed: {response.error_message}")
            
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
    
    # Test 3: Multi-pass optimization
    print("\nTest 3: Multi-pass optimization")
    
    request_multipass = OptimizationRequest(
        output_format="webp",
        optimization_mode=OptimizationMode.SIZE,
        multi_pass=True,
        target_size_kb=50,  # Target 50KB
        perceptual_metrics=False,
        min_quality=40,
        max_quality=95
    )
    
    try:
        response = await optimization_service.optimize_image(
            image_data,
            request_multipass,
            "jpeg"
        )
        
        if response.success:
            print(f"  ✓ Multi-pass optimization successful")
            print(f"    Target size: 50 KB")
            print(f"    Achieved size: {response.optimized_size/1024:.1f} KB")
            print(f"    Total passes: {response.total_passes}")
            print(f"    Converged: {response.converged}")
            
            if response.passes:
                print("    Pass details:")
                for pass_info in response.passes[:3]:  # Show first 3 passes
                    print(f"      Pass {pass_info.pass_number}: quality={pass_info.quality}, size={pass_info.file_size/1024:.1f}KB")
        else:
            print(f"  ❌ Multi-pass optimization failed: {response.error_message}")
            
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
    
    # Test 4: Advanced parameters
    print("\nTest 4: Advanced parameters (progressive JPEG)")
    
    request_advanced = OptimizationRequest(
        output_format="jpeg",
        optimization_mode=OptimizationMode.BALANCED,
        perceptual_metrics=False,
        progressive=True,
        base_quality=85
    )
    
    try:
        response = await optimization_service.optimize_image(
            image_data,
            request_advanced,
            "jpeg"
        )
        
        if response.success:
            print(f"  ✓ Advanced optimization successful")
            print(f"    Output size: {response.optimized_size:,} bytes")
            print(f"    Applied options: {response.encoding_options_applied}")
        else:
            print(f"  ❌ Optimization failed: {response.error_message}")
            
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
    
    print("\n" + "=" * 50)
    print("Real image tests completed!")

if __name__ == "__main__":
    asyncio.run(test_with_real_images())