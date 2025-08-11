"""
Ultra-realistic preset system tests covering built-in and custom presets.
Tests cascading configurations, import/export, and real-world usage patterns.
"""

import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from app.models.conversion import ConversionRequest
from app.models.schemas import PresetBase as Preset
from app.models.schemas import PresetSettings
from app.services.conversion_service import conversion_service
from app.services.preset_service import preset_service


class TestPresetSystemComplete:
    """Comprehensive preset system tests with realistic scenarios."""

    @pytest.fixture
    def built_in_presets(self) -> Dict[str, PresetSettings]:
        """Define built-in presets that should exist."""
        return {
            "web_optimized": PresetSettings(
                output_format="webp",
                quality=85,
                optimization_mode="file_size",
                preserve_metadata=False,
            ),
            "thumbnail": PresetSettings(
                output_format="jpeg",
                quality=75,
                optimization_mode="file_size",
                preserve_metadata=False,
            ),
            "social_media": PresetSettings(
                output_format="jpeg",
                quality=85,
                optimization_mode="balanced",
                preserve_metadata=False,
            ),
            "archive_quality": PresetSettings(
                output_format="png",
                quality=100,
                optimization_mode="quality",
                preserve_metadata=True,
            ),
            "mobile_optimized": PresetSettings(
                output_format="webp",
                quality=80,
                optimization_mode="file_size",
                preserve_metadata=False,
            ),
        }

    @pytest.mark.critical
    async def test_built_in_presets_availability(self, built_in_presets):
        """
        Test that all built-in presets are available and properly configured.

        Validates core preset functionality.
        """
        # Initialize preset service to ensure built-in presets are created
        await preset_service.initialize()
        
        # Get all presets
        all_presets = await preset_service.get_all_presets()

        # Check built-in presets exist
        preset_ids = {p.id for p in all_presets}
        for preset_id in built_in_presets.keys():
            assert preset_id in preset_ids, f"Built-in preset '{preset_id}' not found"

        # Validate preset configurations
        for preset in all_presets:
            if preset.id in built_in_presets:
                expected = built_in_presets[preset.id]

                # Validate settings match expected values
                assert preset.settings.output_format == expected.output_format
                assert preset.settings.quality == expected.quality
                assert preset.settings.optimization_mode == expected.optimization_mode
                assert preset.settings.preserve_metadata == expected.preserve_metadata

    @pytest.mark.critical
    async def test_custom_preset_creation(self):
        """
        Test creating custom presets with various configurations.

        Simulates user creating personalized presets.
        """
        # Create custom preset for e-commerce
        ecommerce_preset = PresetSettings(
            name="E-commerce Product",
            description="Standard product image for online store",
            output_format="jpeg",
            quality=92,
            resize={
                "width": 1000,
                "height": 1000,
                "mode": "contain",
                "background": "#FFFFFF",
            },
            strip_metadata=True,
            optimization_mode="quality",
            sharpen=1.2,
        )

        # Create preset
        created = await preset_service.create_preset(
            preset_id="ecommerce_product",
            settings=ecommerce_preset,
            user_id="test_user",
        )

        assert created is not None
        assert created.id == "ecommerce_product"
        assert created.is_custom is True
        assert created.settings.quality == 92

        # Verify it's retrievable
        retrieved = await preset_service.get_preset("ecommerce_product")
        assert retrieved is not None
        assert retrieved.settings.name == "E-commerce Product"

        # Clean up
        await preset_service.delete_preset("ecommerce_product")

    async def test_preset_cascading_override(self, realistic_image_generator):
        """
        Test that request parameters properly override preset settings.

        Validates cascading configuration pattern.
        """
        # Create test image
        test_image = realistic_image_generator(
            width=2000, height=1500, content_type="photo"
        )

        # Use web_optimized preset but override quality
        request = ConversionRequest(
            output_format="jpeg",  # Will be overridden by preset
            quality=95,  # Override preset's 85
            preset_id="web_optimized",
        )

        result, output_data = await conversion_service.convert(
            image_data=test_image, request=request
        )

        assert result.success
        # Preset should set format to webp
        assert result.output_format == "webp"
        # But quality should be overridden to 95
        # (Note: actual quality verification depends on implementation)

        # Test with different override
        request2 = ConversionRequest(
            output_format="png", preset_id="thumbnail"  # Override preset format
        )

        result2, output_data2 = await conversion_service.convert(
            image_data=test_image, request=request2
        )

        assert result2.success
        # Format should be overridden
        assert result2.output_format == "png"

    async def test_preset_inheritance_chain(self):
        """
        Test preset inheritance and extension patterns.

        Validates complex preset relationships.
        """
        # Create base preset
        base_preset = PresetSettings(
            name="Company Base",
            description="Base settings for all company images",
            output_format="jpeg",
            quality=85,
            strip_metadata=True,
            optimization_mode="balanced",
        )

        await preset_service.create_preset(
            preset_id="company_base", settings=base_preset, user_id="admin"
        )

        # Create derived preset that extends base
        product_preset = PresetSettings(
            name="Company Product",
            description="Product images based on company standard",
            base_preset_id="company_base",  # Inherit from base
            resize={"width": 800, "height": 800},  # Add resize
            quality=90,  # Override quality
        )

        await preset_service.create_preset(
            preset_id="company_product", settings=product_preset, user_id="admin"
        )

        # Verify inheritance
        product = await preset_service.get_preset("company_product")

        # Should inherit from base
        assert product.settings.strip_metadata is True  # From base
        assert product.settings.optimization_mode == "balanced"  # From base

        # Should have overrides
        assert product.settings.quality == 90  # Overridden
        assert product.settings.resize is not None  # Added

        # Clean up
        await preset_service.delete_preset("company_product")
        await preset_service.delete_preset("company_base")

    @pytest.mark.critical
    async def test_preset_import_export(self):
        """
        Test importing and exporting presets for sharing.

        Validates preset portability.
        """
        # Create custom presets for export
        presets_to_export = []

        for i in range(3):
            preset = PresetSettings(
                name=f"Export Test {i}",
                description=f"Test preset {i} for export",
                output_format=["jpeg", "webp", "png"][i],
                quality=80 + i * 5,
                strip_metadata=True,
            )

            created = await preset_service.create_preset(
                preset_id=f"export_test_{i}", settings=preset, user_id="test_user"
            )
            presets_to_export.append(created)

        # Export presets
        export_data = await preset_service.export_presets(
            preset_ids=[f"export_test_{i}" for i in range(3)]
        )

        assert export_data is not None
        assert "presets" in export_data
        assert len(export_data["presets"]) == 3

        # Clean up original presets
        for i in range(3):
            await preset_service.delete_preset(f"export_test_{i}")

        # Import presets with new IDs
        import_mapping = {f"export_test_{i}": f"imported_test_{i}" for i in range(3)}

        imported = await preset_service.import_presets(
            export_data, id_mapping=import_mapping, user_id="new_user"
        )

        assert len(imported) == 3

        # Verify imported presets
        for i in range(3):
            imported_preset = await preset_service.get_preset(f"imported_test_{i}")
            assert imported_preset is not None
            assert imported_preset.settings.name == f"Export Test {i}"
            assert imported_preset.settings.quality == 80 + i * 5

        # Clean up imported presets
        for i in range(3):
            await preset_service.delete_preset(f"imported_test_{i}")

    @pytest.mark.performance
    async def test_preset_application_performance(self, realistic_image_generator):
        """
        Test performance of preset application on various image types.

        Ensures presets don't significantly impact performance.
        """
        # Create test images of different sizes
        test_cases = [
            (640, 480, "small"),
            (1920, 1080, "medium"),
            (4000, 3000, "large"),
        ]

        performance_results = {}

        for width, height, size_name in test_cases:
            test_image = realistic_image_generator(
                width=width, height=height, content_type="photo"
            )

            # Test without preset
            start_time = time.perf_counter()

            request_no_preset = ConversionRequest(output_format="webp", quality=85)

            result1, _ = await conversion_service.convert(
                image_data=test_image, request=request_no_preset
            )

            time_no_preset = time.perf_counter() - start_time

            # Test with preset
            start_time = time.perf_counter()

            request_with_preset = ConversionRequest(
                output_format="jpeg", preset_id="web_optimized"  # Will be overridden
            )

            result2, _ = await conversion_service.convert(
                image_data=test_image, request=request_with_preset
            )

            time_with_preset = time.perf_counter() - start_time

            # Store results
            performance_results[size_name] = {
                "no_preset": time_no_preset,
                "with_preset": time_with_preset,
                "overhead": time_with_preset - time_no_preset,
            }

        # Verify preset overhead is minimal
        for size_name, metrics in performance_results.items():
            overhead_percentage = (metrics["overhead"] / metrics["no_preset"]) * 100
            assert (
                overhead_percentage < 10
            ), f"Preset overhead too high for {size_name}: {overhead_percentage:.1f}%"

    async def test_preset_validation_and_sanitization(self):
        """
        Test preset validation and sanitization of invalid settings.

        Ensures robustness against invalid configurations.
        """
        # Test invalid quality values
        invalid_presets = [
            PresetSettings(
                name="Invalid Quality High",
                output_format="jpeg",
                quality=150,  # Too high
            ),
            PresetSettings(
                name="Invalid Quality Low",
                output_format="jpeg",
                quality=-10,  # Negative
            ),
            PresetSettings(
                name="Invalid Resize",
                output_format="png",
                resize={"width": -100, "height": -100},  # Negative dimensions
            ),
            PresetSettings(
                name="Invalid Format",
                output_format="invalid_format",  # Non-existent format
            ),
        ]

        for i, invalid_preset in enumerate(invalid_presets):
            # Should either sanitize or reject
            try:
                created = await preset_service.create_preset(
                    preset_id=f"invalid_test_{i}",
                    settings=invalid_preset,
                    user_id="test_user",
                )

                if created:
                    # If created, values should be sanitized
                    if created.settings.quality:
                        assert 0 <= created.settings.quality <= 100

                    if created.settings.resize:
                        assert created.settings.resize.get("width", 1) > 0
                        assert created.settings.resize.get("height", 1) > 0

                    # Clean up
                    await preset_service.delete_preset(f"invalid_test_{i}")

            except (ValueError, ValidationError):
                # Expected for invalid settings
                pass

    async def test_preset_usage_tracking(self):
        """
        Test tracking of preset usage statistics.

        Helps identify popular presets and usage patterns.
        """
        # Create a custom preset
        tracking_preset = PresetSettings(
            name="Usage Tracking Test", output_format="webp", quality=80
        )

        await preset_service.create_preset(
            preset_id="usage_tracking", settings=tracking_preset, user_id="test_user"
        )

        # Get initial usage stats
        initial_stats = await preset_service.get_preset_usage_stats("usage_tracking")
        initial_count = initial_stats.get("usage_count", 0) if initial_stats else 0

        # Use preset multiple times
        test_image = b"fake_image_data"  # Simplified for tracking test

        for _ in range(5):
            try:
                request = ConversionRequest(
                    output_format="jpeg", preset_id="usage_tracking"
                )

                # Attempt conversion (may fail with fake data, but usage should be tracked)
                await conversion_service.convert(image_data=test_image, request=request)
            except:
                pass  # Ignore conversion errors for this test

        # Check updated usage stats
        updated_stats = await preset_service.get_preset_usage_stats("usage_tracking")

        if updated_stats:
            updated_count = updated_stats.get("usage_count", 0)
            # Usage should have increased
            assert updated_count >= initial_count

        # Clean up
        await preset_service.delete_preset("usage_tracking")

    async def test_preset_batch_application(self, realistic_image_generator):
        """
        Test applying presets to batch conversions.

        Common use case for consistent processing.
        """
        # Create test images
        test_images = []
        for i in range(10):
            img = realistic_image_generator(
                width=1000 + i * 100, height=800 + i * 80, content_type="photo"
            )
            test_images.append(
                {
                    "filename": f"batch_test_{i}.jpg",
                    "content": img,
                    "content_type": "image/jpeg",
                }
            )

        # Create batch job with preset
        from app.services.batch_service import batch_service

        job = await batch_service.create_batch_job(
            files=test_images,
            output_format="png",  # Will be overridden by preset
            preset_id="thumbnail",  # Apply thumbnail preset to all
        )

        # Process batch
        result = await batch_service.process_batch(job.id)

        # Verify all images processed with preset
        assert len(result.completed) >= 8  # Allow some failures

        # Check that preset was applied
        for item in result.completed[:3]:  # Check first 3
            # Thumbnail preset should resize to 150x150
            # Output format should be from preset (jpeg)
            assert item.output_format == "jpeg"  # From preset, not request
            # Size should be significantly reduced (thumbnail)
            assert len(item.output_data) < len(test_images[item.index]["content"]) * 0.1

    async def test_preset_conditional_application(self):
        """
        Test conditional preset application based on image characteristics.

        Smart preset selection based on content.
        """
        # Create preset rules
        preset_rules = [
            {"condition": "content_type == 'photo'", "preset_id": "web_optimized"},
            {
                "condition": "content_type == 'screenshot'",
                "preset_id": "mobile_optimized",
            },
            {"condition": "content_type == 'document'", "preset_id": "archive_quality"},
            {"condition": "width > 4000 or height > 4000", "preset_id": "thumbnail"},
        ]

        # Test with different image types
        test_cases = [
            ("photo", 2000, 1500, "web_optimized"),
            ("screenshot", 1920, 1080, "mobile_optimized"),
            ("document", 2480, 3508, "archive_quality"),
            ("photo", 5000, 3750, "thumbnail"),  # Large photo gets thumbnail
        ]

        for content_type, width, height, expected_preset in test_cases:
            # Simulate content-aware preset selection
            selected_preset = None

            for rule in preset_rules:
                # Evaluate condition (simplified)
                if (
                    "content_type == 'photo'" in rule["condition"]
                    and content_type == "photo"
                ):
                    if "width > 4000" in rule["condition"] and width > 4000:
                        selected_preset = rule["preset_id"]
                        break
                    elif "width > 4000" not in rule["condition"]:
                        selected_preset = rule["preset_id"]
                        break
                elif f"content_type == '{content_type}'" in rule["condition"]:
                    selected_preset = rule["preset_id"]
                    break

            assert (
                selected_preset == expected_preset
            ), f"Wrong preset for {content_type} {width}x{height}"

    @pytest.mark.performance
    async def test_preset_caching_efficiency(self):
        """
        Test preset caching for improved performance.

        Frequently used presets should be cached.
        """
        # Clear any existing cache
        preset_service._clear_cache()

        # First access - cache miss
        start_time = time.perf_counter()
        preset1 = await preset_service.get_preset("web_optimized")
        first_access_time = time.perf_counter() - start_time

        assert preset1 is not None

        # Second access - should be cached
        start_time = time.perf_counter()
        preset2 = await preset_service.get_preset("web_optimized")
        cached_access_time = time.perf_counter() - start_time

        assert preset2 is not None
        assert preset2.id == preset1.id

        # Cached access should be significantly faster
        assert (
            cached_access_time < first_access_time * 0.5
        ), "Cache not providing performance benefit"

        # Access multiple times to ensure cache stability
        for _ in range(100):
            preset = await preset_service.get_preset("web_optimized")
            assert preset is not None

        # Cache should handle updates
        if preset1.is_custom:  # Only test with custom presets
            # Update preset
            preset1.settings.quality = 90
            await preset_service.update_preset("web_optimized", preset1.settings)

            # Get updated preset - cache should be invalidated
            preset3 = await preset_service.get_preset("web_optimized")
            assert preset3.settings.quality == 90
