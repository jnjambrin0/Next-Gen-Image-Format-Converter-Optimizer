"""
Comprehensive tests for dry-run simulation functionality
Tests estimation algorithms, validation, and preview features
"""

import json
import os
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from app.cli.productivity.dry_run import (
    BatchEstimate,
    ConversionEstimate,
    DryRunSimulator,
    ResourceEstimate,
    SimulationMode,
    ValidationResult,
)


class TestConversionEstimate:
    """Test ConversionEstimate dataclass and calculations"""

    def test_estimate_creation_with_defaults(self):
        """Test creating estimate with default values"""
        estimate = ConversionEstimate(
            input_file="test.jpg",
            output_format="webp",
            input_size=1024000,  # 1MB
            estimated_output_size=512000,  # 500KB
            estimated_time_seconds=2.5,
        )

        assert estimate.input_file == "test.jpg"
        assert estimate.output_format == "webp"
        assert estimate.compression_ratio == 0.5
        assert estimate.success_probability == 0.95
        assert estimate.warnings == []

    def test_estimate_with_warnings(self):
        """Test estimate with warning conditions"""
        estimate = ConversionEstimate(
            input_file="large.png",
            output_format="avif",
            input_size=100 * 1024 * 1024,  # 100MB
            estimated_output_size=10 * 1024 * 1024,
            estimated_time_seconds=60,
            warnings=["Large file may take longer", "AVIF encoding is CPU-intensive"],
        )

        assert len(estimate.warnings) == 2
        assert "Large file" in estimate.warnings[0]

    def test_compression_ratio_calculation(self):
        """Test automatic compression ratio calculation"""
        estimate = ConversionEstimate(
            input_file="test.bmp",
            output_format="jpeg",
            input_size=10000000,  # 10MB
            estimated_output_size=1000000,  # 1MB
        )

        assert estimate.compression_ratio == 0.1

    def test_resource_requirements(self):
        """Test resource requirement estimates"""
        estimate = ConversionEstimate(
            input_file="huge.tiff",
            output_format="webp",
            input_size=500 * 1024 * 1024,  # 500MB
            estimated_output_size=50 * 1024 * 1024,
            estimated_time_seconds=120,
            estimated_memory_mb=2048,
            estimated_cpu_percent=85,
        )

        assert estimate.estimated_memory_mb == 2048
        assert estimate.estimated_cpu_percent == 85
        assert estimate.estimated_time_seconds == 120

    def test_format_conversion_matrix(self):
        """Test format compatibility and success probability"""
        # Test known good conversions
        good_conversion = ConversionEstimate(
            input_file="photo.jpg",
            output_format="png",
            input_size=1000000,
            estimated_output_size=2000000,  # PNG typically larger
            success_probability=0.99,
        )
        assert good_conversion.success_probability > 0.95

        # Test problematic conversions
        risky_conversion = ConversionEstimate(
            input_file="complex.heic",
            output_format="jxl",
            input_size=5000000,
            estimated_output_size=3000000,
            success_probability=0.75,  # Lower due to format complexity
            warnings=["HEIC to JXL conversion may lose some metadata"],
        )
        assert risky_conversion.success_probability < 0.8
        assert len(risky_conversion.warnings) > 0


class TestBatchEstimate:
    """Test batch processing estimates"""

    def test_batch_estimate_aggregation(self):
        """Test aggregating individual estimates into batch"""
        estimates = [
            ConversionEstimate(
                input_file=f"file{i}.jpg",
                output_format="webp",
                input_size=1024000,
                estimated_output_size=512000,
                estimated_time_seconds=2,
            )
            for i in range(10)
        ]

        batch = BatchEstimate(
            total_files=10,
            total_input_size=10 * 1024000,
            total_estimated_output_size=10 * 512000,
            estimated_total_time_seconds=20,
            file_estimates=estimates,
        )

        assert batch.total_files == 10
        assert batch.total_input_size == 10485760
        assert batch.average_compression_ratio == 0.5
        assert batch.estimated_completion_time is not None

    def test_batch_parallelization_estimate(self):
        """Test time estimation with parallel processing"""
        estimates = [
            ConversionEstimate(
                input_file=f"file{i}.jpg",
                output_format="avif",
                input_size=5000000,
                estimated_output_size=2000000,
                estimated_time_seconds=10,  # Each takes 10 seconds
            )
            for i in range(20)
        ]

        # With 4 workers, should take ~50 seconds, not 200
        batch = BatchEstimate(
            total_files=20,
            total_input_size=100000000,
            total_estimated_output_size=40000000,
            estimated_total_time_seconds=50,  # Parallel execution
            file_estimates=estimates,
            parallel_workers=4,
        )

        assert batch.parallel_workers == 4
        assert batch.estimated_total_time_seconds < 200  # Much less than sequential

    def test_batch_failure_probability(self):
        """Test calculating overall batch success probability"""
        estimates = [
            ConversionEstimate(
                input_file=f"file{i}.jpg",
                output_format="webp",
                input_size=1000000,
                estimated_output_size=500000,
                estimated_time_seconds=2,
                success_probability=0.95 if i < 8 else 0.70,  # 2 risky files
            )
            for i in range(10)
        ]

        batch = BatchEstimate(
            total_files=10,
            total_input_size=10000000,
            total_estimated_output_size=5000000,
            estimated_total_time_seconds=20,
            file_estimates=estimates,
        )

        # Calculate expected success rate
        avg_success = sum(e.success_probability for e in estimates) / len(estimates)
        assert batch.expected_success_rate == pytest.approx(avg_success, 0.01)


class TestValidationResult:
    """Test validation result reporting"""

    def test_validation_success(self):
        """Test successful validation result"""
        result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            checks_performed=[
                "File exists",
                "Format supported",
                "Size within limits",
                "Permissions OK",
            ],
        )

        assert result.is_valid is True
        assert len(result.errors) == 0
        assert len(result.checks_performed) == 4

    def test_validation_with_errors(self):
        """Test validation with errors"""
        result = ValidationResult(
            is_valid=False,
            errors=["File not found: image.jpg", "Unsupported format: .xyz"],
            warnings=["Large file size may slow conversion"],
            checks_performed=["File existence", "Format check"],
        )

        assert result.is_valid is False
        assert len(result.errors) == 2
        assert len(result.warnings) == 1

    def test_validation_error_categories(self):
        """Test different error categories"""
        result = ValidationResult(
            is_valid=False,
            errors=[],
            warnings=[],
            checks_performed=[],
            error_categories={
                "file_access": ["Permission denied"],
                "format": ["Invalid image format"],
                "resource": ["Insufficient memory"],
            },
        )

        assert "file_access" in result.error_categories
        assert "format" in result.error_categories
        assert "resource" in result.error_categories


class TestDryRunSimulator:
    """Test DryRunSimulator functionality"""

    @pytest.fixture
    def simulator(self):
        """Create simulator instance"""
        return DryRunSimulator(
            verbose=True, estimate_resources=True, validate_only=False
        )

    @pytest.fixture
    def temp_files(self, tmp_path):
        """Create temporary test files"""
        files = []
        for i in range(5):
            file = tmp_path / f"test{i}.jpg"
            # Create files with different sizes
            file.write_bytes(b"JPEG" + b"\x00" * (1024 * (i + 1) * 100))
            files.append(file)
        return files

    def test_simulator_initialization(self, simulator):
        """Test simulator initializes correctly"""
        assert simulator.verbose is True
        assert simulator.estimate_resources is True
        assert simulator.validate_only is False
        assert hasattr(simulator, "format_characteristics")
        assert hasattr(simulator, "preset_modifiers")

    def test_estimate_single_conversion(self, simulator, temp_files):
        """Test estimating single file conversion"""
        estimate = simulator.estimate_conversion(
            input_file=temp_files[0], output_format="webp", quality=85, preset=None
        )

        assert isinstance(estimate, ConversionEstimate)
        assert estimate.input_file == str(temp_files[0])
        assert estimate.output_format == "webp"
        assert estimate.estimated_output_size > 0
        assert estimate.estimated_time_seconds > 0

    def test_estimate_with_preset(self, simulator, temp_files):
        """Test estimation with optimization preset"""
        estimate = simulator.estimate_conversion(
            input_file=temp_files[1],
            output_format="jpeg",
            quality=None,
            preset="web-optimized",
        )

        # Web-optimized should reduce size significantly
        assert estimate.compression_ratio < 0.5
        assert "web-optimized" in estimate.optimization_notes

    def test_estimate_batch_conversion(self, simulator, temp_files):
        """Test estimating batch conversion"""
        batch_estimate = simulator.estimate_batch(
            input_files=temp_files, output_format="avif", quality=90, parallel_workers=4
        )

        assert isinstance(batch_estimate, BatchEstimate)
        assert batch_estimate.total_files == len(temp_files)
        assert batch_estimate.parallel_workers == 4
        assert len(batch_estimate.file_estimates) == len(temp_files)

        # Parallel should be faster than sequential
        sequential_time = sum(
            e.estimated_time_seconds for e in batch_estimate.file_estimates
        )
        assert batch_estimate.estimated_total_time_seconds < sequential_time

    def test_validate_input_files(self, simulator, temp_files, tmp_path):
        """Test input file validation"""
        # Add non-existent file
        non_existent = tmp_path / "missing.jpg"

        # Add file with bad extension
        bad_ext = tmp_path / "test.xyz"
        bad_ext.write_text("not an image")

        all_files = temp_files + [non_existent, bad_ext]

        validation = simulator.validate_inputs(
            input_files=all_files, output_format="webp"
        )

        assert validation.is_valid is False
        assert len(validation.errors) >= 2
        assert any("not found" in e.lower() for e in validation.errors)
        assert any("unsupported" in e.lower() for e in validation.errors)

    def test_validate_output_permissions(self, simulator, temp_files, tmp_path):
        """Test output directory permission validation"""
        # Create read-only directory
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()

        # Make it read-only (platform-specific)
        try:
            os.chmod(readonly_dir, 0o444)

            validation = simulator.validate_outputs(
                output_dir=readonly_dir, file_count=len(temp_files)
            )

            assert validation.is_valid is False
            assert any("permission" in e.lower() for e in validation.errors)
        finally:
            # Restore permissions for cleanup
            os.chmod(readonly_dir, 0o755)

    def test_estimate_resource_usage(self, simulator, temp_files):
        """Test resource usage estimation"""
        resource_estimate = simulator.estimate_resources(
            input_files=temp_files, output_format="jxl", parallel_workers=4
        )

        assert isinstance(resource_estimate, ResourceEstimate)
        assert resource_estimate.peak_memory_mb > 0
        assert resource_estimate.peak_cpu_percent > 0
        assert resource_estimate.total_disk_space_mb > 0
        assert resource_estimate.temp_space_mb >= 0

    def test_format_specific_estimates(self, simulator, temp_files):
        """Test format-specific estimation characteristics"""
        # AVIF should be slow but small
        avif_estimate = simulator.estimate_conversion(
            input_file=temp_files[0], output_format="avif", quality=85
        )

        # WebP should be fast and reasonably small
        webp_estimate = simulator.estimate_conversion(
            input_file=temp_files[0], output_format="webp", quality=85
        )

        # PNG should be fast but larger
        png_estimate = simulator.estimate_conversion(
            input_file=temp_files[0],
            output_format="png",
            quality=100,  # PNG is lossless
        )

        # AVIF should take longest
        assert (
            avif_estimate.estimated_time_seconds > webp_estimate.estimated_time_seconds
        )

        # PNG should be largest
        assert png_estimate.estimated_output_size > webp_estimate.estimated_output_size

        # WebP should have good compression
        assert webp_estimate.compression_ratio < 0.7

    def test_quality_impact_on_size(self, simulator, temp_files):
        """Test how quality affects size estimates"""
        high_quality = simulator.estimate_conversion(
            input_file=temp_files[2], output_format="jpeg", quality=95
        )

        medium_quality = simulator.estimate_conversion(
            input_file=temp_files[2], output_format="jpeg", quality=75
        )

        low_quality = simulator.estimate_conversion(
            input_file=temp_files[2], output_format="jpeg", quality=50
        )

        # Size should decrease with quality
        assert high_quality.estimated_output_size > medium_quality.estimated_output_size
        assert medium_quality.estimated_output_size > low_quality.estimated_output_size

        # Compression ratio should increase (smaller output)
        assert high_quality.compression_ratio > low_quality.compression_ratio

    def test_simulation_modes(self, simulator, temp_files):
        """Test different simulation modes"""
        # Quick mode - fast estimates
        simulator.mode = SimulationMode.QUICK
        quick_estimate = simulator.estimate_conversion(
            input_file=temp_files[0], output_format="webp"
        )

        # Detailed mode - more accurate
        simulator.mode = SimulationMode.DETAILED
        detailed_estimate = simulator.estimate_conversion(
            input_file=temp_files[0], output_format="webp"
        )

        # Full mode - complete analysis
        simulator.mode = SimulationMode.FULL
        full_estimate = simulator.estimate_conversion(
            input_file=temp_files[0], output_format="webp"
        )

        # Full mode should provide more information
        assert len(full_estimate.analysis_notes) > len(quick_estimate.analysis_notes)

    def test_warning_generation(self, simulator, tmp_path):
        """Test warning generation for edge cases"""
        # Create a very large file
        large_file = tmp_path / "huge.bmp"
        large_file.write_bytes(b"BMP" + b"\x00" * (100 * 1024 * 1024))  # 100MB

        estimate = simulator.estimate_conversion(
            input_file=large_file, output_format="avif"
        )

        # Should have warnings about size and processing time
        assert len(estimate.warnings) > 0
        assert any("large" in w.lower() for w in estimate.warnings)
        assert any(
            "time" in w.lower() or "slow" in w.lower() for w in estimate.warnings
        )

    def test_validation_only_mode(self, simulator, temp_files):
        """Test validation-only mode without estimation"""
        simulator.validate_only = True

        result = simulator.simulate_conversion(
            input_file=temp_files[0], output_format="webp"
        )

        # Should only validate, not estimate
        assert result.validation is not None
        assert result.validation.is_valid is True
        assert result.estimate is None  # No estimation in validate-only mode

    def test_verbose_output_detail(self, simulator, temp_files, capsys):
        """Test verbose output provides detailed information"""
        simulator.verbose = True

        estimate = simulator.estimate_conversion(
            input_file=temp_files[0], output_format="webp", quality=80
        )

        # In verbose mode, should print details
        simulator.print_estimate(estimate)
        captured = capsys.readouterr()

        assert "Input file" in captured.out
        assert "Output format" in captured.out
        assert "Estimated size" in captured.out
        assert "Estimated time" in captured.out

    def test_preset_modifier_effects(self, simulator, temp_files):
        """Test how presets modify estimates"""
        # No preset
        base_estimate = simulator.estimate_conversion(
            input_file=temp_files[1], output_format="jpeg", quality=85
        )

        # Fast preset - larger but quicker
        fast_estimate = simulator.estimate_conversion(
            input_file=temp_files[1],
            output_format="jpeg",
            quality=85,
            preset="fast-processing",
        )

        # Archive preset - smaller but slower
        archive_estimate = simulator.estimate_conversion(
            input_file=temp_files[1], output_format="jpeg", quality=85, preset="archive"
        )

        # Fast should be quicker
        assert (
            fast_estimate.estimated_time_seconds < base_estimate.estimated_time_seconds
        )

        # Archive should be smaller
        assert (
            archive_estimate.estimated_output_size < base_estimate.estimated_output_size
        )

    def test_disk_space_validation(self, simulator, temp_files):
        """Test disk space availability validation"""
        with patch("shutil.disk_usage") as mock_disk:
            # Simulate low disk space
            mock_disk.return_value = MagicMock(free=1024 * 1024)  # Only 1MB free

            validation = simulator.validate_disk_space(
                output_dir=Path("/tmp"), estimated_size_mb=100  # Need 100MB
            )

            assert validation.is_valid is False
            assert any("disk space" in e.lower() for e in validation.errors)

    def test_parallel_efficiency_calculation(self, simulator, temp_files):
        """Test parallel processing efficiency calculations"""
        # Test with varying worker counts
        estimates = []
        for workers in [1, 2, 4, 8]:
            batch_estimate = simulator.estimate_batch(
                input_files=temp_files * 4,  # 20 files
                output_format="webp",
                parallel_workers=workers,
            )
            estimates.append((workers, batch_estimate.estimated_total_time_seconds))

        # More workers should reduce time, but with diminishing returns
        for i in range(len(estimates) - 1):
            workers1, time1 = estimates[i]
            workers2, time2 = estimates[i + 1]
            assert time2 < time1  # More workers = less time

            # But efficiency decreases (not linear speedup)
            speedup = time1 / time2
            worker_ratio = workers2 / workers1
            assert speedup < worker_ratio  # Sublinear speedup

    def test_memory_estimation_accuracy(self, simulator, temp_files):
        """Test memory usage estimation for different scenarios"""
        # Small file
        small_estimate = simulator.estimate_resources(
            input_files=[temp_files[0]], output_format="webp"  # ~100KB
        )

        # Large files
        large_estimate = simulator.estimate_resources(
            input_files=temp_files * 10,  # Many files
            output_format="avif",
            parallel_workers=8,
        )

        # Memory should scale with file size and parallelism
        assert large_estimate.peak_memory_mb > small_estimate.peak_memory_mb

        # AVIF needs more memory than WebP
        assert large_estimate.peak_memory_mb > small_estimate.peak_memory_mb * 10

    def test_edge_case_handling(self, simulator, tmp_path):
        """Test handling of edge cases"""
        # Empty file
        empty_file = tmp_path / "empty.jpg"
        empty_file.write_bytes(b"")

        validation = simulator.validate_inputs(
            input_files=[empty_file], output_format="webp"
        )
        assert validation.is_valid is False
        assert any("empty" in e.lower() for e in validation.errors)

        # Corrupted file
        corrupt_file = tmp_path / "corrupt.jpg"
        corrupt_file.write_bytes(b"NOT_A_JPEG")

        estimate = simulator.estimate_conversion(
            input_file=corrupt_file, output_format="webp"
        )
        assert estimate.success_probability < 0.5
        assert len(estimate.warnings) > 0


class TestDryRunIntegration:
    """Integration tests for dry-run simulation"""

    @pytest.fixture
    def full_simulator(self):
        """Create fully configured simulator"""
        return DryRunSimulator(
            verbose=True,
            estimate_resources=True,
            validate_only=False,
            mode=SimulationMode.DETAILED,
        )

    def test_complete_dry_run_workflow(self, full_simulator, tmp_path):
        """Test complete dry-run workflow"""
        # Create test files
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        files = []
        for i in range(10):
            file = input_dir / f"image{i}.jpg"
            file.write_bytes(b"JPEG" + b"\x00" * (1024 * 100 * (i + 1)))
            files.append(file)

        # Validate inputs
        validation = full_simulator.validate_inputs(files, "webp")
        assert validation.is_valid is True

        # Estimate batch conversion
        batch_estimate = full_simulator.estimate_batch(
            input_files=files, output_format="webp", quality=85, parallel_workers=4
        )

        assert batch_estimate.total_files == 10
        assert batch_estimate.estimated_total_time_seconds > 0

        # Estimate resources
        resources = full_simulator.estimate_resources(
            input_files=files, output_format="webp", parallel_workers=4
        )

        assert resources.peak_memory_mb > 0
        assert resources.peak_cpu_percent > 0

        # Generate summary
        summary = full_simulator.generate_summary(
            batch_estimate=batch_estimate,
            resource_estimate=resources,
            validation_result=validation,
        )

        assert "Total files" in summary
        assert "Estimated time" in summary
        assert "Peak memory" in summary
        assert "Success" in summary

    def test_dry_run_with_mixed_formats(self, full_simulator, tmp_path):
        """Test dry-run with multiple input formats"""
        files = []

        # Create files with different formats
        formats = {
            "jpeg": b"\xff\xd8\xff",
            "png": b"\x89PNG\r\n\x1a\n",
            "bmp": b"BM",
            "gif": b"GIF89a",
        }

        for fmt, magic in formats.items():
            file = tmp_path / f"test.{fmt}"
            file.write_bytes(magic + b"\x00" * 1000)
            files.append(file)

        # Estimate conversions to different formats
        for output_fmt in ["webp", "avif", "jxl"]:
            batch_estimate = full_simulator.estimate_batch(
                input_files=files, output_format=output_fmt
            )

            assert batch_estimate.total_files == len(files)

            # Different formats should have different characteristics
            if output_fmt == "avif":
                assert batch_estimate.estimated_total_time_seconds > 10
            elif output_fmt == "webp":
                assert batch_estimate.estimated_total_time_seconds < 10

    def test_dry_run_json_output(self, full_simulator, tmp_path):
        """Test JSON output format for dry-run results"""
        file = tmp_path / "test.jpg"
        file.write_bytes(b"JPEG" + b"\x00" * 10000)

        estimate = full_simulator.estimate_conversion(
            input_file=file, output_format="webp", quality=85
        )

        # Convert to JSON
        json_output = full_simulator.to_json(estimate)
        data = json.loads(json_output)

        assert "input_file" in data
        assert "output_format" in data
        assert "estimated_output_size" in data
        assert "estimated_time_seconds" in data
        assert "compression_ratio" in data
        assert "success_probability" in data

    def test_dry_run_comparison_mode(self, full_simulator, tmp_path):
        """Test comparing multiple conversion options"""
        file = tmp_path / "test.jpg"
        file.write_bytes(b"JPEG" + b"\x00" * 100000)

        # Compare different formats
        comparisons = full_simulator.compare_formats(
            input_file=file, formats=["webp", "avif", "jxl", "png"], quality=85
        )

        assert len(comparisons) == 4

        # Find best for size
        best_size = min(comparisons, key=lambda x: x.estimated_output_size)
        assert best_size.output_format in ["avif", "jxl"]  # Usually smallest

        # Find fastest
        fastest = min(comparisons, key=lambda x: x.estimated_time_seconds)
        assert fastest.output_format in ["webp", "png"]  # Usually fastest

    def test_dry_run_abort_conditions(self, full_simulator, tmp_path):
        """Test conditions that should abort dry-run"""
        # Create problematic scenarios

        # Scenario 1: No files
        validation = full_simulator.validate_inputs([], "webp")
        assert validation.is_valid is False
        assert any("no files" in e.lower() for e in validation.errors)

        # Scenario 2: All files invalid
        invalid_files = [tmp_path / f"bad{i}.xyz" for i in range(5)]
        for f in invalid_files:
            f.write_text("not an image")

        validation = full_simulator.validate_inputs(invalid_files, "webp")
        assert validation.is_valid is False

        # Scenario 3: Output format not supported
        file = tmp_path / "test.jpg"
        file.write_bytes(b"JPEG" + b"\x00" * 1000)

        validation = full_simulator.validate_conversion(
            input_file=file, output_format="unsupported_format"
        )
        assert validation.is_valid is False
