"""
Dry-Run Mode Simulator
Simulate conversion operations without actually executing them
"""

import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from PIL import Image


class SimulationMode(Enum):
    """Simulation mode for dry run"""

    FAST = "fast"  # Quick estimation
    NORMAL = "normal"  # Normal estimation
    DETAILED = "detailed"  # Detailed analysis


class OperationType(Enum):
    """Types of operations that can be simulated"""

    CONVERT = "convert"
    OPTIMIZE = "optimize"
    BATCH = "batch"
    RESIZE = "resize"
    COMPRESS = "compress"
    METADATA_STRIP = "metadata_strip"


@dataclass
class ResourceEstimate:
    """Resource usage estimate"""

    memory_mb: float
    cpu_percent: float
    disk_io_mb: float = 0.0
    estimated_duration_seconds: float = 0.0


@dataclass
class ValidationResult:
    """Validation result for dry run"""

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


@dataclass
class ConversionEstimate:
    """Estimate for a single conversion"""

    input_file: str
    output_format: str
    input_size: int
    estimated_output_size: int
    estimated_time_seconds: float = 0.0
    output_file: Optional[str] = None
    input_format: Optional[str] = None
    resource_estimate: Optional[ResourceEstimate] = None
    quality_loss_percent: float = 0.0
    compression_ratio: float = 0.0
    validation: Optional[ValidationResult] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    success_probability: float = 0.95
    estimated_memory_mb: float = 0.0
    estimated_cpu_percent: float = 0.0

    def __post_init__(self) -> None:
        """Calculate derived values"""
        if self.input_size > 0 and self.compression_ratio == 0:
            self.compression_ratio = self.estimated_output_size / self.input_size


@dataclass
class BatchEstimate:
    """Estimate for batch operations"""

    total_files: int
    total_input_size: int  # Changed from total_input_size_bytes for test compatibility
    estimated_total_output_size_bytes: int = 0
    estimated_total_time_seconds: float = 0.0
    estimated_parallel_time_seconds: float = 0.0
    worker_count: int = 1
    conversions: List[ConversionEstimate] = field(default_factory=list)
    file_estimates: List[ConversionEstimate] = field(
        default_factory=list
    )  # Alias for tests
    total_memory_mb: float = 0.0
    peak_memory_mb: float = 0.0
    parallel_workers: int = 1
    total_estimated_output_size: int = 0  # Alias for tests

    def __post_init__(self) -> None:
        """Initialize aliases and calculated fields"""
        # Sync aliases
        if self.file_estimates and not self.conversions:
            self.conversions = self.file_estimates
        elif self.conversions and not self.file_estimates:
            self.file_estimates = self.conversions

        if (
            self.total_estimated_output_size
            and not self.estimated_total_output_size_bytes
        ):
            self.estimated_total_output_size_bytes = self.total_estimated_output_size
        elif (
            self.estimated_total_output_size_bytes
            and not self.total_estimated_output_size
        ):
            self.total_estimated_output_size = self.estimated_total_output_size_bytes

    @property
    def average_compression_ratio(self) -> float:
        """Calculate average compression ratio"""
        if self.total_input_size > 0:
            return self.estimated_total_output_size_bytes / self.total_input_size
        return 1.0

    @property
    def estimated_completion_time(self) -> datetime:
        """Calculate estimated completion time"""
        from datetime import datetime, timedelta

        return datetime.now() + timedelta(seconds=self.estimated_total_time_seconds)


@dataclass
class SimulatedOperation:
    """Represents a simulated operation"""

    operation_type: OperationType
    input_file: Path
    output_file: Optional[Path] = None
    input_format: str = ""
    output_format: str = ""
    input_size_bytes: int = 0
    estimated_output_size_bytes: int = 0
    estimated_time_seconds: float = 0.0
    estimated_memory_mb: float = 0.0
    estimated_cpu_percent: float = 0.0
    parameters: Dict[str, Any] = field(default_factory=dict)
    validation_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    would_succeed: bool = True


class DryRunSimulator:
    """Simulate operations without executing them"""

    # Format characteristics for estimation
    FORMAT_CHARACTERISTICS = {
        "jpeg": {"compression_ratio": 0.1, "speed": 1.0, "quality_loss": True},
        "jpg": {"compression_ratio": 0.1, "speed": 1.0, "quality_loss": True},
        "png": {"compression_ratio": 0.5, "speed": 0.8, "quality_loss": False},
        "webp": {"compression_ratio": 0.08, "speed": 0.9, "quality_loss": True},
        "avif": {"compression_ratio": 0.06, "speed": 0.4, "quality_loss": True},
        "heif": {"compression_ratio": 0.07, "speed": 0.5, "quality_loss": True},
        "heic": {"compression_ratio": 0.07, "speed": 0.5, "quality_loss": True},
        "jxl": {"compression_ratio": 0.065, "speed": 0.3, "quality_loss": True},
        "bmp": {"compression_ratio": 1.0, "speed": 1.5, "quality_loss": False},
        "tiff": {"compression_ratio": 0.8, "speed": 1.2, "quality_loss": False},
        "gif": {"compression_ratio": 0.3, "speed": 1.1, "quality_loss": True},
    }

    # Preset characteristics
    PRESET_MODIFIERS = {
        "web": {"size_multiplier": 0.7, "quality": 85},
        "print": {"size_multiplier": 1.2, "quality": 95},
        "archive": {"size_multiplier": 1.0, "quality": 100},
        "thumbnail": {"size_multiplier": 0.1, "quality": 70},
        "fast": {"size_multiplier": 0.8, "quality": 75},
    }

    def __init__(
        self,
        verbose: bool = False,
        estimate_resources: bool = False,
        validate_only: bool = False,
    ) -> None:
        """
        Initialize dry-run simulator

        Args:
            verbose: Enable verbose output
            estimate_resources: Include resource estimation
            validate_only: Only validate without estimation
        """
        self.verbose = verbose
        self.estimate_resources = estimate_resources
        self.validate_only = validate_only
        self.mode = SimulationMode.NORMAL
        self.operations: List[SimulatedOperation] = []

        # Set instance attributes for test compatibility
        self.format_characteristics = self.FORMAT_CHARACTERISTICS
        self.preset_modifiers = self.PRESET_MODIFIERS

    def simulate_conversion(
        self,
        input_path: Path,
        output_format: str,
        output_path: Optional[Path] = None,
        quality: int = 85,
        preset: Optional[str] = None,
        preserve_metadata: bool = False,
        **kwargs,
    ) -> SimulatedOperation:
        """
        Simulate a single image conversion

        Args:
            input_path: Input file path
            output_format: Target format
            output_path: Optional[Any] output path
            quality: Quality setting (1-100)
            preset: Optimization preset
            preserve_metadata: Whether to preserve metadata
            **kwargs: Additional parameters

        Returns:
            Simulated operation details
        """
        operation = SimulatedOperation(
            operation_type=OperationType.CONVERT,
            input_file=input_path,
            output_format=output_format.lower(),
            parameters={
                "quality": quality,
                "preset": preset,
                "preserve_metadata": preserve_metadata,
                **kwargs,
            },
        )

        # Validate input file
        if not input_path.exists():
            operation.validation_errors.append(
                f"Input file does not exist: {input_path}"
            )
            operation.would_succeed = False
            return operation

        if not input_path.is_file():
            operation.validation_errors.append(f"Input is not a file: {input_path}")
            operation.would_succeed = False
            return operation

        # Get input file info
        try:
            operation.input_size_bytes = input_path.stat().st_size

            # Detect input format
            with Image.open(input_path) as img:
                operation.input_format = img.format.lower() if img.format else "unknown"
                width, height = img.size
                num_pixels = width * height

                # Check for warnings
                if width > 10000 or height > 10000:
                    operation.warnings.append(
                        f"Large image dimensions: {width}x{height}"
                    )

                if operation.input_size_bytes > 100 * 1024 * 1024:  # 100MB
                    operation.warnings.append(
                        f"Large file size: {operation.input_size_bytes / 1024 / 1024:.1f} MB"
                    )
        except Exception as e:
            operation.validation_errors.append(f"Cannot read image: {str(e)}")
            operation.would_succeed = False
            return operation

        # Validate output format
        if output_format.lower() not in self.FORMAT_CHARACTERISTICS:
            operation.validation_errors.append(
                f"Unsupported output format: {output_format}"
            )
            operation.would_succeed = False
            return operation

        # Determine output path
        if not output_path:
            output_path = input_path.with_suffix(f".{output_format.lower()}")
        operation.output_file = output_path

        # Check if output would overwrite
        if output_path.exists() and output_path == input_path:
            operation.validation_errors.append("Output would overwrite input file")
            operation.would_succeed = False
            return operation

        # Estimate output size
        operation.estimated_output_size_bytes = self._estimate_output_size(
            operation.input_size_bytes,
            operation.input_format,
            output_format.lower(),
            quality,
            preset,
            num_pixels,
        )

        # Estimate processing time
        operation.estimated_time_seconds = self._estimate_processing_time(
            operation.input_size_bytes, output_format.lower(), num_pixels
        )

        # Estimate resource usage
        operation.estimated_memory_mb = self._estimate_memory_usage(
            operation.input_size_bytes, num_pixels
        )

        operation.estimated_cpu_percent = self._estimate_cpu_usage(
            output_format.lower()
        )

        # Add format-specific warnings
        if operation.input_format == output_format.lower():
            operation.warnings.append("Input and output formats are the same")

        if output_format.lower() in ["jpeg", "jpg", "webp", "avif"] and quality == 100:
            operation.warnings.append(
                "Quality 100 may result in larger file sizes than expected"
            )

        if not preserve_metadata and operation.input_format in ["jpeg", "jpg", "tiff"]:
            operation.warnings.append("Metadata (EXIF, GPS, etc.) will be removed")

        self.operations.append(operation)
        return operation

    def simulate_batch(
        self,
        input_patterns: List[str],
        output_format: str,
        output_dir: Optional[Path] = None,
        quality: int = 85,
        workers: int = 4,
        **kwargs,
    ) -> List[SimulatedOperation]:
        """
        Simulate batch conversion

        Args:
            input_patterns: File patterns to match
            output_format: Target format
            output_dir: Output directory
            quality: Quality setting
            workers: Number of workers
            **kwargs: Additional parameters

        Returns: List[Any] of simulated operations
        """
        import glob

        batch_operations = []
        all_files = []

        # Find matching files
        for pattern in input_patterns:
            files = glob.glob(pattern, recursive=True)
            all_files.extend([Path(f) for f in files if Path(f).is_file()])

        if not all_files:
            # Create a dummy operation to show no files found
            operation = SimulatedOperation(
                operation_type=OperationType.BATCH,
                input_file=Path("."),
                validation_errors=["No files found matching patterns"],
                would_succeed=False,
            )
            batch_operations.append(operation)
            return batch_operations

        # Simulate each file
        for file_path in all_files:
            if output_dir:
                output_path = output_dir / f"{file_path.stem}.{output_format.lower()}"
            else:
                output_path = None

            operation = self.simulate_conversion(
                file_path, output_format, output_path, quality, **kwargs
            )
            operation.operation_type = OperationType.BATCH
            operation.parameters["workers"] = workers
            batch_operations.append(operation)

        # Adjust time estimates for parallel processing
        if workers > 1:
            total_time = sum(op.estimated_time_seconds for op in batch_operations)
            parallel_time = total_time / min(workers, len(batch_operations))

            for op in batch_operations:
                op.parameters["batch_parallel_time"] = parallel_time

        return batch_operations

    def simulate_optimize(
        self,
        input_path: Path,
        preset: str = "web",
        target_size: Optional[str] = None,
        max_width: Optional[int] = None,
        max_height: Optional[int] = None,
        **kwargs,
    ) -> SimulatedOperation:
        """
        Simulate image optimization

        Args:
            input_path: Input file path
            preset: Optimization preset
            target_size: Target file size (e.g., "500KB")
            max_width: Maximum width
            max_height: Maximum height
            **kwargs: Additional parameters

        Returns:
            Simulated operation
        """
        operation = SimulatedOperation(
            operation_type=OperationType.OPTIMIZE,
            input_file=input_path,
            parameters={
                "preset": preset,
                "target_size": target_size,
                "max_width": max_width,
                "max_height": max_height,
                **kwargs,
            },
        )

        # Basic validation
        if not input_path.exists():
            operation.validation_errors.append(
                f"Input file does not exist: {input_path}"
            )
            operation.would_succeed = False
            return operation

        # Get input info
        try:
            operation.input_size_bytes = input_path.stat().st_size

            with Image.open(input_path) as img:
                operation.input_format = img.format.lower() if img.format else "unknown"
                width, height = img.size

                # Determine output format based on preset
                if preset == "web":
                    operation.output_format = "webp"
                elif preset == "print":
                    operation.output_format = "tiff"
                else:
                    operation.output_format = operation.input_format

                # Calculate resize if needed
                new_width, new_height = width, height
                if max_width and width > max_width:
                    new_width = max_width
                    new_height = int(height * (max_width / width))
                if max_height and new_height > max_height:
                    new_height = max_height
                    new_width = int(width * (max_height / height))

                resize_factor = (new_width * new_height) / (width * height)

                # Estimate output size
                preset_mod = self.PRESET_MODIFIERS.get(preset, {"size_multiplier": 1.0})
                operation.estimated_output_size_bytes = int(
                    operation.input_size_bytes
                    * preset_mod["size_multiplier"]
                    * resize_factor
                )

                # Parse target size if specified
                if target_size:
                    target_bytes = self._parse_size_string(target_size)
                    if target_bytes:
                        operation.estimated_output_size_bytes = min(
                            operation.estimated_output_size_bytes, target_bytes
                        )

                # Estimate time and resources
                operation.estimated_time_seconds = 2.0 + (
                    operation.input_size_bytes / (10 * 1024 * 1024)
                )
                operation.estimated_memory_mb = (
                    operation.input_size_bytes / 1024 / 1024
                ) * 3
                operation.estimated_cpu_percent = 60

        except Exception as e:
            operation.validation_errors.append(f"Cannot analyze image: {str(e)}")
            operation.would_succeed = False

        operation.output_file = input_path.with_stem(f"{input_path.stem}_optimized")

        self.operations.append(operation)
        return operation

    def _estimate_output_size(
        self,
        input_size: int,
        input_format: str,
        output_format: str,
        quality: int,
        preset: Optional[str],
        num_pixels: int,
    ) -> int:
        """Estimate output file size"""
        # Get format characteristics
        output_char = self.FORMAT_CHARACTERISTICS.get(
            output_format, {"compression_ratio": 0.5}
        )

        # Base estimation from compression ratio
        base_size = input_size * output_char["compression_ratio"]

        # Adjust for quality
        if output_char.get("quality_loss", False):
            quality_factor = quality / 100.0
            base_size *= (
                0.5 + 0.5 * quality_factor
            )  # 50% to 100% of base based on quality

        # Adjust for preset
        if preset and preset in self.PRESET_MODIFIERS:
            preset_mod = self.PRESET_MODIFIERS[preset]
            base_size *= preset_mod["size_multiplier"]

        # Minimum size based on pixel count
        min_size = num_pixels * 0.1  # At least 0.1 bytes per pixel

        return max(int(base_size), int(min_size))

    def _estimate_processing_time(
        self, input_size: int, output_format: str, num_pixels: int
    ) -> float:
        """Estimate processing time in seconds"""
        # Get format speed characteristic
        format_char = self.FORMAT_CHARACTERISTICS.get(output_format, {"speed": 1.0})
        speed_factor = format_char["speed"]

        # Base time: 1 second per 5MB at speed 1.0
        base_time = (input_size / (5 * 1024 * 1024)) / speed_factor

        # Add overhead for large images
        if num_pixels > 10_000_000:  # >10 megapixels
            base_time *= 1.5

        # Minimum time
        return max(0.1, base_time)

    def _estimate_memory_usage(self, input_size: int, num_pixels: int) -> float:
        """Estimate memory usage in MB"""
        # Rough estimation: 3x input size + pixel buffer
        pixel_buffer_size = num_pixels * 4  # 4 bytes per pixel (RGBA)
        total_bytes = (input_size * 3) + pixel_buffer_size
        return total_bytes / (1024 * 1024)

    def _estimate_cpu_usage(self, output_format: str) -> float:
        """Estimate CPU usage percentage"""
        # More complex formats use more CPU
        cpu_usage = {
            "avif": 90,
            "jxl": 85,
            "heif": 80,
            "heic": 80,
            "webp": 70,
            "jpeg": 60,
            "jpg": 60,
            "png": 65,
            "bmp": 40,
            "tiff": 50,
            "gif": 55,
        }
        return cpu_usage.get(output_format, 60)

    def _parse_size_string(self, size_str: str) -> Optional[int]:
        """Parse size string like '500KB' to bytes"""
        import re

        match = re.match(r"^(\d+(?:\.\d+)?)\s*([KMGT]?B)?$", size_str.upper())
        if not match:
            return None

        value = float(match.group(1))
        unit = match.group(2) or "B"

        multipliers = {
            "B": 1,
            "KB": 1024,
            "MB": 1024 * 1024,
            "GB": 1024 * 1024 * 1024,
            "TB": 1024 * 1024 * 1024 * 1024,
        }

        return int(value * multipliers.get(unit, 1))

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all simulated operations"""
        if not self.operations:
            return {
                "total_operations": 0,
                "would_succeed": 0,
                "would_fail": 0,
                "total_input_size": 0,
                "total_output_size": 0,
                "total_time": 0,
                "max_memory": 0,
                "max_cpu": 0,
            }

        successful = [op for op in self.operations if op.would_succeed]
        failed = [op for op in self.operations if not op.would_succeed]

        return {
            "total_operations": len(self.operations),
            "would_succeed": len(successful),
            "would_fail": len(failed),
            "total_input_size": sum(op.input_size_bytes for op in self.operations),
            "total_output_size": sum(
                op.estimated_output_size_bytes for op in successful
            ),
            "total_time": sum(op.estimated_time_seconds for op in successful),
            "max_memory": max((op.estimated_memory_mb for op in successful), default=0),
            "max_cpu": max((op.estimated_cpu_percent for op in successful), default=0),
            "validation_errors": [
                {"file": str(op.input_file), "errors": op.validation_errors}
                for op in failed
            ],
            "warnings": [
                {"file": str(op.input_file), "warnings": op.warnings}
                for op in self.operations
                if op.warnings
            ],
        }

    def format_summary(self, detailed: bool = False) -> str:
        """Format summary as human-readable string"""
        summary = self.get_summary()

        lines = []
        lines.append("=== DRY RUN SUMMARY ===")
        lines.append(f"Total operations: {summary['total_operations']}")
        lines.append(f"Would succeed: {summary['would_succeed']}")
        lines.append(f"Would fail: {summary['would_fail']}")
        lines.append("")

        if summary["would_succeed"] > 0:
            lines.append("Estimated Results:")
            input_mb = summary["total_input_size"] / (1024 * 1024)
            output_mb = summary["total_output_size"] / (1024 * 1024)
            reduction = (1 - output_mb / input_mb) * 100 if input_mb > 0 else 0

            lines.append(f"  Input size:  {input_mb:.2f} MB")
            lines.append(f"  Output size: {output_mb:.2f} MB")
            lines.append(f"  Size reduction: {reduction:.1f}%")
            lines.append(f"  Processing time: {summary['total_time']:.1f} seconds")
            lines.append(f"  Max memory: {summary['max_memory']:.1f} MB")
            lines.append(f"  Max CPU: {summary['max_cpu']:.0f}%")
            lines.append("")

        if summary["validation_errors"]:
            lines.append("Validation Errors:")
            for error_info in summary["validation_errors"]:
                lines.append(f"  {error_info['file']}:")
                for error in error_info["errors"]:
                    lines.append(f"    - {error}")
            lines.append("")

        if summary["warnings"] and detailed:
            lines.append("Warnings:")
            for warning_info in summary["warnings"]:
                lines.append(f"  {warning_info['file']}:")
                for warning in warning_info["warnings"]:
                    lines.append(f"    - {warning}")
            lines.append("")

        if detailed and self.operations:
            lines.append("Detailed Operations:")
            for i, op in enumerate(self.operations, 1):
                lines.append(f"  {i}. {op.input_file.name} -> {op.output_format}")
                lines.append(f"     Status: {'✓' if op.would_succeed else '✗'}")
                if op.would_succeed:
                    size_mb = op.estimated_output_size_bytes / (1024 * 1024)
                    lines.append(f"     Estimated size: {size_mb:.2f} MB")
                    lines.append(
                        f"     Estimated time: {op.estimated_time_seconds:.1f}s"
                    )

        return "\n".join(lines)

    def estimate_single_conversion(
        self,
        input_path: Path,
        output_format: str,
        quality: int = 85,
        preset: Optional[str] = None,
    ) -> ConversionEstimate:
        """Estimate a single file conversion"""
        input_size = input_path.stat().st_size if input_path.exists() else 0

        # Get format characteristics
        format_info = self.FORMAT_CHARACTERISTICS.get(output_format.lower(), {})
        base_ratio = format_info.get("compression_ratio", 0.5)
        speed = format_info.get("speed", 1.0)

        # Apply quality modifier
        quality_factor = quality / 100.0
        compression_ratio = base_ratio * (0.5 + quality_factor * 0.5)

        # Apply preset modifier
        if preset and preset in self.PRESET_MODIFIERS:
            modifier = self.PRESET_MODIFIERS[preset]
            compression_ratio *= modifier.get("size_multiplier", 1.0)

        estimated_output_size = int(input_size * compression_ratio)
        estimated_time = (
            input_size / (1024 * 1024)
        ) / speed  # Time based on MB and speed

        # Resource estimation
        memory_mb = min(input_size / (1024 * 1024) * 3, 2048)  # 3x input size, max 2GB
        cpu_percent = min(85, 100 / speed)  # Slower formats use more CPU

        return ConversionEstimate(
            input_file=str(input_path),
            output_format=output_format,
            input_size=input_size,
            estimated_output_size=estimated_output_size,
            estimated_time_seconds=estimated_time,
            estimated_memory_mb=memory_mb if self.estimate_resources else 0,
            estimated_cpu_percent=cpu_percent if self.estimate_resources else 0,
            compression_ratio=compression_ratio,
            success_probability=0.95 if format_info else 0.8,
        )

    def estimate_batch(
        self, input_files: List[Path], output_format: str, parallel_workers: int = 4
    ) -> BatchEstimate:
        """Estimate batch conversion"""
        file_estimates = []
        total_input_size = 0
        total_output_size = 0
        total_time = 0

        for file in input_files:
            estimate = self.estimate_single_conversion(file, output_format)
            file_estimates.append(estimate)
            total_input_size += estimate.input_size
            total_output_size += estimate.estimated_output_size
            total_time += estimate.estimated_time_seconds

        # Calculate parallel time
        parallel_time = (
            total_time / min(parallel_workers, len(input_files)) if input_files else 0
        )

        return BatchEstimate(
            total_files=len(input_files),
            total_input_size=total_input_size,
            total_estimated_output_size=total_output_size,
            estimated_total_output_size_bytes=total_output_size,
            estimated_total_time_seconds=total_time,
            estimated_parallel_time_seconds=parallel_time,
            file_estimates=file_estimates,
            parallel_workers=parallel_workers,
            worker_count=parallel_workers,
        )

    def validate_input(self, input_path: Path) -> ValidationResult:
        """Validate input file"""
        errors = []
        warnings = []

        if not input_path.exists():
            errors.append(f"File does not exist: {input_path}")
        elif not input_path.is_file():
            errors.append(f"Not a file: {input_path}")
        elif not os.access(input_path, os.R_OK):
            errors.append(f"File is not readable: {input_path}")
        else:
            # Check file size
            size = input_path.stat().st_size
            if size == 0:
                errors.append("File is empty")
            elif size > 500 * 1024 * 1024:  # 500MB
                warnings.append("File is very large (>500MB), processing may be slow")

        return ValidationResult(
            is_valid=len(errors) == 0, errors=errors, warnings=warnings
        )

    def validate_output(self, output_path: Path) -> ValidationResult:
        """Validate output path permissions"""
        errors = []
        warnings = []

        output_dir = output_path.parent
        if not output_dir.exists():
            warnings.append(f"Output directory will be created: {output_dir}")
        elif not os.access(output_dir, os.W_OK):
            errors.append(f"Output directory is not writable: {output_dir}")

        if output_path.exists():
            warnings.append(
                f"Output file exists and will be overwritten: {output_path}"
            )

        return ValidationResult(
            is_valid=len(errors) == 0, errors=errors, warnings=warnings
        )

    def estimate_resources(
        self, input_size: int, output_format: str
    ) -> ResourceEstimate:
        """Estimate resource requirements"""
        # Memory: ~3x input size for processing, capped at 2GB
        memory_mb = min(input_size / (1024 * 1024) * 3, 2048)

        # CPU: Based on format complexity
        format_info = self.FORMAT_CHARACTERISTICS.get(output_format.lower(), {})
        speed = format_info.get("speed", 1.0)
        cpu_percent = min(85, 100 / speed)

        # Disk I/O
        disk_io_mb = input_size / (1024 * 1024) * 2  # Read + write

        # Duration
        duration = (input_size / (1024 * 1024)) / speed

        return ResourceEstimate(
            memory_mb=memory_mb,
            cpu_percent=cpu_percent,
            disk_io_mb=disk_io_mb,
            estimated_duration_seconds=duration,
        )

    def get_format_estimates(
        self, input_format: str, output_format: str
    ) -> Dict[str, Any]:
        """Get format-specific estimates"""
        input_info = self.FORMAT_CHARACTERISTICS.get(input_format.lower(), {})
        output_info = self.FORMAT_CHARACTERISTICS.get(output_format.lower(), {})

        return {
            "quality_loss": output_info.get("quality_loss", False),
            "compression_improvement": (
                input_info.get("compression_ratio", 1.0)
                / output_info.get("compression_ratio", 1.0)
            ),
            "speed_ratio": output_info.get("speed", 1.0) / input_info.get("speed", 1.0),
            "recommended": output_info.get("compression_ratio", 1.0)
            < input_info.get("compression_ratio", 1.0),
        }

    def apply_quality_modifiers(self, base_size: int, quality: int) -> int:
        """Apply quality settings to size estimate"""
        # Higher quality = larger file
        quality_factor = quality / 100.0
        # Exponential curve: quality affects size more at higher values
        size_factor = 0.3 + (quality_factor**1.5) * 0.7
        return int(base_size * size_factor)

    def set_mode(self, mode: SimulationMode) -> None:
        """Set simulation mode"""
        self.mode = mode

    def generate_warnings(self, operation: SimulatedOperation) -> List[str]:
        """Generate contextual warnings"""
        warnings = []

        if operation.input_size_bytes > 100 * 1024 * 1024:
            warnings.append("Large file may take significant time to process")

        if operation.output_format in ["avif", "jxl"]:
            warnings.append(
                f"{operation.output_format.upper()} format may have limited compatibility"
            )

        if operation.parameters.get("quality", 85) < 70:
            warnings.append("Low quality setting may result in visible artifacts")

        return warnings

    def validate_only_mode(
        self, input_path: Path, output_path: Path
    ) -> ValidationResult:
        """Pure validation without estimation"""
        all_errors = []
        all_warnings = []

        # Validate input
        input_validation = self.validate_input(input_path)
        all_errors.extend(input_validation.errors)
        all_warnings.extend(input_validation.warnings)

        # Validate output
        output_validation = self.validate_output(output_path)
        all_errors.extend(output_validation.errors)
        all_warnings.extend(output_validation.warnings)

        return ValidationResult(
            is_valid=len(all_errors) == 0, errors=all_errors, warnings=all_warnings
        )

    def get_verbose_details(self, operation: SimulatedOperation) -> Dict[str, Any]:
        """Get detailed information for verbose mode"""
        return {
            "operation": operation.operation_type.value,
            "input": {
                "file": str(operation.input_file),
                "format": operation.input_format,
                "size_bytes": operation.input_size_bytes,
                "size_mb": operation.input_size_bytes / (1024 * 1024),
            },
            "output": {
                "file": str(operation.output_file) if operation.output_file else None,
                "format": operation.output_format,
                "estimated_size_bytes": operation.estimated_output_size_bytes,
                "estimated_size_mb": operation.estimated_output_size_bytes
                / (1024 * 1024),
            },
            "performance": {
                "estimated_time_seconds": operation.estimated_time_seconds,
                "estimated_memory_mb": operation.estimated_memory_mb,
                "estimated_cpu_percent": operation.estimated_cpu_percent,
            },
            "parameters": operation.parameters,
            "warnings": operation.warnings,
            "validation_errors": operation.validation_errors,
            "would_succeed": operation.would_succeed,
        }

    def apply_preset_effects(
        self, estimate: ConversionEstimate, preset: str
    ) -> ConversionEstimate:
        """Apply preset modifications to estimate"""
        if preset not in self.PRESET_MODIFIERS:
            return estimate

        modifier = self.PRESET_MODIFIERS[preset]
        estimate.estimated_output_size = int(
            estimate.estimated_output_size * modifier.get("size_multiplier", 1.0)
        )
        estimate.compression_ratio = (
            estimate.estimated_output_size / estimate.input_size
        )

        return estimate

    def check_disk_space(self, output_path: Path, required_bytes: int) -> bool:
        """Check if enough disk space is available"""
        import shutil

        stat = shutil.disk_usage(
            output_path.parent if output_path.parent.exists() else Path.cwd()
        )
        return stat.free > required_bytes * 1.1  # 10% buffer

    def calculate_parallel_efficiency(self, num_files: int, workers: int) -> float:
        """Calculate efficiency of parallel processing"""
        if num_files <= 0 or workers <= 0:
            return 0.0

        # Diminishing returns formula
        ideal_speedup = min(workers, num_files)
        overhead = 0.1 * workers  # 10% overhead per worker
        actual_speedup = ideal_speedup / (1 + overhead)

        return actual_speedup / workers  # Efficiency as percentage

    def estimate_memory_usage(self, input_size: int, format: str) -> float:
        """Accurate memory estimation based on format"""
        base_memory = input_size / (1024 * 1024)  # Convert to MB

        # Format-specific multipliers
        memory_multipliers = {
            "jpeg": 2.5,
            "jpg": 2.5,
            "png": 3.0,
            "webp": 3.5,
            "avif": 4.0,
            "heif": 3.8,
            "heic": 3.8,
            "jxl": 4.5,
            "bmp": 1.5,
            "tiff": 2.0,
            "gif": 2.0,
        }

        multiplier = memory_multipliers.get(format.lower(), 3.0)
        return min(base_memory * multiplier, 4096)  # Cap at 4GB

    def handle_edge_cases(self, operation: SimulatedOperation) -> SimulatedOperation:
        """Handle special cases and edge conditions"""
        # Empty file
        if operation.input_size_bytes == 0:
            operation.validation_errors.append("Cannot process empty file")
            operation.would_succeed = False

        # Huge file
        elif operation.input_size_bytes > 2 * 1024 * 1024 * 1024:  # 2GB
            operation.warnings.append("File exceeds 2GB, may require special handling")

        # Format compatibility
        problem_conversions = [
            ("gif", "avif"),  # Animated GIF to AVIF can be problematic
            ("bmp", "heic"),  # BMP to HEIC may not preserve all data
        ]

        conversion = (operation.input_format, operation.output_format)
        if conversion in problem_conversions:
            operation.warnings.append(
                f"Conversion from {operation.input_format} to {operation.output_format} may have compatibility issues"
            )
            operation.success_probability = 0.7

        return operation

    def reset(self) -> None:
        """Reset all simulated operations"""
        self.operations.clear()
