"""
CLI profiling utilities for performance tracking.
Provides decorators and context managers for profiling CLI operations.
"""

import time
import json
import functools
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from contextlib import contextmanager
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from app.core.monitoring.performance import (
    performance_profiler,
    ConversionMetrics,
    BatchMetrics,
)
from app.cli.utils.emoji import get_emoji, should_use_emoji
from app.cli.ui.themes import get_theme_manager

# Initialize themed console
theme_manager = get_theme_manager()
console = theme_manager.create_console()


class CLIProfiler:
    """
    CLI-specific profiler for tracking command performance.
    """

    def __init__(self):
        """Initialize CLI profiler."""
        self.enabled = False
        self.output_path: Optional[Path] = None
        self.show_summary = True
        self.current_metrics = None

    def enable(self, output_path: Optional[Path] = None, show_summary: bool = True):
        """
        Enable profiling for CLI commands.

        Args:
            output_path: Optional path to save profile JSON
            show_summary: Whether to show summary after command
        """
        self.enabled = True
        self.output_path = output_path
        self.show_summary = show_summary

    def disable(self):
        """Disable profiling."""
        self.enabled = False
        self.output_path = None

    @contextmanager
    def profile_operation(self, operation_name: str):
        """
        Context manager for profiling an operation.

        Args:
            operation_name: Name of the operation to profile
        """
        if not self.enabled:
            yield
            return

        start_time = time.time()

        try:
            performance_profiler.start_profile(operation_name)
            yield
        finally:
            duration = time.time() - start_time
            performance_profiler.add_operation(operation_name, duration)
            profile_data = performance_profiler.stop_profile()

            if profile_data and self.show_summary:
                self.display_profile_summary(profile_data)

            if profile_data and self.output_path:
                self.save_profile(profile_data)

    def track_conversion(
        self,
        input_size: int,
        output_size: int,
        duration: float,
        input_format: str = "",
        output_format: str = "",
        memory_used: int = 0,
    ):
        """
        Track metrics for a single conversion.

        Args:
            input_size: Input file size in bytes
            output_size: Output file size in bytes
            duration: Processing time in seconds
            input_format: Input format name
            output_format: Output format name
            memory_used: Memory used in bytes
        """
        if not self.enabled:
            return

        self.current_metrics = ConversionMetrics(
            file_size=input_size,
            output_size=output_size,
            processing_time=duration,
            memory_used=memory_used,
            input_format=input_format,
            output_format=output_format,
        )

        performance_profiler.add_operation(
            "conversion",
            duration,
            input_mb=input_size / 1024 / 1024,
            output_mb=output_size / 1024 / 1024,
            compression_ratio=input_size / output_size if output_size > 0 else 0,
        )

    def display_profile_summary(self, profile_data: Dict[str, Any]):
        """
        Display a formatted summary of profile data.

        Args:
            profile_data: Profile data dictionary
        """
        # Create main summary table
        summary_table = Table(
            title="Performance Profile Summary",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
        )

        summary_table.add_column("Metric", style="cyan", width=30)
        summary_table.add_column("Value", style="green", justify="right")

        # Add basic metrics
        summary_table.add_row(
            "Total Duration",
            f"{profile_data.get('total_duration_seconds', 0):.3f} seconds",
        )
        summary_table.add_row(
            "Operations Count", str(profile_data.get("operations_count", 0))
        )

        # Add performance metrics if available
        perf = profile_data.get("performance", {})
        if perf:
            cpu_data = perf.get("cpu", {})
            memory_data = perf.get("memory", {})
            io_data = perf.get("io", {})

            if cpu_data:
                summary_table.add_row(
                    "Average CPU Usage", f"{cpu_data.get('average_percent', 0):.1f}%"
                )
                summary_table.add_row(
                    "Peak CPU Usage", f"{cpu_data.get('peak_percent', 0):.1f}%"
                )

            if memory_data:
                summary_table.add_row(
                    "Memory Start", f"{memory_data.get('start_mb', 0):.1f} MB"
                )
                summary_table.add_row(
                    "Memory Peak", f"{memory_data.get('peak_mb', 0):.1f} MB"
                )
                summary_table.add_row(
                    "Memory Delta", f"{memory_data.get('delta_mb', 0):+.1f} MB"
                )

            if io_data:
                summary_table.add_row(
                    "Data Read", f"{io_data.get('read_mb', 0):.1f} MB"
                )
                summary_table.add_row(
                    "Data Written", f"{io_data.get('write_mb', 0):.1f} MB"
                )

        console.print("\n")
        console.print(summary_table)

        # Show operation breakdown if available
        op_stats = profile_data.get("operation_stats", {})
        if op_stats:
            ops_table = Table(
                title="Operation Breakdown",
                show_header=True,
                header_style="bold cyan",
                box=box.SIMPLE,
            )

            ops_table.add_column("Operation", style="yellow")
            ops_table.add_column("Count", justify="right")
            ops_table.add_column("Total (s)", justify="right")
            ops_table.add_column("Average (s)", justify="right")
            ops_table.add_column("Min (s)", justify="right")
            ops_table.add_column("Max (s)", justify="right")

            for op_name, stats in op_stats.items():
                ops_table.add_row(
                    op_name,
                    str(stats.get("count", 0)),
                    f"{stats.get('total_seconds', 0):.3f}",
                    f"{stats.get('average_seconds', 0):.3f}",
                    f"{stats.get('min_seconds', 0):.3f}",
                    f"{stats.get('max_seconds', 0):.3f}",
                )

            console.print("\n")
            console.print(ops_table)

        # Show current conversion metrics if available
        if self.current_metrics:
            metrics_dict = self.current_metrics.to_json()

            conversion_table = Table(
                title="Conversion Metrics", show_header=False, box=box.SIMPLE
            )

            conversion_table.add_column("Metric", style="dim")
            conversion_table.add_column("Value", style="info")

            conversion_table.add_row("Input Size", f"{metrics_dict['input_mb']:.2f} MB")
            conversion_table.add_row(
                "Output Size", f"{metrics_dict['output_mb']:.2f} MB"
            )
            conversion_table.add_row(
                "Compression Ratio", f"{metrics_dict['compression_ratio']:.2f}x"
            )
            conversion_table.add_row(
                "Processing Time", f"{metrics_dict['time_seconds']:.3f} seconds"
            )
            conversion_table.add_row(
                "Throughput", f"{metrics_dict['throughput_mbps']:.2f} MB/s"
            )

            console.print("\n")
            console.print(conversion_table)

    def save_profile(self, profile_data: Dict[str, Any]):
        """
        Save profile data to JSON file.

        Args:
            profile_data: Profile data to save
        """
        if not self.output_path:
            # Generate default path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_path = Path(f"profile_{timestamp}.json")

        try:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_path, "w") as f:
                json.dump(profile_data, f, indent=2)

            if should_use_emoji():
                console.print(
                    f"\n[success]{get_emoji('success')} Profile saved to: [cyan]{self.output_path}[/cyan][/success]"
                )
            else:
                console.print(
                    f"\n[success]Profile saved to: [cyan]{self.output_path}[/cyan][/success]"
                )
        except Exception as e:
            console.print(f"[error]Failed to save profile: {e}[/error]")

    def display_batch_metrics(self, batch_metrics: BatchMetrics):
        """
        Display formatted batch processing metrics.

        Args:
            batch_metrics: Batch metrics object
        """
        report = batch_metrics.to_json()

        # Create summary panel
        summary = report["summary"]
        perf = report["performance"]

        summary_text = f"""
[bold]Batch Processing Complete[/bold]

Files: {summary['completed']}/{summary['total_files']} completed ({summary['success_rate']:.1f}% success)
Time: {summary['elapsed_time_seconds']:.2f} seconds
Workers: {summary['worker_count']} ({summary['worker_efficiency_percent']:.1f}% efficiency)

[bold]Performance:[/bold]
• Throughput: {perf['throughput_files_per_second']:.2f} files/second
• Average Time: {perf['average_time_per_file']:.3f} seconds/file
• Total Input: {perf['total_input_mb']:.2f} MB
• Total Output: {perf['total_output_mb']:.2f} MB
• Compression: {perf['compression_ratio']:.2f}x
• Peak Memory: {perf['peak_memory_mb']:.2f} MB
"""

        panel = Panel(
            summary_text.strip(),
            title="Batch Performance Profile",
            border_style="green",
            box=box.DOUBLE,
        )

        console.print("\n")
        console.print(panel)

        # Show file details if available
        file_details = report.get("file_details", [])
        if file_details:
            files_table = Table(
                title="Recent File Metrics",
                show_header=True,
                header_style="bold",
                box=box.SIMPLE_HEAD,
            )

            files_table.add_column("Format", style="cyan")
            files_table.add_column("Input", justify="right")
            files_table.add_column("Output", justify="right")
            files_table.add_column("Time", justify="right")
            files_table.add_column("Ratio", justify="right")

            for file_metric in file_details[-5:]:  # Show last 5 files
                files_table.add_row(
                    f"{file_metric['input_format']}→{file_metric['output_format']}",
                    f"{file_metric['input_mb']:.1f} MB",
                    f"{file_metric['output_mb']:.1f} MB",
                    f"{file_metric['time_seconds']:.2f}s",
                    f"{file_metric['compression_ratio']:.1f}x",
                )

            console.print("\n")
            console.print(files_table)


# Create singleton instance
cli_profiler = CLIProfiler()


def profile_command(func: Callable) -> Callable:
    """
    Decorator for profiling CLI commands.

    Usage:
        @profile_command
        def my_command(args):
            ...
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Check if profiling is enabled via kwargs
        profile = kwargs.pop("profile", False)
        profile_output = kwargs.pop("profile_output", None)

        if profile:
            cli_profiler.enable(
                output_path=Path(profile_output) if profile_output else None,
                show_summary=True,
            )

            with cli_profiler.profile_operation(func.__name__):
                result = func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)

        return result

    return wrapper
