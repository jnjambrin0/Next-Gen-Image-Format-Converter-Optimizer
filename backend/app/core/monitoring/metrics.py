"""Conversion-specific metrics collection for performance tracking."""

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ConversionMetrics:
    """Detailed metrics for a single conversion operation."""

    # Basic info
    conversion_id: str
    input_format: str
    output_format: str
    requested_format: str  # Original requested format before fallback

    # Timing metrics
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    # Size metrics
    input_size_bytes: int = 0
    output_size_bytes: int = 0

    # Memory metrics
    estimated_memory_mb: int = 0
    peak_memory_mb: int = 0
    memory_violations: int = 0

    # Tool usage
    external_tools_used: List[str] = field(default_factory=list)
    tool_execution_times: Dict[str, float] = field(default_factory=dict)

    # Fallback info
    fallback_used: bool = False
    fallback_reason: Optional[str] = None

    # Sandbox metrics
    sandbox_used: bool = False
    sandbox_execution_time: Optional[float] = None
    sandbox_violations: List[str] = field(default_factory=list)

    # Quality metrics
    quality_settings: Dict[str, Any] = field(default_factory=dict)
    optimization_applied: bool = False

    # Error tracking
    error_occurred: bool = False
    error_type: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def duration_ms(self) -> float:
        """Get total duration in milliseconds."""
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time) * 1000

    @property
    def compression_ratio(self) -> float:
        """Calculate compression ratio."""
        if self.input_size_bytes == 0 or self.output_size_bytes == 0:
            return 0.0
        return self.input_size_bytes / self.output_size_bytes

    @property
    def size_reduction_percent(self) -> float:
        """Calculate size reduction percentage."""
        if self.input_size_bytes == 0:
            return 0.0
        return (
            (self.input_size_bytes - self.output_size_bytes) / self.input_size_bytes
        ) * 100

    @property
    def memory_efficiency(self) -> float:
        """Calculate memory efficiency (actual vs estimated)."""
        if self.estimated_memory_mb == 0:
            return 0.0
        return (self.peak_memory_mb / self.estimated_memory_mb) * 100

    def mark_complete(self, output_size: int) -> None:
        """Mark conversion as complete."""
        self.end_time = time.time()
        self.output_size_bytes = output_size

    def mark_error(self, error_type: str, error_message: str) -> None:
        """Mark conversion as failed."""
        self.end_time = time.time()
        self.error_occurred = True
        self.error_type = error_type
        self.error_message = error_message

    def add_tool_usage(self, tool_name: str, execution_time: float) -> None:
        """Record external tool usage."""
        if tool_name not in self.external_tools_used:
            self.external_tools_used.append(tool_name)
        self.tool_execution_times[tool_name] = execution_time

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "conversion_id": self.conversion_id,
            "input_format": self.input_format,
            "output_format": self.output_format,
            "requested_format": self.requested_format,
            "duration_ms": self.duration_ms,
            "input_size_bytes": self.input_size_bytes,
            "output_size_bytes": self.output_size_bytes,
            "compression_ratio": round(self.compression_ratio, 2),
            "size_reduction_percent": round(self.size_reduction_percent, 2),
            "memory": {
                "estimated_mb": self.estimated_memory_mb,
                "peak_mb": self.peak_memory_mb,
                "efficiency_percent": round(self.memory_efficiency, 2),
                "violations": self.memory_violations,
            },
            "tools": {
                "external_tools_used": self.external_tools_used,
                "execution_times": self.tool_execution_times,
                "total_tool_time_ms": sum(self.tool_execution_times.values()) * 1000,
            },
            "fallback": {
                "used": self.fallback_used,
                "reason": self.fallback_reason,
            },
            "sandbox": {
                "used": self.sandbox_used,
                "execution_time": self.sandbox_execution_time,
                "violations": self.sandbox_violations,
            },
            "quality": {
                "settings": self.quality_settings,
                "optimization_applied": self.optimization_applied,
            },
            "error": {
                "occurred": self.error_occurred,
                "type": self.error_type,
                "message": self.error_message,
            },
        }


class MetricsCollector:
    """Collects and aggregates conversion metrics."""

    def __init__(self, max_history: int = 1000):
        """
        Initialize metrics collector.

        Args:
            max_history: Maximum number of metrics to keep in memory
        """
        self.max_history = max_history
        self._metrics_history: List[ConversionMetrics] = []
        self._current_metrics: Dict[str, ConversionMetrics] = {}

    def start_conversion(
        self,
        conversion_id: str,
        input_format: str,
        output_format: str,
        requested_format: str,
        input_size: int,
        estimated_memory_mb: int,
    ) -> ConversionMetrics:
        """Start tracking a new conversion."""
        metrics = ConversionMetrics(
            conversion_id=conversion_id,
            input_format=input_format,
            output_format=output_format,
            requested_format=requested_format,
            input_size_bytes=input_size,
            estimated_memory_mb=estimated_memory_mb,
        )

        self._current_metrics[conversion_id] = metrics
        return metrics

    def get_metrics(self, conversion_id: str) -> Optional[ConversionMetrics]:
        """Get metrics for a specific conversion."""
        return self._current_metrics.get(conversion_id)

    def complete_conversion(
        self, conversion_id: str, output_size: int, peak_memory_mb: Optional[int] = None
    ) -> None:
        """Mark a conversion as complete."""
        if conversion_id not in self._current_metrics:
            return

        metrics = self._current_metrics[conversion_id]
        metrics.mark_complete(output_size)

        if peak_memory_mb is not None:
            metrics.peak_memory_mb = peak_memory_mb

        # Move to history
        self._add_to_history(metrics)
        del self._current_metrics[conversion_id]

        logger.info(
            "Conversion completed",
            conversion_id=conversion_id,
            duration_ms=metrics.duration_ms,
            compression_ratio=metrics.compression_ratio,
        )

    def fail_conversion(
        self, conversion_id: str, error_type: str, error_message: str
    ) -> None:
        """Mark a conversion as failed."""
        if conversion_id not in self._current_metrics:
            return

        metrics = self._current_metrics[conversion_id]
        metrics.mark_error(error_type, error_message)

        # Move to history
        self._add_to_history(metrics)
        del self._current_metrics[conversion_id]

        logger.info(
            "Conversion failed",
            conversion_id=conversion_id,
            error_type=error_type,
            duration_ms=metrics.duration_ms,
        )

    def _add_to_history(self, metrics: ConversionMetrics) -> None:
        """Add metrics to history, maintaining size limit."""
        self._metrics_history.append(metrics)

        # Keep only recent history
        if len(self._metrics_history) > self.max_history:
            self._metrics_history = self._metrics_history[-self.max_history :]

    def get_recent_metrics(self, count: int = 100) -> List[ConversionMetrics]:
        """Get recent conversion metrics."""
        return self._metrics_history[-count:]

    def get_aggregate_stats(self) -> Dict[str, Any]:
        """Get aggregate statistics from recent conversions."""
        if not self._metrics_history:
            return {
                "total_conversions": 0,
                "success_rate": 0.0,
                "average_duration_ms": 0.0,
                "average_compression_ratio": 0.0,
                "formats_used": {},
                "tools_used": {},
                "fallback_rate": 0.0,
            }

        total = len(self._metrics_history)
        successful = sum(1 for m in self._metrics_history if not m.error_occurred)

        durations = [m.duration_ms for m in self._metrics_history if m.duration_ms > 0]
        compression_ratios = [
            m.compression_ratio
            for m in self._metrics_history
            if m.compression_ratio > 0 and not m.error_occurred
        ]

        # Format usage
        format_counts = {}
        for m in self._metrics_history:
            key = f"{m.input_format}->{m.output_format}"
            format_counts[key] = format_counts.get(key, 0) + 1

        # Tool usage
        tool_counts = {}
        for m in self._metrics_history:
            for tool in m.external_tools_used:
                tool_counts[tool] = tool_counts.get(tool, 0) + 1

        # Fallback usage
        fallback_count = sum(1 for m in self._metrics_history if m.fallback_used)

        return {
            "total_conversions": total,
            "success_rate": (successful / total * 100) if total > 0 else 0.0,
            "average_duration_ms": (
                sum(durations) / len(durations) if durations else 0.0
            ),
            "average_compression_ratio": (
                sum(compression_ratios) / len(compression_ratios)
                if compression_ratios
                else 0.0
            ),
            "formats_used": format_counts,
            "tools_used": tool_counts,
            "fallback_rate": (fallback_count / total * 100) if total > 0 else 0.0,
        }


# Create singleton instance
metrics_collector = MetricsCollector()
