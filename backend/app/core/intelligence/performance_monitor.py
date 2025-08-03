"""Performance monitoring for Intelligence Engine.

Provides real-time monitoring of:
- Classification latency
- Memory usage
- Cache efficiency
- Concurrency metrics
- Resource utilization
"""

import time
import asyncio
import psutil
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging
import statistics

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    timestamp: datetime = field(default_factory=datetime.now)
    classification_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    cache_hit_rate: float = 0.0
    concurrent_requests: int = 0
    cpu_percent: float = 0.0
    
    # Detailed breakdowns
    phase_times: Dict[str, float] = field(default_factory=dict)
    image_dimensions: tuple = (0, 0)
    image_size_bytes: int = 0
    content_type: str = ""
    confidence: float = 0.0
    
    # Resource usage
    memory_peak_mb: float = 0.0
    gc_collections: int = 0


class PerformanceMonitor:
    """Monitor and track Intelligence Engine performance."""
    
    def __init__(self, window_size: int = 100):
        """Initialize performance monitor.
        
        Args:
            window_size: Number of recent metrics to keep
        """
        self.window_size = window_size
        self.metrics: List[PerformanceMetrics] = []
        self._lock = asyncio.Lock()
        
        # Running statistics
        self.total_classifications = 0
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Resource tracking
        self.process = psutil.Process()
        self.start_time = time.time()
    
    async def record_classification(
        self,
        metrics: PerformanceMetrics
    ) -> None:
        """Record classification metrics.
        
        Args:
            metrics: Performance metrics to record
        """
        async with self._lock:
            self.metrics.append(metrics)
            self.total_classifications += 1
            
            # Maintain window size
            if len(self.metrics) > self.window_size:
                self.metrics.pop(0)
    
    async def record_cache_access(self, hit: bool) -> None:
        """Record cache hit/miss.
        
        Args:
            hit: Whether cache hit occurred
        """
        async with self._lock:
            if hit:
                self.cache_hits += 1
            else:
                self.cache_misses += 1
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current performance statistics.
        
        Returns:
            Dictionary of performance statistics
        """
        if not self.metrics:
            return self._empty_stats()
        
        recent_metrics = self.metrics[-10:]  # Last 10 classifications
        
        # Calculate statistics
        latencies = [m.classification_time_ms for m in recent_metrics]
        memory_usage = [m.memory_usage_mb for m in recent_metrics]
        cpu_usage = [m.cpu_percent for m in recent_metrics]
        confidences = [m.confidence for m in recent_metrics if m.confidence > 0]
        
        # Cache statistics
        total_cache_accesses = self.cache_hits + self.cache_misses
        cache_hit_rate = (
            self.cache_hits / total_cache_accesses 
            if total_cache_accesses > 0 else 0.0
        )
        
        # Resource usage
        current_memory = self.process.memory_info().rss / 1024 / 1024
        current_cpu = self.process.cpu_percent(interval=0.1)
        
        return {
            "summary": {
                "total_classifications": self.total_classifications,
                "uptime_seconds": time.time() - self.start_time,
                "average_latency_ms": statistics.mean(latencies) if latencies else 0,
                "p95_latency_ms": self._percentile(latencies, 0.95),
                "p99_latency_ms": self._percentile(latencies, 0.99),
                "cache_hit_rate": cache_hit_rate,
                "current_memory_mb": current_memory,
                "current_cpu_percent": current_cpu,
            },
            "recent_performance": {
                "latency_trend": latencies,
                "memory_trend": memory_usage,
                "cpu_trend": cpu_usage,
                "confidence_avg": statistics.mean(confidences) if confidences else 0,
            },
            "resource_usage": {
                "memory_mb": {
                    "current": current_memory,
                    "average": statistics.mean(memory_usage) if memory_usage else 0,
                    "peak": max(memory_usage) if memory_usage else 0,
                },
                "cpu_percent": {
                    "current": current_cpu,
                    "average": statistics.mean(cpu_usage) if cpu_usage else 0,
                    "peak": max(cpu_usage) if cpu_usage else 0,
                }
            },
            "phase_breakdown": self._get_phase_breakdown(recent_metrics),
        }
    
    def check_performance_degradation(self) -> Optional[str]:
        """Check for performance degradation.
        
        Returns:
            Warning message if degradation detected, None otherwise
        """
        if len(self.metrics) < 10:
            return None
        
        recent = self.metrics[-10:]
        older = self.metrics[-20:-10] if len(self.metrics) >= 20 else self.metrics[:10]
        
        # Compare latencies
        recent_latency = statistics.mean(m.classification_time_ms for m in recent)
        older_latency = statistics.mean(m.classification_time_ms for m in older)
        
        if recent_latency > older_latency * 1.5:
            return f"Performance degradation detected: latency increased from {older_latency:.1f}ms to {recent_latency:.1f}ms"
        
        # Check memory growth
        recent_memory = statistics.mean(m.memory_usage_mb for m in recent)
        older_memory = statistics.mean(m.memory_usage_mb for m in older)
        
        if recent_memory > older_memory * 1.3:
            return f"Memory usage increasing: from {older_memory:.1f}MB to {recent_memory:.1f}MB"
        
        return None
    
    async def log_performance_summary(self) -> None:
        """Log performance summary."""
        stats = self.get_current_stats()
        summary = stats["summary"]
        
        logger.info(
            f"Performance Summary - "
            f"Total: {summary['total_classifications']}, "
            f"Avg Latency: {summary['average_latency_ms']:.1f}ms, "
            f"P95: {summary['p95_latency_ms']:.1f}ms, "
            f"Cache Hit: {summary['cache_hit_rate']:.1%}, "
            f"Memory: {summary['current_memory_mb']:.1f}MB"
        )
        
        # Check for issues
        warning = self.check_performance_degradation()
        if warning:
            logger.warning(warning)
    
    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile of values."""
        if not values:
            return 0.0
        
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile)
        index = min(index, len(sorted_values) - 1)
        return sorted_values[index]
    
    def _get_phase_breakdown(self, metrics: List[PerformanceMetrics]) -> Dict[str, float]:
        """Get average phase timing breakdown."""
        if not metrics:
            return {}
        
        all_phases = {}
        for m in metrics:
            for phase, time_ms in m.phase_times.items():
                if phase not in all_phases:
                    all_phases[phase] = []
                all_phases[phase].append(time_ms)
        
        return {
            phase: statistics.mean(times)
            for phase, times in all_phases.items()
        }
    
    def _empty_stats(self) -> Dict[str, Any]:
        """Return empty statistics structure."""
        return {
            "summary": {
                "total_classifications": 0,
                "uptime_seconds": 0,
                "average_latency_ms": 0,
                "p95_latency_ms": 0,
                "p99_latency_ms": 0,
                "cache_hit_rate": 0,
                "current_memory_mb": 0,
                "current_cpu_percent": 0,
            },
            "recent_performance": {
                "latency_trend": [],
                "memory_trend": [],
                "cpu_trend": [],
                "confidence_avg": 0,
            },
            "resource_usage": {
                "memory_mb": {"current": 0, "average": 0, "peak": 0},
                "cpu_percent": {"current": 0, "average": 0, "peak": 0}
            },
            "phase_breakdown": {},
        }


# Global performance monitor instance
performance_monitor = PerformanceMonitor()