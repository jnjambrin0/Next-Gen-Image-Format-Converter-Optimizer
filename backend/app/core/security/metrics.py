"""
Security metrics collection for network monitoring.
"""

import time
from typing import Dict, Any, Optional
from datetime import datetime
from threading import Lock

from app.core.security.types import SecurityMetrics


class SecurityMetricsCollector:
    """Collects metrics for security monitoring performance."""
    
    def __init__(self):
        """Initialize metrics collector."""
        self._metrics: SecurityMetrics = {
            "verification_time_ms": 0.0,
            "monitoring_cycles": 0,
            "connections_checked": 0,
            "violations_detected": 0,
            "processes_terminated": 0,
            "last_check_timestamp": None
        }
        self._lock = Lock()
        self._verification_start_time: Optional[float] = None
        self._cycle_start_time: Optional[float] = None
    
    def start_verification(self) -> None:
        """Mark start of network verification."""
        self._verification_start_time = time.time()
    
    def end_verification(self) -> None:
        """Mark end of network verification and record time."""
        if self._verification_start_time:
            elapsed_ms = (time.time() - self._verification_start_time) * 1000
            with self._lock:
                self._metrics["verification_time_ms"] = elapsed_ms
                self._verification_start_time = None
    
    def start_monitoring_cycle(self) -> None:
        """Mark start of a monitoring cycle."""
        self._cycle_start_time = time.time()
    
    def end_monitoring_cycle(self, connections_checked: int = 0) -> None:
        """Mark end of monitoring cycle."""
        with self._lock:
            self._metrics["monitoring_cycles"] += 1
            self._metrics["connections_checked"] += connections_checked
            self._metrics["last_check_timestamp"] = datetime.utcnow().isoformat()
    
    def record_violation(self) -> None:
        """Record a security violation."""
        with self._lock:
            self._metrics["violations_detected"] += 1
    
    def record_process_termination(self) -> None:
        """Record a process termination."""
        with self._lock:
            self._metrics["processes_terminated"] += 1
    
    def get_metrics(self) -> SecurityMetrics:
        """Get current metrics."""
        with self._lock:
            return self._metrics.copy()
    
    def reset_metrics(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self._metrics = {
                "verification_time_ms": 0.0,
                "monitoring_cycles": 0,
                "connections_checked": 0,
                "violations_detected": 0,
                "processes_terminated": 0,
                "last_check_timestamp": None
            }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary with calculated values."""
        with self._lock:
            metrics = self._metrics.copy()
            
            # Calculate averages
            avg_connections_per_cycle = (
                metrics["connections_checked"] / metrics["monitoring_cycles"]
                if metrics["monitoring_cycles"] > 0 else 0
            )
            
            violation_rate = (
                metrics["violations_detected"] / metrics["monitoring_cycles"]
                if metrics["monitoring_cycles"] > 0 else 0
            )
            
            return {
                "raw_metrics": metrics,
                "calculated": {
                    "avg_connections_per_cycle": avg_connections_per_cycle,
                    "violation_rate_per_cycle": violation_rate,
                    "termination_rate": (
                        metrics["processes_terminated"] / metrics["violations_detected"]
                        if metrics["violations_detected"] > 0 else 0
                    )
                }
            }