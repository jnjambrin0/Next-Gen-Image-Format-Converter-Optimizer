"""
Privacy-focused statistics collection for the image converter.
Collects only aggregate data with no user correlation.
"""

import asyncio
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json
import sqlite3
from contextlib import contextmanager
from threading import Lock
import os

from app.utils.logging import get_logger
from app.core.constants import (
    HOURLY_STATS_RETENTION_HOURS,
    DAILY_STATS_RETENTION_DAYS,
    MAX_PROCESSING_TIMES_MEMORY,
    FILE_SIZE_CATEGORIES,
    KB_TO_BYTES_FACTOR,
    MB_TO_BYTES_FACTOR,
    DB_CHECK_SAME_THREAD
)

logger = get_logger(__name__)


@dataclass
class ConversionStats:
    """Aggregate statistics for conversions."""

    total_conversions: int = 0
    successful_conversions: int = 0
    failed_conversions: int = 0
    format_counts: Dict[str, int] = field(default_factory=dict)
    size_distribution: Dict[str, int] = field(default_factory=dict)
    processing_times: List[float] = field(default_factory=list)
    error_types: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_conversions": self.total_conversions,
            "successful_conversions": self.successful_conversions,
            "failed_conversions": self.failed_conversions,
            "success_rate": self.success_rate,
            "format_counts": self.format_counts,
            "size_distribution": self.size_distribution,
            "average_processing_time": self.average_processing_time,
            "median_processing_time": self.median_processing_time,
            "error_types": self.error_types,
        }

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_conversions == 0:
            return 0.0
        return (self.successful_conversions / self.total_conversions) * 100

    @property
    def average_processing_time(self) -> float:
        """Calculate average processing time in seconds."""
        if not self.processing_times:
            return 0.0
        return sum(self.processing_times) / len(self.processing_times)

    @property
    def median_processing_time(self) -> float:
        """Calculate median processing time in seconds."""
        if not self.processing_times:
            return 0.0
        sorted_times = sorted(self.processing_times)
        n = len(sorted_times)
        if n % 2 == 0:
            return (sorted_times[n // 2 - 1] + sorted_times[n // 2]) / 2
        return sorted_times[n // 2]


class StatsCollector:
    """
    Collects privacy-safe aggregate statistics.
    No user data or file information is stored.
    """

    def __init__(self, persist_to_db: bool = False, db_path: Optional[str] = None):
        """
        Initialize the stats collector.

        Args:
            persist_to_db: Whether to persist stats to SQLite
            db_path: Path to SQLite database (uses memory if None)
        """
        self.persist_to_db = persist_to_db
        self.db_path = db_path or ":memory:"
        self._lock = Lock()

        # In-memory counters
        self._hourly_stats: Dict[str, ConversionStats] = defaultdict(ConversionStats)
        self._daily_stats: Dict[str, ConversionStats] = defaultdict(ConversionStats)
        self._all_time_stats = ConversionStats()

        # Size buckets for distribution (using file size categories from constants)
        self.size_buckets = []
        prev_limit = 0
        for category, limit in FILE_SIZE_CATEGORIES.items():
            self.size_buckets.append((category.lower(), prev_limit, limit))
            prev_limit = limit

        if self.persist_to_db:
            self._init_database()

    def _init_database(self):
        """Initialize SQLite database for persistent stats."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with self._get_db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS aggregate_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    period_type TEXT NOT NULL,  -- 'hourly', 'daily', 'all_time'
                    period_key TEXT NOT NULL,   -- e.g., '2024-01-01T14' for hourly
                    stats_json TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(period_type, period_key)
                )
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_period 
                ON aggregate_stats(period_type, period_key)
            """
            )

    @contextmanager
    def _get_db(self):
        """Get database connection context manager."""
        conn = sqlite3.connect(self.db_path, check_same_thread=DB_CHECK_SAME_THREAD)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _get_size_bucket(self, size_bytes: int) -> str:
        """Determine size bucket for a file size."""
        for bucket_name, min_size, max_size in self.size_buckets:
            if min_size <= size_bytes < max_size:
                return bucket_name
        return "unknown"

    def _get_time_keys(self) -> tuple[str, str]:
        """Get current hourly and daily time keys."""
        now = datetime.now()
        hourly_key = now.strftime("%Y-%m-%dT%H")
        daily_key = now.strftime("%Y-%m-%d")
        return hourly_key, daily_key

    async def record_conversion(
        self,
        input_format: str,
        output_format: str,
        input_size: int,
        processing_time: float,
        success: bool,
        error_type: Optional[str] = None,
    ):
        """
        Record a conversion event.

        Args:
            input_format: Input file format (e.g., 'jpeg')
            output_format: Output file format (e.g., 'webp')
            input_size: Input file size in bytes
            processing_time: Processing time in seconds
            success: Whether conversion succeeded
            error_type: Type of error if failed (e.g., 'timeout', 'memory_limit')
        """
        with self._lock:
            hourly_key, daily_key = self._get_time_keys()
            size_bucket = self._get_size_bucket(input_size)

            # Update all stat collections
            for stats in [
                self._hourly_stats[hourly_key],
                self._daily_stats[daily_key],
                self._all_time_stats,
            ]:
                stats.total_conversions += 1

                if success:
                    stats.successful_conversions += 1
                else:
                    stats.failed_conversions += 1
                    if error_type:
                        stats.error_types[error_type] = (
                            stats.error_types.get(error_type, 0) + 1
                        )

                # Record format conversion
                format_key = f"{input_format}->{output_format}"
                stats.format_counts[format_key] = (
                    stats.format_counts.get(format_key, 0) + 1
                )

                # Record size distribution
                stats.size_distribution[size_bucket] = (
                    stats.size_distribution.get(size_bucket, 0) + 1
                )

                # Record processing time (limit to prevent memory issues)
                if len(stats.processing_times) < MAX_PROCESSING_TIMES_MEMORY:
                    stats.processing_times.append(processing_time)
                else:
                    # Keep a rolling window of recent times
                    stats.processing_times.pop(0)
                    stats.processing_times.append(processing_time)

        # Persist if enabled
        if self.persist_to_db:
            await self._persist_stats(hourly_key, daily_key)

        logger.info(
            "Recorded conversion stats",
            format_conversion=f"{input_format}->{output_format}",
            size_bucket=size_bucket,
            success=success,
            processing_time=round(processing_time, 2),
        )

    async def _persist_stats(self, hourly_key: str, daily_key: str):
        """Persist current stats to database."""
        try:
            with self._get_db() as conn:
                # Persist hourly stats
                conn.execute(
                    """
                    INSERT OR REPLACE INTO aggregate_stats 
                    (period_type, period_key, stats_json)
                    VALUES (?, ?, ?)
                """,
                    (
                        "hourly",
                        hourly_key,
                        json.dumps(self._hourly_stats[hourly_key].to_dict()),
                    ),
                )

                # Persist daily stats
                conn.execute(
                    """
                    INSERT OR REPLACE INTO aggregate_stats 
                    (period_type, period_key, stats_json)
                    VALUES (?, ?, ?)
                """,
                    (
                        "daily",
                        daily_key,
                        json.dumps(self._daily_stats[daily_key].to_dict()),
                    ),
                )

                # Persist all-time stats
                conn.execute(
                    """
                    INSERT OR REPLACE INTO aggregate_stats 
                    (period_type, period_key, stats_json)
                    VALUES (?, ?, ?)
                """,
                    ("all_time", "total", json.dumps(self._all_time_stats.to_dict())),
                )
        except Exception as e:
            logger.error("Failed to persist stats", error=str(e))

    def get_current_stats(self) -> Dict[str, Any]:
        """Get current aggregate statistics."""
        hourly_key, daily_key = self._get_time_keys()

        with self._lock:
            return {
                "current_hour": self._hourly_stats[hourly_key].to_dict(),
                "current_day": self._daily_stats[daily_key].to_dict(),
                "all_time": self._all_time_stats.to_dict(),
            }

    def get_hourly_stats(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get stats for the last N hours."""
        stats = []
        now = datetime.now()

        for i in range(hours):
            hour_time = now - timedelta(hours=i)
            hour_key = hour_time.strftime("%Y-%m-%dT%H")

            if hour_key in self._hourly_stats:
                stats.append(
                    {"hour": hour_key, "stats": self._hourly_stats[hour_key].to_dict()}
                )

        return stats

    def get_daily_stats(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get stats for the last N days."""
        stats = []
        now = datetime.now()

        for i in range(days):
            day_time = now - timedelta(days=i)
            day_key = day_time.strftime("%Y-%m-%d")

            if day_key in self._daily_stats:
                stats.append(
                    {"day": day_key, "stats": self._daily_stats[day_key].to_dict()}
                )

        return stats

    async def cleanup_old_stats(
        self, hourly_retention: int = HOURLY_STATS_RETENTION_HOURS, daily_retention: int = DAILY_STATS_RETENTION_DAYS
    ):
        """
        Clean up old statistics.

        Args:
            hourly_retention: Hours to retain hourly stats (default 7 days)
            daily_retention: Days to retain daily stats
        """
        now = datetime.now()

        with self._lock:
            # Clean hourly stats
            hourly_cutoff = now - timedelta(hours=hourly_retention)
            hourly_keys_to_remove = []
            for key in self._hourly_stats:
                try:
                    key_time = datetime.strptime(key, "%Y-%m-%dT%H")
                    if key_time < hourly_cutoff:
                        hourly_keys_to_remove.append(key)
                except ValueError:
                    continue

            for key in hourly_keys_to_remove:
                del self._hourly_stats[key]

            # Clean daily stats
            daily_cutoff = now - timedelta(days=daily_retention)
            daily_keys_to_remove = []
            for key in self._daily_stats:
                try:
                    key_time = datetime.strptime(key, "%Y-%m-%d")
                    if key_time < daily_cutoff:
                        daily_keys_to_remove.append(key)
                except ValueError:
                    continue

            for key in daily_keys_to_remove:
                del self._daily_stats[key]

        # Clean database if persisting
        if self.persist_to_db:
            try:
                with self._get_db() as conn:
                    conn.execute(
                        """
                        DELETE FROM aggregate_stats 
                        WHERE period_type = 'hourly' 
                        AND datetime(period_key || ':00:00') < datetime('now', '-' || ? || ' hours')
                    """,
                        (hourly_retention,),
                    )

                    conn.execute(
                        """
                        DELETE FROM aggregate_stats 
                        WHERE period_type = 'daily' 
                        AND date(period_key) < date('now', '-' || ? || ' days')
                    """,
                        (daily_retention,),
                    )
            except Exception as e:
                logger.error("Failed to cleanup database stats", error=str(e))

        logger.info(
            "Cleaned up old statistics",
            hourly_removed=len(hourly_keys_to_remove),
            daily_removed=len(daily_keys_to_remove),
        )

    async def track_event(self, event_name: str, event_data: Dict[str, Any]) -> None:
        """
        Track a custom event with associated data.
        
        Args:
            event_name: Name of the event to track
            event_data: Dictionary of event data
        """
        # Log the event for now - can be extended to store in DB if needed
        logger.info(
            "Event tracked",
            event_name=event_name,
            **{k: v for k, v in event_data.items() if k not in ['password', 'token', 'secret', 'event']}
        )
    
    async def increment_counter(self, counter_name: str, value: int = 1) -> None:
        """
        Increment a named counter.
        
        Args:
            counter_name: Name of the counter to increment
            value: Amount to increment by (default 1)
        """
        # For now, just log - can be extended to maintain counters
        logger.debug(
            "Counter incremented",
            counter=counter_name,
            increment=value
        )
    
    async def record_timing(self, metric_name: str, duration_ms: float) -> None:
        """
        Record a timing metric.
        
        Args:
            metric_name: Name of the timing metric
            duration_ms: Duration in milliseconds
        """
        # For now, just log - can be extended to calculate percentiles
        logger.debug(
            "Timing recorded",
            metric=metric_name,
            duration_ms=round(duration_ms, 2)
        )


# Create singleton instance
stats_collector = StatsCollector()
