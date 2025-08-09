"""
Local-only error reporting system for privacy-focused monitoring.
"""

import hashlib
import json
import os
import sqlite3
import traceback
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional

from app.core.constants import (
    DB_CHECK_SAME_THREAD,
    DEFAULT_MONITORING_HOURS,
    ERROR_MESSAGE_MAX_LENGTH,
    ERROR_RETENTION_DAYS,
    ERROR_SIGNATURE_HASH_LENGTH,
    MAX_CATEGORY_ERRORS_DISPLAY,
    MAX_TOP_ERRORS_DISPLAY,
)
from app.utils.logging import filter_sensitive_data, get_logger

logger = get_logger(__name__)


@dataclass
class ErrorReport:
    """Privacy-safe error report."""

    error_id: str
    error_type: str
    error_category: str
    count: int = 1
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    stack_hash: Optional[str] = None
    sanitized_message: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "error_id": self.error_id,
            "error_type": self.error_type,
            "error_category": self.error_category,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "stack_hash": self.stack_hash,
            "sanitized_message": self.sanitized_message,
            "context": self.context,
        }


class ErrorReporter:
    """
    Local-only error reporting with privacy-safe aggregation.
    Stores errors in SQLite with no PII.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        """
        Initialize the error reporter.

        Args:
            db_path: Path to SQLite database (uses memory if None)
        """
        self.db_path = db_path or ":memory:"
        self._lock = Lock()
        self._error_cache: Dict[str, ErrorReport] = {}
        self._category_counts: Counter = Counter()

        self._init_database()

    def _init_database(self) -> None:
        """Initialize SQLite database for error storage."""
        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with self._get_db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS error_reports (
                    error_id TEXT PRIMARY KEY,
                    error_type TEXT NOT NULL,
                    error_category TEXT NOT NULL,
                    count INTEGER DEFAULT 1,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    stack_hash TEXT,
                    sanitized_message TEXT,
                    context_json TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_error_type 
                ON error_reports(error_type, error_category)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_last_seen 
                ON error_reports(last_seen)
            """
            )

    @contextmanager
    def _get_db(self) -> None:
        """Get database connection context manager."""
        conn = sqlite3.connect(self.db_path, check_same_thread=DB_CHECK_SAME_THREAD)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _categorize_error(self, error: Exception) -> str:
        """
        Categorize an error into privacy-safe categories.

        Args:
            error: The exception to categorize

        Returns:
            Error category string
        """
        error_str = str(error).lower()
        error_type = type(error).__name__

        # Map to privacy-safe categories
        if "timeout" in error_str or "TimeoutError" in error_type:
            return "timeout"
        elif "memory" in error_str or "MemoryError" in error_type:
            return "memory_limit"
        elif "permission" in error_str or "PermissionError" in error_type:
            return "permission"
        elif "validation" in error_str or "ValidationError" in error_type:
            return "validation"
        elif "format" in error_str or "unsupported" in error_str:
            return "format_error"
        elif "connection" in error_str or "network" in error_str:
            return "connection"
        elif "sandbox" in error_str:
            return "sandbox_violation"
        elif "overflow" in error_str or "too large" in error_str:
            return "resource_limit"
        else:
            return "general_error"

    def _sanitize_error_message(self, message: str) -> str:
        """
        Sanitize error message to remove any PII.

        Args:
            message: Original error message

        Returns:
            Sanitized message
        """
        # Use the same privacy filter as logging
        sanitized_dict = filter_sensitive_data(None, None, {"message": message})
        sanitized_msg = sanitized_dict.get("message", "Error message sanitized")

        # Additional sanitization for common patterns
        import re

        # Remove file paths
        sanitized_msg = re.sub(r"[/\\][\w/\\.-]+\.\w+", "<file_path>", sanitized_msg)

        # Remove email-like patterns
        sanitized_msg = re.sub(r"\b[\w.-]+@[\w.-]+\.\w+\b", "<email>", sanitized_msg)

        # Remove IP addresses
        sanitized_msg = re.sub(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<ip_address>", sanitized_msg
        )

        # Truncate if too long
        if len(sanitized_msg) > ERROR_MESSAGE_MAX_LENGTH:
            sanitized_msg = sanitized_msg[: ERROR_MESSAGE_MAX_LENGTH - 3] + "..."

        return sanitized_msg

    def _hash_stack_trace(self, tb_lines: List[str]) -> str:
        """
        Create a hash of the stack trace for deduplication.

        Args:
            tb_lines: Traceback lines

        Returns:
            SHA256 hash of the stack trace
        """
        # Extract only file names (not full paths) and line numbers
        signature_parts = []
        for line in tb_lines:
            if 'File "' in line:
                # Extract just the filename and line number
                import re

                match = re.search(r'File ".*[/\\]([^/\\]+)", line (\d+)', line)
                if match:
                    signature_parts.append(f"{match.group(1)}:{match.group(2)}")

        signature = "|".join(signature_parts)
        return hashlib.sha256(signature.encode()).hexdigest()[
            :ERROR_SIGNATURE_HASH_LENGTH
        ]

    async def record_error(
        self, error: Exception, context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Record an error in a privacy-safe way.

        Args:
            error: The exception to record
            context: Optional[Any] context (will be sanitized)

        Returns:
            Error ID for reference
        """
        try:
            # Get error details
            error_type = type(error).__name__
            error_category = self._categorize_error(error)

            # Sanitize error message
            sanitized_message = self._sanitize_error_message(str(error))

            # Get stack trace hash (for deduplication)
            tb_lines = (
                traceback.format_tb(error.__traceback__) if error.__traceback__ else []
            )
            stack_hash = self._hash_stack_trace(tb_lines) if tb_lines else None

            # Create error ID based on type and stack
            error_id = f"{error_type}_{stack_hash or 'no_stack'}"

            # Sanitize context
            safe_context = {}
            if context:
                safe_context = filter_sensitive_data(None, None, context)

            with self._lock:
                # Check if we've seen this error before
                if error_id in self._error_cache:
                    # Update existing error
                    report = self._error_cache[error_id]
                    report.count += 1
                    report.last_seen = datetime.now()
                else:
                    # Create new error report
                    report = ErrorReport(
                        error_id=error_id,
                        error_type=error_type,
                        error_category=error_category,
                        stack_hash=stack_hash,
                        sanitized_message=sanitized_message,
                        context=safe_context,
                    )
                    self._error_cache[error_id] = report

                # Update category counts
                self._category_counts[error_category] += 1

                # Persist to database
                await self._persist_error(report)

            logger.info(
                "Error recorded",
                error_type=error_type,
                error_category=error_category,
                error_id=error_id,
            )

            return error_id

        except Exception as e:
            logger.error(f"Failed to record error: {e}")
            return "error_recording_failed"

    async def _persist_error(self, report: ErrorReport):
        """Persist error report to database."""
        try:
            with self._get_db() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO error_reports 
                    (error_id, error_type, error_category, count, first_seen, 
                     last_seen, stack_hash, sanitized_message, context_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        report.error_id,
                        report.error_type,
                        report.error_category,
                        report.count,
                        report.first_seen,
                        report.last_seen,
                        report.stack_hash,
                        report.sanitized_message,
                        json.dumps(report.context),
                    ),
                )
        except Exception as e:
            logger.error(f"Failed to persist error report: {e}")

    def get_error_summary(
        self, hours: int = DEFAULT_MONITORING_HOURS
    ) -> Dict[str, Any]:
        """
        Get summary of errors in the specified time period.

        Args:
            hours: Number of hours to look back

        Returns:
            Error summary with privacy-safe aggregates
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)

        with self._get_db() as conn:
            # Get error counts by category
            category_counts = {}
            cursor = conn.execute(
                """
                SELECT error_category, SUM(count) as total
                FROM error_reports
                WHERE last_seen > ?
                GROUP BY error_category
                ORDER BY total DESC
            """,
                (cutoff_time,),
            )

            for row in cursor:
                category_counts[row["error_category"]] = row["total"]

            # Get error counts by type
            type_counts = {}
            cursor = conn.execute(
                """
                SELECT error_type, SUM(count) as total
                FROM error_reports
                WHERE last_seen > ?
                GROUP BY error_type
                ORDER BY total DESC
                LIMIT ?
            """,
                (cutoff_time, MAX_TOP_ERRORS_DISPLAY),
            )

            for row in cursor:
                type_counts[row["error_type"]] = row["total"]

            # Get total unique errors
            cursor = conn.execute(
                """
                SELECT COUNT(DISTINCT error_id) as unique_errors,
                       SUM(count) as total_occurrences
                FROM error_reports
                WHERE last_seen > ?
            """,
                (cutoff_time,),
            )

            stats = cursor.fetchone()

            # Get most frequent errors
            frequent_errors = []
            cursor = conn.execute(
                """
                SELECT error_id, error_type, error_category, 
                       sanitized_message, count
                FROM error_reports
                WHERE last_seen > ?
                ORDER BY count DESC
                LIMIT ?
            """,
                (cutoff_time, MAX_CATEGORY_ERRORS_DISPLAY),
            )

            for row in cursor:
                frequent_errors.append(
                    {
                        "error_id": row["error_id"],
                        "type": row["error_type"],
                        "category": row["error_category"],
                        "message": row["sanitized_message"],
                        "count": row["count"],
                    }
                )

        return {
            "time_period_hours": hours,
            "unique_errors": stats["unique_errors"] if stats else 0,
            "total_occurrences": stats["total_occurrences"] if stats else 0,
            "errors_by_category": category_counts,
            "errors_by_type": type_counts,
            "most_frequent": frequent_errors,
            "privacy_notice": "All error data has been sanitized to remove PII",
        }

    def get_error_details(self, error_id: str) -> Optional[Dict[str, Any]]:
        """
        Get details for a specific error.

        Args:
            error_id: Error ID to retrieve

        Returns:
            Error details or None if not found
        """
        with self._get_db() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM error_reports
                WHERE error_id = ?
            """,
                (error_id,),
            )

            row = cursor.fetchone()
            if row:
                return {
                    "error_id": row["error_id"],
                    "error_type": row["error_type"],
                    "error_category": row["error_category"],
                    "count": row["count"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "stack_hash": row["stack_hash"],
                    "sanitized_message": row["sanitized_message"],
                    "context": (
                        json.loads(row["context_json"]) if row["context_json"] else {}
                    ),
                }

        return None

    async def cleanup_old_errors(self, retention_days: int = ERROR_RETENTION_DAYS):
        """
        Clean up old error reports.

        Args:
            retention_days: Days to retain error reports
        """
        cutoff_time = datetime.now() - timedelta(days=retention_days)

        try:
            with self._get_db() as conn:
                cursor = conn.execute(
                    """
                    DELETE FROM error_reports
                    WHERE last_seen < ?
                """,
                    (cutoff_time,),
                )

                deleted_count = cursor.rowcount

            # Clean up cache
            with self._lock:
                expired_ids = [
                    error_id
                    for error_id, report in self._error_cache.items()
                    if report.last_seen < cutoff_time
                ]
                for error_id in expired_ids:
                    del self._error_cache[error_id]

            logger.info(
                "Cleaned up old error reports",
                deleted_count=deleted_count,
                retention_days=retention_days,
            )

        except Exception as e:
            logger.error(f"Failed to cleanup old errors: {e}")
