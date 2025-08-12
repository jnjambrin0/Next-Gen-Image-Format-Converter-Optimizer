"""Batch History Service for persisting batch job data."""

import asyncio
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from app.core.batch.models import BatchJobStatus, BatchProgress, BatchResult
from app.core.constants import (
    BATCH_JOB_RETENTION_DAYS,
    DB_CHECK_SAME_THREAD,
)
from app.utils.logging import get_logger

logger = get_logger(__name__)


class BatchHistoryService:
    """Service for persisting and retrieving batch job history."""

    def __init__(self, db_path: str = "./data/batch_history.db"):
        """Initialize the batch history service.

        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._lock = asyncio.Lock()
        self._init_db()

    def _init_db(self):
        """Initialize database tables."""
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        with self._get_db() as conn:
            # Create batch_jobs table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS batch_jobs (
                    job_id TEXT PRIMARY KEY,
                    total_files INTEGER NOT NULL,
                    completed_files INTEGER DEFAULT 0,
                    failed_files INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    settings TEXT,  -- JSON
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    user_ip TEXT,  -- For rate limiting
                    processing_time_seconds REAL
                )
            """
            )

            # Create batch_job_files table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS batch_job_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT REFERENCES batch_jobs(job_id) ON DELETE CASCADE,
                    file_index INTEGER NOT NULL,
                    filename TEXT NOT NULL,  -- Original filename for display only
                    status TEXT NOT NULL,
                    error_message TEXT,
                    processing_time REAL,
                    output_size INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(job_id, file_index)
                )
            """
            )

            # Create indexes for performance
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_batch_jobs_created 
                ON batch_jobs(created_at)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_batch_jobs_status 
                ON batch_jobs(status)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_batch_job_files_job 
                ON batch_job_files(job_id)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_batch_jobs_user_ip 
                ON batch_jobs(user_ip, created_at)
            """
            )

    @contextmanager
    def _get_db(self):
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

    async def create_job(
        self,
        job_id: str,
        total_files: int,
        settings: Dict[str, Any],
        user_ip: Optional[str] = None,
    ) -> None:
        """Create a new batch job record.

        Args:
            job_id: Unique job identifier
            total_files: Total number of files in the batch
            settings: Conversion settings for the batch
            user_ip: User IP address for rate limiting
        """
        async with self._lock:
            with self._get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO batch_jobs (
                        job_id, total_files, status, settings, user_ip
                    ) VALUES (?, ?, ?, ?, ?)
                """,
                    (job_id, total_files, "pending", json.dumps(settings), user_ip),
                )

    async def update_job_status(
        self,
        job_id: str,
        status: str,
        completed_files: Optional[int] = None,
        failed_files: Optional[int] = None,
        processing_time: Optional[float] = None,
    ) -> None:
        """Update batch job status.

        Args:
            job_id: Job identifier
            status: New status
            completed_files: Number of completed files
            failed_files: Number of failed files
            processing_time: Total processing time in seconds
        """
        async with self._lock:
            with self._get_db() as conn:
                updates = ["status = ?"]
                params = [status]

                if completed_files is not None:
                    updates.append("completed_files = ?")
                    params.append(completed_files)

                if failed_files is not None:
                    updates.append("failed_files = ?")
                    params.append(failed_files)

                if processing_time is not None:
                    updates.append("processing_time_seconds = ?")
                    params.append(processing_time)

                if status in ["completed", "failed", "cancelled"]:
                    updates.append("completed_at = CURRENT_TIMESTAMP")

                # Build parameterized query safely
                params.append(job_id)
                # Pre-validate that all updates are safe column assignments
                safe_updates = []
                for update in updates:
                    # Only allow specific safe column updates
                    if any(
                        update.startswith(col)
                        for col in [
                            "status = ?",
                            "completed_files = ?",
                            "failed_files = ?",
                            "processing_time_seconds = ?",
                            "completed_at = CURRENT_TIMESTAMP",
                        ]
                    ):
                        safe_updates.append(update)

                if safe_updates:
                    # Build parameterized query - safe_updates are validated above
                    # This is not SQL injection as safe_updates contains only literal column names
                    query = f"UPDATE batch_jobs SET {', '.join(safe_updates)} WHERE job_id = ?"  # nosec B608
                    conn.execute(query, params)

    async def add_file_record(
        self, job_id: str, file_index: int, filename: str, status: str = "pending"
    ) -> None:
        """Add a file record to a batch job.

        Args:
            job_id: Job identifier
            file_index: Index of the file in the batch
            filename: Original filename (for display only)
            status: Initial status
        """
        async with self._lock:
            with self._get_db() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO batch_job_files (
                        job_id, file_index, filename, status
                    ) VALUES (?, ?, ?, ?)
                """,
                    (job_id, file_index, filename, status),
                )

    async def update_file_status(
        self,
        job_id: str,
        file_index: int,
        status: str,
        error_message: Optional[str] = None,
        processing_time: Optional[float] = None,
        output_size: Optional[int] = None,
    ) -> None:
        """Update file processing status.

        Args:
            job_id: Job identifier
            file_index: Index of the file in the batch
            status: New status
            error_message: Error message if failed
            processing_time: Processing time in seconds
            output_size: Output file size in bytes
        """
        async with self._lock:
            with self._get_db() as conn:
                updates = ["status = ?"]
                params = [status]

                if error_message is not None:
                    updates.append("error_message = ?")
                    params.append(error_message)

                if processing_time is not None:
                    updates.append("processing_time = ?")
                    params.append(processing_time)

                if output_size is not None:
                    updates.append("output_size = ?")
                    params.append(output_size)

                # Build parameterized query safely
                params.extend([job_id, file_index])

                # Pre-validate that all updates are safe column assignments
                safe_updates = []
                for update in updates:
                    # Only allow specific safe column updates
                    if any(
                        update.startswith(col)
                        for col in [
                            "status = ?",
                            "error_message = ?",
                            "processing_time = ?",
                            "output_size = ?",
                        ]
                    ):
                        safe_updates.append(update)

                if safe_updates:
                    # Build parameterized query - safe_updates are validated above
                    # This is not SQL injection as safe_updates contains only literal column names
                    query = f"""
                        UPDATE batch_job_files 
                        SET {', '.join(safe_updates)} 
                        WHERE job_id = ? AND file_index = ?
                    """  # nosec B608
                    conn.execute(query, params)

    async def get_job_status(self, job_id: str) -> Optional[BatchJobStatus]:
        """Get batch job status.

        Args:
            job_id: Job identifier

        Returns:
            BatchJobStatus if found, None otherwise
        """
        async with self._lock:
            with self._get_db() as conn:
                # Get job info
                job_row = conn.execute(
                    """
                    SELECT * FROM batch_jobs WHERE job_id = ?
                """,
                    (job_id,),
                ).fetchone()

                if not job_row:
                    return None

                # Get file details
                file_rows = conn.execute(
                    """
                    SELECT * FROM batch_job_files 
                    WHERE job_id = ? 
                    ORDER BY file_index
                """,
                    (job_id,),
                ).fetchall()

                # Build file statuses
                files = []
                for row in file_rows:
                    files.append(
                        {
                            "index": row["file_index"],
                            "filename": row["filename"],
                            "status": row["status"],
                            "error": row["error_message"],
                            "processing_time": row["processing_time"],
                            "output_size": row["output_size"],
                        }
                    )

                # Calculate progress
                progress = 0
                if job_row["total_files"] > 0:
                    progress = int(
                        (job_row["completed_files"] + job_row["failed_files"])
                        / job_row["total_files"]
                        * 100
                    )

                return BatchJobStatus(
                    job_id=job_id,
                    status=job_row["status"],
                    total_files=job_row["total_files"],
                    completed_files=job_row["completed_files"],
                    failed_files=job_row["failed_files"],
                    progress=progress,
                    files=files,
                    created_at=job_row["created_at"],
                    completed_at=job_row["completed_at"],
                    processing_time_seconds=job_row["processing_time_seconds"],
                )

    async def get_job_results(self, job_id: str) -> Optional[BatchResult]:
        """Get batch job results.

        Args:
            job_id: Job identifier

        Returns:
            BatchResult if found, None otherwise
        """
        status = await self.get_job_status(job_id)
        if not status:
            return None

        # Convert status to result format
        successful_files = []
        failed_files = []

        for file in status.files:
            if file["status"] == "completed":
                successful_files.append(
                    {
                        "filename": file["filename"],
                        "index": file["index"],
                        "output_size": file["output_size"] or 0,
                    }
                )
            elif file["status"] == "failed":
                failed_files.append(
                    {
                        "filename": file["filename"],
                        "index": file["index"],
                        "error": file["error"] or "Unknown error",
                    }
                )

        return BatchResult(
            job_id=job_id,
            total_files=status.total_files,
            successful_files=successful_files,
            failed_files=failed_files,
            processing_time_seconds=status.processing_time_seconds or 0,
            report_format="json",
        )

    async def cleanup_old_jobs(self) -> int:
        """Clean up batch jobs older than retention period.

        Returns:
            Number of jobs deleted
        """
        cutoff_date = datetime.now() - timedelta(days=BATCH_JOB_RETENTION_DAYS)

        async with self._lock:
            with self._get_db() as conn:
                # Get jobs to delete
                old_jobs = conn.execute(
                    """
                    SELECT job_id FROM batch_jobs 
                    WHERE created_at < ? 
                    AND status IN ('completed', 'failed', 'cancelled')
                """,
                    (cutoff_date.isoformat(),),
                ).fetchall()

                deleted_count = len(old_jobs)

                if deleted_count > 0:
                    # Delete jobs (cascades to files)
                    job_ids = [row["job_id"] for row in old_jobs]
                    # Create placeholders for parameterized query
                    placeholders = ",".join("?" * len(job_ids))
                    # This is safe as placeholders only contains "?" characters
                    conn.execute(
                        f"""
                        DELETE FROM batch_jobs 
                        WHERE job_id IN ({placeholders})
                    """,  # nosec B608
                        job_ids,
                    )

                    logger.info(f"Cleaned up {deleted_count} old batch jobs")

                return deleted_count

    async def get_recent_jobs_by_ip(
        self, user_ip: str, minutes: int = 60
    ) -> List[Dict[str, Any]]:
        """Get recent jobs by user IP for rate limiting.

        Args:
            user_ip: User IP address
            minutes: Time window in minutes

        Returns:
            List of recent jobs
        """
        cutoff_time = datetime.now() - timedelta(minutes=minutes)

        async with self._lock:
            with self._get_db() as conn:
                rows = conn.execute(
                    """
                    SELECT job_id, total_files, created_at, status
                    FROM batch_jobs
                    WHERE user_ip = ? AND created_at > ?
                    ORDER BY created_at DESC
                """,
                    (user_ip, cutoff_time.isoformat()),
                ).fetchall()

                return [dict(row) for row in rows]


# Singleton instance
batch_history_service = BatchHistoryService()
