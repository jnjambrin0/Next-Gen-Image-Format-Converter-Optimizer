"""User preference tracking for format recommendations."""

import os
import sqlite3
import time
from contextlib import contextmanager
from threading import Lock
from typing import Any, Dict, List, Optional

from app.core.constants import DB_CHECK_SAME_THREAD
from app.core.security.errors_simplified import (create_file_error,
                                                 create_rate_limit_error)
from app.models.conversion import ContentType, OutputFormat
from app.models.recommendation import UseCaseType, UserFormatPreference
from app.utils.logging import get_logger

logger = get_logger(__name__)


class UserPreferenceTracker:
    """Tracks user format preferences in a privacy-aware manner."""

    # Preference decay settings
    PREFERENCE_DECAY_DAYS = 90  # Preferences decay over 90 days
    MAX_PREFERENCE_WEIGHT = 0.5  # Maximum adjustment to recommendation score
    MIN_PREFERENCE_WEIGHT = -0.5  # Minimum adjustment to recommendation score
    PREFERENCE_THRESHOLD = 3  # Minimum selections before preference is significant
    MAX_PREFERENCES_PER_TYPE = 1000  # Maximum preferences to store per content type
    PREFERENCE_RATE_LIMIT_WINDOW = 60  # Rate limit window in seconds
    PREFERENCE_RATE_LIMIT_MAX = 10  # Max preferences per window

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize preference tracker.

        Args:
            db_path: Path to SQLite database (uses memory if None)
        """
        self.db_path = db_path or ":memory:"
        self._lock = Lock()
        self._init_database()
        self._preference_cache = {}
        self._cache_timestamp = 0
        self._cache_ttl = 300  # 5 minute cache
        self._rate_limit_tracker = {}  # Track rate limiting

    def _init_database(self) -> None:
        """Initialize SQLite database for preferences."""
        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        # For in-memory databases, we need to create tables immediately
        conn = sqlite3.connect(self.db_path, check_same_thread=DB_CHECK_SAME_THREAD)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS format_preferences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content_type TEXT NOT NULL,
                    use_case TEXT,
                    chosen_format TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    selection_count INTEGER DEFAULT 1
                )
            """
            )

            # Create indexes
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_content_type_format 
                ON format_preferences (content_type, chosen_format)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON format_preferences (timestamp)
            """
            )

            # Preference summary table for performance
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS preference_summary (
                    content_type TEXT NOT NULL,
                    use_case TEXT,
                    format TEXT NOT NULL,
                    total_selections INTEGER DEFAULT 0,
                    last_selected REAL,
                    preference_score REAL DEFAULT 0.0,
                    PRIMARY KEY (content_type, use_case, format)
                )
            """
            )
            conn.commit()
        finally:
            conn.close()

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

    async def record_preference(
        self,
        content_type: ContentType,
        chosen_format: OutputFormat,
        use_case: Optional[UseCaseType] = None,
    ) -> None:
        """Record a user's format choice.

        Args:
            content_type: Type of content
            chosen_format: Format chosen by user
            use_case: Optional[Any] use case context
        """
        # Rate limiting check
        if not self._check_rate_limit():
            raise create_rate_limit_error(limit_type="preference_recording")

        # Validate inputs (enums already provide validation)
        timestamp = time.time()

        with self._lock:
            try:
                with self._get_db() as conn:
                    # Check if we're at the limit for this content type
                    count_result = conn.execute(
                        """
                        SELECT COUNT(*) as count 
                        FROM format_preferences 
                        WHERE content_type = ?
                    """,
                        (content_type.value,),
                    ).fetchone()

                    if (
                        count_result
                        and count_result["count"] >= self.MAX_PREFERENCES_PER_TYPE
                    ):
                        # Delete oldest preferences to make room
                        conn.execute(
                            """
                            DELETE FROM format_preferences 
                            WHERE content_type = ? 
                            AND timestamp < (
                                SELECT timestamp FROM format_preferences 
                                WHERE content_type = ? 
                                ORDER BY timestamp DESC 
                                LIMIT 1 OFFSET ?
                            )
                        """,
                            (
                                content_type.value,
                                content_type.value,
                                self.MAX_PREFERENCES_PER_TYPE - 10,
                            ),
                        )

                    # Record individual preference
                    conn.execute(
                        """
                        INSERT INTO format_preferences 
                        (content_type, use_case, chosen_format, timestamp)
                        VALUES (?, ?, ?, ?)
                    """,
                        (
                            content_type.value,
                            use_case.value if use_case else None,
                            chosen_format.value,
                            timestamp,
                        ),
                    )

                    # Update summary
                    self._update_preference_summary(
                        conn,
                        content_type.value,
                        use_case.value if use_case else None,
                        chosen_format.value,
                        timestamp,
                    )

                # Invalidate cache
                self._preference_cache.clear()

                # Privacy-aware logging - no specific values
                logger.info("Format preference recorded successfully")

            except sqlite3.Error as e:
                logger.error("Database error recording preference")
                raise create_file_error(
                    operation="database", reason="Failed to record preference"
                )
            except Exception as e:
                logger.error("Unexpected error recording preference")
                raise

    def _update_preference_summary(
        self,
        conn: sqlite3.Connection,
        content_type: str,
        use_case: Optional[str],
        format_chosen: str,
        timestamp: float,
    ) -> None:
        """Update preference summary table."""
        # Check if entry exists
        result = conn.execute(
            """
            SELECT total_selections FROM preference_summary
            WHERE content_type = ? AND 
                  (use_case = ? OR (use_case IS NULL AND ? IS NULL)) AND 
                  format = ?
        """,
            (content_type, use_case, use_case, format_chosen),
        ).fetchone()

        if result:
            # Update existing
            conn.execute(
                """
                UPDATE preference_summary
                SET total_selections = total_selections + 1,
                    last_selected = ?,
                    preference_score = MIN(?, 
                        (total_selections + 1.0) / ? * ?)
                WHERE content_type = ? AND 
                      (use_case = ? OR (use_case IS NULL AND ? IS NULL)) AND 
                      format = ?
            """,
                (
                    timestamp,
                    self.MAX_PREFERENCE_WEIGHT,
                    self.PREFERENCE_THRESHOLD * 2,
                    self.MAX_PREFERENCE_WEIGHT,
                    content_type,
                    use_case,
                    use_case,
                    format_chosen,
                ),
            )
        else:
            # Insert new
            conn.execute(
                """
                INSERT INTO preference_summary
                (content_type, use_case, format, total_selections, 
                 last_selected, preference_score)
                VALUES (?, ?, ?, 1, ?, ?)
            """,
                (
                    content_type,
                    use_case,
                    format_chosen,
                    timestamp,
                    self.MAX_PREFERENCE_WEIGHT / self.PREFERENCE_THRESHOLD,
                ),
            )

    async def get_preference_score(
        self,
        content_type: ContentType,
        format_option: OutputFormat,
        use_case: Optional[UseCaseType] = None,
    ) -> float:
        """Get preference score for a format option.

        Args:
            content_type: Type of content
            format_option: Format to check preference for
            use_case: Optional[Any] use case context

        Returns:
            Preference score adjustment (-0.5 to 0.5)
        """
        # Check cache
        cache_key = (
            content_type.value,
            format_option.value,
            use_case.value if use_case else None,
        )
        current_time = time.time()

        if (
            cache_key in self._preference_cache
            and current_time - self._cache_timestamp < self._cache_ttl
        ):
            return self._preference_cache[cache_key]

        with self._lock:
            try:
                with self._get_db() as conn:
                    # Get preference data
                    result = conn.execute(
                        """
                        SELECT total_selections, last_selected, preference_score
                        FROM preference_summary
                        WHERE content_type = ? AND 
                              (use_case = ? OR (use_case IS NULL AND ? IS NULL)) AND 
                              format = ?
                    """,
                        (
                            content_type.value,
                            use_case.value if use_case else None,
                            use_case.value if use_case else None,
                            format_option.value,
                        ),
                    ).fetchone()

                    if (
                        not result
                        or result["total_selections"] < self.PREFERENCE_THRESHOLD
                    ):
                        score = 0.0
                    else:
                        # Apply time decay
                        days_old = (current_time - result["last_selected"]) / 86400
                        decay_factor = max(
                            0.0, 1.0 - (days_old / self.PREFERENCE_DECAY_DAYS)
                        )

                        # Calculate score with decay
                        base_score = result["preference_score"]
                        score = base_score * decay_factor

                    # Cache result
                    self._preference_cache[cache_key] = score
                    self._cache_timestamp = current_time

                    return score

            except Exception as e:
                logger.error(f"Failed to get preference score: {e}")
                return 0.0

    async def get_format_preferences(
        self,
        content_type: ContentType,
        use_case: Optional[UseCaseType] = None,
        limit: int = 5,
    ) -> List[UserFormatPreference]:
        """Get user's format preferences for content type.

        Args:
            content_type: Type of content
            use_case: Optional[Any] use case context
            limit: Maximum number of preferences to return

        Returns: List[Any] of user format preferences
        """
        with self._lock:
            try:
                with self._get_db() as conn:
                    # Get preferences with scores
                    query = """
                        SELECT format, total_selections, last_selected, preference_score
                        FROM preference_summary
                        WHERE content_type = ?
                    """
                    params = [content_type.value]

                    if use_case:
                        query += " AND use_case = ?"
                        params.append(use_case.value)
                    else:
                        query += " AND use_case IS NULL"

                    query += (
                        " ORDER BY preference_score DESC, last_selected DESC LIMIT ?"
                    )
                    params.append(limit)

                    results = conn.execute(query, params).fetchall()

                    preferences = []
                    for row in results:
                        try:
                            format_enum = OutputFormat(row["format"])
                            preferences.append(
                                UserFormatPreference(
                                    content_type=content_type.value,
                                    chosen_format=format_enum,
                                    use_case=use_case,
                                    timestamp=row["last_selected"],
                                    score_adjustment=row["preference_score"],
                                )
                            )
                        except ValueError:
                            # Skip invalid format values
                            continue

                    return preferences

            except Exception as e:
                logger.error(f"Failed to get format preferences: {e}")
                return []

    async def reset_preferences(
        self,
        content_type: Optional[ContentType] = None,
        format_option: Optional[OutputFormat] = None,
    ) -> int:
        """Reset user preferences.

        Args:
            content_type: Optional[Any] content type to reset (all if None)
            format_option: Optional[Any] format to reset (all if None)

        Returns:
            Number of preferences reset
        """
        with self._lock:
            try:
                with self._get_db() as conn:
                    # Build query
                    if content_type and format_option:
                        # Reset specific combination
                        conn.execute(
                            """
                            DELETE FROM format_preferences
                            WHERE content_type = ? AND chosen_format = ?
                        """,
                            (content_type.value, format_option.value),
                        )
                        conn.execute(
                            """
                            DELETE FROM preference_summary
                            WHERE content_type = ? AND format = ?
                        """,
                            (content_type.value, format_option.value),
                        )
                    elif content_type:
                        # Reset all for content type
                        conn.execute(
                            """
                            DELETE FROM format_preferences
                            WHERE content_type = ?
                        """,
                            (content_type.value,),
                        )
                        conn.execute(
                            """
                            DELETE FROM preference_summary
                            WHERE content_type = ?
                        """,
                            (content_type.value,),
                        )
                    elif format_option:
                        # Reset all for format
                        conn.execute(
                            """
                            DELETE FROM format_preferences
                            WHERE chosen_format = ?
                        """,
                            (format_option.value,),
                        )
                        conn.execute(
                            """
                            DELETE FROM preference_summary
                            WHERE format = ?
                        """,
                            (format_option.value,),
                        )
                    else:
                        # Reset all
                        conn.execute("DELETE FROM format_preferences")
                        conn.execute("DELETE FROM preference_summary")

                    count = conn.total_changes

                # Clear cache
                self._preference_cache.clear()

                # Privacy-aware logging
                logger.info(f"Reset {count} user preferences")

                return count

            except Exception as e:
                logger.error(f"Failed to reset preferences: {e}")
                return 0

    async def cleanup_old_preferences(self, days: int = 365) -> int:
        """Clean up old preference data.

        Args:
            days: Remove preferences older than this many days

        Returns:
            Number of records cleaned up
        """
        cutoff_timestamp = time.time() - (days * 86400)

        with self._lock:
            try:
                with self._get_db() as conn:
                    # Delete old individual preferences
                    conn.execute(
                        """
                        DELETE FROM format_preferences
                        WHERE timestamp < ?
                    """,
                        (cutoff_timestamp,),
                    )

                    # Update summary to remove stale entries
                    conn.execute(
                        """
                        DELETE FROM preference_summary
                        WHERE last_selected < ? AND total_selections < ?
                    """,
                        (cutoff_timestamp, self.PREFERENCE_THRESHOLD),
                    )

                    count = conn.total_changes

                logger.info(f"Cleaned up {count} old preference records")
                return count

            except Exception as e:
                logger.error(f"Failed to cleanup preferences: {e}")
                return 0

    def get_preference_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored preferences.

        Returns:
            Dictionary of preference statistics
        """
        with self._lock:
            try:
                with self._get_db() as conn:
                    # Total preferences
                    total = conn.execute(
                        "SELECT COUNT(*) as count FROM format_preferences"
                    ).fetchone()["count"]

                    # Preferences by content type
                    by_content = {}
                    for row in conn.execute(
                        """
                        SELECT content_type, COUNT(*) as count
                        FROM format_preferences
                        GROUP BY content_type
                    """
                    ):
                        by_content[row["content_type"]] = row["count"]

                    # Most popular formats
                    popular_formats = []
                    for row in conn.execute(
                        """
                        SELECT format, SUM(total_selections) as selections
                        FROM preference_summary
                        GROUP BY format
                        ORDER BY selections DESC
                        LIMIT 5
                    """
                    ):
                        popular_formats.append(
                            {"format": row["format"], "selections": row["selections"]}
                        )

                    return {
                        "total_preferences": total,
                        "by_content_type": by_content,
                        "popular_formats": popular_formats,
                        "cache_size": len(self._preference_cache),
                    }

            except Exception as e:
                logger.error("Failed to get preference statistics")
                return {}

    def _check_rate_limit(self) -> bool:
        """Check if rate limit allows recording preference.

        Returns:
            True if within rate limit, False otherwise
        """
        current_time = time.time()
        window_start = current_time - self.PREFERENCE_RATE_LIMIT_WINDOW

        # Clean old entries
        self._rate_limit_tracker = {
            t: count
            for t, count in self._rate_limit_tracker.items()
            if t > window_start
        }

        # Check current window count
        window_count = sum(self._rate_limit_tracker.values())
        if window_count >= self.PREFERENCE_RATE_LIMIT_MAX:
            return False

        # Record this request
        self._rate_limit_tracker[current_time] = 1
        return True
