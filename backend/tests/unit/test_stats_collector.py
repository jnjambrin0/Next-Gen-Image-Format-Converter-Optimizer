import pytest
import asyncio
from datetime import datetime, timedelta
from app.core.monitoring.stats import StatsCollector, ConversionStats


class TestConversionStats:
    """Test ConversionStats data class."""

    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        stats = ConversionStats()
        assert stats.success_rate == 0.0

        stats.total_conversions = 100
        stats.successful_conversions = 85
        stats.failed_conversions = 15
        assert stats.success_rate == 85.0

        stats.total_conversions = 0
        assert stats.success_rate == 0.0

    def test_processing_time_calculations(self):
        """Test average and median processing time calculations."""
        stats = ConversionStats()
        assert stats.average_processing_time == 0.0
        assert stats.median_processing_time == 0.0

        # Test with odd number of values
        stats.processing_times = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert stats.average_processing_time == 3.0
        assert stats.median_processing_time == 3.0

        # Test with even number of values
        stats.processing_times = [1.0, 2.0, 3.0, 4.0]
        assert stats.average_processing_time == 2.5
        assert stats.median_processing_time == 2.5

    def test_to_dict_serialization(self):
        """Test dictionary serialization."""
        stats = ConversionStats()
        stats.total_conversions = 10
        stats.successful_conversions = 8
        stats.failed_conversions = 2
        stats.format_counts = {"jpeg->webp": 5, "png->avif": 3}
        stats.processing_times = [1.0, 2.0, 3.0]

        result = stats.to_dict()
        assert result["total_conversions"] == 10
        assert result["successful_conversions"] == 8
        assert result["success_rate"] == 80.0
        assert result["format_counts"]["jpeg->webp"] == 5
        assert result["average_processing_time"] == 2.0


class TestStatsCollector:
    """Test StatsCollector functionality."""

    @pytest.fixture
    def collector(self):
        """Create a stats collector instance."""
        return StatsCollector(persist_to_db=False)

    @pytest.mark.asyncio
    async def test_record_successful_conversion(self, collector):
        """Test recording a successful conversion."""
        await collector.record_conversion(
            input_format="jpeg",
            output_format="webp",
            input_size=1024 * 1024,  # 1MB
            processing_time=1.5,
            success=True,
        )

        stats = collector.get_current_stats()
        assert stats["current_hour"]["total_conversions"] == 1
        assert stats["current_hour"]["successful_conversions"] == 1
        assert stats["current_hour"]["failed_conversions"] == 0
        assert stats["current_hour"]["format_counts"]["jpeg->webp"] == 1
        assert stats["current_hour"]["size_distribution"]["medium"] == 1
        assert stats["current_hour"]["average_processing_time"] == 1.5

    @pytest.mark.asyncio
    async def test_record_failed_conversion(self, collector):
        """Test recording a failed conversion."""
        await collector.record_conversion(
            input_format="png",
            output_format="avif",
            input_size=60 * 1024 * 1024,  # 60MB
            processing_time=10.0,
            success=False,
            error_type="timeout",
        )

        stats = collector.get_current_stats()
        assert stats["current_hour"]["total_conversions"] == 1
        assert stats["current_hour"]["successful_conversions"] == 0
        assert stats["current_hour"]["failed_conversions"] == 1
        assert stats["current_hour"]["error_types"]["timeout"] == 1
        assert stats["current_hour"]["size_distribution"]["huge"] == 1

    def test_size_bucket_determination(self, collector):
        """Test size bucket categorization."""
        assert collector._get_size_bucket(50 * 1024) == "tiny"
        assert collector._get_size_bucket(500 * 1024) == "small"
        assert collector._get_size_bucket(5 * 1024 * 1024) == "medium"
        assert collector._get_size_bucket(25 * 1024 * 1024) == "large"
        assert collector._get_size_bucket(100 * 1024 * 1024) == "huge"

    @pytest.mark.asyncio
    async def test_multiple_conversions_aggregation(self, collector):
        """Test aggregation of multiple conversions."""
        # Record multiple conversions
        conversions = [
            ("jpeg", "webp", 1024 * 1024, 1.0, True, None),
            ("png", "avif", 2 * 1024 * 1024, 2.0, True, None),
            ("jpeg", "webp", 500 * 1024, 0.5, True, None),
            ("gif", "webp", 5 * 1024 * 1024, 3.0, False, "memory_limit"),
            ("jpeg", "png", 1024 * 1024, 1.5, True, None),
        ]

        for args in conversions:
            await collector.record_conversion(*args)

        stats = collector.get_current_stats()
        hourly = stats["current_hour"]

        assert hourly["total_conversions"] == 5
        assert hourly["successful_conversions"] == 4
        assert hourly["failed_conversions"] == 1
        assert hourly["success_rate"] == 80.0
        assert hourly["format_counts"]["jpeg->webp"] == 2
        assert hourly["format_counts"]["png->avif"] == 1
        assert hourly["error_types"]["memory_limit"] == 1
        assert len(hourly["processing_times"]) == 5
        assert hourly["average_processing_time"] == 1.6  # (1+2+0.5+3+1.5)/5

    @pytest.mark.asyncio
    async def test_rolling_window_for_processing_times(self, collector):
        """Test that processing times maintain a rolling window."""
        # Record more than 1000 conversions
        for i in range(1100):
            await collector.record_conversion(
                input_format="jpeg",
                output_format="webp",
                input_size=1024 * 1024,
                processing_time=float(i),
                success=True,
            )

        stats = collector.get_current_stats()
        # Should only keep last 1000 processing times
        assert len(stats["current_hour"]["processing_times"]) == 1000
        # Should have the last 1000 values (100-1099)
        assert min(stats["current_hour"]["processing_times"]) == 100.0
        assert max(stats["current_hour"]["processing_times"]) == 1099.0

    @pytest.mark.asyncio
    async def test_cleanup_old_stats(self, collector):
        """Test cleanup of old statistics."""
        # Manually add old stats
        old_hourly_key = (datetime.now() - timedelta(hours=200)).strftime("%Y-%m-%dT%H")
        old_daily_key = (datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d")
        recent_hourly_key = datetime.now().strftime("%Y-%m-%dT%H")
        recent_daily_key = datetime.now().strftime("%Y-%m-%d")

        collector._hourly_stats[old_hourly_key] = ConversionStats(total_conversions=10)
        collector._hourly_stats[recent_hourly_key] = ConversionStats(
            total_conversions=5
        )
        collector._daily_stats[old_daily_key] = ConversionStats(total_conversions=100)
        collector._daily_stats[recent_daily_key] = ConversionStats(total_conversions=50)

        # Run cleanup
        await collector.cleanup_old_stats(hourly_retention=168, daily_retention=90)

        # Old stats should be removed
        assert old_hourly_key not in collector._hourly_stats
        assert old_daily_key not in collector._daily_stats
        # Recent stats should remain
        assert recent_hourly_key in collector._hourly_stats
        assert recent_daily_key in collector._daily_stats

    def test_hourly_stats_retrieval(self, collector):
        """Test retrieval of hourly statistics."""
        # Add some hourly stats
        now = datetime.now()
        for i in range(5):
            hour_key = (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H")
            collector._hourly_stats[hour_key] = ConversionStats(
                total_conversions=10 - i, successful_conversions=8 - i
            )

        # Get last 3 hours
        hourly_stats = collector.get_hourly_stats(hours=3)
        assert len(hourly_stats) == 3
        # Should be in reverse chronological order
        assert hourly_stats[0]["stats"]["total_conversions"] == 10
        assert hourly_stats[1]["stats"]["total_conversions"] == 9
        assert hourly_stats[2]["stats"]["total_conversions"] == 8

    def test_daily_stats_retrieval(self, collector):
        """Test retrieval of daily statistics."""
        # Add some daily stats
        now = datetime.now()
        for i in range(7):
            day_key = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            collector._daily_stats[day_key] = ConversionStats(
                total_conversions=100 - (i * 10), successful_conversions=90 - (i * 10)
            )

        # Get last 5 days
        daily_stats = collector.get_daily_stats(days=5)
        assert len(daily_stats) == 5
        # Should be in reverse chronological order
        assert daily_stats[0]["stats"]["total_conversions"] == 100
        assert daily_stats[4]["stats"]["total_conversions"] == 60


class TestStatsCollectorWithPersistence:
    """Test StatsCollector with database persistence."""

    @pytest.fixture
    def collector_with_db(self, tmp_path):
        """Create a stats collector with database persistence."""
        db_path = tmp_path / "test_stats.db"
        return StatsCollector(persist_to_db=True, db_path=str(db_path))

    @pytest.mark.asyncio
    async def test_database_persistence(self, collector_with_db, tmp_path):
        """Test that stats are persisted to database."""
        # Record a conversion
        await collector_with_db.record_conversion(
            input_format="jpeg",
            output_format="webp",
            input_size=1024 * 1024,
            processing_time=1.5,
            success=True,
        )

        # Create a new collector instance with same DB
        db_path = tmp_path / "test_stats.db"
        new_collector = StatsCollector(persist_to_db=True, db_path=str(db_path))

        # Check that database has the stats
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT COUNT(*) FROM aggregate_stats")
        count = cursor.fetchone()[0]
        conn.close()

        assert count >= 3  # Should have hourly, daily, and all_time entries
