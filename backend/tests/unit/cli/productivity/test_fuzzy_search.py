"""
Unit tests for fuzzy search functionality
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from app.cli.productivity.fuzzy_search import (
    FuzzySearcher,
    HistoryEntry,
    HistoryExporter,
    InteractiveHistoryBrowser,
)


class TestHistoryEntry:
    """Test HistoryEntry data class"""

    def test_entry_creation(self):
        """Test creating history entry"""
        entry = HistoryEntry(
            command="img convert photo.jpg -f webp",
            timestamp=datetime.now(),
            success=True,
        )

        assert entry.command == "img convert photo.jpg -f webp"
        assert entry.success is True
        assert entry.result is None

    def test_entry_to_dict(self):
        """Test converting entry to dictionary"""
        timestamp = datetime.now()
        entry = HistoryEntry(
            command="img batch *.png",
            timestamp=timestamp,
            success=False,
            result={"error": "File not found"},
        )

        data = entry.to_dict()
        assert data["command"] == "img batch *.png"
        assert data["timestamp"] == timestamp.isoformat()
        assert data["success"] is False
        assert data["result"]["error"] == "File not found"

    def test_entry_from_dict(self):
        """Test creating entry from dictionary"""
        timestamp = datetime.now()
        data = {
            "command": "img optimize photo.jpg",
            "timestamp": timestamp.isoformat(),
            "success": True,
            "result": None,
        }

        entry = HistoryEntry.from_dict(data)
        assert entry.command == "img optimize photo.jpg"
        assert entry.timestamp == timestamp
        assert entry.success is True


class TestFuzzySearcher:
    """Test fuzzy search functionality"""

    @pytest.fixture
    def sample_history(self):
        """Create sample history entries"""
        base_time = datetime.now()
        return [
            HistoryEntry(
                command="img convert photo.jpg -f webp -q 85",
                timestamp=base_time - timedelta(hours=5),
                success=True,
            ),
            HistoryEntry(
                command="img batch *.png -f avif --preset web",
                timestamp=base_time - timedelta(hours=4),
                success=True,
            ),
            HistoryEntry(
                command="img optimize image.jpg --preset thumbnail",
                timestamp=base_time - timedelta(hours=3),
                success=True,
            ),
            HistoryEntry(
                command="img convert document.pdf -f png",
                timestamp=base_time - timedelta(hours=2),
                success=False,
            ),
            HistoryEntry(
                command="img analyze photo.jpg --metadata",
                timestamp=base_time - timedelta(hours=1),
                success=True,
            ),
        ]

    @pytest.fixture
    def searcher(self):
        """Create FuzzySearcher instance"""
        return FuzzySearcher(threshold=60.0)

    def test_basic_search(self, searcher, sample_history):
        """Test basic fuzzy search"""
        results = searcher.search("convert", sample_history)

        assert len(results) > 0
        # Should find commands with "convert"
        assert any("convert" in entry.command for entry, _ in results)

    def test_fuzzy_matching(self, searcher, sample_history):
        """Test fuzzy matching with typos"""
        # Search with typo
        results = searcher.search("conver", sample_history)  # Missing 't'

        assert len(results) > 0
        # Should still find convert commands
        assert any("convert" in entry.command for entry, _ in results)

    def test_partial_matching(self, searcher, sample_history):
        """Test partial string matching"""
        results = searcher.search("webp", sample_history)

        assert len(results) > 0
        # Should find command with webp
        assert any("webp" in entry.command for entry, _ in results)

    def test_filter_by_success(self, searcher, sample_history):
        """Test filtering by success status"""
        # Only successful commands
        results = searcher.search("img", sample_history, filter_success=True)
        assert all(entry.success for entry, _ in results)

        # Only failed commands
        results = searcher.search("img", sample_history, filter_success=False)
        assert all(not entry.success for entry, _ in results)
        assert len(results) == 1  # Only one failed command in sample

    def test_limit_results(self, searcher, sample_history):
        """Test result limiting"""
        results = searcher.search("img", sample_history, limit=2)
        assert len(results) <= 2

    def test_scoring_order(self, searcher, sample_history):
        """Test that results are ordered by score"""
        results = searcher.search("convert photo", sample_history)

        if len(results) > 1:
            # Scores should be in descending order
            scores = [score for _, score in results]
            assert scores == sorted(scores, reverse=True)

    def test_search_with_time_filter(self, searcher, sample_history):
        """Test searching with time range filter"""
        now = datetime.now()

        # Search in last 3 hours
        results = searcher.search_with_filters(
            "img", sample_history, time_range=(now - timedelta(hours=3), now)
        )

        # Should only find entries from last 3 hours
        assert len(results) <= 3
        for entry, _ in results:
            assert entry.timestamp >= now - timedelta(hours=3)

    def test_search_with_command_prefix(self, searcher, sample_history):
        """Test searching with command prefix filter"""
        results = searcher.search_with_filters(
            "jpg", sample_history, command_prefix="img convert"
        )

        # Should only find convert commands
        assert all(entry.command.startswith("img convert") for entry, _ in results)

    def test_find_similar_commands(self, searcher, sample_history):
        """Test finding similar commands"""
        reference = "img convert image.png -f webp -q 90"
        results = searcher.find_similar_commands(reference, sample_history)

        assert len(results) > 0
        # Should find other convert commands
        assert any("convert" in entry.command for entry, _ in results)
        # Should not include the exact command
        assert not any(entry.command == reference for entry, _ in results)

    def test_search_by_pattern(self, searcher, sample_history):
        """Test pattern-based search"""
        # Simple substring search
        results = searcher.search_by_pattern("preset", sample_history)
        assert all("preset" in entry.command for entry in results)

        # Regex search
        results = searcher.search_by_pattern(r"\*.png", sample_history, is_regex=True)
        assert any("*.png" in entry.command for entry in results)

    def test_search_by_invalid_regex(self, searcher, sample_history):
        """Test search with invalid regex falls back to substring"""
        # Invalid regex should fall back to substring search
        results = searcher.search_by_pattern("[invalid(", sample_history, is_regex=True)
        # Should not crash, might return empty or use substring
        assert isinstance(results, list)

    def test_get_command_frequency(self, searcher):
        """Test command frequency calculation"""
        history = [
            HistoryEntry("img convert a.jpg", datetime.now(), True),
            HistoryEntry("img convert b.jpg", datetime.now(), True),
            HistoryEntry("img batch *.png", datetime.now(), True),
            HistoryEntry("img convert c.jpg", datetime.now(), True),
        ]

        frequencies = searcher.get_command_frequency(history, top_n=2)

        assert len(frequencies) <= 2
        # Convert commands should be most frequent
        assert frequencies[0][0] in [
            "img convert a.jpg",
            "img convert b.jpg",
            "img convert c.jpg",
        ]
        assert frequencies[0][1] >= 1

    def test_get_command_patterns(self, searcher, sample_history):
        """Test command pattern extraction"""
        patterns = searcher.get_command_patterns(sample_history)

        assert "convert_commands" in patterns
        assert "batch_commands" in patterns
        assert "optimize_commands" in patterns
        assert "with_quality" in patterns
        assert "with_format" in patterns
        assert "with_preset" in patterns

        # Check that commands are categorized correctly
        assert any("convert" in cmd for cmd in patterns["convert_commands"])
        assert any("batch" in cmd for cmd in patterns["batch_commands"])

    def test_empty_search(self, searcher):
        """Test search with empty query or history"""
        # Empty query
        results = searcher.search("", [])
        assert results == []

        # Empty history
        results = searcher.search("test", [])
        assert results == []


class TestInteractiveHistoryBrowser:
    """Test interactive history browser"""

    @pytest.fixture
    def browser(self):
        """Create browser instance"""
        searcher = FuzzySearcher()
        return InteractiveHistoryBrowser(searcher)

    @pytest.fixture
    def sample_history(self):
        """Create sample history"""
        return [
            HistoryEntry("img convert a.jpg", datetime.now(), True),
            HistoryEntry("img batch *.png", datetime.now(), True),
            HistoryEntry("img optimize b.jpg", datetime.now(), True),
        ]

    def test_search_and_display(self, browser, sample_history):
        """Test search and display functionality"""
        # Mock display callback
        display_called = False

        def mock_display(results, index):
            nonlocal display_called
            display_called = True
            assert len(results) > 0
            assert index == 0

        result = browser.search_and_display(
            "convert", sample_history, display_callback=mock_display
        )

        assert display_called
        assert result is not None
        assert "convert" in result.command

    def test_navigation(self, browser, sample_history):
        """Test result navigation"""
        # Perform search first
        browser.search_and_display("img", sample_history)

        # Navigate down
        initial = browser.get_selected()
        next_entry = browser.navigate_down()
        assert next_entry != initial

        # Navigate up
        prev_entry = browser.navigate_up()
        assert prev_entry == initial

    def test_navigation_boundaries(self, browser, sample_history):
        """Test navigation at boundaries"""
        browser.search_and_display("img", sample_history)

        # Navigate to top
        for _ in range(10):
            browser.navigate_up()

        # Should stay at index 0
        assert browser.current_index == 0

        # Navigate to bottom
        for _ in range(10):
            browser.navigate_down()

        # Should stay at last index
        assert browser.current_index == len(browser.current_results) - 1


class TestHistoryExporter:
    """Test history export/import functionality"""

    @pytest.fixture
    def sample_history(self):
        """Create sample history with PII"""
        return [
            HistoryEntry(
                command="img convert /home/user/photo.jpg -f webp",
                timestamp=datetime.now(),
                success=True,
                result={"output": "/home/user/output.webp"},
            ),
            HistoryEntry(
                command="img batch /Users/john/*.png",
                timestamp=datetime.now(),
                success=True,
            ),
        ]

    def test_export_with_pii_removal(self, sample_history, tmp_path):
        """Test export removes PII"""
        output_file = tmp_path / "history.json"

        success = HistoryExporter.export_sanitized(
            sample_history, str(output_file), remove_pii=True
        )

        assert success
        assert output_file.exists()

        # Check exported content
        import json

        with open(output_file, "r") as f:
            data = json.load(f)

        # Check that PII is removed
        for entry in data:
            assert "/home/user" not in entry["command"]
            assert "photo.jpg" not in entry["command"]
            assert "/Users/john" not in entry["command"]
            assert entry["result"] is None  # Results removed

    def test_export_without_pii_removal(self, sample_history, tmp_path):
        """Test export without PII removal"""
        output_file = tmp_path / "history.json"

        success = HistoryExporter.export_sanitized(
            sample_history, str(output_file), remove_pii=False
        )

        assert success

        # Check that original commands are preserved
        import json

        with open(output_file, "r") as f:
            data = json.load(f)

        assert any("/home/user/photo.jpg" in entry["command"] for entry in data)

    def test_import_history(self, tmp_path):
        """Test importing history"""
        # Create test import file
        import json

        import_data = [
            {
                "command": "img convert <FILE> -f webp",
                "timestamp": datetime.now().isoformat(),
                "success": True,
                "result": None,
            },
            {
                "command": "img batch <PATH>",
                "timestamp": datetime.now().isoformat(),
                "success": False,
                "result": None,
            },
        ]

        import_file = tmp_path / "import.json"
        with open(import_file, "w") as f:
            json.dump(import_data, f)

        # Import
        entries = HistoryExporter.import_history(str(import_file), validate=True)

        assert entries is not None
        assert len(entries) == 2
        assert entries[0].command == "img convert <FILE> -f webp"
        assert entries[0].success is True
        assert entries[1].command == "img batch <PATH>"
        assert entries[1].success is False

    def test_import_validates_commands(self, tmp_path):
        """Test that import validates commands"""
        import json

        import_data = [
            {
                "command": "img convert file.jpg",  # Valid
                "timestamp": datetime.now().isoformat(),
                "success": True,
            },
            {
                "command": "rm -rf /",  # Invalid - should be skipped
                "timestamp": datetime.now().isoformat(),
                "success": True,
            },
            {
                "command": "img batch *.png",  # Valid
                "timestamp": datetime.now().isoformat(),
                "success": True,
            },
        ]

        import_file = tmp_path / "import.json"
        with open(import_file, "w") as f:
            json.dump(import_data, f)

        entries = HistoryExporter.import_history(str(import_file), validate=True)

        assert entries is not None
        # Should only import valid img commands
        assert len(entries) == 2
        assert all(e.command.startswith("img") for e in entries)

    def test_import_handles_invalid_file(self):
        """Test import handles invalid file gracefully"""
        entries = HistoryExporter.import_history("/nonexistent/file.json")
        assert entries is None

    def test_import_handles_invalid_json(self, tmp_path):
        """Test import handles invalid JSON"""
        import_file = tmp_path / "invalid.json"
        import_file.write_text("not valid json{]}")

        entries = HistoryExporter.import_history(str(import_file))
        assert entries is None
