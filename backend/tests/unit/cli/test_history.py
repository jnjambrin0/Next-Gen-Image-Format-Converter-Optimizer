"""
from typing import Any
Unit tests for command history
"""

import tempfile
from collections import deque
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.cli.utils.history import HistoryManager


class TestHistoryManager:
    """Test history manager"""

    @pytest.fixture
    def temp_history_dir(self) -> None:
        """Create temporary history directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            history_dir = Path(tmpdir) / "history"
            history_dir.mkdir()
            yield history_dir

    @pytest.fixture
    def mock_config(self) -> None:
        """Mock configuration"""
        config = Mock()
        config.history_enabled = True
        config.history_size = 100
        return config

    def test_history_manager_init(self, temp_history_dir, mock_config) -> None:
        """Test history manager initialization"""
        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                assert manager.history_dir == temp_history_dir
                assert manager.history_file == temp_history_dir / "commands.json"
                assert manager.undo_stack_file == temp_history_dir / "undo_stack.json"
                assert manager.redo_stack_file == temp_history_dir / "redo_stack.json"
                assert isinstance(manager.history, list)
                assert isinstance(manager.undo_stack, deque)
                assert isinstance(manager.redo_stack, deque)

    def test_add_command_success(self, temp_history_dir, mock_config) -> None:
        """Test adding a successful command to history"""
        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                manager.add_command("convert test.jpg -f webp", success=True)

                assert len(manager.history) == 1
                assert manager.history[0]["command"] == "convert test.jpg -f webp"
                assert manager.history[0]["success"] == True
                assert "timestamp" in manager.history[0]

                # Should be added to undo stack
                assert len(manager.undo_stack) == 1
                assert manager.undo_stack[0]["command"] == "convert test.jpg -f webp"

    def test_add_command_failure(self, temp_history_dir, mock_config) -> None:
        """Test adding a failed command to history"""
        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                manager.add_command("convert invalid.jpg -f webp", success=False)

                assert len(manager.history) == 1
                assert manager.history[0]["success"] == False

                # Should NOT be added to undo stack
                assert len(manager.undo_stack) == 0

    def test_add_command_disabled(self, temp_history_dir, mock_config) -> None:
        """Test adding command when history is disabled"""
        mock_config.history_enabled = False

        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                manager.add_command("convert test.jpg -f webp", success=True)

                # Should not add to history
                assert len(manager.history) == 0

    def test_get_history(self, temp_history_dir, mock_config) -> None:
        """Test getting command history"""
        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                # Add some commands
                for i in range(15):
                    manager.add_command(f"command {i}", success=True)

                # Get last 10
                recent = manager.get_history(10)

                assert len(recent) == 10
                assert recent[0]["command"] == "command 5"
                assert recent[-1]["command"] == "command 14"

    def test_undo(self, temp_history_dir, mock_config) -> None:
        """Test undo functionality"""
        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                # Add commands
                manager.add_command("command 1", success=True)
                manager.add_command("command 2", success=True)

                # Undo last command
                undone = manager.undo()

                assert undone["command"] == "command 2"
                assert len(manager.undo_stack) == 1
                assert len(manager.redo_stack) == 1

    def test_undo_empty(self, temp_history_dir, mock_config) -> None:
        """Test undo with empty stack"""
        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                undone = manager.undo()

                assert undone is None

    def test_redo(self, temp_history_dir, mock_config) -> None:
        """Test redo functionality"""
        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                # Add and undo
                manager.add_command("command 1", success=True)
                manager.undo()

                # Redo
                redone = manager.redo()

                assert redone["command"] == "command 1"
                assert len(manager.undo_stack) == 1
                assert len(manager.redo_stack) == 0

    def test_clear_history(self, temp_history_dir, mock_config) -> None:
        """Test clearing history"""
        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                # Add some commands
                manager.add_command("command 1", success=True)
                manager.add_command("command 2", success=True)

                # Clear
                manager.clear_history()

                assert len(manager.history) == 0
                assert len(manager.undo_stack) == 0
                assert len(manager.redo_stack) == 0

    def test_history_size_limit(self, temp_history_dir, mock_config) -> None:
        """Test history size limit"""
        mock_config.history_size = 5

        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                # Add more than limit
                for i in range(10):
                    manager.add_command(f"command {i}", success=True)

                # Save should trim to size limit
                manager._save_history()

                # Reload and check
                saved_history = manager._load_history()
                assert len(saved_history) <= 5

    def test_new_command_clears_redo(self, temp_history_dir, mock_config) -> None:
        """Test that new command clears redo stack"""
        with patch("app.cli.utils.history.get_history_dir") as mock_get_dir:
            with patch("app.cli.utils.history.get_config") as mock_get_config:
                mock_get_dir.return_value = temp_history_dir
                mock_get_config.return_value = mock_config

                manager = HistoryManager()

                # Add, undo, then add new
                manager.add_command("command 1", success=True)
                manager.undo()
                assert len(manager.redo_stack) == 1

                manager.add_command("command 2", success=True)
                assert len(manager.redo_stack) == 0
