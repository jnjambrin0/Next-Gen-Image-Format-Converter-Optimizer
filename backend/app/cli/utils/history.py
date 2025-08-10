"""
Command History Management
Handles command history for undo/redo functionality with fuzzy search
"""

import json
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.cli.config import get_config, get_history_dir
from app.cli.productivity.autocomplete import PrivacySanitizer
from app.cli.productivity.fuzzy_search import (FuzzySearcher, HistoryEntry,
                                               HistoryExporter,
                                               InteractiveHistoryBrowser)


class HistoryManager:
    """Manages command history for undo/redo with fuzzy search"""

    def __init__(self) -> None:
        self.history_dir = get_history_dir()
        self.history_file = self.history_dir / "commands.json"
        self.undo_stack_file = self.history_dir / "undo_stack.json"
        self.redo_stack_file = self.history_dir / "redo_stack.json"

        self._ensure_history_dir()
        self.config = get_config()

        # Load history
        self.history = self._load_history()
        self.undo_stack = deque(
            self._load_stack(self.undo_stack_file), maxlen=self.config.history_size
        )
        self.redo_stack = deque(
            self._load_stack(self.redo_stack_file), maxlen=self.config.history_size
        )

        # Initialize fuzzy search components
        self.fuzzy_searcher = FuzzySearcher(threshold=60.0)
        self.interactive_browser = InteractiveHistoryBrowser(self.fuzzy_searcher)
        self.sanitizer = PrivacySanitizer()

        # Apply retention limit on startup
        self._apply_retention_limit()

    def _ensure_history_dir(self) -> None:
        """Ensure history directory exists"""
        self.history_dir.mkdir(parents=True, exist_ok=True)

    def _load_history(self) -> List[Dict]:
        """Load command history"""
        if self.history_file.exists():
            try:
                with open(self.history_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []

    def _save_history(self) -> None:
        """Save command history"""
        # Keep only the most recent entries
        if len(self.history) > self.config.history_size:
            self.history = self.history[-self.config.history_size :]

        with open(self.history_file, "w") as f:
            json.dump(self.history, f, indent=2)

    def _load_stack(self, file: Path) -> List[Dict]:
        """Load undo/redo stack"""
        if file.exists():
            try:
                with open(file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []

    def _save_stack(self, stack: deque, file: Path) -> None:
        """Save undo/redo stack"""
        with open(file, "w") as f:
            json.dump(list(stack), f, indent=2)

    def add_command(
        self, command: str, success: bool = True, result: Optional[Dict] = None
    ) -> None:
        """Add a command to history"""
        if not self.config.history_enabled:
            return

        entry = {
            "command": command,
            "timestamp": datetime.now().isoformat(),
            "success": success,
            "result": result,
        }

        self.history.append(entry)
        self._save_history()

        # Add to undo stack if successful
        if success:
            self.undo_stack.append(entry)
            self._save_stack(self.undo_stack, self.undo_stack_file)

            # Clear redo stack on new command
            self.redo_stack.clear()
            self._save_stack(self.redo_stack, self.redo_stack_file)

    def get_history(self, count: int = 10) -> List[Dict]:
        """Get recent command history"""
        return self.history[-count:] if self.history else []

    def undo(self) -> Optional[Dict]:
        """Undo last command"""
        if not self.undo_stack:
            return None

        command = self.undo_stack.pop()
        self.redo_stack.append(command)

        self._save_stack(self.undo_stack, self.undo_stack_file)
        self._save_stack(self.redo_stack, self.redo_stack_file)

        return command

    def redo(self) -> Optional[Dict]:
        """Redo last undone command"""
        if not self.redo_stack:
            return None

        command = self.redo_stack.pop()
        self.undo_stack.append(command)

        self._save_stack(self.undo_stack, self.undo_stack_file)
        self._save_stack(self.redo_stack, self.redo_stack_file)

        return command

    def clear_history(self) -> None:
        """Clear all history"""
        self.history.clear()
        self.undo_stack.clear()
        self.redo_stack.clear()

        self._save_history()
        self._save_stack(self.undo_stack, self.undo_stack_file)
        self._save_stack(self.redo_stack, self.redo_stack_file)

    def _apply_retention_limit(self, days: int = 7) -> None:
        """Apply retention limit to history (default 7 days)"""
        if not self.history:
            return

        cutoff_date = datetime.now() - timedelta(days=days)

        # Filter history entries
        self.history = [
            entry
            for entry in self.history
            if datetime.fromisoformat(entry["timestamp"]) > cutoff_date
        ]

        self._save_history()

    def fuzzy_search(
        self, query: str, limit: int = 10, filter_success: Optional[bool] = None
    ) -> List[Tuple[HistoryEntry, float]]:
        """
        Search history using fuzzy matching

        Args:
            query: Search query
            limit: Maximum number of results
            filter_success: Filter by success status

        Returns: List[Any] of (entry, score) tuples
        """
        # Convert history dicts to HistoryEntry objects
        entries = [HistoryEntry.from_dict(h) for h in self.history]

        return self.fuzzy_searcher.search(query, entries, limit, filter_success)

    def search_with_filters(
        self,
        query: str,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        command_prefix: Optional[str] = None,
        limit: int = 10,
    ) -> List[Tuple[HistoryEntry, float]]:
        """
        Search with additional filters

        Args:
            query: Search query
            time_range: Optional[Any] time range filter
            command_prefix: Filter by command prefix
            limit: Maximum results

        Returns:
            Filtered search results
        """
        entries = [HistoryEntry.from_dict(h) for h in self.history]

        return self.fuzzy_searcher.search_with_filters(
            query, entries, time_range, command_prefix, limit
        )

    def find_similar_commands(
        self, command: str, limit: int = 5
    ) -> List[Tuple[HistoryEntry, float]]:
        """
        Find commands similar to a given command

        Args:
            command: Reference command
            limit: Maximum results

        Returns:
            Similar commands with scores
        """
        entries = [HistoryEntry.from_dict(h) for h in self.history]
        return self.fuzzy_searcher.find_similar_commands(command, entries, limit)

    def search_by_pattern(
        self, pattern: str, is_regex: bool = False
    ) -> List[HistoryEntry]:
        """
        Search using pattern matching

        Args:
            pattern: Search pattern
            is_regex: Whether pattern is a regex

        Returns:
            Matching entries
        """
        entries = [HistoryEntry.from_dict(h) for h in self.history]
        return self.fuzzy_searcher.search_by_pattern(pattern, entries, is_regex)

    def get_command_frequency(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """
        Get most frequently used commands

        Args:
            top_n: Number of top commands

        Returns: List[Any] of (command, count) tuples
        """
        entries = [HistoryEntry.from_dict(h) for h in self.history]
        return self.fuzzy_searcher.get_command_frequency(entries, top_n)

    def get_command_patterns(self) -> Dict[str, List[str]]:
        """
        Extract common command patterns

        Returns:
            Dictionary of pattern categories
        """
        entries = [HistoryEntry.from_dict(h) for h in self.history]
        return self.fuzzy_searcher.get_command_patterns(entries)

    def interactive_search(
        self, query: str, display_callback=None
    ) -> Optional[HistoryEntry]:
        """
        Perform interactive search with navigation

        Args:
            query: Search query
            display_callback: Optional[Any] display callback

        Returns:
            Selected entry or None
        """
        entries = [HistoryEntry.from_dict(h) for h in self.history]
        return self.interactive_browser.search_and_display(
            query, entries, display_callback
        )

    def export_history(self, output_file: str, remove_pii: bool = True) -> bool:
        """
        Export history with optional PII removal

        Args:
            output_file: Output file path
            remove_pii: Whether to remove PII

        Returns:
            Success status
        """
        entries = [HistoryEntry.from_dict(h) for h in self.history]
        return HistoryExporter.export_sanitized(entries, output_file, remove_pii)

    def import_history(self, input_file: str, merge: bool = True) -> bool:
        """
        Import history from file

        Args:
            input_file: Input file path
            merge: Whether to merge with existing history

        Returns:
            Success status
        """
        imported = HistoryExporter.import_history(input_file, validate=True)

        if not imported:
            return False

        if not merge:
            self.history.clear()

        # Convert to dict format and add
        for entry in imported:
            # Sanitize before adding
            sanitized_command = self.sanitizer.sanitize(entry.command)
            self.history.append(
                {
                    "command": sanitized_command,
                    "timestamp": entry.timestamp.isoformat(),
                    "success": entry.success,
                    "result": None,  # Don't import results (might contain PII)
                }
            )

        self._save_history()
        return True


# Global history manager
_history_manager = None


def get_history_manager() -> HistoryManager:
    """Get or create history manager"""
    global _history_manager
    if _history_manager is None:
        _history_manager = HistoryManager()
    return _history_manager


def record_command(
    command: str, success: bool = True, result: Optional[Dict] = None
) -> None:
    """Record a command in history"""
    manager = get_history_manager()
    manager.add_command(command, success, result)
