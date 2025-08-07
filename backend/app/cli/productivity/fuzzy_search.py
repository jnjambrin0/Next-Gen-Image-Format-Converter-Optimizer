"""
Fuzzy Search Module for Command History
Provides intelligent fuzzy matching for command history search
"""

import re
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
from rapidfuzz import fuzz, process
from rapidfuzz.distance import Levenshtein


@dataclass
class HistoryEntry:
    """Represents a command history entry"""
    command: str
    timestamp: datetime
    success: bool
    result: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return {
            "command": self.command,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "result": self.result
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'HistoryEntry':
        """Create from dictionary"""
        return cls(
            command=data["command"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            success=data.get("success", True),
            result=data.get("result")
        )


class FuzzySearcher:
    """Fuzzy search engine for command history"""
    
    def __init__(self, threshold: float = 60.0):
        """
        Initialize fuzzy searcher
        
        Args:
            threshold: Minimum similarity score (0-100) for matches
        """
        self.threshold = threshold
        self.cache = {}  # Cache for search results
    
    def search(
        self,
        query: str,
        history: List[HistoryEntry],
        limit: int = 10,
        filter_success: Optional[bool] = None
    ) -> List[Tuple[HistoryEntry, float]]:
        """
        Search history using fuzzy matching
        
        Args:
            query: Search query
            history: List of history entries to search
            limit: Maximum number of results
            filter_success: Filter by success status (None = all)
            
        Returns:
            List of (entry, score) tuples sorted by relevance
        """
        if not query or not history:
            return []
        
        # Filter by success if requested
        if filter_success is not None:
            history = [e for e in history if e.success == filter_success]
        
        # Extract commands for searching
        commands = [entry.command for entry in history]
        
        # Use multiple scoring strategies
        results = []
        
        # Strategy 1: Fuzzy token set ratio (handles word order variations)
        token_results = process.extract(
            query,
            commands,
            scorer=fuzz.token_set_ratio,
            limit=limit * 2  # Get more candidates
        )
        
        # Strategy 2: Partial ratio (handles substring matches)
        partial_results = process.extract(
            query,
            commands,
            scorer=fuzz.partial_ratio,
            limit=limit * 2
        )
        
        # Strategy 3: Levenshtein distance for typos
        lev_results = process.extract(
            query,
            commands,
            scorer=fuzz.ratio,
            limit=limit * 2
        )
        
        # Combine and weight scores
        score_map = {}
        for cmd, score, _ in token_results:
            if score >= self.threshold:
                score_map[cmd] = score_map.get(cmd, 0) + score * 1.2  # Weight token matches higher
        
        for cmd, score, _ in partial_results:
            if score >= self.threshold:
                score_map[cmd] = score_map.get(cmd, 0) + score * 1.0
        
        for cmd, score, _ in lev_results:
            if score >= self.threshold:
                score_map[cmd] = score_map.get(cmd, 0) + score * 0.8
        
        # Calculate average scores and create results
        for cmd, total_score in score_map.items():
            avg_score = total_score / 3  # Average of three strategies
            
            # Find corresponding history entry
            for entry in history:
                if entry.command == cmd:
                    results.append((entry, avg_score))
                    break
        
        # Sort by score (descending) and timestamp (recent first for ties)
        results.sort(key=lambda x: (x[1], x[0].timestamp), reverse=True)
        
        return results[:limit]
    
    def search_with_filters(
        self,
        query: str,
        history: List[HistoryEntry],
        time_range: Optional[Tuple[datetime, datetime]] = None,
        command_prefix: Optional[str] = None,
        limit: int = 10
    ) -> List[Tuple[HistoryEntry, float]]:
        """
        Search with additional filters
        
        Args:
            query: Search query
            history: List of history entries
            time_range: Optional (start, end) datetime tuple
            command_prefix: Filter by command prefix (e.g., "convert")
            limit: Maximum results
            
        Returns:
            Filtered and scored results
        """
        filtered_history = history
        
        # Apply time range filter
        if time_range:
            start, end = time_range
            filtered_history = [
                e for e in filtered_history
                if start <= e.timestamp <= end
            ]
        
        # Apply command prefix filter
        if command_prefix:
            filtered_history = [
                e for e in filtered_history
                if e.command.startswith(command_prefix)
            ]
        
        return self.search(query, filtered_history, limit)
    
    def find_similar_commands(
        self,
        command: str,
        history: List[HistoryEntry],
        limit: int = 5
    ) -> List[Tuple[HistoryEntry, float]]:
        """
        Find commands similar to a given command
        
        Args:
            command: Reference command
            history: History to search
            limit: Maximum results
            
        Returns:
            Similar commands with scores
        """
        # Filter out exact matches
        filtered = [e for e in history if e.command != command]
        
        # Use token set ratio for finding similar structure
        return self.search(command, filtered, limit)
    
    def search_by_pattern(
        self,
        pattern: str,
        history: List[HistoryEntry],
        is_regex: bool = False
    ) -> List[HistoryEntry]:
        """
        Search using pattern matching (exact or regex)
        
        Args:
            pattern: Search pattern
            history: History to search
            is_regex: Whether pattern is a regex
            
        Returns:
            Matching entries
        """
        results = []
        
        if is_regex:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                results = [e for e in history if regex.search(e.command)]
            except re.error:
                # Invalid regex, fall back to substring search
                pattern_lower = pattern.lower()
                results = [e for e in history if pattern_lower in e.command.lower()]
        else:
            # Simple substring search
            pattern_lower = pattern.lower()
            results = [e for e in history if pattern_lower in e.command.lower()]
        
        # Sort by timestamp (recent first)
        results.sort(key=lambda x: x.timestamp, reverse=True)
        
        return results
    
    def get_command_frequency(
        self,
        history: List[HistoryEntry],
        top_n: int = 10
    ) -> List[Tuple[str, int]]:
        """
        Get most frequently used commands
        
        Args:
            history: History entries
            top_n: Number of top commands to return
            
        Returns:
            List of (command, count) tuples
        """
        from collections import Counter
        
        # Count command frequencies
        command_counts = Counter(e.command for e in history)
        
        return command_counts.most_common(top_n)
    
    def get_command_patterns(
        self,
        history: List[HistoryEntry]
    ) -> Dict[str, List[str]]:
        """
        Extract common command patterns
        
        Args:
            history: History entries
            
        Returns:
            Dictionary of pattern -> example commands
        """
        patterns = {
            "convert_commands": [],
            "batch_commands": [],
            "optimize_commands": [],
            "with_quality": [],
            "with_format": [],
            "with_preset": []
        }
        
        for entry in history:
            cmd = entry.command
            
            # Categorize by command type
            if cmd.startswith("img convert") or cmd.startswith("imgc"):
                patterns["convert_commands"].append(cmd)
            elif cmd.startswith("img batch") or cmd.startswith("imgb"):
                patterns["batch_commands"].append(cmd)
            elif cmd.startswith("img optimize") or cmd.startswith("imgo"):
                patterns["optimize_commands"].append(cmd)
            
            # Categorize by parameters
            if "-q " in cmd or "--quality" in cmd:
                patterns["with_quality"].append(cmd)
            if "-f " in cmd or "--format" in cmd:
                patterns["with_format"].append(cmd)
            if "--preset" in cmd:
                patterns["with_preset"].append(cmd)
        
        # Limit each category to unique commands
        for key in patterns:
            patterns[key] = list(set(patterns[key]))[:5]
        
        return patterns


class InteractiveHistoryBrowser:
    """Interactive history browser with arrow key navigation"""
    
    def __init__(self, searcher: FuzzySearcher):
        """
        Initialize interactive browser
        
        Args:
            searcher: FuzzySearcher instance
        """
        self.searcher = searcher
        self.current_results = []
        self.current_index = 0
    
    def search_and_display(
        self,
        query: str,
        history: List[HistoryEntry],
        display_callback=None
    ) -> Optional[HistoryEntry]:
        """
        Search and display results interactively
        
        Args:
            query: Search query
            history: History to search
            display_callback: Optional callback for custom display
            
        Returns:
            Selected history entry or None
        """
        # Perform search
        results = self.searcher.search(query, history)
        
        if not results:
            return None
        
        self.current_results = results
        self.current_index = 0
        
        # Display results
        if display_callback:
            display_callback(results, self.current_index)
        else:
            self._default_display(results, self.current_index)
        
        return results[0][0] if results else None
    
    def _default_display(
        self,
        results: List[Tuple[HistoryEntry, float]],
        selected_index: int
    ):
        """Default display implementation"""
        print("\nSearch Results:")
        print("-" * 60)
        
        for i, (entry, score) in enumerate(results[:10]):
            marker = ">" if i == selected_index else " "
            status = "✓" if entry.success else "✗"
            timestamp = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            
            print(f"{marker} [{status}] {timestamp} (Score: {score:.1f}%)")
            print(f"  {entry.command}")
            print()
    
    def navigate_up(self) -> Optional[HistoryEntry]:
        """Navigate to previous result"""
        if self.current_results and self.current_index > 0:
            self.current_index -= 1
            return self.current_results[self.current_index][0]
        return None
    
    def navigate_down(self) -> Optional[HistoryEntry]:
        """Navigate to next result"""
        if self.current_results and self.current_index < len(self.current_results) - 1:
            self.current_index += 1
            return self.current_results[self.current_index][0]
        return None
    
    def get_selected(self) -> Optional[HistoryEntry]:
        """Get currently selected entry"""
        if self.current_results and 0 <= self.current_index < len(self.current_results):
            return self.current_results[self.current_index][0]
        return None


class HistoryExporter:
    """Export/import history with privacy protection"""
    
    @staticmethod
    def export_sanitized(
        history: List[HistoryEntry],
        output_file: str,
        remove_pii: bool = True
    ) -> bool:
        """
        Export history with PII removed
        
        Args:
            history: History to export
            output_file: Output file path
            remove_pii: Whether to remove PII
            
        Returns:
            Success status
        """
        import json
        from app.cli.productivity.autocomplete import PrivacySanitizer
        
        try:
            export_data = []
            
            for entry in history:
                entry_dict = entry.to_dict()
                
                if remove_pii:
                    # Sanitize command
                    entry_dict["command"] = PrivacySanitizer.sanitize(entry_dict["command"])
                    # Remove any result data that might contain PII
                    entry_dict["result"] = None
                
                export_data.append(entry_dict)
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def import_history(
        input_file: str,
        validate: bool = True
    ) -> Optional[List[HistoryEntry]]:
        """
        Import history from file
        
        Args:
            input_file: Input file path
            validate: Whether to validate entries
            
        Returns:
            List of history entries or None on error
        """
        import json
        
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
            
            entries = []
            for item in data:
                try:
                    entry = HistoryEntry.from_dict(item)
                    
                    if validate:
                        # Basic validation
                        if not entry.command or not entry.command.startswith("img"):
                            continue
                    
                    entries.append(entry)
                except (KeyError, ValueError):
                    # Skip invalid entries
                    continue
            
            return entries
        except Exception:
            return None