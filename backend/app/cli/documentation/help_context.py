"""
Help Context Analyzer
Provides context-aware help based on current command state
"""

import json
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import typer
from rich.columns import Columns
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from app.cli.productivity.fuzzy_search import FuzzySearcher


@dataclass
class HelpContext:
    """Represents the current help context"""

    command_chain: List[str]
    current_params: Dict[str, Any]
    error_state: Optional[str] = None
    suggestions: List[str] = field(default_factory=list)
    relevant_examples: List[str] = field(default_factory=list)
    related_topics: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for caching"""
        return {
            "command_chain": self.command_chain,
            "current_params": self.current_params,
            "error_state": str(self.error_state) if self.error_state else None,
            "suggestions": self.suggestions,
            "relevant_examples": self.relevant_examples,
            "related_topics": self.related_topics,
        }


class HelpContextAnalyzer:
    """Analyzes command context to provide relevant help"""

    # Constants for cache management
    DEFAULT_CACHE_TTL = 300  # 5 minutes
    MAX_CACHE_SIZE = 100  # Maximum number of cached contexts
    CACHE_CLEANUP_INTERVAL = 600  # 10 minutes

    def __init__(
        self, console: Optional[Console] = None, cache_ttl: int = DEFAULT_CACHE_TTL
    ):
        self.console = console or Console()
        self.fuzzy_searcher = FuzzySearcher(threshold=60.0)
        self._help_cache: Dict[str, HelpContext] = {}
        self._cache_ttl = cache_ttl
        self._cache_timestamps: Dict[str, float] = {}
        self._last_cleanup = time.time()
        self._cache_access_count: Dict[str, int] = {}  # Track access frequency
        self._load_help_database()

    def _load_help_database(self):
        """Load help content database"""
        # Help content is embedded for offline operation
        self.help_topics = {
            "convert": {
                "brief": "Convert single image to different format",
                "description": "Converts a single image file to a specified output format with optional quality and optimization settings.",
                "examples": [
                    "img convert photo.jpg -f webp",
                    "img convert input.png -f avif --quality 85",
                    "img convert document.pdf -f png --preset document",
                ],
                "related": ["batch", "optimize", "formats"],
                "common_errors": {
                    "CONV001": "File not found - check the input path",
                    "CONV002": "Unsupported format - see 'img formats' for supported types",
                    "CONV003": "Permission denied - check file permissions",
                },
            },
            "batch": {
                "brief": "Process multiple images at once",
                "description": "Batch convert multiple images with pattern matching and parallel processing.",
                "examples": [
                    "img batch *.png -f webp",
                    "img batch photos/*.jpg -f avif --workers 4",
                    "img batch --input-dir ./images --output-dir ./converted -f jpeg",
                ],
                "related": ["convert", "watch", "chain"],
                "common_errors": {
                    "BATCH001": "No files matched pattern - check glob pattern",
                    "BATCH002": "Output directory not writable",
                    "BATCH003": "Worker limit exceeded - reduce --workers value",
                },
            },
            "optimize": {
                "brief": "Intelligently optimize images",
                "description": "Optimize images using AI-powered content detection and quality analysis.",
                "examples": [
                    "img optimize photo.jpg --preset web",
                    "img optimize screenshot.png --target-size 100kb",
                    "img optimize logo.svg --lossless",
                ],
                "related": ["analyze", "presets", "convert"],
                "common_errors": {
                    "OPT001": "Cannot achieve target size - try lower quality",
                    "OPT002": "Preset not found - see 'img presets list'",
                    "OPT003": "Content detection failed - fallback to default",
                },
            },
            "analyze": {
                "brief": "Analyze image content and metadata",
                "description": "Analyze images for content type, quality metrics, and metadata.",
                "examples": [
                    "img analyze photo.jpg",
                    "img analyze image.png --detailed",
                    "img analyze *.jpg --export-csv report.csv",
                ],
                "related": ["optimize", "formats"],
                "common_errors": {
                    "ANA001": "Corrupt image file",
                    "ANA002": "Metadata extraction failed",
                },
            },
            "formats": {
                "brief": "Show supported formats and capabilities",
                "description": "Display information about supported input and output formats.",
                "examples": [
                    "img formats",
                    "img formats --detailed webp",
                    "img formats --compatibility-matrix",
                ],
                "related": ["convert", "batch"],
                "common_errors": {},
            },
            "presets": {
                "brief": "Manage conversion presets",
                "description": "Create, edit, and manage conversion presets for common use cases.",
                "examples": [
                    "img presets list",
                    "img presets create web-optimized --format webp --quality 85",
                    "img presets apply web-optimized photo.jpg",
                ],
                "related": ["optimize", "convert"],
                "common_errors": {
                    "PRE001": "Preset already exists",
                    "PRE002": "Invalid preset configuration",
                },
            },
            "watch": {
                "brief": "Watch directory for automatic conversion",
                "description": "Monitor a directory and automatically convert new or modified images.",
                "examples": [
                    "img watch ./uploads -f webp",
                    "img watch --pattern '*.png' --output-dir ./processed",
                    "img watch ./photos --preset web --recursive",
                ],
                "related": ["batch", "chain"],
                "common_errors": {
                    "WATCH001": "Directory not found",
                    "WATCH002": "Too many files to watch - increase limit",
                    "WATCH003": "File system events not supported",
                },
            },
            "chain": {
                "brief": "Chain multiple operations",
                "description": "Execute multiple conversion operations in sequence.",
                "examples": [
                    "img chain 'convert {input} -f png' 'optimize {output} --preset web'",
                    "img chain --from-file workflow.txt",
                    "img chain 'analyze {input}' 'convert {input} -f {recommended}'",
                ],
                "related": ["batch", "watch", "optimize"],
                "common_errors": {
                    "CHAIN001": "Invalid chain syntax",
                    "CHAIN002": "Chain step failed",
                },
            },
        }

        # Command shortcuts and aliases
        self.command_aliases = {
            "c": "convert",
            "b": "batch",
            "o": "optimize",
            "a": "analyze",
            "f": "formats",
            "p": "presets",
            "w": "watch",
            "ch": "chain",
        }

    def get_context(self, ctx: typer.Context) -> HelpContext:
        """
        Analyze current context and return help information

        Args:
            ctx: Typer context object

        Returns:
            HelpContext with relevant help information
        """
        # Extract context information
        command_path = ctx.command_path if ctx.command_path else ""
        command_chain = command_path.split() if command_path else []

        # Remove 'img' from chain if present
        if command_chain and command_chain[0] == "img":
            command_chain = command_chain[1:]

        # Get current parameters
        current_params = ctx.params if ctx.params else {}

        # Check for error state
        error_state = ctx.obj.get("last_error") if ctx.obj else None

        # Generate cache key
        cache_key = (
            f"{':'.join(command_chain)}:{str(current_params)}:{str(error_state)}"
        )

        # Perform cache cleanup if needed
        self._maybe_cleanup_cache()

        # Check cache
        if cache_key in self._help_cache:
            timestamp = self._cache_timestamps.get(cache_key, 0)
            if time.time() - timestamp < self._cache_ttl:
                # Update access count for LRU tracking
                self._cache_access_count[cache_key] = (
                    self._cache_access_count.get(cache_key, 0) + 1
                )
                return self._help_cache[cache_key]
            else:
                # Expired entry, remove it
                self._evict_cache_entry(cache_key)

        # Build context
        context = HelpContext(
            command_chain=command_chain,
            current_params=current_params,
            error_state=error_state,
        )

        # Get relevant help
        if command_chain:
            primary_command = self._resolve_alias(command_chain[0])
            if primary_command in self.help_topics:
                topic = self.help_topics[primary_command]
                context.relevant_examples = topic.get("examples", [])
                context.related_topics = topic.get("related", [])

                # Add error-specific help if applicable
                if error_state:
                    # Extract error code from error string if present
                    import re

                    error_code_match = re.search(
                        r"(CONV|BATCH|OPT)\d{3}", str(error_state)
                    )
                    if error_code_match:
                        error_code = error_code_match.group(0)
                        error_help = topic.get("common_errors", {}).get(error_code)
                        if error_help:
                            context.suggestions.append(error_help)

        # Get suggestions based on partial input
        if command_chain and not context.relevant_examples:
            suggestions = self._get_command_suggestions(command_chain[-1])
            context.suggestions.extend(suggestions)

        # Cache the context
        self._help_cache[cache_key] = context
        self._cache_timestamps[cache_key] = time.time()

        return context

    def _resolve_alias(self, command: str) -> str:
        """Resolve command alias to full command name"""
        return self.command_aliases.get(command, command)

    def _get_command_suggestions(self, partial_command: str) -> List[str]:
        """Get command suggestions for partial input"""
        from difflib import get_close_matches

        all_commands = list(self.help_topics.keys())

        # Find similar commands using difflib
        matches = get_close_matches(partial_command, all_commands, n=3, cutoff=0.6)

        suggestions = []
        for cmd in matches:
            if cmd in self.help_topics:
                brief = self.help_topics[cmd].get("brief", "")
                suggestions.append(f"{cmd} - {brief}")

        return suggestions

    def search_help(self, query: str) -> List[Dict[str, Any]]:
        """
        Search help database for relevant topics

        Args:
            query: Search query

        Returns:
            List of matching help topics
        """
        results = []
        query_lower = query.lower()

        for command, topic in self.help_topics.items():
            score = 0

            # Check command name
            if query_lower in command.lower():
                score += 10

            # Check brief description
            if query_lower in topic.get("brief", "").lower():
                score += 5

            # Check full description
            if query_lower in topic.get("description", "").lower():
                score += 3

            # Check examples
            for example in topic.get("examples", []):
                if query_lower in example.lower():
                    score += 2
                    break

            # Check error codes and messages
            for error_code, error_msg in topic.get("common_errors", {}).items():
                if (
                    query_lower in error_code.lower()
                    or query_lower in error_msg.lower()
                ):
                    score += 2
                    break

            if score > 0:
                results.append({"command": command, "topic": topic, "score": score})

        # Sort by score
        results.sort(key=lambda x: x["score"], reverse=True)

        return results[:10]  # Return top 10 results

    def display_context_help(self, context: HelpContext, verbose: bool = False):
        """
        Display context-aware help in the console

        Args:
            context: Help context to display
            verbose: Show detailed help
        """
        if not context.command_chain:
            self._display_general_help()
            return

        primary_command = self._resolve_alias(context.command_chain[0])

        if primary_command in self.help_topics:
            topic = self.help_topics[primary_command]

            # Title
            title = (
                f"[bold cyan]{primary_command}[/bold cyan] - {topic.get('brief', '')}"
            )

            # Build help content
            content = []

            # Description
            if verbose or not topic.get("examples"):
                content.append(
                    f"\n[yellow]Description:[/yellow]\n{topic.get('description', '')}"
                )

            # Examples
            if topic.get("examples"):
                content.append("\n[yellow]Examples:[/yellow]")
                for example in topic["examples"][: 3 if not verbose else None]:
                    content.append(f"  [green]$[/green] {example}")

            # Error help
            if context.error_state:
                content.append(f"\n[red]Error Help:[/red]")
                for suggestion in context.suggestions:
                    content.append(f"  • {suggestion}")

            # Related topics
            if topic.get("related"):
                related = ", ".join([f"[cyan]{r}[/cyan]" for r in topic["related"]])
                content.append(f"\n[yellow]Related:[/yellow] {related}")

            # Display panel
            panel = Panel(
                "\n".join(content), title=title, border_style="cyan", padding=(1, 2)
            )
            self.console.print(panel)

            # Additional suggestions
            if context.suggestions and not context.error_state:
                self.console.print("\n[yellow]💡 Suggestions:[/yellow]")
                for suggestion in context.suggestions:
                    self.console.print(f"  • {suggestion}")
        else:
            # Command not found - show suggestions
            self._display_suggestions(context)

    def _display_general_help(self):
        """Display general help when no command is specified"""
        # Create command table
        table = Table(title="Available Commands", box=None, padding=(0, 2))
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Shortcut", style="green")
        table.add_column("Description")

        for cmd, topic in sorted(self.help_topics.items()):
            shortcut = next(
                (k for k, v in self.command_aliases.items() if v == cmd), "-"
            )
            table.add_row(cmd, shortcut, topic.get("brief", ""))

        self.console.print(table)
        self.console.print(
            "\n[yellow]Use 'img COMMAND --help' for detailed help[/yellow]"
        )

    def _display_suggestions(self, context: HelpContext):
        """Display command suggestions"""
        if context.suggestions:
            self.console.print("[yellow]Did you mean:[/yellow]")
            for suggestion in context.suggestions:
                self.console.print(f"  • {suggestion}")
        else:
            self.console.print(
                f"[red]Unknown command:[/red] {' '.join(context.command_chain)}"
            )
            self.console.print(
                "[yellow]Use 'img --help' to see available commands[/yellow]"
            )

    def clear_cache(self):
        """Clear help cache"""
        self._help_cache.clear()
        self._cache_timestamps.clear()
        self._cache_access_count.clear()
        self._last_cleanup = time.time()

    def _maybe_cleanup_cache(self, force: bool = False):
        """Perform cache cleanup if needed"""
        current_time = time.time()

        # Check if cleanup is needed
        if (
            not force
            and current_time - self._last_cleanup < self.CACHE_CLEANUP_INTERVAL
        ):
            return

        self._last_cleanup = current_time

        # Remove expired entries
        expired_keys = []
        for key, timestamp in self._cache_timestamps.items():
            if current_time - timestamp >= self._cache_ttl:
                expired_keys.append(key)

        for key in expired_keys:
            self._evict_cache_entry(key)

        # If cache is still too large, remove least recently used
        if len(self._help_cache) > self.MAX_CACHE_SIZE:
            self._evict_lru_entries()

    def _evict_cache_entry(self, key: str):
        """Evict a single cache entry"""
        self._help_cache.pop(key, None)
        self._cache_timestamps.pop(key, None)
        self._cache_access_count.pop(key, None)

    def _evict_lru_entries(self):
        """Evict least recently used entries to maintain cache size"""
        if len(self._help_cache) <= self.MAX_CACHE_SIZE:
            return

        # Sort by access count and timestamp
        cache_items = []
        for key in self._help_cache.keys():
            access_count = self._cache_access_count.get(key, 0)
            timestamp = self._cache_timestamps.get(key, 0)
            # Score combines access frequency and recency
            score = access_count * 1000 + timestamp
            cache_items.append((key, score))

        # Sort by score (lower score = less frequently/recently used)
        cache_items.sort(key=lambda x: x[1])

        # Remove entries until cache size is acceptable
        entries_to_remove = (
            len(self._help_cache) - self.MAX_CACHE_SIZE + 10
        )  # Remove 10 extra
        for i in range(min(entries_to_remove, len(cache_items))):
            self._evict_cache_entry(cache_items[i][0])
