"""
Offline Documentation Browser
Browse and search documentation with full-text search
"""

import json
from pathlib import Path
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.tree import Tree
from rich.table import Table
from rich.prompt import Prompt

# Optional import for search
try:
    from whoosh import index, fields, qparser
    from whoosh.filedb.filestore import RamStorage
    from whoosh.highlight import UppercaseFormatter

    WHOOSH_AVAILABLE = True
except ImportError:
    WHOOSH_AVAILABLE = False


@dataclass
class DocSection:
    """Represents a documentation section"""

    id: str
    title: str
    content: str
    category: str
    parent_id: Optional[str] = None
    children: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    related: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "category": self.category,
            "parent_id": self.parent_id,
            "children": self.children,
            "tags": self.tags,
            "related": self.related,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "DocSection":
        """Create from dictionary"""
        return cls(
            id=data["id"],
            title=data["title"],
            content=data["content"],
            category=data["category"],
            parent_id=data.get("parent_id"),
            children=data.get("children", []),
            tags=data.get("tags", []),
            related=data.get("related", []),
        )


@dataclass
class Bookmark:
    """Documentation bookmark"""

    section_id: str
    title: str
    timestamp: datetime
    notes: Optional[str] = None


class DocumentationBrowser:
    """Browse documentation with search and navigation"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.sections: Dict[str, DocSection] = {}
        self.bookmarks: List[Bookmark] = []
        self.history: List[str] = []
        self.current_section: Optional[str] = None
        self.search_index = None
        self.config_dir = Path.home() / ".image-converter" / "docs"

        self._load_documentation()
        self._init_search_index()
        self._load_bookmarks()

    def _load_documentation(self):
        """Load documentation sections"""
        # Documentation is embedded for offline operation
        docs = [
            DocSection(
                id="root",
                title="Image Converter CLI Documentation",
                content="""# Image Converter CLI Documentation

Welcome to the comprehensive documentation for the Image Converter CLI.

## Quick Navigation

- **Getting Started** - Installation and basic usage
- **Commands** - Detailed command reference
- **Formats** - Supported image formats
- **Optimization** - Advanced optimization techniques
- **Troubleshooting** - Common issues and solutions

Use arrow keys to navigate, Enter to select, 'b' for bookmarks, 's' to search.""",
                category="root",
                children=[
                    "getting-started",
                    "commands",
                    "formats",
                    "optimization",
                    "troubleshooting",
                ],
            ),
            DocSection(
                id="getting-started",
                title="Getting Started",
                content="""# Getting Started

## Installation

The Image Converter CLI is included with your installation. No additional setup required.

## Basic Usage

### Convert a Single Image

```bash
img convert photo.jpg -f webp
```

### Batch Convert Multiple Images

```bash
img batch *.png -f avif
```

### Optimize for Web

```bash
img optimize photo.jpg --preset web
```

## Next Steps

- Learn about [Commands](#commands)
- Explore [Formats](#formats)
- Master [Optimization](#optimization)""",
                category="guide",
                parent_id="root",
                children=["basic-conversion", "batch-processing"],
                tags=["beginner", "installation", "quickstart"],
            ),
            DocSection(
                id="commands",
                title="Command Reference",
                content="""# Command Reference

## Core Commands

### convert
Convert single images between formats.

### batch
Process multiple images at once.

### optimize
Intelligently optimize images using AI.

### analyze
Analyze image content and metadata.

### formats
Display supported formats and capabilities.

### presets
Manage conversion presets.

### watch
Monitor directories for automatic conversion.

### chain
Chain multiple operations together.""",
                category="reference",
                parent_id="root",
                children=["cmd-convert", "cmd-batch", "cmd-optimize"],
                tags=["commands", "reference", "api"],
            ),
            DocSection(
                id="cmd-convert",
                title="Convert Command",
                content="""# Convert Command

## Synopsis

```bash
img convert [OPTIONS] INPUT_FILE
```

## Description

Converts a single image file to a different format with customizable settings.

## Options

- `-f, --format FORMAT` - Output format (required)
- `-o, --output FILE` - Output filename
- `--quality VALUE` - Quality setting (1-100)
- `--preset NAME` - Apply a conversion preset
- `--resize WxH` - Resize to specific dimensions
- `--strip-metadata` - Remove all metadata
- `--preserve-metadata` - Keep original metadata

## Examples

### Basic Conversion
```bash
img convert photo.jpg -f webp
```

### With Quality Control
```bash
img convert image.png -f jpeg --quality 90
```

### Using Presets
```bash
img convert large.jpg --preset thumbnail
```

## Related Commands

- [batch](#cmd-batch) - Convert multiple files
- [optimize](#cmd-optimize) - Optimize intelligently""",
                category="command",
                parent_id="commands",
                tags=["convert", "single", "format"],
            ),
            DocSection(
                id="formats",
                title="Image Formats",
                content="""# Supported Image Formats

## Input Formats

### JPEG (.jpg, .jpeg)
- **Pros**: Universal support, small file size
- **Cons**: Lossy compression, no transparency
- **Best for**: Photos, web images

### PNG (.png)
- **Pros**: Lossless, transparency support
- **Cons**: Large file sizes
- **Best for**: Screenshots, logos, graphics

### WebP (.webp)
- **Pros**: Excellent compression, transparency
- **Cons**: Limited older browser support
- **Best for**: Web images, modern applications

### HEIF/HEIC (.heif, .heic)
- **Pros**: Excellent compression, Apple ecosystem
- **Cons**: Limited support outside Apple
- **Best for**: iOS photos, Apple devices

## Output Formats

### WebP
Modern format with excellent compression and wide support.

### AVIF
Next-generation format with best-in-class compression.

### JPEG XL
Future JPEG replacement with progressive decoding.

## Format Comparison

| Format | Compression | Quality | Browser Support | File Size |
|--------|------------|---------|-----------------|-----------|
| JPEG   | Lossy      | Good    | Universal       | Medium    |
| PNG    | Lossless   | Perfect | Universal       | Large     |
| WebP   | Both       | Great   | Modern          | Small     |
| AVIF   | Both       | Best    | Growing         | Smallest  |""",
                category="reference",
                parent_id="root",
                children=["format-webp", "format-avif"],
                tags=["formats", "comparison", "features"],
            ),
            DocSection(
                id="optimization",
                title="Optimization Guide",
                content="""# Image Optimization Guide

## Intelligent Optimization

The CLI uses AI to analyze images and apply optimal settings.

## Content Detection

### Photo Detection
- Preserves detail in faces
- Maintains color accuracy
- Balances file size and quality

### Illustration Detection
- Optimizes flat colors
- Reduces color palette
- Preserves sharp edges

### Screenshot Detection
- Maintains text clarity
- Optimizes UI elements
- Uses appropriate formats

## Optimization Strategies

### For Web
```bash
img optimize photo.jpg --preset web
```

### For Email
```bash
img optimize large.jpg --target-size 500kb
```

### Lossless
```bash
img optimize diagram.png --lossless
```

## Performance Tips

1. Use batch processing for multiple files
2. Enable parallel workers
3. Choose appropriate presets
4. Consider target environment""",
                category="guide",
                parent_id="root",
                tags=["optimization", "ai", "performance"],
            ),
            DocSection(
                id="troubleshooting",
                title="Troubleshooting",
                content="""# Troubleshooting Guide

## Common Issues

### File Not Found (CONV001)
**Problem**: Input file cannot be located.
**Solution**: Check file path and permissions.

### Out of Memory (CONV500)
**Problem**: Large images exhaust available memory.
**Solutions**:
- Reduce parallel workers
- Process smaller batches
- Lower quality settings

### Slow Conversion
**Problem**: Processing takes too long.
**Solutions**:
- Use `--workers` for parallel processing
- Choose faster formats (WebP over AVIF)
- Reduce output dimensions

### Format Not Supported
**Problem**: Input or output format not available.
**Solution**: Check `img formats` for supported types.

## Debug Commands

```bash
# Enable verbose output
img convert file.jpg -f webp --verbose

# Show debug information
img convert file.jpg -f webp --debug

# Dry run without processing
img batch *.png -f webp --dry-run
```

## Getting Help

- Use `img help COMMAND` for command help
- Run `img tutorial` for interactive learning
- Check `img help --errors` for error reference""",
                category="guide",
                parent_id="root",
                tags=["troubleshooting", "errors", "debug"],
            ),
        ]

        # Index sections
        for section in docs:
            self.sections[section.id] = section

    def _init_search_index(self):
        """Initialize search index"""
        if not WHOOSH_AVAILABLE:
            return

        # Create schema
        schema = fields.Schema(
            id=fields.ID(stored=True),
            title=fields.TEXT(stored=True),
            content=fields.TEXT(stored=True),
            category=fields.ID,
            tags=fields.KEYWORD(commas=True),
        )

        # Use RAM storage
        storage = RamStorage()
        self.search_index = storage.create_index(schema)

        # Index all sections
        writer = self.search_index.writer()
        for section in self.sections.values():
            writer.add_document(
                id=section.id,
                title=section.title,
                content=section.content,
                category=section.category,
                tags=",".join(section.tags),
            )
        writer.commit()

    def _load_bookmarks(self):
        """Load saved bookmarks"""
        bookmark_file = self.config_dir / "bookmarks.json"
        if bookmark_file.exists():
            try:
                with open(bookmark_file, "r") as f:
                    data = json.load(f)
                    self.bookmarks = [
                        Bookmark(
                            section_id=b["section_id"],
                            title=b["title"],
                            timestamp=datetime.fromisoformat(b["timestamp"]),
                            notes=b.get("notes"),
                        )
                        for b in data.get("bookmarks", [])
                    ]
            except Exception:
                self.bookmarks = []

    def _save_bookmarks(self):
        """Save bookmarks to disk"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        bookmark_file = self.config_dir / "bookmarks.json"

        data = {
            "bookmarks": [
                {
                    "section_id": b.section_id,
                    "title": b.title,
                    "timestamp": b.timestamp.isoformat(),
                    "notes": b.notes,
                }
                for b in self.bookmarks
            ]
        }

        with open(bookmark_file, "w") as f:
            json.dump(data, f, indent=2)

    def browse(self, start_section: str = "root"):
        """Start interactive documentation browser"""
        self.current_section = start_section

        while True:
            section = self.sections.get(self.current_section)
            if not section:
                self.console.print(
                    f"[red]Section not found:[/red] {self.current_section}"
                )
                self.current_section = "root"
                continue

            # Add to history
            if not self.history or self.history[-1] != self.current_section:
                self.history.append(self.current_section)

            # Display section
            self.display_section(section)

            # Show navigation options
            self._show_navigation(section)

            # Get user input
            action = self._get_action()

            if action == "quit":
                break
            elif action == "back":
                self.go_back()
            elif action == "home":
                self.current_section = "root"
            elif action == "search":
                self.search_interactive()
            elif action == "bookmark":
                self.add_bookmark(section)
            elif action == "bookmarks":
                self.show_bookmarks()
            elif action.isdigit():
                # Navigate to child section
                index = int(action) - 1
                if 0 <= index < len(section.children):
                    self.current_section = section.children[index]

    def display_section(self, section: DocSection):
        """Display a documentation section"""
        # Clear screen for better readability
        self.console.clear()

        # Breadcrumb navigation
        breadcrumb = self._get_breadcrumb(section)
        if breadcrumb:
            self.console.print(f"[dim]{breadcrumb}[/dim]\n")

        # Display content as markdown
        md = Markdown(section.content)
        panel = Panel(
            md,
            title=f"[bold cyan]{section.title}[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
        self.console.print(panel)

        # Show related sections
        if section.related:
            self.console.print("\n[yellow]Related Topics:[/yellow]")
            for related_id in section.related:
                related = self.sections.get(related_id)
                if related:
                    self.console.print(f"  • {related.title}")

    def _get_breadcrumb(self, section: DocSection) -> str:
        """Build breadcrumb navigation"""
        parts = []
        current = section

        while current and current.id != "root":
            parts.append(current.title)
            if current.parent_id:
                current = self.sections.get(current.parent_id)
            else:
                break

        parts.append("Home")
        parts.reverse()

        return " > ".join(parts)

    def _show_navigation(self, section: DocSection):
        """Show navigation options"""
        self.console.print("\n" + "─" * 50)

        # Child sections
        if section.children:
            self.console.print("\n[bold]Navigate to:[/bold]")
            for i, child_id in enumerate(section.children, 1):
                child = self.sections.get(child_id)
                if child:
                    self.console.print(f"  {i}. {child.title}")

        # Commands
        self.console.print("\n[bold]Commands:[/bold]")
        self.console.print(
            "  [cyan]b[/cyan]ack | [cyan]h[/cyan]ome | [cyan]s[/cyan]earch | boo[cyan]k[/cyan]mark | [cyan]m[/cyan]arks | [cyan]q[/cyan]uit"
        )

    def _get_action(self) -> str:
        """Get user action"""
        action = Prompt.ask("\n[cyan]>[/cyan]").lower().strip()

        # Map shortcuts
        shortcuts = {
            "b": "back",
            "h": "home",
            "s": "search",
            "k": "bookmark",
            "m": "bookmarks",
            "q": "quit",
        }

        return shortcuts.get(action, action)

    def go_back(self):
        """Navigate back in history"""
        if len(self.history) > 1:
            self.history.pop()  # Remove current
            self.current_section = self.history[-1]
        else:
            self.current_section = "root"

    def search(self, query: str) -> List[DocSection]:
        """Search documentation"""
        if self.search_index and WHOOSH_AVAILABLE:
            return self._whoosh_search(query)
        else:
            return self._simple_search(query)

    def _whoosh_search(self, query: str) -> List[DocSection]:
        """Search using Whoosh"""
        parser = qparser.MultifieldParser(
            ["title", "content", "tags"], self.search_index.schema
        )
        parsed_query = parser.parse(query)

        results = []
        with self.search_index.searcher() as searcher:
            search_results = searcher.search(parsed_query, limit=10)

            for hit in search_results:
                section_id = hit["id"]
                section = self.sections.get(section_id)
                if section:
                    results.append(section)

        return results

    def _simple_search(self, query: str) -> List[DocSection]:
        """Simple text search"""
        results = []
        query_lower = query.lower()

        for section in self.sections.values():
            score = 0

            if query_lower in section.title.lower():
                score += 10
            if query_lower in section.content.lower():
                score += 5
            for tag in section.tags:
                if query_lower in tag.lower():
                    score += 3
                    break

            if score > 0:
                results.append((score, section))

        results.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in results[:10]]

    def search_interactive(self):
        """Interactive search"""
        query = Prompt.ask("\n[cyan]Search for[/cyan]")

        results = self.search(query)

        if not results:
            self.console.print("[yellow]No results found[/yellow]")
            return

        # Display results
        self.console.print(f"\n[bold]Search Results for '{query}':[/bold]\n")

        for i, section in enumerate(results, 1):
            self.console.print(f"{i}. [cyan]{section.title}[/cyan]")
            # Show preview
            preview = section.content[:100].replace("\n", " ")
            self.console.print(f"   [dim]{preview}...[/dim]\n")

        # Select result
        choice = Prompt.ask(
            "Select result (number) or press Enter to cancel", default=""
        )

        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(results):
                self.current_section = results[index].id

    def add_bookmark(self, section: DocSection):
        """Add bookmark for current section"""
        notes = Prompt.ask("Add notes (optional)", default="")

        bookmark = Bookmark(
            section_id=section.id,
            title=section.title,
            timestamp=datetime.now(),
            notes=notes if notes else None,
        )

        self.bookmarks.append(bookmark)
        self._save_bookmarks()

        self.console.print(f"[green]✓[/green] Bookmarked: {section.title}")

    def show_bookmarks(self):
        """Display bookmarks"""
        if not self.bookmarks:
            self.console.print("[yellow]No bookmarks yet[/yellow]")
            return

        self.console.print("\n[bold]Bookmarks:[/bold]\n")

        for i, bookmark in enumerate(self.bookmarks, 1):
            self.console.print(f"{i}. [cyan]{bookmark.title}[/cyan]")
            self.console.print(
                f"   [dim]{bookmark.timestamp.strftime('%Y-%m-%d %H:%M')}[/dim]"
            )
            if bookmark.notes:
                self.console.print(f"   [italic]{bookmark.notes}[/italic]")
            self.console.print()

        # Navigate to bookmark
        choice = Prompt.ask(
            "Select bookmark (number) or press Enter to cancel", default=""
        )

        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(self.bookmarks):
                self.current_section = self.bookmarks[index].section_id

    def export_section(self, section_id: str, format: str = "markdown") -> str:
        """Export documentation section"""
        section = self.sections.get(section_id)
        if not section:
            return ""

        if format == "markdown":
            return section.content
        elif format == "html":
            # Convert markdown to HTML (simplified)
            html = f"<h1>{section.title}</h1>\n"
            html += section.content.replace("#", "").replace("*", "")
            return html
        else:
            return section.content
