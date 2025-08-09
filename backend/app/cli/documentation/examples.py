"""
Example Database System
Manages command examples with safe execution and validation
"""

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

# Optional clipboard support
try:
    import pyperclip

    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False


class ExampleCategory(str, Enum):
    """Categories for examples"""

    CONVERSION = "conversion"
    BATCH = "batch"
    OPTIMIZATION = "optimization"
    ANALYSIS = "analysis"
    PRESETS = "presets"
    FORMATS = "formats"
    ADVANCED = "advanced"
    TROUBLESHOOTING = "troubleshooting"


@dataclass
class CommandExample:
    """Represents a command example"""

    id: str
    command: str
    description: str
    category: ExampleCategory
    tags: List[str] = field(default_factory=list)
    output_preview: Optional[str] = None
    prerequisites: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    variations: List[Dict[str, str]] = field(default_factory=list)
    validated: bool = False
    safe_to_run: bool = True

    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return {
            "id": self.id,
            "command": self.command,
            "description": self.description,
            "category": self.category,
            "tags": self.tags,
            "output_preview": self.output_preview,
            "prerequisites": self.prerequisites,
            "warnings": self.warnings,
            "variations": self.variations,
            "validated": self.validated,
            "safe_to_run": self.safe_to_run,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CommandExample":
        """Create from dictionary"""
        return cls(
            id=data["id"],
            command=data["command"],
            description=data["description"],
            category=ExampleCategory(data["category"]),
            tags=data.get("tags", []),
            output_preview=data.get("output_preview"),
            prerequisites=data.get("prerequisites", []),
            warnings=data.get("warnings", []),
            variations=data.get("variations", []),
            validated=data.get("validated", False),
            safe_to_run=data.get("safe_to_run", True),
        )

    def sanitized_command(self) -> str:
        """Return sanitized command with PII removed"""
        # Remove real file paths and names
        sanitized = self.command

        # Enhanced PII patterns following CLAUDE.md privacy requirements
        patterns = [
            # User directories
            (r"/home/[\w\-\.]+/", "/home/user/"),
            (r"/Users/[\w\-\.]+/", "/Users/user/"),
            (r"C:\\Users\\[\w\-\.]+\\", "C:\\Users\\user\\"),
            (r"/var/folders/[\w\-\./]+", "/var/folders/***"),
            # Email addresses
            (
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "user@example.com",
            ),
            # IP addresses (IPv4 and IPv6)
            (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "127.0.0.1"),
            (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", "::1"),
            # Phone numbers
            (r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", "555-0100"),
            (
                r"\b\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",
                "+1-555-0100",
            ),
            # Social Security Numbers
            (r"\b\d{3}-\d{2}-\d{4}\b", "XXX-XX-XXXX"),
            # Credit card numbers
            (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "XXXX-XXXX-XXXX-XXXX"),
            # Personal names in common paths
            (r"/Documents and Settings/[\w\s]+/", "/Documents and Settings/User/"),
            (
                r"/(Desktop|Downloads|Documents|Pictures)/[\w\s\-\.]+\.(jpg|png|pdf|doc)",
                "/\1/sample.\2",
            ),
            # API keys and tokens (common patterns)
            (r"\b[A-Za-z0-9]{32,}\b", "REDACTED_TOKEN"),
            (r'api[_-]?key["\s:=]+["\']\w+["\']', 'api_key="REDACTED"'),
            (r'token["\s:=]+["\']\w+["\']', 'token="REDACTED"'),
            (r"bearer\s+[A-Za-z0-9\-._~+/]+=*", "bearer REDACTED"),
            (r"sk-[a-zA-Z0-9]{48}", "sk-REDACTED"),  # OpenAI API keys
            # AWS credentials
            (r"AKIA[0-9A-Z]{16}", "AKIA_REDACTED"),
            (
                r'aws_secret_access_key\s*=\s*["\']?[\w/+=]+["\']?',
                "aws_secret_access_key=REDACTED",
            ),
            # Database connection strings
            (
                r"(mongodb|postgres|mysql|redis)://[^@]+@[^\s]+",
                r"\1://user:pass@host/db",
            ),
            # MAC addresses
            (r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b", "XX:XX:XX:XX:XX:XX"),
        ]

        for pattern, replacement in patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized


class ExampleDatabase:
    """Database of command examples"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.examples: Dict[str, CommandExample] = {}
        self.sandbox_dir = Path(tempfile.gettempdir()) / "img-cli-examples"
        self._load_examples()

    def _load_examples(self):
        """Load example database"""
        # Examples are embedded for offline operation
        examples_data = [
            # Conversion Examples
            CommandExample(
                id="conv_basic",
                command="img convert photo.jpg -f webp -o photo.webp",
                description="Convert JPEG to WebP format",
                category=ExampleCategory.CONVERSION,
                tags=["basic", "jpeg", "webp"],
                output_preview="✓ Converted photo.jpg to photo.webp (reduced size by 35%)",
            ),
            CommandExample(
                id="conv_quality",
                command="img convert image.png -f jpeg --quality 85 -o image.jpg",
                description="Convert PNG to JPEG with custom quality",
                category=ExampleCategory.CONVERSION,
                tags=["quality", "png", "jpeg"],
                output_preview="✓ Converted with 85% quality",
                variations=[
                    {
                        "command": "img convert image.png -f jpeg --quality 95",
                        "note": "Higher quality, larger file",
                    },
                    {
                        "command": "img convert image.png -f jpeg --quality 70",
                        "note": "Lower quality, smaller file",
                    },
                ],
            ),
            CommandExample(
                id="conv_avif",
                command="img convert photo.jpg -f avif --quality 80 -o photo.avif",
                description="Convert to modern AVIF format for better compression",
                category=ExampleCategory.CONVERSION,
                tags=["avif", "modern", "compression"],
                output_preview="✓ Converted to AVIF (50% smaller than JPEG)",
            ),
            # Batch Examples
            CommandExample(
                id="batch_all_png",
                command="img batch *.png -f webp --output-dir converted/",
                description="Convert all PNG files to WebP",
                category=ExampleCategory.BATCH,
                tags=["batch", "glob", "png", "webp"],
                output_preview="✓ Converted 12 files in 3.2 seconds",
                prerequisites=["PNG files in current directory"],
            ),
            CommandExample(
                id="batch_recursive",
                command="img batch '**/*.jpg' -f avif --recursive --workers 4",
                description="Recursively convert all JPEG files using 4 workers",
                category=ExampleCategory.BATCH,
                tags=["batch", "recursive", "parallel"],
                output_preview="✓ Processed 45 files across 5 directories",
                warnings=["Can process many files - use with caution"],
            ),
            CommandExample(
                id="batch_pattern",
                command="img batch 'photo_*.png' -f jpeg --quality 90 --prefix 'compressed_'",
                description="Batch convert with filename pattern and prefix",
                category=ExampleCategory.BATCH,
                tags=["batch", "pattern", "prefix"],
                output_preview="✓ Created compressed_photo_001.jpg, compressed_photo_002.jpg...",
            ),
            # Optimization Examples
            CommandExample(
                id="opt_web",
                command="img optimize photo.jpg --preset web",
                description="Optimize image for web using intelligent preset",
                category=ExampleCategory.OPTIMIZATION,
                tags=["optimize", "preset", "web"],
                output_preview="✓ Optimized for web: 75% smaller, imperceptible quality loss",
            ),
            CommandExample(
                id="opt_target_size",
                command="img optimize large.png --target-size 100kb",
                description="Optimize to achieve specific file size",
                category=ExampleCategory.OPTIMIZATION,
                tags=["optimize", "size", "target"],
                output_preview="✓ Achieved 98KB (target: 100KB)",
                variations=[
                    {
                        "command": "img optimize large.png --target-size 500kb",
                        "note": "Larger target allows better quality",
                    },
                    {
                        "command": "img optimize large.png --target-size 50kb",
                        "note": "Aggressive compression for tiny size",
                    },
                ],
            ),
            CommandExample(
                id="opt_lossless",
                command="img optimize screenshot.png --lossless",
                description="Lossless optimization preserving exact quality",
                category=ExampleCategory.OPTIMIZATION,
                tags=["optimize", "lossless", "quality"],
                output_preview="✓ Reduced size by 20% with no quality loss",
            ),
            CommandExample(
                id="opt_auto",
                command="img optimize auto photo.jpg",
                description="Auto-detect content type and optimize accordingly",
                category=ExampleCategory.OPTIMIZATION,
                tags=["optimize", "auto", "intelligent"],
                output_preview="✓ Detected: Photo, Applied: photo-optimized preset",
            ),
            # Analysis Examples
            CommandExample(
                id="analyze_basic",
                command="img analyze image.jpg",
                description="Analyze image for format, dimensions, and metadata",
                category=ExampleCategory.ANALYSIS,
                tags=["analyze", "metadata", "info"],
                output_preview="Format: JPEG, Size: 1920x1080, Color: RGB, EXIF: Yes",
            ),
            CommandExample(
                id="analyze_detailed",
                command="img analyze photo.jpg --detailed",
                description="Detailed analysis including quality metrics",
                category=ExampleCategory.ANALYSIS,
                tags=["analyze", "detailed", "metrics"],
                output_preview="SSIM: 0.95, PSNR: 42.3dB, Content: Photo, Faces: 2",
            ),
            CommandExample(
                id="analyze_batch_csv",
                command="img analyze *.jpg --export-csv analysis.csv",
                description="Analyze multiple images and export to CSV",
                category=ExampleCategory.ANALYSIS,
                tags=["analyze", "batch", "export", "csv"],
                output_preview="✓ Analyzed 25 images, exported to analysis.csv",
            ),
            # Preset Examples
            CommandExample(
                id="preset_list",
                command="img presets list",
                description="List all available presets",
                category=ExampleCategory.PRESETS,
                tags=["presets", "list"],
                output_preview="web, thumbnail, archive, social-media, print...",
            ),
            CommandExample(
                id="preset_create",
                command="img presets create my-preset --format webp --quality 85 --resize 1200x800",
                description="Create custom preset with specific settings",
                category=ExampleCategory.PRESETS,
                tags=["presets", "create", "custom"],
                output_preview="✓ Created preset 'my-preset'",
            ),
            CommandExample(
                id="preset_apply",
                command="img convert photo.jpg --preset social-media",
                description="Apply preset during conversion",
                category=ExampleCategory.PRESETS,
                tags=["presets", "apply", "convert"],
                output_preview="✓ Applied 'social-media' preset: 1080x1080, JPEG, 85% quality",
            ),
            # Format Examples
            CommandExample(
                id="format_list",
                command="img formats",
                description="Show all supported input and output formats",
                category=ExampleCategory.FORMATS,
                tags=["formats", "list", "support"],
                output_preview="Input: JPEG, PNG, WebP, HEIF, BMP... Output: WebP, AVIF, JPEG XL...",
            ),
            CommandExample(
                id="format_detail",
                command="img formats --detailed webp",
                description="Get detailed information about a specific format",
                category=ExampleCategory.FORMATS,
                tags=["formats", "detailed", "info"],
                output_preview="WebP: Lossy/Lossless, Animation: Yes, Alpha: Yes, Max: 16383x16383",
            ),
            CommandExample(
                id="format_matrix",
                command="img formats --compatibility-matrix",
                description="Show format conversion compatibility matrix",
                category=ExampleCategory.FORMATS,
                tags=["formats", "compatibility", "matrix"],
                output_preview="[Table showing which formats can convert to which]",
            ),
            # Advanced Examples
            CommandExample(
                id="adv_chain",
                command="img chain 'convert {input} -f png' 'optimize {output} --preset web'",
                description="Chain multiple operations in sequence",
                category=ExampleCategory.ADVANCED,
                tags=["chain", "pipeline", "advanced"],
                output_preview="✓ Step 1: Converted to PNG, Step 2: Optimized for web",
            ),
            CommandExample(
                id="adv_watch",
                command="img watch ./uploads -f webp --output-dir ./processed",
                description="Watch directory and auto-convert new files",
                category=ExampleCategory.ADVANCED,
                tags=["watch", "monitor", "auto"],
                output_preview="👁 Watching ./uploads... (Press Ctrl+C to stop)",
                warnings=["Runs continuously until stopped"],
            ),
            CommandExample(
                id="adv_dry_run",
                command="img batch *.png -f avif --dry-run",
                description="Preview what would happen without executing",
                category=ExampleCategory.ADVANCED,
                tags=["dry-run", "preview", "safe"],
                output_preview="[DRY RUN] Would convert: photo1.png → photo1.avif...",
            ),
            CommandExample(
                id="adv_parallel",
                command="img batch *.jpg -f webp --workers 8 --progress",
                description="Parallel processing with progress display",
                category=ExampleCategory.ADVANCED,
                tags=["parallel", "performance", "progress"],
                output_preview="[████████--] 80% (8/10 files) ETA: 2s",
            ),
            # Troubleshooting Examples
            CommandExample(
                id="trouble_verbose",
                command="img convert problem.jpg -f webp --verbose",
                description="Enable verbose output for debugging",
                category=ExampleCategory.TROUBLESHOOTING,
                tags=["debug", "verbose", "troubleshoot"],
                output_preview="[DEBUG] Loading image... [DEBUG] Detected format: JPEG...",
            ),
            CommandExample(
                id="trouble_force",
                command="img convert corrupt.jpg -f png --force --ignore-errors",
                description="Force conversion even with errors",
                category=ExampleCategory.TROUBLESHOOTING,
                tags=["force", "error", "recovery"],
                output_preview="⚠ Warning: Corrupt metadata ignored, conversion completed",
                warnings=["May produce unexpected results"],
            ),
        ]

        # Index examples by ID
        for example in examples_data:
            self.examples[example.id] = example

    def search(
        self, query: str, category: Optional[ExampleCategory] = None
    ) -> List[CommandExample]:
        """
        Search examples by query and optional category

        Args:
            query: Search string
            category: Optional category filter

        Returns:
            List of matching examples
        """
        results = []
        query_lower = query.lower()

        for example in self.examples.values():
            # Filter by category if specified
            if category and example.category != category:
                continue

            # Score based on matches
            score = 0

            # Check command
            if query_lower in example.command.lower():
                score += 10

            # Check description
            if query_lower in example.description.lower():
                score += 5

            # Check tags
            for tag in example.tags:
                if query_lower in tag.lower():
                    score += 3
                    break

            # Check category
            if query_lower in example.category.lower():
                score += 2

            if score > 0:
                results.append((score, example))

        # Sort by score and return examples
        results.sort(key=lambda x: x[0], reverse=True)
        return [ex for _, ex in results]

    def get_by_category(self, category: ExampleCategory) -> List[CommandExample]:
        """Get all examples in a category"""
        return [ex for ex in self.examples.values() if ex.category == category]

    def display_example(self, example: CommandExample, show_variations: bool = False):
        """Display a single example"""
        # Title
        title = f"{example.description}"

        # Build content
        content = []

        # Command with syntax highlighting
        content.append("[yellow]Command:[/yellow]")
        self.console.print(Syntax(example.sanitized_command(), "bash", theme="monokai"))

        # Output preview
        if example.output_preview:
            content.append(
                f"\n[green]Expected Output:[/green]\n{example.output_preview}"
            )

        # Prerequisites
        if example.prerequisites:
            content.append(f"\n[cyan]Prerequisites:[/cyan]")
            for prereq in example.prerequisites:
                content.append(f"  • {prereq}")

        # Warnings
        if example.warnings:
            content.append(f"\n[red]Warnings:[/red]")
            for warning in example.warnings:
                content.append(f"  ⚠ {warning}")

        # Variations
        if show_variations and example.variations:
            content.append(f"\n[yellow]Variations:[/yellow]")
            for var in example.variations:
                content.append(f"  • {var['command']}")
                if "note" in var:
                    content.append(f"    [dim]{var['note']}[/dim]")

        # Tags
        tags = " ".join([f"[dim]#{tag}[/dim]" for tag in example.tags])
        content.append(f"\n{tags}")

        # Create panel
        panel = Panel(
            "\n".join(content),
            title=f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
        self.console.print(panel)

    def copy_to_clipboard(self, example: CommandExample) -> bool:
        """
        Copy example command to clipboard

        Returns:
            True if successful
        """
        if not CLIPBOARD_AVAILABLE:
            self.console.print(
                "[yellow]Clipboard not available. Install pyperclip:[/yellow]"
            )
            self.console.print("[dim]pip install pyperclip[/dim]")
            self.console.print(f"[dim]Command: {example.sanitized_command()}[/dim]")
            return False

        try:
            pyperclip.copy(example.sanitized_command())
            self.console.print(
                f"[green]✓[/green] Copied to clipboard: {example.sanitized_command()}"
            )
            return True
        except Exception as e:
            self.console.print(f"[yellow]Could not copy to clipboard:[/yellow] {e}")
            self.console.print(f"[dim]Command: {example.sanitized_command()}[/dim]")
            return False

    async def run_example(
        self, example: CommandExample, dry_run: bool = False
    ) -> Optional[str]:
        """
        Run an example command safely

        Args:
            example: Example to run
            dry_run: If True, only show what would be executed

        Returns:
            Command output or None if failed
        """
        if not example.safe_to_run and not dry_run:
            self.console.print("[red]⚠ This example is not safe to run directly[/red]")
            self.console.print(
                "[yellow]Use --dry-run to see what would happen[/yellow]"
            )
            return None

        # Prepare sandbox
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize command for execution
        command = example.sanitized_command()

        # Replace sample files with test files
        command = self._prepare_sandbox_command(command)

        if dry_run:
            self.console.print(f"[yellow][DRY RUN][/yellow] Would execute: {command}")
            return "[DRY RUN] No output"

        try:
            # Create secure environment for sandbox execution
            safe_env = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": str(self.sandbox_dir),
                "TMPDIR": str(self.sandbox_dir / "tmp"),
                "IMAGE_CONVERTER_ENABLE_SANDBOXING": "true",
                "IMAGE_CONVERTER_SANDBOX_STRICTNESS": "paranoid",
                # Block network access
                "http_proxy": "http://127.0.0.1:1",
                "https_proxy": "http://127.0.0.1:1",
                "no_proxy": "*",
            }

            # Execute in sandbox with restricted environment
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.sandbox_dir,
                capture_output=True,
                text=True,
                timeout=10,
                env=safe_env,  # Use restricted environment
            )

            if result.returncode == 0:
                self.console.print(f"[green]✓[/green] Example executed successfully")
                return result.stdout
            else:
                self.console.print(f"[red]✗[/red] Example failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            self.console.print("[red]✗[/red] Example timed out")
            return None
        except Exception as e:
            self.console.print(f"[red]✗[/red] Error running example: {e}")
            return None

    def _prepare_sandbox_command(self, command: str) -> str:
        """Prepare command for sandbox execution"""
        # Create sample files referenced in command
        sample_files = re.findall(r"\b(\w+\.\w{3,4})\b", command)

        for filename in sample_files:
            if any(
                filename.endswith(ext)
                for ext in [".jpg", ".jpeg", ".png", ".gif", ".webp"]
            ):
                # Create minimal test image
                filepath = self.sandbox_dir / filename
                if not filepath.exists():
                    self._create_test_image(filepath)

        return command

    def _create_test_image(self, filepath: Path):
        """Create a minimal test image"""
        # Create a 1x1 PNG
        png_data = (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
            b"\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\xd8\xdc\xcb\xd3"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        filepath.write_bytes(png_data)

    def validate_example(self, example: CommandExample) -> bool:
        """
        Validate that an example command is correct

        Returns:
            True if valid
        """
        # Basic validation - check command structure
        if not example.command.startswith("img "):
            return False

        # Check for dangerous patterns
        dangerous_patterns = [
            r"\brm\b",
            r"\bdd\b",
            r"\bformat\b",
            r">\s*/dev/",
            r"curl\b",
            r"wget\b",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, example.command):
                example.safe_to_run = False
                return False

        example.validated = True
        return True

    def export_examples(
        self, filepath: Path, category: Optional[ExampleCategory] = None
    ):
        """Export examples to file"""
        examples = (
            self.get_by_category(category) if category else list(self.examples.values())
        )

        data = {
            "examples": [ex.to_dict() for ex in examples],
            "categories": list(ExampleCategory),
            "total": len(examples),
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        self.console.print(
            f"[green]✓[/green] Exported {len(examples)} examples to {filepath}"
        )
