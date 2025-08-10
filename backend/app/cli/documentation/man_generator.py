"""
Man Page Generator
Generates man pages from command metadata
"""

import os
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import re

from rich.console import Console


class ManPageGenerator:
    """Generates man pages in troff/groff format"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.man_dir = Path.home() / ".image-converter" / "man"
        self.commands = self._load_command_metadata()

    def _load_command_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Load command metadata for man page generation"""
        return {
            "img": {
                "section": 1,
                "title": "Image Converter CLI",
                "synopsis": "img [OPTIONS] COMMAND [ARGS]...",
                "description": """Professional image format conversion and optimization tool.
                
The Image Converter CLI provides powerful image processing capabilities
including format conversion, batch processing, intelligent optimization,
and content analysis - all running locally for privacy.""",
                "options": [
                    ("--version, -v", "Show version information"),
                    ("--verbose", "Enable verbose output"),
                    ("--debug", "Enable debug mode with detailed errors"),
                    ("--output, -O FORMAT", "Output format (json, table, plain, rich)"),
                    ("--lang, -L CODE", "Language code (en, es, fr, de, zh, ja)"),
                    ("--help, -h", "Show help message"),
                ],
                "commands": {
                    "convert": "Convert single image to different format",
                    "batch": "Process multiple images at once",
                    "optimize": "Intelligently optimize images",
                    "analyze": "Analyze image content and metadata",
                    "formats": "Show supported formats and capabilities",
                    "presets": "Manage conversion presets",
                    "watch": "Watch directory for automatic conversion",
                    "chain": "Chain multiple operations",
                    "help": "Get context-aware help",
                    "tutorial": "Launch interactive tutorials",
                },
                "examples": [
                    ("img convert photo.jpg -f webp", "Convert JPEG to WebP"),
                    ("img batch *.png -f avif", "Batch convert PNG files to AVIF"),
                    ("img optimize photo.jpg --preset web", "Optimize for web"),
                    ("img analyze image.png --detailed", "Detailed image analysis"),
                ],
                "files": [
                    ("~/.image-converter/config.json", "CLI configuration file"),
                    ("~/.image-converter/presets.json", "User-defined presets"),
                    ("~/.image-converter/history.json", "Command history"),
                ],
                "see_also": ["img-convert(1)", "img-batch(1)", "img-optimize(1)"],
                "author": "Image Converter Development Team",
                "bugs": "Report bugs at https://github.com/image-converter/cli/issues",
            },
            "img-convert": {
                "section": 1,
                "title": "img convert",
                "synopsis": "img convert [OPTIONS] INPUT_FILE",
                "description": """Convert a single image file to a different format.
                
Supports various input and output formats with customizable quality
settings, metadata handling, and optimization options.""",
                "options": [
                    ("-f, --format FORMAT", "Output format (required)"),
                    ("-o, --output FILE", "Output filename"),
                    ("--quality VALUE", "Quality (1-100, default: 85)"),
                    ("--preset NAME", "Apply conversion preset"),
                    ("--resize WxH", "Resize image to dimensions"),
                    ("--strip-metadata", "Remove all metadata"),
                    ("--preserve-metadata", "Keep original metadata"),
                    ("--force", "Overwrite existing files"),
                    ("--dry-run", "Preview without executing"),
                ],
                "examples": [
                    ("img convert photo.jpg -f webp -o photo.webp", "Basic conversion"),
                    (
                        "img convert image.png -f jpeg --quality 90",
                        "With quality setting",
                    ),
                    ("img convert pic.heic -f png --strip-metadata", "Remove metadata"),
                ],
            },
            "img-batch": {
                "section": 1,
                "title": "img batch",
                "synopsis": "img batch [OPTIONS] PATTERN",
                "description": """Process multiple images matching a pattern.
                
Uses glob patterns to select files and processes them in parallel
for maximum efficiency.""",
                "options": [
                    ("-f, --format FORMAT", "Output format (required)"),
                    ("--output-dir DIR", "Output directory"),
                    ("--workers N", "Number of parallel workers"),
                    ("--recursive", "Process subdirectories"),
                    ("--prefix TEXT", "Add prefix to output names"),
                    ("--suffix TEXT", "Add suffix to output names"),
                    ("--progress", "Show progress bar"),
                    ("--continue-on-error", "Don't stop on failures"),
                ],
                "examples": [
                    ("img batch '*.png' -f webp", "Convert all PNG files"),
                    (
                        "img batch '**/*.jpg' -f avif --recursive",
                        "Recursive conversion",
                    ),
                    ("img batch photos/*.* -f jpeg --workers 8", "Parallel processing"),
                ],
            },
            "img-formats": {
                "section": 5,
                "title": "Image Formats",
                "synopsis": "Supported image formats and their capabilities",
                "description": """Reference for supported input and output formats.
                
This page describes the image formats supported by the Image Converter CLI,
their capabilities, and conversion compatibility.""",
                "sections": {
                    "INPUT FORMATS": """
JPEG (.jpg, .jpeg) - Joint Photographic Experts Group
PNG (.png) - Portable Network Graphics
WebP (.webp) - Google's image format
HEIF/HEIC (.heif, .heic) - High Efficiency Image Format
BMP (.bmp) - Bitmap Image File
TIFF (.tif, .tiff) - Tagged Image File Format
GIF (.gif) - Graphics Interchange Format
AVIF (.avif) - AV1 Image Format""",
                    "OUTPUT FORMATS": """
WebP - Excellent compression, wide support
AVIF - Best compression, growing support
JPEG XL (.jxl) - Next-gen JPEG, excellent quality
HEIF - Apple ecosystem, good compression
PNG - Lossless, transparency support
JPEG - Universal compatibility
WebP2 - Experimental next-gen WebP""",
                    "CAPABILITIES": """
Format   | Lossy | Lossless | Alpha | Animation | Max Size
---------|-------|----------|-------|-----------|----------
WebP     | Yes   | Yes      | Yes   | Yes       | 16383x16383
AVIF     | Yes   | Yes      | Yes   | Yes       | 65536x65536
JPEG XL  | Yes   | Yes      | Yes   | Yes       | 1073741823x1073741823
PNG      | No    | Yes      | Yes   | No        | 2^31-1 x 2^31-1
JPEG     | Yes   | No       | No    | No        | 65535x65535""",
                },
            },
        }

    def generate(self, command: str = "img") -> str:
        """
        Generate man page content in troff format

        Args:
            command: Command to generate man page for

        Returns:
            Man page content in troff format
        """
        if command not in self.commands:
            raise ValueError(f"Unknown command: {command}")

        meta = self.commands[command]
        section = meta.get("section", 1)

        # Build man page in troff format
        lines = []

        # Header
        lines.append(
            f'.TH "{command.upper()}" "{section}" "{datetime.now().strftime("%B %Y")}" "Image Converter CLI" "User Commands"'
        )

        # Name section
        lines.append(".SH NAME")
        lines.append(f"{command} \\- {meta['title']}")

        # Synopsis
        lines.append(".SH SYNOPSIS")
        lines.append(f".B {meta['synopsis']}")

        # Description
        lines.append(".SH DESCRIPTION")
        lines.extend(self._format_description(meta["description"]))

        # Options (if present)
        if "options" in meta:
            lines.append(".SH OPTIONS")
            for option, desc in meta["options"]:
                lines.append(f".TP")
                lines.append(f".B {option}")
                lines.append(desc)

        # Commands (if present)
        if "commands" in meta:
            lines.append(".SH COMMANDS")
            for cmd, desc in meta["commands"].items():
                lines.append(f".TP")
                lines.append(f".B {cmd}")
                lines.append(desc)

        # Sections (for format reference)
        if "sections" in meta:
            for section_name, content in meta["sections"].items():
                lines.append(f".SH {section_name}")
                lines.extend(self._format_description(content))

        # Examples
        if "examples" in meta:
            lines.append(".SH EXAMPLES")
            for example, desc in meta["examples"]:
                lines.append(f".PP")
                lines.append(f"{desc}:")
                lines.append(f".PP")
                lines.append(f".RS 4")
                lines.append(f".B {example}")
                lines.append(f".RE")

        # Files (if present)
        if "files" in meta:
            lines.append(".SH FILES")
            for filepath, desc in meta["files"]:
                lines.append(f".TP")
                lines.append(f".I {filepath}")
                lines.append(desc)

        # Environment variables
        lines.append(".SH ENVIRONMENT")
        lines.append(".TP")
        lines.append(".B IMAGE_CONVERTER_CONFIG")
        lines.append("Path to configuration file")
        lines.append(".TP")
        lines.append(".B IMAGE_CONVERTER_SANDBOX_STRICTNESS")
        lines.append("Sandbox strictness level (standard, strict, paranoid)")

        # See also
        if "see_also" in meta:
            lines.append(".SH SEE ALSO")
            lines.append(", ".join([f".BR {ref}" for ref in meta["see_also"]]))

        # Author
        if "author" in meta:
            lines.append(".SH AUTHOR")
            lines.append(meta["author"])

        # Bugs
        if "bugs" in meta:
            lines.append(".SH BUGS")
            lines.append(meta["bugs"])

        return "\n".join(lines)

    def _format_description(self, text: str) -> List[str]:
        """Format description text for man page"""
        lines = []
        paragraphs = text.strip().split("\n\n")

        for para in paragraphs:
            # Clean up whitespace
            para = " ".join(para.split())

            # Handle line breaks for readability
            if len(para) > 70:
                words = para.split()
                current_line = []
                current_length = 0

                for word in words:
                    if current_length + len(word) + 1 > 70:
                        lines.append(" ".join(current_line))
                        current_line = [word]
                        current_length = len(word)
                    else:
                        current_line.append(word)
                        current_length += len(word) + 1

                if current_line:
                    lines.append(" ".join(current_line))
            else:
                lines.append(para)

            lines.append(".PP")  # Paragraph break

        return lines

    def install(self, command: str = "img") -> bool:
        """
        Install man page to system location

        Args:
            command: Command to install man page for

        Returns:
            True if successful
        """
        try:
            # Generate man page
            content = self.generate(command)

            # Determine section
            section = self.commands[command].get("section", 1)

            # Create temporary file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=f".{section}", delete=False
            ) as f:
                f.write(content)
                temp_path = f.name

            # Try to install to system man directory
            man_paths = [
                f"/usr/local/share/man/man{section}",
                f"/usr/share/man/man{section}",
                Path.home() / f".local/share/man/man{section}",
            ]

            installed = False
            for man_path in man_paths:
                man_dir = Path(man_path)
                if man_dir.exists() or self._can_create_dir(man_dir):
                    try:
                        man_dir.mkdir(parents=True, exist_ok=True)
                        dest = man_dir / f"{command}.{section}"

                        # Copy file
                        import shutil

                        shutil.copy2(temp_path, dest)

                        # Update man database
                        subprocess.run(["mandb"], capture_output=True)

                        self.console.print(
                            f"[green]✓[/green] Installed man page to {dest}"
                        )
                        installed = True
                        break
                    except Exception:
                        continue

            # Clean up temp file
            Path(temp_path).unlink(missing_ok=True)

            if not installed:
                # Fall back to local directory
                self.man_dir.mkdir(parents=True, exist_ok=True)
                local_dest = self.man_dir / f"{command}.{section}"
                local_dest.write_text(content)
                self.console.print(
                    f"[yellow]Installed locally to {local_dest}[/yellow]"
                )
                self.console.print(f"[dim]View with: man {local_dest}[/dim]")

            return True

        except Exception as e:
            self.console.print(f"[red]Failed to install man page:[/red] {e}")
            return False

    def _can_create_dir(self, path: Path) -> bool:
        """Check if we can create a directory"""
        try:
            # Check parent directory permissions
            parent = path.parent
            while not parent.exists():
                parent = parent.parent

            return os.access(parent, os.W_OK)
        except:
            return False

    def generate_html(self, command: str = "img") -> str:
        """
        Generate HTML version of man page

        Args:
            command: Command to generate for

        Returns:
            HTML content
        """
        if command not in self.commands:
            raise ValueError(f"Unknown command: {command}")

        meta = self.commands[command]

        # Build HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{command} - {meta['title']}</title>
    <style>
        body {{ font-family: monospace; max-width: 800px; margin: 0 auto; padding: 20px; }}
        h1, h2 {{ color: #333; }}
        .synopsis {{ background: #f0f0f0; padding: 10px; }}
        .option {{ font-weight: bold; color: #0066cc; }}
        .example {{ background: #f9f9f9; padding: 10px; margin: 10px 0; }}
        pre {{ overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>{command.upper()}({meta.get('section', 1)})</h1>
    <h2>NAME</h2>
    <p>{command} - {meta['title']}</p>
    
    <h2>SYNOPSIS</h2>
    <div class="synopsis">{meta['synopsis']}</div>
    
    <h2>DESCRIPTION</h2>
    <p>{meta['description'].replace(chr(10), '<br>')}</p>
"""

        # Add options
        if "options" in meta:
            html += "<h2>OPTIONS</h2><dl>"
            for option, desc in meta["options"]:
                html += f'<dt class="option">{option}</dt><dd>{desc}</dd>'
            html += "</dl>"

        # Add commands
        if "commands" in meta:
            html += "<h2>COMMANDS</h2><dl>"
            for cmd, desc in meta["commands"].items():
                html += f'<dt class="option">{cmd}</dt><dd>{desc}</dd>'
            html += "</dl>"

        # Add examples
        if "examples" in meta:
            html += "<h2>EXAMPLES</h2>"
            for example, desc in meta["examples"]:
                html += f'<div class="example"><strong>{desc}:</strong><br><pre>{example}</pre></div>'

        html += "</body></html>"

        return html

    def generate_all(self) -> Dict[str, str]:
        """Generate all man pages"""
        pages = {}
        for command in self.commands:
            pages[command] = self.generate(command)
        return pages
