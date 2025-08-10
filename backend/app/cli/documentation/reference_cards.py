"""
Quick Reference Card Generator
Creates PDF and Markdown reference cards for commands
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

# Optional import for PDF generation
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    from reportlab.platypus import Table as RLTable
    from reportlab.platypus import TableStyle

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ReferenceCardGenerator:
    """Generates quick reference cards in various formats"""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()
        self.output_dir = Path.home() / ".image-converter" / "reference"
        self.cards = self._load_reference_data()

    def _load_reference_data(self) -> Dict[str, Dict[str, Any]]:
        """Load reference card data"""
        return {
            "basic": {
                "title": "Image Converter CLI - Quick Reference",
                "sections": [
                    {
                        "name": "Basic Commands",
                        "items": [
                            ("img convert FILE -f FORMAT", "Convert single image"),
                            ("img batch PATTERN -f FORMAT", "Batch convert files"),
                            ("img optimize FILE --preset NAME", "Optimize with preset"),
                            ("img analyze FILE", "Analyze image"),
                            ("img formats", "List supported formats"),
                            ("img help COMMAND", "Get command help"),
                        ],
                    },
                    {
                        "name": "Common Options",
                        "items": [
                            ("-f, --format", "Output format"),
                            ("-o, --output", "Output filename"),
                            ("--quality NUM", "Quality (1-100)"),
                            ("--preset NAME", "Use preset"),
                            ("--workers NUM", "Parallel workers"),
                            ("--dry-run", "Preview only"),
                        ],
                    },
                    {
                        "name": "Format Shortcuts",
                        "items": [
                            ("webp", "Google WebP"),
                            ("avif", "AV1 Image Format"),
                            ("jxl", "JPEG XL"),
                            ("heif", "High Efficiency"),
                            ("png", "Portable Network"),
                            ("jpg/jpeg", "Joint Photographic"),
                        ],
                    },
                ],
            },
            "advanced": {
                "title": "Advanced Features Reference",
                "sections": [
                    {
                        "name": "Batch Processing",
                        "items": [
                            ("img batch '*.png'", "All PNG files"),
                            ("img batch '**/*.jpg'", "Recursive search"),
                            ("img batch --workers 8", "8 parallel threads"),
                            ("img batch --output-dir DIR", "Specify output"),
                            ("img batch --continue-on-error", "Skip failures"),
                            ("img batch --progress", "Show progress bar"),
                        ],
                    },
                    {
                        "name": "Optimization",
                        "items": [
                            ("img optimize auto FILE", "Auto-detect type"),
                            ("--target-size SIZE", "Target file size"),
                            ("--lossless", "No quality loss"),
                            ("--preset web", "Web optimization"),
                            ("--preset thumbnail", "Small preview"),
                            ("--preset archive", "Long-term storage"),
                        ],
                    },
                    {
                        "name": "Advanced Operations",
                        "items": [
                            ("img chain 'cmd1' 'cmd2'", "Chain commands"),
                            ("img watch DIR -f FORMAT", "Auto-convert"),
                            ("img analyze --export-csv", "Export analysis"),
                            ("img presets create NAME", "Custom preset"),
                            ("--strip-metadata", "Remove EXIF"),
                            ("--resize WxH", "Resize image"),
                        ],
                    },
                ],
            },
            "presets": {
                "title": "Preset Reference",
                "sections": [
                    {
                        "name": "Built-in Presets",
                        "items": [
                            ("web", "WebP, 85%, optimized for web"),
                            ("thumbnail", "JPEG, 150x150, 70% quality"),
                            ("social-media", "JPEG, 1080x1080, 85%"),
                            ("archive", "PNG, lossless, compressed"),
                            ("print", "TIFF, 300 DPI, uncompressed"),
                            ("email", "JPEG, 800x600, 70% quality"),
                        ],
                    },
                    {
                        "name": "Preset Management",
                        "items": [
                            ("img presets list", "Show all presets"),
                            ("img presets create", "Create new preset"),
                            ("img presets edit NAME", "Modify preset"),
                            ("img presets delete NAME", "Remove preset"),
                            ("img presets export", "Export to file"),
                            ("img presets import FILE", "Import presets"),
                        ],
                    },
                ],
            },
            "troubleshooting": {
                "title": "Troubleshooting Guide",
                "sections": [
                    {
                        "name": "Common Issues",
                        "items": [
                            ("File not found", "Check path and permissions"),
                            ("Unsupported format", "Use 'img formats' to check"),
                            ("Out of memory", "Reduce --workers or quality"),
                            ("Permission denied", "Check write permissions"),
                            ("Slow conversion", "Use --workers for parallel"),
                            ("Quality loss", "Increase --quality value"),
                        ],
                    },
                    {
                        "name": "Debug Commands",
                        "items": [
                            ("--verbose", "Detailed output"),
                            ("--debug", "Show errors"),
                            ("--dry-run", "Test without running"),
                            ("img analyze FILE", "Check file info"),
                            ("img help --errors", "Error reference"),
                            ("img tutorial", "Interactive help"),
                        ],
                    },
                ],
            },
        }

    def generate_markdown(self, card_type: str = "basic") -> str:
        """
        Generate Markdown reference card

        Args:
            card_type: Type of reference card

        Returns:
            Markdown content
        """
        if card_type not in self.cards:
            raise ValueError(f"Unknown card type: {card_type}")

        card = self.cards[card_type]
        lines = []

        # Title
        lines.append(f"# {card['title']}")
        lines.append(f"*Generated: {datetime.now().strftime('%Y-%m-%d')}*")
        lines.append("")

        # Sections
        for section in card["sections"]:
            lines.append(f"## {section['name']}")
            lines.append("")

            # Create table
            lines.append("| Command/Option | Description |")
            lines.append("|---------------|-------------|")

            for cmd, desc in section["items"]:
                # Escape pipe characters
                cmd = cmd.replace("|", "\\|")
                desc = desc.replace("|", "\\|")
                lines.append(f"| `{cmd}` | {desc} |")

            lines.append("")

        # Footer
        lines.append("---")
        lines.append("*Image Converter CLI - Professional Image Processing*")

        return "\n".join(lines)

    def _generate_text_fallback(
        self, card_type: str = "basic", output_path: Optional[Path] = None
    ) -> Optional[Path]:
        """
        Generate text-based reference card as PDF fallback

        Args:
            card_type: Type of reference card
            output_path: Output file path

        Returns:
            Path to generated text file
        """
        if card_type not in self.cards:
            raise ValueError(f"Unknown card type: {card_type}")

        card = self.cards[card_type]

        # Setup output path with .txt extension
        if not output_path:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            output_path = self.output_dir / f"reference_{card_type}.txt"
        else:
            # Change extension to .txt if it was .pdf
            if output_path.suffix == ".pdf":
                output_path = output_path.with_suffix(".txt")

        # Generate formatted text content
        lines = []
        lines.append("=" * 70)
        lines.append(f"{card['title']:^70}")
        lines.append("=" * 70)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("=" * 70)
        lines.append("")

        for section in card["sections"]:
            lines.append(f"\n## {section['name']}")
            lines.append("-" * 50)

            if isinstance(section["items"][0], tuple):
                # Two-column format
                max_cmd_len = max(len(item[0]) for item in section["items"])
                for cmd, desc in section["items"]:
                    lines.append(f"  {cmd:<{max_cmd_len}}  {desc}")
            else:
                # Single column format
                for item in section["items"]:
                    lines.append(f"  • {item}")

            lines.append("")

        lines.append("=" * 70)
        lines.append(
            "Note: PDF generation unavailable. Install 'reportlab' for PDF support."
        )
        lines.append("=" * 70)

        # Write to file
        output_path.write_text("\n".join(lines))

        self.console.print(
            f"[green]✓[/green] Text reference card saved to: {output_path}"
        )
        return output_path

    def generate_pdf(
        self, card_type: str = "basic", output_path: Optional[Path] = None
    ) -> Optional[Path]:
        """
        Generate PDF reference card

        Args:
            card_type: Type of reference card
            output_path: Output file path

        Returns:
            Path to generated PDF or None if not available
        """
        if not REPORTLAB_AVAILABLE:
            self.console.print(
                "[yellow]PDF generation not available. Falling back to text format.[/yellow]"
            )
            self.console.print("[dim]To enable PDF: pip install reportlab[/dim]")
            # Generate text-based alternative
            return self._generate_text_fallback(card_type, output_path)

        if card_type not in self.cards:
            raise ValueError(f"Unknown card type: {card_type}")

        card = self.cards[card_type]

        # Setup output path
        if not output_path:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            output_path = self.output_dir / f"reference_{card_type}.pdf"

        # Create PDF
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=16,
            textColor=colors.HexColor("#1e40af"),
            spaceAfter=12,
            alignment=TA_CENTER,
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#1e40af"),
            spaceAfter=6,
        )

        # Build content
        story = []

        # Title
        story.append(Paragraph(card["title"], title_style))
        story.append(Spacer(1, 0.2 * inch))

        # Date
        story.append(
            Paragraph(
                f"Generated: {datetime.now().strftime('%B %d, %Y')}", styles["Normal"]
            )
        )
        story.append(Spacer(1, 0.3 * inch))

        # Sections
        for section in card["sections"]:
            # Section heading
            story.append(Paragraph(section["name"], heading_style))

            # Create table data
            table_data = [["Command/Option", "Description"]]
            for cmd, desc in section["items"]:
                table_data.append([cmd, desc])

            # Create table
            table = RLTable(table_data, colWidths=[3 * inch, 3.5 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0e7ff")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                        ("FONTNAME", (0, 1), (0, -1), "Courier"),
                        ("FONTSIZE", (0, 1), (0, -1), 8),
                        ("FONTNAME", (1, 1), (1, -1), "Helvetica"),
                        ("FONTSIZE", (1, 1), (1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 1), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 1), (-1, -1), 2),
                    ]
                )
            )

            story.append(table)
            story.append(Spacer(1, 0.2 * inch))

        # Footer
        story.append(Spacer(1, 0.3 * inch))
        story.append(
            Paragraph(
                "Image Converter CLI - Professional Image Processing", styles["Italic"]
            )
        )

        # Build PDF
        doc.build(story)

        self.console.print(
            f"[green]✓[/green] Generated PDF reference card: {output_path}"
        )
        return output_path

    def generate_text(self, card_type: str = "basic") -> str:
        """
        Generate plain text reference card

        Args:
            card_type: Type of reference card

        Returns:
            Plain text content
        """
        if card_type not in self.cards:
            raise ValueError(f"Unknown card type: {card_type}")

        card = self.cards[card_type]
        lines = []

        # Title
        title = card["title"]
        lines.append("=" * len(title))
        lines.append(title)
        lines.append("=" * len(title))
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d')}")
        lines.append("")

        # Sections
        for section in card["sections"]:
            lines.append(section["name"])
            lines.append("-" * len(section["name"]))

            # Find max width for alignment
            max_cmd = max(len(cmd) for cmd, _ in section["items"])

            for cmd, desc in section["items"]:
                lines.append(f"{cmd.ljust(max_cmd + 2)} {desc}")

            lines.append("")

        # Footer
        lines.append("-" * 50)
        lines.append("Image Converter CLI - Professional Image Processing")

        return "\n".join(lines)

    def list_cards(self) -> List[Dict[str, str]]:
        """List available reference cards"""
        cards = []
        for card_id, card_data in self.cards.items():
            cards.append(
                {
                    "id": card_id,
                    "title": card_data["title"],
                    "sections": len(card_data["sections"]),
                }
            )
        return cards

    def display_card(self, card_type: str = "basic") -> None:
        """Display reference card in console"""
        if card_type not in self.cards:
            self.console.print(f"[red]Unknown card type:[/red] {card_type}")
            return

        card = self.cards[card_type]

        # Title
        self.console.print(f"\n[bold cyan]{card['title']}[/bold cyan]")
        self.console.print(
            f"[dim]Generated: {datetime.now().strftime('%Y-%m-%d')}[/dim]\n"
        )

        # Sections
        for section in card["sections"]:
            # Section title
            self.console.print(f"[bold yellow]{section['name']}[/bold yellow]")

            # Create table
            table = Table(box=None, padding=(0, 2))
            table.add_column("Command/Option", style="green", no_wrap=True)
            table.add_column("Description")

            for cmd, desc in section["items"]:
                table.add_row(f"[cyan]{cmd}[/cyan]", desc)

            self.console.print(table)
            self.console.print()

    def export_all(self, format: str = "markdown") -> List[Path]:
        """Export all reference cards in specified format"""
        exported = []

        self.output_dir.mkdir(parents=True, exist_ok=True)

        for card_type in self.cards:
            if format == "markdown":
                content = self.generate_markdown(card_type)
                output_path = self.output_dir / f"reference_{card_type}.md"
                output_path.write_text(content)
                exported.append(output_path)

            elif format == "pdf" and REPORTLAB_AVAILABLE:
                path = self.generate_pdf(card_type)
                if path:
                    exported.append(path)

            elif format == "text":
                content = self.generate_text(card_type)
                output_path = self.output_dir / f"reference_{card_type}.txt"
                output_path.write_text(content)
                exported.append(output_path)

        self.console.print(f"[green]✓[/green] Exported {len(exported)} reference cards")
        return exported

    def create_custom_card(self, name: str, sections: List[Dict[str, Any]]) -> str:
        """Create a custom reference card"""
        self.cards[name] = {"title": f"Custom Reference - {name}", "sections": sections}

        # Save to file for persistence
        custom_file = self.output_dir / f"custom_{name}.json"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        with open(custom_file, "w") as f:
            json.dump(self.cards[name], f, indent=2)

        self.console.print(f"[green]✓[/green] Created custom reference card: {name}")
        return name
