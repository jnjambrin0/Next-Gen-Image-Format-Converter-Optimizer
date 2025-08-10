"""
Image Preview Module
ASCII and ANSI art generation for terminal image preview
"""

import sys
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import List, Optional, Tuple

from PIL import Image
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.cli.utils.terminal import get_safe_width, get_terminal_detector


class PreviewMode(str, Enum):
    """Preview rendering modes"""

    ASCII = "ascii"  # Classic ASCII art
    ANSI = "ansi"  # ANSI color blocks
    BRAILLE = "braille"  # Unicode Braille patterns
    BLOCKS = "blocks"  # Unicode block characters
    GRADIENT = "gradient"  # Gradient ASCII characters


class ImagePreview:
    """Generate terminal-based image previews"""

    # ASCII gradient characters (from darkest to lightest)
    ASCII_CHARS = " .:-=+*#%@"
    ASCII_GRADIENT = (
        " .'`^\",:;Il!i><~+_-?][}{1)(|/tfjrxnuvczXYUJCLQ0OZmwqpdbkhao*#MW&8%B@$"
    )

    # Unicode block characters for higher resolution
    BLOCK_CHARS = " ▁▂▃▄▅▆▇█"

    # Braille Unicode range for detailed rendering
    BRAILLE_OFFSET = 0x2800
    BRAILLE_DOTS = [(0x01, 0x08), (0x02, 0x10), (0x04, 0x20), (0x40, 0x80)]

    def __init__(self, console: Optional[Console] = None):
        """Initialize preview generator"""
        self.console = console or Console()
        self.detector = get_terminal_detector()

    def generate_preview(
        self,
        image_path: Path,
        mode: PreviewMode = PreviewMode.ANSI,
        width: Optional[int] = None,
        height: Optional[int] = None,
        show_info: bool = True,
    ) -> str:
        """
        Generate image preview in specified mode with error handling

        Args:
            image_path: Path to image file
            mode: Preview rendering mode
            width: Target width in characters
            height: Target height in characters
            show_info: Show image information

        Returns:
            Preview string
        """
        # Validate file exists
        if not image_path.exists():
            return f"Error: File not found: {image_path}"

        # Check file size for memory safety (max 50MB for preview)
        MAX_PREVIEW_SIZE = 50 * 1024 * 1024  # 50MB
        file_size = image_path.stat().st_size
        if file_size > MAX_PREVIEW_SIZE:
            return f"Error: File too large for preview ({file_size / 1024 / 1024:.1f}MB > 50MB)"

        try:
            # Open image with error handling
            try:
                image = Image.open(image_path)
            except (IOError, OSError) as e:
                return f"Error: Unsupported or corrupted image format: {str(e)}"
            except Exception as e:
                return f"Error: Failed to open image: {str(e)}"

            # Validate image dimensions for memory safety
            MAX_DIMENSION = 10000
            if image.width > MAX_DIMENSION or image.height > MAX_DIMENSION:
                return f"Error: Image dimensions too large ({image.width}x{image.height} > {MAX_DIMENSION}x{MAX_DIMENSION})"

            # Convert to RGB if necessary
            try:
                if image.mode not in ("RGB", "RGBA"):
                    image = image.convert("RGB")
            except Exception as e:
                return f"Error: Failed to convert image mode: {str(e)}"

            # Auto-detect dimensions if not specified
            if width is None:
                width = min(get_safe_width(), 80)
            if height is None:
                height = min(width // 2, 40)  # Adjust for aspect ratio

            # Validate preview dimensions
            width = max(1, min(width, 200))  # Limit to reasonable range
            height = max(1, min(height, 100))

            # Resize image to target dimensions
            try:
                image = self._resize_image(image, width, height)
            except Exception as e:
                return f"Error: Failed to resize image: {str(e)}"

            # Generate preview based on mode with fallback
            preview = None
            try:
                if mode == PreviewMode.ASCII:
                    preview = self._generate_ascii(image)
                elif mode == PreviewMode.ANSI:
                    preview = self._generate_ansi(image)
                elif mode == PreviewMode.BRAILLE:
                    preview = self._generate_braille(image)
                elif mode == PreviewMode.BLOCKS:
                    preview = self._generate_blocks(image)
                elif mode == PreviewMode.GRADIENT:
                    preview = self._generate_gradient(image)
                else:
                    preview = self._generate_ansi(image)
            except Exception as e:
                # Fallback to ASCII if preferred mode fails
                try:
                    preview = self._generate_ascii(image)
                except Exception:
                    return f"Error: Failed to generate preview: {str(e)}"

            # Add image info if requested
            if show_info:
                try:
                    info = self._get_image_info(image_path, image)
                    return f"{info}\n\n{preview}"
                except Exception:
                    # Return preview without info if info generation fails
                    return preview

            return preview

        except MemoryError:
            return "Error: Insufficient memory to generate preview"
        except Exception as e:
            return f"Error generating preview: {str(e)}"
        finally:
            # Clean up image object to free memory
            if "image" in locals():
                try:
                    image.close()
                except:
                    pass

    def _resize_image(self, image: Image.Image, width: int, height: int) -> Image.Image:
        """Resize image maintaining aspect ratio"""
        # Account for terminal character aspect ratio (roughly 2:1)
        terminal_aspect = 2.0
        img_aspect = image.width / image.height

        if img_aspect > terminal_aspect * (width / height):
            # Image is wider
            new_width = width
            new_height = int(width / (img_aspect * terminal_aspect))
        else:
            # Image is taller
            new_height = height
            new_width = int(height * img_aspect * terminal_aspect)

        return image.resize((new_width, new_height), Image.Resampling.LANCZOS)

    def _generate_ascii(self, image: Image.Image) -> str:
        """Generate classic ASCII art"""
        width, height = image.size
        ascii_art = []

        # Convert to grayscale
        image = image.convert("L")

        for y in range(height):
            row = []
            for x in range(width):
                pixel = image.getpixel((x, y))
                # Map pixel value to ASCII character
                char_index = int(pixel * (len(self.ASCII_CHARS) - 1) / 255)
                row.append(self.ASCII_CHARS[char_index])
            ascii_art.append("".join(row))

        return "\n".join(ascii_art)

    def _generate_gradient(self, image: Image.Image) -> str:
        """Generate ASCII art with extended gradient"""
        width, height = image.size
        ascii_art = []

        # Convert to grayscale
        image = image.convert("L")

        for y in range(height):
            row = []
            for x in range(width):
                pixel = image.getpixel((x, y))
                # Map pixel value to gradient character
                char_index = int(pixel * (len(self.ASCII_GRADIENT) - 1) / 255)
                row.append(self.ASCII_GRADIENT[char_index])
            ascii_art.append("".join(row))

        return "\n".join(ascii_art)

    def _generate_ansi(self, image: Image.Image) -> str:
        """Generate ANSI color block art"""
        width, height = image.size
        lines = []

        for y in range(height):
            line = Text()
            for x in range(width):
                pixel = image.getpixel((x, y))
                if len(pixel) == 4:  # RGBA
                    r, g, b, a = pixel
                    if a < 128:  # Transparent
                        line.append(" ")
                        continue
                else:  # RGB
                    r, g, b = pixel[:3]

                # Create colored block
                line.append("█", style=f"rgb({r},{g},{b})")

            lines.append(line)

        # Render lines
        result = []
        for line in lines:
            with self.console.capture() as capture:
                self.console.print(line, end="")
            result.append(capture.get())

        return "\n".join(result)

    def _generate_blocks(self, image: Image.Image) -> str:
        """Generate preview using Unicode block characters"""
        width, height = image.size
        block_art = []

        # Convert to grayscale
        image = image.convert("L")

        for y in range(height):
            row = []
            for x in range(width):
                pixel = image.getpixel((x, y))
                # Map pixel value to block character
                char_index = int(pixel * (len(self.BLOCK_CHARS) - 1) / 255)
                row.append(self.BLOCK_CHARS[char_index])
            block_art.append("".join(row))

        return "\n".join(block_art)

    def _generate_braille(self, image: Image.Image) -> str:
        """Generate preview using Braille Unicode characters"""
        width, height = image.size

        # Convert to grayscale
        image = image.convert("L")

        # Process in 2x4 blocks (Braille pattern size)
        braille_art = []
        for y in range(0, height, 4):
            row = []
            for x in range(0, width, 2):
                # Calculate Braille character for this block
                dots = 0
                for dy, (left_dot, right_dot) in enumerate(self.BRAILLE_DOTS):
                    py = y + dy
                    if py < height:
                        if x < width and image.getpixel((x, py)) > 127:
                            dots |= left_dot
                        if x + 1 < width and image.getpixel((x + 1, py)) > 127:
                            dots |= right_dot

                row.append(chr(self.BRAILLE_OFFSET + dots))
            braille_art.append("".join(row))

        return "\n".join(braille_art)

    def _get_image_info(self, path: Path, image: Image.Image) -> str:
        """Get formatted image information"""
        file_size = path.stat().st_size / 1024  # KB

        info = Table(show_header=False, box=None)
        info.add_column("Property", style="cyan")
        info.add_column("Value", style="green")

        info.add_row("File", path.name)
        info.add_row("Format", image.format or "Unknown")
        info.add_row("Mode", image.mode)
        info.add_row("Size", f"{image.width} x {image.height}")
        info.add_row("File Size", f"{file_size:.1f} KB")

        with self.console.capture() as capture:
            self.console.print(info)

        return capture.get()

    def create_side_by_side(
        self,
        image1_path: Path,
        image2_path: Path,
        mode: PreviewMode = PreviewMode.ANSI,
        width: Optional[int] = None,
    ) -> str:
        """Create side-by-side preview of two images"""
        if width is None:
            width = get_safe_width() // 2 - 2

        preview1 = self.generate_preview(image1_path, mode, width, show_info=False)
        preview2 = self.generate_preview(image2_path, mode, width, show_info=False)

        lines1 = preview1.split("\n")
        lines2 = preview2.split("\n")

        # Pad shorter preview
        max_lines = max(len(lines1), len(lines2))
        lines1.extend([""] * (max_lines - len(lines1)))
        lines2.extend([""] * (max_lines - len(lines2)))

        # Combine side by side
        combined = []
        for line1, line2 in zip(lines1, lines2):
            combined.append(f"{line1}  {line2}")

        return "\n".join(combined)

    def create_thumbnail_grid(
        self,
        image_paths: List[Path],
        columns: int = 3,
        mode: PreviewMode = PreviewMode.BLOCKS,
    ) -> str:
        """Create a grid of image thumbnails"""
        width = get_safe_width() // columns - 2
        height = width // 2

        previews = []
        for path in image_paths:
            preview = self.generate_preview(path, mode, width, height, show_info=False)
            previews.append(preview)

        # Arrange in grid
        grid = []
        for i in range(0, len(previews), columns):
            row_previews = previews[i : i + columns]

            # Split each preview into lines
            preview_lines = [p.split("\n") for p in row_previews]

            # Find max height
            max_height = max(len(lines) for lines in preview_lines)

            # Pad to same height
            for lines in preview_lines:
                lines.extend([""] * (max_height - len(lines)))

            # Combine horizontally
            for line_idx in range(max_height):
                row = "  ".join(
                    lines[line_idx] if line_idx < len(lines) else ""
                    for lines in preview_lines
                )
                grid.append(row)

            # Add separator between rows
            if i + columns < len(previews):
                grid.append("")

        return "\n".join(grid)


def create_ascii_preview(
    image_path: Path,
    width: Optional[int] = None,
    height: Optional[int] = None,
    mode: str = "ansi",
) -> str:
    """
    Convenience function to create image preview

    Args:
        image_path: Path to image file
        width: Target width in characters
        height: Target height in characters
        mode: Preview mode (ascii, ansi, braille, blocks, gradient)

    Returns:
        Preview string
    """
    preview = ImagePreview()
    preview_mode = PreviewMode(mode.lower())
    return preview.generate_preview(image_path, preview_mode, width, height)


def show_image_comparison(
    original_path: Path, converted_path: Path, console: Optional[Console] = None
) -> None:
    """Show before/after comparison in terminal"""
    console = console or Console()
    preview = ImagePreview(console)

    # Detect terminal capabilities
    detector = get_terminal_detector()
    if detector.supports_truecolor():
        mode = PreviewMode.ANSI
    elif detector.supports_unicode():
        mode = PreviewMode.BLOCKS
    else:
        mode = PreviewMode.ASCII

    comparison = preview.create_side_by_side(original_path, converted_path, mode)

    panel = Panel(
        comparison, title="[cyan]Before / After Comparison[/cyan]", border_style="green"
    )

    console.print(panel)
