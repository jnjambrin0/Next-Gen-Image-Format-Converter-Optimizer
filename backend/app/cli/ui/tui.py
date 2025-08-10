"""
Terminal UI (TUI) Interface
Interactive terminal interface using Textual framework
"""

import asyncio
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.reactive import reactive
from textual.validation import ValidationResult, Validator
from textual.widgets import (Button, Checkbox, DataTable, DirectoryTree,
                             Footer, Header, Input, Label, ProgressBar,
                             RichLog, Select, Tab, Tabs)

from app.cli.config import get_config
# Import SDK client
from app.cli.utils import setup_sdk_path
from app.cli.utils.emoji import get_emoji, get_format_emoji

setup_sdk_path()
try:
    from image_converter.client import ImageConverterClient
    from image_converter.models import ConversionRequest
    from image_converter.models import OutputFormat as SDKOutputFormat

    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False


class FileSelected(Message):
    """Message sent when a file is selected"""

    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__()


class QualityValidator(Validator):
    """Validator for quality input (1-100)"""

    def validate(self, value: str) -> ValidationResult:
        """Validate quality value"""
        if not value:
            return self.failure("Quality is required")

        try:
            quality = int(value)
            if quality < 1 or quality > 100:
                return self.failure("Quality must be between 1 and 100")
            return self.success()
        except ValueError:
            return self.failure("Quality must be a number")


class ConversionSettings(Container):
    """Container for conversion settings"""

    def compose(self) -> ComposeResult:
        """Create settings UI"""
        yield Label("Output Format", classes="label")
        yield Select(
            [
                (f"{get_format_emoji(fmt)} {fmt.upper()}", fmt)
                for fmt in ["webp", "avif", "jpeg", "png", "jxl", "heif"]
            ],
            id="output_format",
            value="webp",
        )

        yield Label("Quality (1-100)", classes="label")
        yield Input(
            value="85",
            placeholder="Enter quality (1-100)",
            type="integer",
            id="quality",
            validators=[QualityValidator()],
        )

        yield Label("Optimization Preset", classes="label")
        yield Select(
            [
                ("None", None),
                ("Web", "web"),
                ("Print", "print"),
                ("Archive", "archive"),
                ("Thumbnail", "thumbnail"),
            ],
            id="preset",
            value=None,
        )

        yield Label("Options", classes="label")
        yield Checkbox("Preserve metadata", id="preserve_metadata")
        yield Checkbox("Auto-optimize", id="auto_optimize")
        yield Checkbox("Progressive encoding", id="progressive")
        yield Checkbox("Lossless compression", id="lossless")


class FileBrowser(Container):
    """File browser for selecting images"""

    def compose(self) -> ComposeResult:
        """Create file browser UI"""
        yield Label("Select Images", classes="section-title")
        yield DirectoryTree(str(Path.home()), id="file_tree")


class ConversionProgress(Container):
    """Progress display for conversions"""

    def compose(self) -> ComposeResult:
        """Create progress UI"""
        yield Label("Conversion Progress", classes="section-title")
        yield ProgressBar(total=100, show_eta=True, id="main_progress")
        yield RichLog(id="progress_log", highlight=True, markup=True)


class ResultsTable(Container):
    """Results table showing conversion outcomes"""

    def compose(self) -> ComposeResult:
        """Create results table"""
        yield Label("Conversion Results", classes="section-title")
        table = DataTable(id="results_table")
        table.add_column("File", width=30)
        table.add_column("Original", width=15)
        table.add_column("Converted", width=15)
        table.add_column("Savings", width=10)
        table.add_column("Status", width=10)
        yield table


class PathSanitizer:
    """Path sanitizer for secure file selection"""

    @staticmethod
    def is_safe_path(path: Path, base_path: Optional[Path] = None) -> bool:
        """
        Check if a path is safe to access

        Args:
            path: Path to check
            base_path: Optional[Any] base directory to restrict access to

        Returns:
            True if path is safe
        """
        try:
            # Resolve to absolute path
            abs_path = path.resolve()

            # Check if path exists
            if not abs_path.exists():
                return False

            # Check for dangerous patterns
            path_str = str(abs_path)
            dangerous_patterns = [
                "..",  # Directory traversal
                "~",  # Home directory expansion
                "$",  # Environment variable
                "|",  # Pipe
                ";",  # Command separator
                "&",  # Background execution
                ">",  # Redirect
                "<",  # Redirect
                "`",  # Command substitution
                "\\0",  # Null byte
                "\n",  # Newline injection
                "\r",  # Carriage return
            ]

            for pattern in dangerous_patterns:
                if pattern in path_str:
                    return False

            # If base_path is specified, ensure path is within it
            if base_path:
                base_abs = base_path.resolve()
                try:
                    # Check if path is relative to base
                    abs_path.relative_to(base_abs)
                except ValueError:
                    # Path is outside base directory
                    return False

            # Check file permissions (readable)
            if abs_path.is_file():
                return os.access(abs_path, os.R_OK)

            return True

        except Exception:
            # Any exception means the path is not safe
            return False

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize a filename for safe use

        Args:
            filename: Filename to sanitize

        Returns:
            Sanitized filename
        """
        # Remove path separators
        filename = filename.replace("/", "_").replace("\\", "_")

        # Remove dangerous characters
        dangerous_chars = [
            "..",
            "~",
            "$",
            "|",
            ";",
            "&",
            ">",
            "<",
            "`",
            "\0",
            "\n",
            "\r",
        ]
        for char in dangerous_chars:
            filename = filename.replace(char, "_")

        # Limit length
        max_length = 255
        if len(filename) > max_length:
            # Keep extension if possible
            name, ext = os.path.splitext(filename)
            if len(ext) < 10:  # Reasonable extension length
                name = name[: max_length - len(ext)]
                filename = name + ext
            else:
                filename = filename[:max_length]

        # Ensure filename is not empty
        if not filename or filename == ".":
            filename = "unnamed_file"

        return filename


class RateLimiter:
    """Rate limiter for preventing excessive updates"""

    def __init__(self, min_interval: float = 0.1) -> None:
        """
        Initialize rate limiter

        Args:
            min_interval: Minimum seconds between operations
        """
        self.min_interval = min_interval
        self.last_call: Dict[str, float] = {}
        self.lock = threading.Lock()

    def should_allow(self, key: str) -> bool:
        """
        Check if operation should be allowed

        Args:
            key: Operation identifier

        Returns:
            True if operation is allowed
        """
        current_time = time.time()

        with self.lock:
            if key not in self.last_call:
                self.last_call[key] = current_time
                return True

            time_since_last = current_time - self.last_call[key]
            if time_since_last >= self.min_interval:
                self.last_call[key] = current_time
                return True

            return False

    def wait_if_needed(self, key: str) -> None:
        """
        Wait if necessary to respect rate limit

        Args:
            key: Operation identifier
        """
        current_time = time.time()

        with self.lock:
            if key in self.last_call:
                time_since_last = current_time - self.last_call[key]
                if time_since_last < self.min_interval:
                    time.sleep(self.min_interval - time_since_last)

            self.last_call[key] = time.time()


class ImageConverterTUI(App):
    """Main TUI application for image converter"""

    CSS = """
    Screen {
        background: $surface;
    }
    
    Header {
        background: $primary;
    }
    
    Footer {
        background: $primary;
    }
    
    .label {
        margin: 1 0;
        color: $text;
        text-style: bold;
    }
    
    .section-title {
        margin: 1 0;
        color: $primary;
        text-style: bold underline;
        text-align: center;
    }
    
    #sidebar {
        width: 40;
        border-right: solid $primary;
        padding: 1;
    }
    
    #main-content {
        padding: 1;
    }
    
    #file_tree {
        height: 100%;
    }
    
    #progress_log {
        height: 10;
        border: solid $primary;
        padding: 1;
    }
    
    #results_table {
        height: 100%;
        border: solid $primary;
    }
    
    Button {
        margin: 1 2;
    }
    
    .success {
        color: $success;
    }
    
    .error {
        color: $error;
    }
    
    .warning {
        color: $warning;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "convert", "Convert"),
        ("s", "settings", "Settings"),
        ("h", "help", "Help"),
        ("d", "toggle_dark", "Toggle Dark Mode"),
    ]

    TITLE = f"{get_emoji('convert')} Image Converter - Interactive Mode"

    selected_files: reactive[List[Path]] = reactive(list)
    is_converting: reactive[bool] = reactive(False)

    def __init__(self) -> None:
        """Initialize TUI with rate limiter and path sanitizer"""
        super().__init__()
        # Rate limiters for different operations
        self.progress_limiter = RateLimiter(
            min_interval=0.1
        )  # 10 updates per second max
        self.log_limiter = RateLimiter(
            min_interval=0.05
        )  # 20 log entries per second max
        self.table_limiter = RateLimiter(
            min_interval=0.2
        )  # 5 table updates per second max
        # Path sanitizer for secure file operations
        self.path_sanitizer = PathSanitizer()
        # Base path for file operations (user's home by default)
        self.base_path = Path.home()

    def compose(self) -> ComposeResult:
        """Create the main UI layout"""
        yield Header()

        with Horizontal():
            # Left sidebar with file browser and settings
            with Vertical(id="sidebar"):
                with Tabs():
                    with Tab("Files", id="files_tab"):
                        yield FileBrowser()
                    with Tab("Settings", id="settings_tab"):
                        yield ConversionSettings()

            # Main content area
            with Vertical(id="main-content"):
                # Action buttons
                with Horizontal(classes="button-bar"):
                    yield Button(
                        f"{get_emoji('convert')} Convert Selected",
                        id="convert_btn",
                        variant="primary",
                    )
                    yield Button(
                        f"{get_emoji('analyze')} Analyze",
                        id="analyze_btn",
                        variant="default",
                    )
                    yield Button(
                        f"{get_emoji('preview')} Preview",
                        id="preview_btn",
                        variant="default",
                    )

                # Progress and results
                yield ConversionProgress()
                yield ResultsTable()

        yield Footer()

    def on_mount(self) -> None:
        """Initialize on mount"""
        self.title = self.TITLE
        self.sub_title = f"Selected: {len(self.selected_files)} files"

        # Set up file tree filter
        tree = self.query_one("#file_tree", DirectoryTree)
        tree.filter = lambda path: (
            path.is_dir()
            or path.suffix.lower()
            in {
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".webp",
                ".avif",
                ".heif",
                ".heic",
                ".bmp",
                ".tiff",
                ".tif",
            }
        )

    @on(DirectoryTree.FileSelected)
    def handle_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        """Handle file selection from tree with path sanitization"""
        path = Path(event.path)

        # Sanitize and validate the path
        if not self.path_sanitizer.is_safe_path(path, self.base_path):
            self._log_message(f"Invalid or unsafe path: {path.name}", "error")
            return

        # Check if file is readable
        if not os.access(path, os.R_OK):
            self._log_message(f"Cannot read file: {path.name}", "error")
            return

        # Check file size (max 100MB for safety)
        max_size = 100 * 1024 * 1024  # 100MB
        try:
            if path.stat().st_size > max_size:
                self._log_message(f"File too large (>100MB): {path.name}", "error")
                return
        except Exception:
            self._log_message(f"Cannot check file size: {path.name}", "error")
            return

        if path not in self.selected_files:
            self.selected_files.append(path)
            self._update_selection_display()
            self._log_message(f"Selected: {path.name}", "info")

    def _update_selection_display(self) -> None:
        """Update the selection count in subtitle"""
        self.sub_title = f"Selected: {len(self.selected_files)} files"

    def _log_message(self, message: str, level: str = "info") -> None:
        """Log a message to the progress log with rate limiting"""
        # Apply rate limiting to prevent log spam
        if not self.log_limiter.should_allow("log"):
            return

        log = self.query_one("#progress_log", RichLog)

        if level == "error":
            styled_msg = f"[red]{get_emoji('error')} {message}[/red]"
        elif level == "success":
            styled_msg = f"[green]{get_emoji('success')} {message}[/green]"
        elif level == "warning":
            styled_msg = f"[yellow]{get_emoji('warning')} {message}[/yellow]"
        else:
            styled_msg = f"[cyan]{get_emoji('info')} {message}[/cyan]"

        log.write(styled_msg)

    async def action_convert(self) -> None:
        """Handle convert action with real SDK conversion"""
        if not self.selected_files:
            self._log_message("No files selected", "warning")
            return

        if self.is_converting:
            self._log_message("Conversion already in progress", "warning")
            return

        if not SDK_AVAILABLE:
            self._log_message(
                "SDK not available. Please install the Image Converter SDK.", "error"
            )
            return

        self.is_converting = True
        convert_btn = self.query_one("#convert_btn", Button)
        convert_btn.disabled = True

        # Get settings
        format_select = self.query_one("#output_format", Select)
        quality_input = self.query_one("#quality", Input)
        preset_select = self.query_one("#preset", Select)

        # Validate quality input
        if not quality_input.is_valid:
            self._log_message(
                "Invalid quality value. Must be between 1 and 100.", "error"
            )
            self.is_converting = False
            convert_btn.disabled = False
            return

        output_format = format_select.value
        quality = int(quality_input.value) if quality_input.value else 85
        preset = preset_select.value

        # Get checkboxes
        preserve_metadata = self.query_one("#preserve_metadata", Checkbox).value
        auto_optimize = self.query_one("#auto_optimize", Checkbox).value
        progressive = self.query_one("#progressive", Checkbox).value
        lossless = self.query_one("#lossless", Checkbox).value

        # Update progress bar
        progress = self.query_one("#main_progress", ProgressBar)
        progress.update(total=len(self.selected_files))
        progress.update(progress=0)

        # Get results table
        table = self.query_one("#results_table", DataTable)
        table.clear()

        self._log_message(
            f"Starting conversion of {len(self.selected_files)} files to {output_format.upper()}",
            "info",
        )

        # Initialize SDK client
        config = get_config()
        try:
            client = ImageConverterClient(
                host=config.api_host,
                port=config.api_port,
                api_key=config.api_key,
                timeout=config.api_timeout,
            )
        except Exception as e:
            self._log_message(f"Failed to initialize SDK client: {str(e)}", "error")
            self.is_converting = False
            convert_btn.disabled = False
            return

        # Process each file
        for i, file_path in enumerate(self.selected_files):
            self._log_message(f"Converting {file_path.name}...", "info")

            try:
                # Read input file
                with open(file_path, "rb") as f:
                    image_data = f.read()

                original_size = len(image_data) / 1024  # KB

                # Create conversion request
                request = ConversionRequest(
                    output_format=SDKOutputFormat(output_format.lower()),
                    quality=quality,
                    preset_id=preset,
                    preserve_metadata=preserve_metadata,
                    optimize_level=2 if auto_optimize else None,
                    progressive=progressive,
                    lossless=lossless,
                )

                # Perform conversion
                result = await asyncio.to_thread(
                    client.convert,
                    image_data=image_data,
                    request=request,
                    input_filename=file_path.name,
                )

                # Generate output path with sanitized filename
                sanitized_name = self.path_sanitizer.sanitize_filename(file_path.stem)
                output_path = (
                    file_path.parent / f"{sanitized_name}.{output_format.lower()}"
                )

                # Validate output path
                if not self.path_sanitizer.is_safe_path(
                    output_path.parent, self.base_path
                ):
                    raise ValueError("Output path is not safe")

                # Write output file
                with open(output_path, "wb") as f:
                    f.write(result.output_data)

                # Calculate statistics
                converted_size = len(result.output_data) / 1024  # KB
                savings = (
                    int((1 - converted_size / original_size) * 100)
                    if original_size > 0
                    else 0
                )

                # Add to results table with rate limiting
                if self.table_limiter.should_allow("table"):
                    table.add_row(
                        file_path.name[:30],
                        f"{original_size:.1f} KB",
                        f"{converted_size:.1f} KB",
                        f"{savings}%",
                        f"{get_emoji('success')} Done",
                    )

                self._log_message(
                    f"Converted {file_path.name} - Saved {savings}%", "success"
                )

            except Exception as e:
                # Handle conversion errors with rate limiting
                if self.table_limiter.should_allow("table"):
                    table.add_row(
                        file_path.name[:30],
                        "N/A",
                        "N/A",
                        "N/A",
                        f"{get_emoji('error')} Failed",
                    )
                self._log_message(
                    f"Failed to convert {file_path.name}: {str(e)}", "error"
                )

            # Update progress with rate limiting
            if self.progress_limiter.should_allow("progress"):
                progress.update(progress=i + 1)

        self._log_message("All conversions complete!", "success")
        self.is_converting = False
        convert_btn.disabled = False

    def action_settings(self) -> None:
        """Show settings tab"""
        tabs = self.query_one(Tabs)
        tabs.active = "settings_tab"

    def action_help(self) -> None:
        """Show help"""
        self._log_message("Image Converter TUI Help:", "info")
        self._log_message("• Use arrow keys to navigate file tree", "info")
        self._log_message("• Press Enter to select files", "info")
        self._log_message("• Configure settings in the Settings tab", "info")
        self._log_message("• Press 'c' or click Convert to start conversion", "info")
        self._log_message("• Press 'q' to quit", "info")

    def action_toggle_dark(self) -> None:
        """Toggle dark mode"""
        self.dark = not self.dark
        self._log_message(
            f"Dark mode: {'enabled' if self.dark else 'disabled'}", "info"
        )

    def action_quit(self) -> None:
        """Quit the application"""
        if self.is_converting:
            self._log_message("Cannot quit while conversion in progress", "warning")
            return
        self.exit()


def launch_tui() -> None:
    """Launch the TUI application"""
    app = ImageConverterTUI()
    app.run()
