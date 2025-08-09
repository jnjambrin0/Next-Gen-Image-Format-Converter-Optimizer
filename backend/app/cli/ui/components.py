"""
TUI Components
Reusable components for Terminal UI
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Optional

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Label,
    ListItem,
    ListView,
    ProgressBar,
    RadioButton,
    RadioSet,
    Static,
    Switch,
)

from app.cli.utils.emoji import get_emoji, get_format_emoji


@dataclass
class ConversionOptions:
    """Data class for conversion options"""

    output_format: str
    quality: int
    preset: Optional[str] = None
    preserve_metadata: bool = False
    auto_optimize: bool = False
    progressive: bool = False
    lossless: bool = False


class FormatSelector(Container):
    """Component for selecting output format"""

    DEFAULT_FORMATS = ["webp", "avif", "jpeg", "png", "jxl", "heif"]

    def __init__(
        self,
        formats: Optional[List[str]] = None,
        default: str = "webp",
        on_change: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.formats = formats or self.DEFAULT_FORMATS
        self.default = default
        self.on_change = on_change

    def compose(self) -> ComposeResult:
        """Create format selector UI"""
        yield Label("Output Format", classes="component-label")

        with RadioSet(id="format_selector"):
            for fmt in self.formats:
                yield RadioButton(
                    f"{get_format_emoji(fmt)} {fmt.upper()}",
                    value=fmt == self.default,
                    id=f"format_{fmt}",
                )

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle format selection change"""
        if self.on_change and event.radio_set.id == "format_selector":
            selected = event.radio_set.pressed_button
            if selected:
                format_name = selected.id.replace("format_", "")
                self.on_change(format_name)


class QualitySlider(Container):
    """Component for quality selection with visual feedback"""

    def __init__(
        self,
        min_value: int = 1,
        max_value: int = 100,
        default: int = 85,
        on_change: Optional[Callable[[int], None]] = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.min_value = min_value
        self.max_value = max_value
        self.default = default
        self.current_value = reactive(default)
        self.on_change = on_change

    def compose(self) -> ComposeResult:
        """Create quality slider UI"""
        yield Label("Quality", classes="component-label")

        with Horizontal(classes="slider-container"):
            yield Button("-", id="quality_decrease", classes="slider-button")
            yield Static(
                str(self.current_value), id="quality_display", classes="quality-value"
            )
            yield Button("+", id="quality_increase", classes="slider-button")

        yield ProgressBar(
            total=self.max_value - self.min_value,
            progress=self.default - self.min_value,
            id="quality_bar",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle slider button presses"""
        if event.button.id == "quality_decrease":
            self._adjust_quality(-5)
        elif event.button.id == "quality_increase":
            self._adjust_quality(5)

    def _adjust_quality(self, delta: int) -> None:
        """Adjust quality value"""
        new_value = max(self.min_value, min(self.max_value, self.current_value + delta))
        if new_value != self.current_value:
            self.current_value = new_value
            self._update_display()
            if self.on_change:
                self.on_change(new_value)

    def _update_display(self) -> None:
        """Update quality display"""
        display = self.query_one("#quality_display", Static)
        display.update(str(self.current_value))

        bar = self.query_one("#quality_bar", ProgressBar)
        bar.update(progress=self.current_value - self.min_value)


class PresetPicker(Container):
    """Component for selecting optimization presets"""

    PRESETS = {
        "none": {"name": "None", "icon": "settings", "description": "No preset"},
        "web": {"name": "Web", "icon": "globe", "description": "Optimized for web"},
        "print": {
            "name": "Print",
            "icon": "printer",
            "description": "High quality for printing",
        },
        "archive": {
            "name": "Archive",
            "icon": "archive",
            "description": "Archival quality",
        },
        "thumbnail": {
            "name": "Thumbnail",
            "icon": "image",
            "description": "Small thumbnails",
        },
        "social": {
            "name": "Social Media",
            "icon": "share",
            "description": "Social media optimized",
        },
    }

    def __init__(
        self, on_select: Optional[Callable[[str], None]] = None, **kwargs
    ) -> None:
        super().__init__(**kwargs)
        self.on_select = on_select
        self.selected_preset = reactive("none")

    def compose(self) -> ComposeResult:
        """Create preset picker UI"""
        yield Label("Optimization Preset", classes="component-label")

        with Horizontal(classes="preset-grid"):
            for preset_id, preset_info in self.PRESETS.items():
                yield Button(
                    f"{get_emoji(preset_info['icon'])} {preset_info['name']}",
                    id=f"preset_{preset_id}",
                    classes="preset-button",
                    variant="default" if preset_id != "none" else "primary",
                )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle preset selection"""
        if event.button.id.startswith("preset_"):
            preset_id = event.button.id.replace("preset_", "")
            self.selected_preset = preset_id
            self._update_button_states()
            if self.on_select:
                self.on_select(preset_id if preset_id != "none" else None)

    def _update_button_states(self) -> None:
        """Update button visual states"""
        for preset_id in self.PRESETS:
            btn = self.query_one(f"#preset_{preset_id}", Button)
            btn.variant = "primary" if preset_id == self.selected_preset else "default"


class FileList(Container):
    """Component for displaying selected files"""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.files: List[Path] = []

    def compose(self) -> ComposeResult:
        """Create file list UI"""
        yield Label(
            f"{get_emoji('folder')} Selected Files (0)",
            id="file_list_header",
            classes="component-label",
        )
        yield ListView(id="file_list_view")

    def add_file(self, file_path: Path) -> None:
        """Add a file to the list"""
        if file_path not in self.files:
            self.files.append(file_path)
            self._update_list()

    def remove_file(self, file_path: Path) -> None:
        """Remove a file from the list"""
        if file_path in self.files:
            self.files.remove(file_path)
            self._update_list()

    def clear_files(self) -> None:
        """Clear all files"""
        self.files.clear()
        self._update_list()

    def _update_list(self) -> None:
        """Update the file list display"""
        list_view = self.query_one("#file_list_view", ListView)
        list_view.clear()

        for file_path in self.files:
            list_view.append(
                ListItem(
                    Static(f"{get_format_emoji(file_path.suffix[1:])} {file_path.name}")
                )
            )

        # Update header count
        header = self.query_one("#file_list_header", Label)
        header.update(f"{get_emoji('folder')} Selected Files ({len(self.files)})")


class StatusIndicator(Static):
    """Component for showing status with emoji"""

    STATUSES = {
        "idle": ("clock", "Idle", "dim"),
        "processing": ("processing", "Processing...", "yellow"),
        "success": ("success", "Success", "green"),
        "error": ("error", "Error", "red"),
        "warning": ("warning", "Warning", "yellow"),
    }

    def __init__(self, initial_status: str = "idle", **kwargs) -> None:
        super().__init__("", **kwargs)
        self.set_status(initial_status)

    def set_status(self, status: str, custom_text: Optional[str] = None) -> None:
        """Update status display"""
        if status in self.STATUSES:
            emoji_key, default_text, style = self.STATUSES[status]
            text = custom_text or default_text
            self.update(f"{get_emoji(emoji_key)} {text}")
            self.styles.color = style
        else:
            self.update(custom_text or status)


class ConversionForm(Container):
    """Complete form for conversion settings"""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.options = ConversionOptions(output_format="webp", quality=85)

    def compose(self) -> ComposeResult:
        """Create conversion form UI"""
        with Vertical(classes="form-container"):
            # Format selector
            yield FormatSelector(on_change=self._on_format_change)

            # Quality slider
            yield QualitySlider(on_change=self._on_quality_change)

            # Preset picker
            yield PresetPicker(on_select=self._on_preset_select)

            # Additional options
            yield Label("Additional Options", classes="component-label")
            with Vertical(classes="options-list"):
                yield Switch(
                    value=False, id="preserve_metadata", name="Preserve Metadata"
                )
                yield Switch(value=False, id="auto_optimize", name="Auto-Optimize")
                yield Switch(value=False, id="progressive", name="Progressive Encoding")
                yield Switch(value=False, id="lossless", name="Lossless Compression")

    def _on_format_change(self, format_name: str) -> None:
        """Handle format change"""
        self.options.output_format = format_name

    def _on_quality_change(self, quality: int) -> None:
        """Handle quality change"""
        self.options.quality = quality

    def _on_preset_select(self, preset: Optional[str]) -> None:
        """Handle preset selection"""
        self.options.preset = preset

    def get_options(self) -> ConversionOptions:
        """Get current conversion options"""
        # Update switch values
        self.options.preserve_metadata = self.query_one(
            "#preserve_metadata", Switch
        ).value
        self.options.auto_optimize = self.query_one("#auto_optimize", Switch).value
        self.options.progressive = self.query_one("#progressive", Switch).value
        self.options.lossless = self.query_one("#lossless", Switch).value

        return self.options


class BatchProgressDisplay(Container):
    """Component for displaying batch conversion progress"""

    def __init__(self, total_files: int = 0, **kwargs) -> None:
        super().__init__(**kwargs)
        self.total_files = total_files
        self.completed_files = 0

    def compose(self) -> ComposeResult:
        """Create batch progress UI"""
        yield Label("Batch Progress", classes="component-label")

        # Overall progress
        yield Static(
            f"{get_emoji('batch')} Overall: 0/{self.total_files}", id="overall_label"
        )
        yield ProgressBar(total=max(1, self.total_files), id="overall_progress")

        # Current file progress
        yield Static(f"{get_emoji('file')} Current File: -", id="current_file_label")
        yield ProgressBar(total=100, id="current_file_progress")

        # Status
        yield StatusIndicator(id="batch_status")

    def set_total_files(self, total: int) -> None:
        """Set total number of files"""
        self.total_files = total
        self.completed_files = 0
        self._update_progress()

    def update_file_progress(self, file_name: str, progress: int) -> None:
        """Update current file progress"""
        label = self.query_one("#current_file_label", Static)
        label.update(f"{get_emoji('file')} Current File: {file_name}")

        bar = self.query_one("#current_file_progress", ProgressBar)
        bar.update(progress=progress)

    def complete_file(self) -> None:
        """Mark current file as complete"""
        self.completed_files += 1
        self._update_progress()

    def _update_progress(self) -> None:
        """Update overall progress display"""
        label = self.query_one("#overall_label", Static)
        label.update(
            f"{get_emoji('batch')} Overall: {self.completed_files}/{self.total_files}"
        )

        bar = self.query_one("#overall_progress", ProgressBar)
        bar.update(total=max(1, self.total_files), progress=self.completed_files)

        # Update status
        status = self.query_one("#batch_status", StatusIndicator)
        if self.completed_files == 0:
            status.set_status("idle")
        elif self.completed_files < self.total_files:
            status.set_status(
                "processing", f"Processing... {self.completed_files}/{self.total_files}"
            )
        else:
            status.set_status("success", "All files converted!")
