"""
Progress Display Utilities
Enhanced Rich progress bars and indicators with animations
"""

import asyncio
import time
from contextlib import contextmanager
from enum import Enum
from typing import Any, Callable, List, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    FileSizeColumn,
    MofNCompleteColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    Task,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TotalFileSizeColumn,
    TransferSpeedColumn,
)
from rich.style import Style
from rich.table import Column
from rich.text import Text

from app.cli.utils.terminal import get_terminal_detector, should_use_emoji


class SpinnerStyle(str, Enum):
    """Available spinner styles"""

    DOTS = "dots"
    DOTS2 = "dots2"
    DOTS3 = "dots3"
    LINE = "line"
    PIPE = "pipe"
    STAR = "star"
    ARROW = "arrow"
    BOUNCINGBAR = "bouncingBar"
    BOUNCINGBALL = "bouncingBall"
    CLOCK = "clock"
    EARTH = "earth"
    MOON = "moon"
    HEARTS = "hearts"
    LAYER = "layer"


class PercentageColumn(ProgressColumn):
    """Custom percentage column with color coding"""

    def render(self, task: Task) -> Text:
        """Render the percentage with color based on progress"""
        if task.total is None:
            return Text("")

        percentage = task.percentage
        if percentage is None:
            return Text("")

        # Color based on percentage
        if percentage < 33:
            style = "red"
        elif percentage < 66:
            style = "yellow"
        else:
            style = "green"

        return Text(f"{percentage:.1f}%", style=style)


class EmojiProgressColumn(ProgressColumn):
    """Progress column with emoji indicators"""

    def render(self, task: Task) -> Text:
        """Render emoji based on task status"""
        if not should_use_emoji():
            return Text("")

        if task.finished:
            return Text("✅")
        elif task.started:
            if task.percentage:
                if task.percentage < 25:
                    return Text("🔄")
                elif task.percentage < 50:
                    return Text("⏳")
                elif task.percentage < 75:
                    return Text("⚡")
                else:
                    return Text("🚀")
            else:
                return Text("⏸️")
        else:
            return Text("⏸️")


class AdaptiveBarColumn(BarColumn):
    """Adaptive progress bar that adjusts to terminal width"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        detector = get_terminal_detector()
        width, _ = detector.get_terminal_size()

        # Adjust bar width based on terminal size
        if width < 80:
            self.bar_width = 20
        elif width < 120:
            self.bar_width = 40
        else:
            self.bar_width = 60


def create_progress_bar(
    description: str = "Processing...",
    total: Optional[int] = None,
    show_speed: bool = False,
    show_time: bool = True,
    show_emoji: bool = True,
    spinner_style: SpinnerStyle = SpinnerStyle.DOTS,
    console: Optional[Console] = None,
    auto_refresh: bool = True,
    expand: bool = False,
) -> Progress:
    """Create a customized progress bar with enhanced features"""
    columns = []

    # Add emoji column if supported
    if show_emoji and should_use_emoji():
        columns.append(EmojiProgressColumn())

    # Add spinner with selected style
    columns.append(SpinnerColumn(spinner_name=spinner_style.value))

    # Add description
    columns.append(TextColumn("[progress.description]{task.description}"))

    if total is not None:
        columns.extend(
            [
                MofNCompleteColumn(),
                AdaptiveBarColumn(
                    complete_style="green", finished_style="bright_green"
                ),
                PercentageColumn(),
            ]
        )

    if show_speed:
        columns.append(TransferSpeedColumn())

    if show_time:
        columns.append(TimeRemainingColumn())
        columns.append(TextColumn("•"))
        columns.append(TimeElapsedColumn())

    return Progress(
        *columns,
        console=console,
        auto_refresh=auto_refresh,
        expand=expand,
        refresh_per_second=10,
    )


def create_download_progress(console: Optional[Console] = None) -> Progress:
    """Create a progress bar for downloads"""
    columns = []

    if should_use_emoji():
        columns.append(TextColumn("📥"))

    columns.extend(
        [
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            FileSizeColumn(),
            TextColumn("/"),
            TotalFileSizeColumn(),
            AdaptiveBarColumn(complete_style="cyan", finished_style="bright_cyan"),
            PercentageColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
        ]
    )

    return Progress(*columns, console=console)


def create_upload_progress(console: Optional[Console] = None) -> Progress:
    """Create a progress bar for uploads"""
    columns = []

    if should_use_emoji():
        columns.append(TextColumn("📤"))

    columns.extend(
        [
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            FileSizeColumn(),
            TextColumn("/"),
            TotalFileSizeColumn(),
            AdaptiveBarColumn(
                complete_style="magenta", finished_style="bright_magenta"
            ),
            PercentageColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
        ]
    )

    return Progress(*columns, console=console)


def create_simple_spinner(
    description: str,
    spinner_style: SpinnerStyle = SpinnerStyle.DOTS,
    console: Optional[Console] = None,
) -> Progress:
    """Create a simple spinner without progress bar"""
    columns = []

    if should_use_emoji():
        columns.append(EmojiProgressColumn())

    columns.extend(
        [
            SpinnerColumn(spinner_name=spinner_style.value),
            TextColumn("[progress.description]{task.description}"),
        ]
    )

    return Progress(*columns, console=console)


def create_multi_progress(
    tasks: List[str], console: Optional[Console] = None
) -> Progress:
    """Create a multi-task progress display"""
    columns = []

    if should_use_emoji():
        columns.append(EmojiProgressColumn())

    columns.extend(
        [
            TextColumn("[bold blue]{task.fields[name]}", justify="right"),
            SpinnerColumn(),
            AdaptiveBarColumn(bar_width=40),
            PercentageColumn(),
            TimeRemainingColumn(),
        ]
    )

    progress = Progress(*columns, console=console)

    # Add tasks
    task_ids = {}
    for task_name in tasks:
        task_id = progress.add_task(task_name, name=task_name)
        task_ids[task_name] = task_id

    return progress, task_ids


class InterruptableProgress:
    """Progress bar that can be interrupted with Ctrl+C"""

    def __init__(self, *args, **kwargs):
        self.progress = create_progress_bar(*args, **kwargs)
        self._interrupted = False

    def __enter__(self):
        self.progress.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is KeyboardInterrupt:
            self._interrupted = True
            self.progress.console.print(
                "\n[yellow]⚠️ Operation interrupted by user[/yellow]"
            )
        return self.progress.__exit__(exc_type, exc_val, exc_tb)

    def add_task(self, *args, **kwargs):
        return self.progress.add_task(*args, **kwargs)

    def update(self, task_id, **kwargs):
        if not self._interrupted:
            self.progress.update(task_id, **kwargs)

    def advance(self, task_id, advance: float = 1):
        if not self._interrupted:
            self.progress.advance(task_id, advance)

    @property
    def interrupted(self) -> bool:
        return self._interrupted


@contextmanager
def progress_context(description: str, total: Optional[int] = None, **kwargs):
    """Context manager for progress display"""
    progress = create_progress_bar(description, total, **kwargs)
    task_id = None

    try:
        with progress:
            task_id = progress.add_task(description, total=total)
            yield progress, task_id
    except KeyboardInterrupt:
        if progress.console:
            progress.console.print("\n[yellow]Operation cancelled[/yellow]")
        raise
    finally:
        if task_id is not None:
            progress.update(task_id, completed=total if total else 100)


async def animate_progress(
    progress: Progress,
    task_id: Any,
    duration: float = 5.0,
    steps: int = 100,
):
    """Animate progress over a duration"""
    step_duration = duration / steps

    for i in range(steps):
        if hasattr(progress, "_interrupted") and progress._interrupted:
            break

        progress.update(task_id, advance=1)
        await asyncio.sleep(step_duration)


def create_pulsing_progress(
    description: str, console: Optional[Console] = None
) -> Progress:
    """Create a pulsing progress indicator for indeterminate tasks"""
    return Progress(
        TextColumn("[blink]●[/blink]"),
        TextColumn(description),
        TextColumn("[blink]●[/blink]"),
        console=console,
        transient=True,
    )
