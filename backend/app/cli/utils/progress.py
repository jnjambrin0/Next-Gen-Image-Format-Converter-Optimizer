"""
Progress Display Utilities
Rich progress bars and indicators
"""

from typing import Optional
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    MofNCompleteColumn,
    DownloadColumn,
    TransferSpeedColumn,
)
from rich.console import Console


def create_progress_bar(
    description: str = "Processing...",
    total: Optional[int] = None,
    show_speed: bool = False,
    show_time: bool = True,
    console: Optional[Console] = None
) -> Progress:
    """Create a customized progress bar"""
    columns = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
    ]
    
    if total is not None:
        columns.append(MofNCompleteColumn())
        columns.append(BarColumn())
        columns.append(TaskProgressColumn())
    
    if show_speed:
        columns.append(TransferSpeedColumn())
    
    if show_time:
        columns.append(TimeRemainingColumn())
    
    return Progress(*columns, console=console)


def create_download_progress(console: Optional[Console] = None) -> Progress:
    """Create a progress bar for downloads"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console
    )


def create_simple_spinner(description: str, console: Optional[Console] = None) -> Progress:
    """Create a simple spinner without progress bar"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    )