"""
Smart Table Formatting
Advanced table generation with sorting, statistics, and export
"""

import csv
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Callable
from enum import Enum
from datetime import datetime
from io import StringIO

from rich.table import Table, Column
from rich.console import Console
from rich.text import Text
from rich.align import Align
from rich import box

from app.cli.utils.emoji import get_emoji, get_format_emoji, get_status_emoji, get_quality_stars
from app.cli.utils.terminal import get_safe_width


class SortOrder(str, Enum):
    """Sort order options"""
    ASCENDING = "asc"
    DESCENDING = "desc"


class ColumnType(str, Enum):
    """Column data types for smart formatting"""
    TEXT = "text"
    NUMBER = "number"
    PERCENTAGE = "percentage"
    FILE_SIZE = "file_size"
    DURATION = "duration"
    STATUS = "status"
    FORMAT = "format"
    QUALITY = "quality"
    PATH = "path"


class SmartTable:
    """Advanced table with sorting, filtering, and statistics"""
    
    def __init__(
        self,
        title: Optional[str] = None,
        console: Optional[Console] = None,
        show_statistics: bool = True,
        adaptive_width: bool = True
    ):
        """Initialize smart table"""
        self.console = console or Console()
        self.title = title
        self.show_statistics = show_statistics
        self.adaptive_width = adaptive_width
        
        self.columns: List[Dict[str, Any]] = []
        self.rows: List[List[Any]] = []
        self.sort_column: Optional[int] = None
        self.sort_order = SortOrder.ASCENDING
        self._statistics: Dict[str, Any] = {}
    
    def add_column(
        self,
        name: str,
        column_type: ColumnType = ColumnType.TEXT,
        width: Optional[int] = None,
        justify: str = "left",
        sortable: bool = True,
        format_func: Optional[Callable] = None
    ) -> None:
        """Add a column definition"""
        self.columns.append({
            "name": name,
            "type": column_type,
            "width": width,
            "justify": justify,
            "sortable": sortable,
            "format_func": format_func
        })
    
    def add_row(self, *values) -> None:
        """Add a row of data"""
        if len(values) != len(self.columns):
            raise ValueError(f"Expected {len(self.columns)} values, got {len(values)}")
        self.rows.append(list(values))
    
    def sort_by(self, column: int, order: SortOrder = SortOrder.ASCENDING) -> None:
        """Sort table by specified column"""
        if column >= len(self.columns):
            return
        
        self.sort_column = column
        self.sort_order = order
        
        # Define sort key based on column type
        col_type = self.columns[column]["type"]
        
        def get_sort_key(row):
            value = row[column]
            if value is None:
                return (1, 0)  # Nulls last
            
            if col_type == ColumnType.NUMBER:
                return (0, float(value) if value else 0)
            elif col_type == ColumnType.PERCENTAGE:
                return (0, float(str(value).rstrip('%')) if value else 0)
            elif col_type == ColumnType.FILE_SIZE:
                return (0, self._parse_file_size(value))
            elif col_type == ColumnType.DURATION:
                return (0, self._parse_duration(value))
            else:
                return (0, str(value))
        
        reverse = (order == SortOrder.DESCENDING)
        self.rows.sort(key=get_sort_key, reverse=reverse)
    
    def _parse_file_size(self, size_str: str) -> float:
        """Parse file size string to bytes"""
        if not size_str:
            return 0
        
        size_str = str(size_str).strip()
        units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
        
        for unit, multiplier in units.items():
            if size_str.endswith(unit):
                try:
                    return float(size_str[:-len(unit)].strip()) * multiplier
                except ValueError:
                    return 0
        
        try:
            return float(size_str)
        except ValueError:
            return 0
    
    def _parse_duration(self, duration_str: str) -> float:
        """Parse duration string to seconds"""
        if not duration_str:
            return 0
        
        duration_str = str(duration_str).strip()
        
        if "ms" in duration_str:
            try:
                return float(duration_str.replace("ms", "").strip()) / 1000
            except ValueError:
                return 0
        elif "s" in duration_str:
            try:
                return float(duration_str.replace("s", "").strip())
            except ValueError:
                return 0
        elif "m" in duration_str:
            try:
                return float(duration_str.replace("m", "").strip()) * 60
            except ValueError:
                return 0
        
        try:
            return float(duration_str)
        except ValueError:
            return 0
    
    def calculate_statistics(self) -> Dict[str, Any]:
        """Calculate statistics for numeric columns"""
        stats = {}
        
        for col_idx, col in enumerate(self.columns):
            if col["type"] in [ColumnType.NUMBER, ColumnType.PERCENTAGE, 
                              ColumnType.FILE_SIZE, ColumnType.DURATION]:
                values = []
                for row in self.rows:
                    value = row[col_idx]
                    if value is not None:
                        if col["type"] == ColumnType.PERCENTAGE:
                            values.append(float(str(value).rstrip('%')))
                        elif col["type"] == ColumnType.FILE_SIZE:
                            values.append(self._parse_file_size(value))
                        elif col["type"] == ColumnType.DURATION:
                            values.append(self._parse_duration(value))
                        else:
                            values.append(float(value))
                
                if values:
                    stats[col["name"]] = {
                        "min": min(values),
                        "max": max(values),
                        "avg": sum(values) / len(values),
                        "sum": sum(values),
                        "count": len(values)
                    }
        
        self._statistics = stats
        return stats
    
    def render(self, max_rows: Optional[int] = None) -> Table:
        """Render the table with Rich"""
        # Create Rich table
        table = Table(
            title=self.title,
            show_header=True,
            header_style="bold cyan",
            box=box.ROUNDED
        )
        
        # Add columns with sorting indicators
        for col_idx, col in enumerate(self.columns):
            # Add sort indicator
            header = col["name"]
            if col["sortable"] and col_idx == self.sort_column:
                if self.sort_order == SortOrder.ASCENDING:
                    header += " ↑"
                else:
                    header += " ↓"
            
            # Adaptive width calculation
            if self.adaptive_width and col["width"] is None:
                terminal_width = get_safe_width()
                col_width = min(terminal_width // len(self.columns), 30)
            else:
                col_width = col["width"]
            
            table.add_column(
                header,
                justify=col["justify"],
                width=col_width,
                overflow="ellipsis"
            )
        
        # Add rows with formatting
        row_count = 0
        for row in self.rows:
            if max_rows and row_count >= max_rows:
                break
            
            formatted_row = []
            for col_idx, value in enumerate(row):
                col = self.columns[col_idx]
                formatted_value = self._format_value(value, col)
                formatted_row.append(formatted_value)
            
            table.add_row(*formatted_row)
            row_count += 1
        
        # Add statistics row if enabled
        if self.show_statistics and self._statistics:
            self._add_statistics_row(table)
        
        return table
    
    def _format_value(self, value: Any, column: Dict[str, Any]) -> str:
        """Format value based on column type"""
        if value is None:
            return "-"
        
        # Use custom format function if provided
        if column["format_func"]:
            return column["format_func"](value)
        
        col_type = column["type"]
        
        if col_type == ColumnType.STATUS:
            emoji = get_status_emoji(str(value).lower())
            return f"{emoji} {value}"
        
        elif col_type == ColumnType.FORMAT:
            emoji = get_format_emoji(str(value).lower())
            return f"{emoji} {value.upper()}"
        
        elif col_type == ColumnType.QUALITY:
            stars = get_quality_stars(int(value) if value else 0)
            return f"{stars} ({value}%)"
        
        elif col_type == ColumnType.PERCENTAGE:
            pct = float(str(value).rstrip('%'))
            color = "green" if pct >= 50 else "yellow" if pct >= 25 else "red"
            return Text(f"{pct:.1f}%", style=color)
        
        elif col_type == ColumnType.FILE_SIZE:
            return self._format_file_size(value)
        
        elif col_type == ColumnType.DURATION:
            return self._format_duration(value)
        
        elif col_type == ColumnType.PATH:
            path = Path(str(value))
            return path.name if path.exists() else str(value)
        
        else:
            return str(value)
    
    def _format_file_size(self, size: Any) -> str:
        """Format file size with appropriate units"""
        if isinstance(size, str):
            return size
        
        size = float(size)
        units = [(1024**3, "GB"), (1024**2, "MB"), (1024, "KB"), (1, "B")]
        
        for divisor, unit in units:
            if size >= divisor:
                return f"{size / divisor:.1f} {unit}"
        
        return f"{size:.0f} B"
    
    def _format_duration(self, duration: Any) -> str:
        """Format duration with appropriate units"""
        if isinstance(duration, str):
            return duration
        
        duration = float(duration)
        
        if duration < 0.001:
            return f"{duration * 1000000:.0f}μs"
        elif duration < 1:
            return f"{duration * 1000:.0f}ms"
        elif duration < 60:
            return f"{duration:.1f}s"
        else:
            return f"{duration / 60:.1f}m"
    
    def _add_statistics_row(self, table: Table) -> None:
        """Add statistics summary row to table"""
        stats_row = []
        
        for col_idx, col in enumerate(self.columns):
            if col["name"] in self._statistics:
                stat = self._statistics[col["name"]]
                
                if col["type"] == ColumnType.FILE_SIZE:
                    value = f"Avg: {self._format_file_size(stat['avg'])}"
                elif col["type"] == ColumnType.DURATION:
                    value = f"Avg: {self._format_duration(stat['avg'])}"
                elif col["type"] == ColumnType.PERCENTAGE:
                    value = f"Avg: {stat['avg']:.1f}%"
                else:
                    value = f"Avg: {stat['avg']:.1f}"
                
                stats_row.append(Text(value, style="italic dim"))
            else:
                stats_row.append(Text("", style="dim"))
        
        table.add_row(*stats_row)
    
    def export_csv(self, file_path: Optional[Path] = None) -> str:
        """Export table to CSV format"""
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([col["name"] for col in self.columns])
        
        # Write rows
        for row in self.rows:
            writer.writerow(row)
        
        csv_content = output.getvalue()
        
        if file_path:
            file_path.write_text(csv_content)
        
        return csv_content
    
    def export_json(self, file_path: Optional[Path] = None) -> str:
        """Export table to JSON format"""
        data = {
            "columns": [col["name"] for col in self.columns],
            "rows": self.rows,
            "statistics": self._statistics
        }
        
        json_content = json.dumps(data, indent=2, default=str)
        
        if file_path:
            file_path.write_text(json_content)
        
        return json_content
    
    def export_markdown(self, file_path: Optional[Path] = None) -> str:
        """Export table to Markdown format"""
        lines = []
        
        # Title
        if self.title:
            lines.append(f"# {self.title}")
            lines.append("")
        
        # Header
        headers = [col["name"] for col in self.columns]
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join(["-" * len(h) for h in headers]) + " |")
        
        # Rows
        for row in self.rows:
            formatted_row = []
            for col_idx, value in enumerate(row):
                formatted_value = str(value) if value is not None else "-"
                formatted_row.append(formatted_value)
            lines.append("| " + " | ".join(formatted_row) + " |")
        
        # Statistics
        if self.show_statistics and self._statistics:
            lines.append("")
            lines.append("## Statistics")
            for col_name, stats in self._statistics.items():
                lines.append(f"- **{col_name}**: Min={stats['min']:.2f}, "
                           f"Max={stats['max']:.2f}, Avg={stats['avg']:.2f}")
        
        markdown_content = "\n".join(lines)
        
        if file_path:
            file_path.write_text(markdown_content)
        
        return markdown_content


def create_conversion_table(
    results: List[Dict[str, Any]],
    console: Optional[Console] = None
) -> SmartTable:
    """Create a conversion results table"""
    table = SmartTable(
        title="Conversion Results",
        console=console,
        show_statistics=True
    )
    
    # Define columns
    table.add_column("File", ColumnType.PATH, width=30)
    table.add_column("Format", ColumnType.FORMAT, width=10)
    table.add_column("Original", ColumnType.FILE_SIZE, width=12)
    table.add_column("Converted", ColumnType.FILE_SIZE, width=12)
    table.add_column("Savings", ColumnType.PERCENTAGE, width=10)
    table.add_column("Quality", ColumnType.QUALITY, width=15)
    table.add_column("Time", ColumnType.DURATION, width=10)
    table.add_column("Status", ColumnType.STATUS, width=10)
    
    # Add rows
    for result in results:
        table.add_row(
            result.get("file_path", ""),
            result.get("output_format", ""),
            result.get("original_size", 0),
            result.get("converted_size", 0),
            result.get("savings_percentage", 0),
            result.get("quality", 85),
            result.get("duration", 0),
            result.get("status", "success")
        )
    
    # Calculate statistics
    table.calculate_statistics()
    
    return table


def create_batch_summary_table(
    batch_results: List[Dict[str, Any]],
    console: Optional[Console] = None
) -> SmartTable:
    """Create a batch operation summary table"""
    table = SmartTable(
        title="Batch Operation Summary",
        console=console,
        show_statistics=True
    )
    
    # Define columns
    table.add_column("Batch ID", ColumnType.TEXT, width=15)
    table.add_column("Files", ColumnType.NUMBER, width=10)
    table.add_column("Completed", ColumnType.NUMBER, width=10)
    table.add_column("Failed", ColumnType.NUMBER, width=10)
    table.add_column("Total Size", ColumnType.FILE_SIZE, width=12)
    table.add_column("Saved", ColumnType.FILE_SIZE, width=12)
    table.add_column("Avg Savings", ColumnType.PERCENTAGE, width=12)
    table.add_column("Duration", ColumnType.DURATION, width=10)
    
    # Add rows
    for batch in batch_results:
        table.add_row(
            batch.get("batch_id", ""),
            batch.get("total_files", 0),
            batch.get("completed_files", 0),
            batch.get("failed_files", 0),
            batch.get("total_size", 0),
            batch.get("saved_size", 0),
            batch.get("avg_savings", 0),
            batch.get("duration", 0)
        )
    
    # Calculate statistics
    table.calculate_statistics()
    
    return table