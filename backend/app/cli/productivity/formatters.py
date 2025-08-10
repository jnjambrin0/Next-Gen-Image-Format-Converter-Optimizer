"""
Output Formatters for Scriptable Output
Support JSON, CSV, YAML and other structured output formats
"""

import json
import csv
import io
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from enum import Enum
from pathlib import Path

import yaml
from dataclasses import dataclass, field


class OutputFormat(Enum):
    """Supported output formats"""

    JSON = "json"
    JSON_PRETTY = "json-pretty"
    JSON_JQ = "jq"  # jq-friendly single-line JSON
    CSV = "csv"
    TSV = "tsv"
    YAML = "yaml"
    TABLE = "table"
    PLAIN = "plain"
    MARKDOWN = "markdown"
    XML = "xml"


class OutputFormatter:
    """Universal output formatter for CLI commands"""

    @staticmethod
    def format(
        data: Any,
        format: Union[OutputFormat, str, "FormatType"],
        fields: Optional[List[str]] = None,
        flatten: bool = False,
        options: Optional["FormatterOptions"] = None,
    ) -> str:
        """
        Format data in specified format

        Args:
            data: Data to format
            format: Output format
            fields: Specific fields to include (for tabular formats)
            flatten: Whether to flatten nested structures

        Returns:
            Formatted string
        """
        if isinstance(format, str):
            try:
                format = OutputFormat(format.lower())
            except ValueError:
                format = OutputFormat.PLAIN

        # Use options if provided
        if options:
            flatten = options.flatten
            fields = options.fields or fields

        # Flatten data if requested
        if flatten:
            data = OutputFormatter._flatten_data(data)

        # Format based on type
        if format == OutputFormat.JSON:
            pretty = options.pretty if options else False
            indent = options.indent if options else 2
            return OutputFormatter.format_json(data, pretty=pretty, indent=indent)
        elif format == OutputFormat.JSON_PRETTY:
            indent = options.indent if options else 2
            return OutputFormatter.format_json(data, pretty=True, indent=indent)
        elif format == OutputFormat.JSON_JQ:
            return OutputFormatter.format_json_jq(data)
        elif format == OutputFormat.CSV:
            return OutputFormatter.format_csv(data, fields)
        elif format == OutputFormat.TSV:
            return OutputFormatter.format_tsv(data, fields)
        elif format == OutputFormat.YAML:
            return OutputFormatter.format_yaml(data)
        elif format == OutputFormat.TABLE:
            return OutputFormatter.format_table(data, fields)
        elif format == OutputFormat.MARKDOWN:
            return OutputFormatter.format_markdown(data, fields)
        elif format == OutputFormat.XML:
            return OutputFormatter.format_xml(data)
        else:
            return OutputFormatter.format_plain(data)

    @staticmethod
    def format_json(data: Any, pretty: bool = True, indent: int = 2) -> str:
        """Format as JSON"""

        def json_serializer(obj):
            """Custom JSON serializer for non-serializable types"""
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, Path):
                return str(obj)
            elif isinstance(obj, Enum):
                return obj.value
            elif hasattr(obj, "__dict__"):
                return obj.__dict__
            else:
                return str(obj)

        if pretty:
            return json.dumps(
                data, indent=indent, default=json_serializer, sort_keys=True
            )
        else:
            return json.dumps(data, default=json_serializer, separators=(",", ":"))

    @staticmethod
    def format_json_jq(data: Any) -> str:
        """Format as jq-friendly JSON (one object per line for arrays)"""

        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, Path):
                return str(obj)
            elif isinstance(obj, Enum):
                return obj.value
            elif hasattr(obj, "__dict__"):
                return obj.__dict__
            else:
                return str(obj)

        if isinstance(data, list):
            # Output each item on its own line for jq processing
            lines = []
            for item in data:
                lines.append(
                    json.dumps(item, default=json_serializer, separators=(",", ":"))
                )
            return "\n".join(lines)
        else:
            return json.dumps(data, default=json_serializer, separators=(",", ":"))

    @staticmethod
    def format_csv(data: Any, fields: Optional[List[str]] = None) -> str:
        """Format as CSV"""
        output = io.StringIO()

        # Normalize data to list of dicts
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            data = [{"value": str(data)}]

        if not data:
            return ""

        # Flatten any nested dicts
        flat_data = []
        for item in data:
            if isinstance(item, dict):
                flat_data.append(OutputFormatter._flatten_dict(item))
            else:
                flat_data.append({"value": str(item)})

        # Determine fields
        if not fields and flat_data:
            fields = list(flat_data[0].keys())

        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flat_data)

        return output.getvalue()

    @staticmethod
    def format_tsv(data: Any, fields: Optional[List[str]] = None) -> str:
        """Format as TSV (Tab-Separated Values)"""
        output = io.StringIO()

        # Normalize data to list of dicts
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            data = [{"value": str(data)}]

        if not data:
            return ""

        # Flatten any nested dicts
        flat_data = []
        for item in data:
            if isinstance(item, dict):
                flat_data.append(OutputFormatter._flatten_dict(item))
            else:
                flat_data.append({"value": str(item)})

        # Determine fields
        if not fields and flat_data:
            fields = list(flat_data[0].keys())

        writer = csv.DictWriter(
            output, fieldnames=fields, delimiter="\t", extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(flat_data)

        return output.getvalue()

    @staticmethod
    def format_yaml(data: Any) -> str:
        """Format as YAML"""

        def yaml_representer(dumper, data):
            """Custom YAML representer for non-serializable types"""
            if isinstance(data, datetime):
                return dumper.represent_scalar(
                    "tag:yaml.org,2002:str", data.isoformat()
                )
            elif isinstance(data, Path):
                return dumper.represent_scalar("tag:yaml.org,2002:str", str(data))
            elif isinstance(data, Enum):
                return dumper.represent_scalar("tag:yaml.org,2002:str", data.value)
            else:
                return dumper.represent_scalar("tag:yaml.org,2002:str", str(data))

        yaml.add_representer(datetime, yaml_representer)
        yaml.add_representer(Path, yaml_representer)
        yaml.add_representer(Enum, yaml_representer)

        return yaml.dump(
            data, default_flow_style=False, sort_keys=True, allow_unicode=True
        )

    @staticmethod
    def format_table(data: Any, fields: Optional[List[str]] = None) -> str:
        """Format as ASCII table"""
        # Normalize data
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            return str(data)

        if not data:
            return "No data"

        # Flatten data
        flat_data = []
        for item in data:
            if isinstance(item, dict):
                flat_data.append(OutputFormatter._flatten_dict(item))
            else:
                flat_data.append({"value": str(item)})

        # Determine fields
        if not fields and flat_data:
            fields = list(flat_data[0].keys())

        if not fields:
            return "No fields"

        # Calculate column widths
        col_widths = {}
        for field in fields:
            col_widths[field] = len(field)
            for row in flat_data:
                value = str(row.get(field, ""))
                col_widths[field] = max(col_widths[field], len(value))

        # Build table
        lines = []

        # Header
        header = " | ".join(field.ljust(col_widths[field]) for field in fields)
        lines.append(header)
        lines.append("-" * len(header))

        # Rows
        for row in flat_data:
            row_str = " | ".join(
                str(row.get(field, "")).ljust(col_widths[field]) for field in fields
            )
            lines.append(row_str)

        return "\n".join(lines)

    @staticmethod
    def format_markdown(data: Any, fields: Optional[List[str]] = None) -> str:
        """Format as Markdown table with headers and code blocks"""
        # For single values, use inline code
        if not isinstance(data, (dict, list)):
            return f"`{str(data)}`"

        # Normalize data
        if isinstance(data, dict):
            # For complex dicts with nested data, include both formatted output and table
            lines = ["# Data Output\n"]

            # Add summary info with nested values in code blocks
            has_nested = False
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    has_nested = True
                    lines.append(f"## {key}\n")
                    lines.append("```json")
                    lines.append(json.dumps(value, indent=2))
                    lines.append("```\n")
                else:
                    lines.append(f"**{key}**: {value}\n")

            # Also add a table view of the flattened data
            if has_nested:
                lines.append("\n## Summary Table\n")
            flat_dict = OutputFormatter._flatten_dict(data)
            table_fields = list(flat_dict.keys())
            lines.append("| " + " | ".join(table_fields) + " |")
            lines.append("| " + " | ".join("---" for _ in table_fields) + " |")
            lines.append(
                "| " + " | ".join(str(flat_dict[f]) for f in table_fields) + " |"
            )

            return "\n".join(lines)
        elif not isinstance(data, list):
            return f"`{str(data)}`"

        if not data:
            return "*No data*"

        # Check if all items are dicts for table formatting
        all_dicts = all(isinstance(item, dict) for item in data)
        if not all_dicts:
            # Format as list
            lines = ["# Results\n"]
            for i, item in enumerate(data, 1):
                lines.append(f"{i}. `{str(item)}`")
            return "\n".join(lines)

        # Flatten data for table
        flat_data = []
        for item in data:
            flat_data.append(OutputFormatter._flatten_dict(item))

        # Determine fields
        if not fields and flat_data:
            fields = list(flat_data[0].keys())

        if not fields:
            return "*No fields*"

        # Build markdown with header and table
        lines = ["# Table Data\n"]

        # Table header
        lines.append("| " + " | ".join(fields) + " |")
        lines.append("| " + " | ".join("---" for _ in fields) + " |")

        # Table rows
        for row in flat_data:
            row_values = [str(row.get(field, "")) for field in fields]
            lines.append("| " + " | ".join(row_values) + " |")

        return "\n".join(lines)

    @staticmethod
    def format_xml(data: Any, root_name: str = "data") -> str:
        """Format as XML"""
        import xml.etree.ElementTree as ET
        from xml.dom import minidom

        def dict_to_xml(tag, d):
            """Convert dictionary to XML element"""
            elem = ET.Element(tag)

            if isinstance(d, dict):
                # Separate attributes from child elements
                attributes = {}
                children = {}

                for key, val in d.items():
                    # Check if it's an attribute (starts with @)
                    if key.startswith("@"):
                        attr_name = key[1:].replace(" ", "_").replace("-", "_")
                        attributes[attr_name] = str(val)
                    else:
                        children[key] = val

                # Set attributes
                for attr_name, attr_val in attributes.items():
                    elem.set(attr_name, attr_val)

                # Process children
                for key, val in children.items():
                    # Sanitize key for XML
                    key = key.replace(" ", "_").replace("-", "_")
                    if isinstance(val, (list, tuple)):
                        for item in val:
                            child = dict_to_xml(key, item)
                            elem.append(child)
                    elif isinstance(val, dict):
                        child = dict_to_xml(key, val)
                        elem.append(child)
                    else:
                        child = ET.SubElement(elem, key)
                        child.text = str(val)
            else:
                elem.text = str(d)

            return elem

        # Create root element
        if isinstance(data, list):
            root = ET.Element(root_name)
            for item in data:
                child = dict_to_xml("item", item)
                root.append(child)
        else:
            root = dict_to_xml(root_name, data)

        # Pretty print
        rough_string = ET.tostring(root, encoding="unicode")
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", newl="\n").strip()

    @staticmethod
    def format_plain(data: Any) -> str:
        """Format as plain text"""
        if isinstance(data, dict):
            lines = []
            for key, value in data.items():
                lines.append(f"{key}: {value}")
            return "\n".join(lines)
        elif isinstance(data, list):
            return "\n".join(str(item) for item in data)
        else:
            return str(data)

    @staticmethod
    def _flatten_dict(d: Dict, parent_key: str = "", sep: str = "_") -> Dict:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(OutputFormatter._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, ", ".join(str(i) for i in v)))
            else:
                items.append((new_key, v))
        return dict(items)

    @staticmethod
    def _flatten_data(data: Any) -> Any:
        """Flatten nested data structures"""
        if isinstance(data, dict):
            return OutputFormatter._flatten_dict(data)
        elif isinstance(data, list):
            return [OutputFormatter._flatten_data(item) for item in data]
        else:
            return data

    @staticmethod
    def detect_format(data: Any) -> OutputFormat:
        """Auto-detect appropriate format from data structure or file extension"""
        # If it's a string that looks like a file path, check extension
        if isinstance(data, str):
            if data.endswith(".json"):
                return OutputFormat.JSON
            elif data.endswith(".csv"):
                return OutputFormat.CSV
            elif data.endswith(".yaml") or data.endswith(".yml"):
                return OutputFormat.YAML
            elif data.endswith(".xml"):
                return OutputFormat.XML
            elif data.endswith(".md") or data.endswith(".markdown"):
                return OutputFormat.MARKDOWN
            # Fall through to data structure detection

        # Detect from data structure
        if isinstance(data, list) and len(data) > 0:
            # List of dicts -> CSV/Table
            if isinstance(data[0], dict):
                return OutputFormat.CSV
            else:
                return OutputFormat.JSON
        elif isinstance(data, dict):
            # Single dict -> JSON
            return OutputFormat.JSON
        else:
            # Simple data -> Plain text
            return OutputFormat.PLAIN

    @staticmethod
    def validate_data(data: Any, format: OutputFormat) -> bool:
        """Validate data is appropriate for format"""
        if format in [OutputFormat.CSV, OutputFormat.TSV, OutputFormat.TABLE]:
            # These formats need list of dicts
            if not isinstance(data, list):
                return False
            if data and not isinstance(data[0], dict):
                return False
        elif format == OutputFormat.XML:
            # XML needs dict or list of dicts
            if not isinstance(data, (dict, list)):
                return False
        return True

    @staticmethod
    def format_safe(data: Any, format: OutputFormat) -> str:
        """Format data safely, handling errors gracefully"""
        try:
            # Filter out None values
            if isinstance(data, list):
                data = [item for item in data if item is not None]
            return OutputFormatter.format(data, format)
        except Exception as e:
            # Return error as formatted output
            error_data = {
                "error": True,
                "message": f"Formatting error: {str(e)}",
                "timestamp": datetime.now().isoformat(),
            }
            return OutputFormatter.format(error_data, format)

    @staticmethod
    def stream_format(data_generator, format: OutputFormat, output_buffer):
        """Format streaming data"""
        # Collect all data first for JSON formatting
        all_data = list(data_generator)
        formatted = OutputFormatter.format(all_data, format)
        output_buffer.write(formatted)


class ErrorFormatter:
    """Format error messages in parseable formats"""

    @staticmethod
    def format_error(
        error_data: Union[Dict[str, Any], str],
        format: Union[OutputFormat, str] = OutputFormat.JSON,
        options: Optional["FormatterOptions"] = None,
        error_code: Optional[str] = None,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Format error message

        Args:
            error_data: Error data dict or error code string
            format: Output format
            options: Formatting options
            error_code: Error code (legacy parameter)
            message: Error message (legacy parameter)
            details: Additional error details (legacy parameter)

        Returns:
            Formatted error
        """
        # Handle different call patterns
        if isinstance(error_data, dict):
            # New style - error_data is a dict
            data = error_data.copy()
            if "error" not in data:
                data["error"] = True
            if "timestamp" not in data:
                data["timestamp"] = datetime.now().isoformat()
        else:
            # Legacy style - build from parameters
            data = {
                "error": True,
                "error_code": error_code or error_data,
                "message": message or "",
                "timestamp": datetime.now().isoformat(),
            }
            if details:
                data["details"] = details

        # Handle user-friendly mode
        if options and hasattr(options, "user_friendly") and options.user_friendly:
            if format == OutputFormat.MARKDOWN or format == "markdown":
                lines = ["❌ **Error**\n"]
                if "message" in data:
                    lines.append(f"{data['message']}\n")
                if "suggestions" in data:
                    lines.append("\n**Suggestions:**")
                    for suggestion in data["suggestions"]:
                        lines.append(f"- {suggestion}")
                return "\n".join(lines)

        return OutputFormatter.format(data, format)

    @staticmethod
    def format_validation_errors(
        errors: List[str], format: Union[OutputFormat, str] = OutputFormat.JSON
    ) -> str:
        """Format validation errors"""
        error_data = {
            "error": True,
            "error_type": "validation",
            "errors": errors,
            "timestamp": datetime.now().isoformat(),
        }

        return OutputFormatter.format(error_data, format)

    @staticmethod
    def format_batch_errors(
        errors: List[Dict], format: Union[OutputFormat, str] = OutputFormat.CSV
    ) -> str:
        """Format batch errors"""
        return OutputFormatter.format(errors, format)

    @staticmethod
    def aggregate_errors(errors: List[Dict]) -> Dict[str, Any]:
        """Aggregate error statistics"""
        stats = {
            "total_errors": len(errors),
            "by_type": {},
            "by_code": {},
            "unique_codes": 0,
        }

        for error in errors:
            # Count by type
            error_type = error.get("type", "Unknown")
            stats["by_type"][error_type] = stats["by_type"].get(error_type, 0) + 1

            # Count by code
            error_code = error.get("code", "UNKNOWN")
            stats["by_code"][error_code] = stats["by_code"].get(error_code, 0) + 1

        stats["unique_codes"] = len(stats["by_code"])
        return stats


class ProgressFormatter:
    """Format progress updates for scripting"""

    @staticmethod
    def format_progress(
        current: int,
        total: int,
        operation: str,
        details: Optional[Dict[str, Any]] = None,
        format: Union[OutputFormat, str] = OutputFormat.JSON,
    ) -> str:
        """
        Format progress update

        Args:
            current: Current item number
            total: Total items
            operation: Current operation
            details: Additional details
            format: Output format

        Returns:
            Formatted progress
        """
        progress_data = {
            "progress": {
                "current": current,
                "total": total,
                "percentage": round((current / total * 100) if total > 0 else 0, 2),
                "operation": operation,
                "timestamp": datetime.now().isoformat(),
            }
        }

        if details:
            progress_data["progress"]["details"] = details

        return OutputFormatter.format(progress_data, format)

    @staticmethod
    def format_progress_bar(progress: Dict, width: int = 50) -> str:
        """Format a text progress bar"""
        percentage = progress.get("percentage", 0)
        filled = int(width * percentage / 100)
        bar = "=" * filled + "-" * (width - filled)
        return f"[{bar}] {percentage:.0f}%"

    @staticmethod
    def format_time(seconds: float) -> str:
        """Format time in human-readable format"""
        if seconds < 1:
            return "<1s"
        elif seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            remaining = seconds % 3600
            minutes = int(remaining // 60)
            secs = int(remaining % 60)
            return f"{hours}h {minutes}m {secs}s"

    @staticmethod
    def calculate_speed(progress: Dict) -> float:
        """Calculate processing speed in bytes/second"""
        bytes_processed = progress.get("bytes_processed", 0)
        elapsed_time = progress.get("elapsed_time", 1)
        return bytes_processed / elapsed_time if elapsed_time > 0 else 0

    @staticmethod
    def format_speed(speed: float) -> str:
        """Format speed in human-readable format"""
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if speed < 1024.0:
                return f"{speed:.1f} {unit}"
            speed /= 1024.0
        return f"{speed:.1f} TB/s"


class ResultFormatter:
    """Format operation results"""

    @staticmethod
    def format_result(
        data: Dict[str, Any],
        format: Union[OutputFormat, str] = OutputFormat.JSON,
        options: Optional["FormatterOptions"] = None,
    ) -> str:
        """Format a single result"""
        if options and options.fields:
            # Filter to only requested fields
            filtered_data = {k: v for k, v in data.items() if k in options.fields}
            return OutputFormatter.format(filtered_data, format, options=options)
        return OutputFormatter.format(data, format, options=options)

    @staticmethod
    def format_batch_results(
        results: List[Dict], format: Union[OutputFormat, str] = OutputFormat.JSON
    ) -> str:
        """Format batch results"""
        return OutputFormatter.format(results, format)

    @staticmethod
    def format_summary(
        summary: Dict[str, Any],
        format: Union[OutputFormat, str] = OutputFormat.MARKDOWN,
    ) -> str:
        """Format a summary with appropriate headers"""
        if format == OutputFormat.MARKDOWN or format == "markdown":
            lines = ["# Conversion Summary\n"]

            # Basic stats
            if "total_files" in summary:
                lines.append(f"**Total Files**: {summary['total_files']}\n")
            if "successful" in summary:
                success_rate = (
                    (summary["successful"] / summary["total_files"] * 100)
                    if summary.get("total_files")
                    else 0
                )
                lines.append(f"**Success Rate**: {success_rate:.1f}%\n")
            if "average_compression" in summary:
                lines.append(
                    f"**Average Compression**: {summary['average_compression'] * 100:.0f}%\n"
                )

            # Additional details
            if "formats_used" in summary:
                lines.append("\n## Formats Used\n")
                for fmt in summary["formats_used"]:
                    lines.append(f"- {fmt}")
                lines.append("")

            if "top_compressions" in summary:
                lines.append("\n## Top Compressions\n")
                for item in summary["top_compressions"]:
                    lines.append(
                        f"- **{item['file']}**: {item['ratio'] * 100:.0f}% reduction"
                    )

            return "\n".join(lines)
        else:
            return OutputFormatter.format(summary, format)

    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Format size in human-readable format"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0:
                if unit == "B":
                    return f"{size_bytes} {unit}"
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    @staticmethod
    def format_conversion_result(
        input_file: str,
        output_file: str,
        input_size: int,
        output_size: int,
        time_seconds: float,
        success: bool = True,
        error: Optional[str] = None,
        format: Union[OutputFormat, str] = OutputFormat.JSON,
    ) -> str:
        """Format conversion result"""
        result_data = {
            "success": success,
            "input": {
                "file": input_file,
                "size_bytes": input_size,
            },
            "output": {
                "file": output_file,
                "size_bytes": output_size,
            },
            "metrics": {
                "time_seconds": round(time_seconds, 3),
                "compression_ratio": (
                    round(output_size / input_size, 3) if input_size > 0 else 0
                ),
                "size_reduction_percent": (
                    round((1 - output_size / input_size) * 100, 2)
                    if input_size > 0
                    else 0
                ),
            },
            "timestamp": datetime.now().isoformat(),
        }

        if error:
            result_data["error"] = error

        return OutputFormatter.format(result_data, format)

    @staticmethod
    def format_batch_result(
        total_files: int,
        successful: int,
        failed: int,
        total_time: float,
        total_input_size: int,
        total_output_size: int,
        errors: Optional[List[Dict]] = None,
        format: Union[OutputFormat, str] = OutputFormat.JSON,
    ) -> str:
        """Format batch operation result"""
        result_data = {
            "batch_result": {
                "total_files": total_files,
                "successful": successful,
                "failed": failed,
                "success_rate": round(
                    (successful / total_files * 100) if total_files > 0 else 0, 2
                ),
            },
            "metrics": {
                "total_time_seconds": round(total_time, 3),
                "avg_time_per_file": (
                    round(total_time / total_files, 3) if total_files > 0 else 0
                ),
                "total_input_bytes": total_input_size,
                "total_output_bytes": total_output_size,
                "total_reduction_percent": (
                    round((1 - total_output_size / total_input_size) * 100, 2)
                    if total_input_size > 0
                    else 0
                ),
            },
            "timestamp": datetime.now().isoformat(),
        }

        if errors:
            result_data["errors"] = errors

        return OutputFormatter.format(result_data, format)


# Alias for compatibility with tests
FormatType = OutputFormat


@dataclass
class FormatterOptions:
    """Options for formatters"""

    fields: Optional[List[str]] = None
    flatten: bool = False
    pretty: bool = False
    include_headers: bool = True
    delimiter: str = ","
    indent: int = 2
    headers: Optional[List[str]] = None
    format_hints: Optional[Dict[str, Any]] = None
    verbose: bool = False
    user_friendly: bool = False
    alignment: Optional[Dict[str, str]] = None
    max_rows: Optional[int] = None


class TableFormatter:
    """Format data as tables"""

    @staticmethod
    def format_table(
        data: List[Dict],
        fields: Optional[List[str]] = None,
        include_headers: bool = True,
        style: str = "ascii",
        options: Optional["FormatterOptions"] = None,
    ) -> str:
        """Format data as a table"""
        if style == "markdown":
            return OutputFormatter.format_markdown(data, fields)
        elif style == "ascii":
            # ASCII table with borders
            if not data:
                return "No data"

            # Determine fields
            if not fields:
                fields = list(data[0].keys()) if data else []

            if not fields:
                return "No fields"

            # Calculate column widths
            widths = TableFormatter.calculate_column_widths(data, fields)

            # Build table
            lines = []

            # Top border
            border = "+" + "+".join("-" * (widths[f] + 2) for f in fields) + "+"
            lines.append(border)

            # Header
            header = "|" + "|".join(f" {f.ljust(widths[f])} " for f in fields) + "|"
            lines.append(header)
            lines.append(border)

            # Data rows (handle truncation if requested)
            max_rows = getattr(options, "max_rows", None) if options else None
            row_count = 0

            for row in data:
                if max_rows and row_count >= max_rows:
                    lines.append(
                        "|"
                        + "|".join(" ... ".center(widths[f] + 2) for f in fields)
                        + "|"
                    )
                    lines.append(f"... {len(data) - max_rows} more rows truncated ...")
                    break

                row_str = (
                    "|"
                    + "|".join(
                        f" {str(row.get(f, '')).ljust(widths[f])} " for f in fields
                    )
                    + "|"
                )
                lines.append(row_str)
                row_count += 1

            # Bottom border
            lines.append(border)

            return "\n".join(lines)
        else:
            return OutputFormatter.format_table(data, fields)

    @staticmethod
    def calculate_column_widths(
        data: List[Dict], fields: Optional[List[str]] = None
    ) -> Dict[str, int]:
        """Calculate appropriate column widths"""
        if not fields and data:
            fields = list(data[0].keys())

        widths = {}
        for field in fields:
            # Start with field name length
            widths[field] = len(field)
            # Check all data rows
            for row in data:
                value = str(row.get(field, ""))
                widths[field] = max(widths[field], len(value))

        return widths
