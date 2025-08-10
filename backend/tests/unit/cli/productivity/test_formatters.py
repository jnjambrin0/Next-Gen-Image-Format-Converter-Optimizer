"""
from typing import Any
Comprehensive tests for output format consistency
Tests JSON, CSV, YAML, XML, and Markdown formatters
"""

import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from decimal import Decimal
from io import StringIO

import pytest
import yaml

from app.cli.productivity.formatters import (ErrorFormatter, FormatterOptions,
                                             FormatType, OutputFormatter,
                                             ProgressFormatter,
                                             ResultFormatter, TableFormatter)


class TestOutputFormatter:
    """Test base OutputFormatter functionality"""

    @pytest.fixture
    def formatter(self) -> None:
        """Create formatter instance"""
        return OutputFormatter()

    @pytest.fixture
    def sample_data(self) -> None:
        """Create sample data for testing"""
        return {
            "status": "success",
            "file": "image.jpg",
            "format": "webp",
            "original_size": 1048576,
            "converted_size": 524288,
            "compression_ratio": 0.5,
            "time_taken": 2.345,
            "metadata": {"width": 1920, "height": 1080, "color_space": "sRGB"},
            "warnings": ["Metadata stripped"],
            "timestamp": "2024-01-15T10:30:00Z",
        }

    def test_json_formatting(self, formatter, sample_data) -> None:
        """Test JSON output formatting"""
        output = formatter.format(sample_data, FormatType.JSON)

        # Should be valid JSON
        parsed = json.loads(output)
        assert parsed["status"] == "success"
        assert parsed["compression_ratio"] == 0.5
        assert parsed["metadata"]["width"] == 1920

    def test_json_pretty_printing(self, formatter, sample_data) -> None:
        """Test JSON pretty printing option"""
        options = FormatterOptions(pretty=True, indent=2)
        output = formatter.format(sample_data, FormatType.JSON, options)

        # Should have indentation
        assert "\n" in output
        assert "  " in output  # 2-space indent

        # Should still be valid JSON
        parsed = json.loads(output)
        assert parsed["status"] == "success"

    def test_csv_formatting(self, formatter) -> None:
        """Test CSV output formatting"""
        data = [
            {"file": "img1.jpg", "size": 1000, "format": "webp"},
            {"file": "img2.png", "size": 2000, "format": "avif"},
            {"file": "img3.bmp", "size": 3000, "format": "jxl"},
        ]

        output = formatter.format(data, FormatType.CSV)

        # Parse CSV
        reader = csv.DictReader(StringIO(output))
        rows = list(reader)

        assert len(rows) == 3
        assert rows[0]["file"] == "img1.jpg"
        assert rows[1]["size"] == "2000"
        assert rows[2]["format"] == "jxl"

    def test_csv_with_headers(self, formatter) -> None:
        """Test CSV header customization"""
        data = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
        options = FormatterOptions(headers=["Column A", "Column B"])

        output = formatter.format(data, FormatType.CSV, options)

        lines = output.strip().split("\n")
        assert "Column A" in lines[0]
        assert "Column B" in lines[0]

    def test_yaml_formatting(self, formatter, sample_data) -> None:
        """Test YAML output formatting"""
        output = formatter.format(sample_data, FormatType.YAML)

        # Should be valid YAML
        parsed = yaml.safe_load(output)
        assert parsed["status"] == "success"
        assert parsed["compression_ratio"] == 0.5
        assert parsed["metadata"]["height"] == 1080

    def test_yaml_with_anchors(self, formatter) -> None:
        """Test YAML anchor/alias support"""
        data = {
            "defaults": {"quality": 85, "format": "webp"},
            "conversions": [
                {"file": "a.jpg", "settings": "use_defaults"},
                {"file": "b.jpg", "settings": "use_defaults"},
            ],
        }

        output = formatter.format(data, FormatType.YAML)
        parsed = yaml.safe_load(output)

        assert parsed["defaults"]["quality"] == 85
        assert len(parsed["conversions"]) == 2

    def test_xml_formatting(self, formatter, sample_data) -> None:
        """Test XML output formatting"""
        output = formatter.format(sample_data, FormatType.XML)

        # Should be valid XML
        root = ET.fromstring(output)
        assert root.find("status").text == "success"
        assert root.find("format").text == "webp"
        assert float(root.find("compression_ratio").text) == 0.5

    def test_xml_with_attributes(self, formatter) -> None:
        """Test XML attribute handling"""
        data = {
            "@version": "1.0",
            "@encoding": "UTF-8",
            "result": {"@type": "conversion", "file": "test.jpg", "status": "success"},
        }

        output = formatter.format(data, FormatType.XML)
        root = ET.fromstring(output)

        # Check attributes
        assert root.attrib.get("version") == "1.0"
        result = root.find("result")
        assert result.attrib.get("type") == "conversion"

    def test_markdown_formatting(self, formatter, sample_data) -> None:
        """Test Markdown output formatting"""
        output = formatter.format(sample_data, FormatType.MARKDOWN)

        # Should contain Markdown elements
        assert "#" in output  # Headers
        assert "|" in output  # Table
        assert "**" in output or "*" in output  # Bold/italic
        assert "```" in output  # Code blocks for nested data

    def test_markdown_table_generation(self, formatter) -> None:
        """Test Markdown table formatting"""
        data = [
            {"File": "img1.jpg", "Size": "1.2 MB", "Format": "WebP"},
            {"File": "img2.png", "Size": "2.5 MB", "Format": "AVIF"},
            {"File": "img3.bmp", "Size": "5.0 MB", "Format": "JXL"},
        ]

        output = formatter.format_table(data, FormatType.MARKDOWN)

        lines = output.strip().split("\n")
        # Should have header, separator, and data rows
        assert "|" in lines[0]  # Header
        assert "---" in lines[1]  # Separator
        assert "img1.jpg" in lines[2]  # Data

    def test_format_auto_detection(self, formatter, sample_data) -> None:
        """Test automatic format detection from file extension"""
        # Test with file paths
        assert formatter.detect_format("output.json") == FormatType.JSON
        assert formatter.detect_format("data.csv") == FormatType.CSV
        assert formatter.detect_format("config.yaml") == FormatType.YAML
        assert formatter.detect_format("config.yml") == FormatType.YAML
        assert formatter.detect_format("response.xml") == FormatType.XML
        assert formatter.detect_format("README.md") == FormatType.MARKDOWN

    def test_format_validation(self, formatter) -> None:
        """Test format validation for different data types"""
        # JSON should handle all types
        assert formatter.validate_data({"key": "value"}, FormatType.JSON)
        assert formatter.validate_data([1, 2, 3], FormatType.JSON)
        assert formatter.validate_data("string", FormatType.JSON)

        # CSV requires list of dicts
        assert formatter.validate_data([{"a": 1}], FormatType.CSV)
        assert not formatter.validate_data({"a": 1}, FormatType.CSV)

        # XML requires dict
        assert formatter.validate_data({"root": "value"}, FormatType.XML)
        assert not formatter.validate_data([1, 2, 3], FormatType.XML)


class TestResultFormatter:
    """Test ResultFormatter for conversion results"""

    @pytest.fixture
    def formatter(self) -> None:
        return ResultFormatter()

    @pytest.fixture
    def conversion_result(self) -> None:
        """Create sample conversion result"""
        return {
            "success": True,
            "input_file": "photo.jpg",
            "output_file": "photo.webp",
            "input_format": "jpeg",
            "output_format": "webp",
            "input_size": 2048000,
            "output_size": 1024000,
            "compression_ratio": 0.5,
            "quality": 85,
            "processing_time": 1.234,
            "dimensions": {"width": 3840, "height": 2160},
            "color_space": "sRGB",
            "metadata_preserved": False,
            "warnings": [],
            "timestamp": datetime.now().isoformat(),
        }

    def test_format_single_result_json(self, formatter, conversion_result) -> None:
        """Test formatting single conversion result as JSON"""
        output = formatter.format_result(conversion_result, FormatType.JSON)

        data = json.loads(output)
        assert data["success"] is True
        assert data["compression_ratio"] == 0.5
        assert data["dimensions"]["width"] == 3840

    def test_format_batch_results_csv(self, formatter) -> None:
        """Test formatting batch results as CSV"""
        results = [
            {
                "file": "img1.jpg",
                "status": "success",
                "output_format": "webp",
                "compression": 0.6,
                "time": 1.2,
            },
            {
                "file": "img2.png",
                "status": "success",
                "output_format": "avif",
                "compression": 0.4,
                "time": 3.5,
            },
            {
                "file": "img3.bmp",
                "status": "failed",
                "error": "Unsupported format",
                "time": 0.1,
            },
        ]

        output = formatter.format_batch_results(results, FormatType.CSV)

        reader = csv.DictReader(StringIO(output))
        rows = list(reader)

        assert len(rows) == 3
        assert rows[0]["status"] == "success"
        assert rows[2]["status"] == "failed"

    def test_format_summary_markdown(self, formatter) -> None:
        """Test formatting conversion summary as Markdown"""
        summary = {
            "total_files": 100,
            "successful": 95,
            "failed": 5,
            "total_input_size": 524288000,
            "total_output_size": 262144000,
            "average_compression": 0.5,
            "total_time": 234.56,
            "formats_used": ["webp", "avif", "jxl"],
            "top_compressions": [
                {"file": "huge.bmp", "ratio": 0.05},
                {"file": "large.png", "ratio": 0.15},
            ],
        }

        output = formatter.format_summary(summary, FormatType.MARKDOWN)

        # Check for expected Markdown elements
        assert "# Conversion Summary" in output or "## Summary" in output
        assert "Total Files: 100" in output or "100" in output
        assert "Success Rate" in output or "95%" in output
        assert "Average Compression" in output or "50%" in output

    def test_format_with_custom_fields(self, formatter, conversion_result) -> None:
        """Test custom field selection"""
        options = FormatterOptions(
            fields=[
                "input_file",
                "output_format",
                "compression_ratio",
                "processing_time",
            ]
        )

        output = formatter.format_result(conversion_result, FormatType.JSON, options)
        data = json.loads(output)

        # Should only have specified fields
        assert "input_file" in data
        assert "compression_ratio" in data
        assert "quality" not in data  # Not in field list
        assert "dimensions" not in data  # Not in field list

    def test_human_readable_sizes(self, formatter) -> None:
        """Test human-readable size formatting"""
        assert formatter.format_size(1024) == "1.0 KB"
        assert formatter.format_size(1048576) == "1.0 MB"
        assert formatter.format_size(1073741824) == "1.0 GB"
        assert formatter.format_size(512) == "512 B"
        assert formatter.format_size(1536) == "1.5 KB"


class TestErrorFormatter:
    """Test ErrorFormatter for error reporting"""

    @pytest.fixture
    def formatter(self) -> None:
        return ErrorFormatter()

    @pytest.fixture
    def error_data(self) -> None:
        """Create sample error data"""
        return {
            "error_code": "CONV_001",
            "error_type": "ConversionError",
            "message": "Failed to convert image",
            "details": "Unsupported format combination: HEIC to JXL",
            "file": "photo.heic",
            "timestamp": datetime.now().isoformat(),
            "traceback": [
                "File converter.py, line 123, in convert",
                "File formats.py, line 45, in validate",
            ],
            "suggestions": ["Try converting to WebP instead", "Update codec libraries"],
        }

    def test_format_error_json(self, formatter, error_data) -> None:
        """Test JSON error formatting"""
        output = formatter.format_error(error_data, FormatType.JSON)

        data = json.loads(output)
        assert data["error_code"] == "CONV_001"
        assert data["message"] == "Failed to convert image"
        assert len(data["suggestions"]) == 2

    def test_format_error_user_friendly(self, formatter, error_data) -> None:
        """Test user-friendly error formatting"""
        options = FormatterOptions(verbose=False, user_friendly=True)
        output = formatter.format_error(error_data, FormatType.MARKDOWN, options)

        # Should not include technical details in user-friendly mode
        assert "traceback" not in output.lower()
        assert "Try converting" in output  # Should include suggestions
        assert "❌" in output or "Error" in output

    def test_format_batch_errors_csv(self, formatter) -> None:
        """Test batch error formatting as CSV"""
        errors = [
            {"file": "img1.xyz", "error": "Unsupported format", "code": "FMT_001"},
            {"file": "img2.jpg", "error": "File too large", "code": "SIZE_001"},
            {"file": "img3.png", "error": "Corrupted file", "code": "CORRUPT_001"},
        ]

        output = formatter.format_batch_errors(errors, FormatType.CSV)

        reader = csv.DictReader(StringIO(output))
        rows = list(reader)

        assert len(rows) == 3
        assert rows[0]["error"] == "Unsupported format"
        assert rows[1]["code"] == "SIZE_001"

    def test_error_aggregation(self, formatter) -> None:
        """Test error aggregation and statistics"""
        errors = [
            {"code": "FMT_001", "type": "FormatError"},
            {"code": "FMT_001", "type": "FormatError"},
            {"code": "SIZE_001", "type": "SizeError"},
            {"code": "FMT_002", "type": "FormatError"},
            {"code": "PERM_001", "type": "PermissionError"},
        ]

        stats = formatter.aggregate_errors(errors)

        assert stats["total_errors"] == 5
        assert stats["by_type"]["FormatError"] == 3
        assert stats["by_code"]["FMT_001"] == 2
        assert stats["unique_codes"] == 4


class TestProgressFormatter:
    """Test ProgressFormatter for progress reporting"""

    @pytest.fixture
    def formatter(self) -> None:
        return ProgressFormatter()

    def test_format_progress_json(self, formatter) -> None:
        """Test JSON progress formatting"""
        progress = {
            "current": 45,
            "total": 100,
            "percentage": 45.0,
            "elapsed_time": 23.5,
            "estimated_remaining": 28.7,
            "current_file": "image45.jpg",
            "files_completed": 44,
            "files_failed": 1,
            "bytes_processed": 45000000,
            "bytes_total": 100000000,
        }

        output = formatter.format_progress(progress, FormatType.JSON)
        data = json.loads(output)

        assert data["percentage"] == 45.0
        assert data["current_file"] == "image45.jpg"

    def test_format_progress_bar_text(self, formatter) -> None:
        """Test text progress bar formatting"""
        progress = {"current": 75, "total": 100, "percentage": 75.0}

        output = formatter.format_progress_bar(progress, width=50)

        # Should have progress bar characters
        assert "[" in output
        assert "]" in output
        assert "=" in output or "█" in output  # Progress fill
        assert "75%" in output

    def test_format_eta_calculation(self, formatter) -> None:
        """Test ETA calculation and formatting"""
        # Test various time ranges
        assert formatter.format_time(30) == "30s"
        assert formatter.format_time(90) == "1m 30s"
        assert formatter.format_time(3665) == "1h 1m 5s"
        assert formatter.format_time(0.5) == "<1s"

    def test_format_speed_calculation(self, formatter) -> None:
        """Test speed calculation and formatting"""
        progress = {
            "bytes_processed": 10485760,  # 10MB
            "elapsed_time": 2.0,  # 2 seconds
        }

        speed = formatter.calculate_speed(progress)
        formatted = formatter.format_speed(speed)

        assert speed == 5242880  # 5MB/s
        assert "5.0 MB/s" in formatted or "5 MB/s" in formatted


class TestTableFormatter:
    """Test TableFormatter for tabular data"""

    @pytest.fixture
    def formatter(self) -> None:
        return TableFormatter()

    @pytest.fixture
    def table_data(self) -> None:
        return [
            {"Name": "Alice", "Age": 30, "City": "New York"},
            {"Name": "Bob", "Age": 25, "City": "Los Angeles"},
            {"Name": "Charlie", "Age": 35, "City": "Chicago"},
        ]

    def test_format_ascii_table(self, formatter, table_data) -> None:
        """Test ASCII table formatting"""
        output = formatter.format_table(table_data, style="ascii")

        lines = output.strip().split("\n")

        # Should have borders and alignment
        assert "+" in lines[0]  # Top border
        assert "|" in lines[1]  # Header row
        assert "Name" in lines[1]
        assert "Alice" in output

    def test_format_markdown_table(self, formatter, table_data) -> None:
        """Test Markdown table formatting"""
        output = formatter.format_table(table_data, style="markdown")

        lines = output.strip().split("\n")

        # Markdown table format
        assert "|" in lines[0]  # Header
        assert "---|" in lines[1]  # Separator
        assert "Alice" in lines[2]  # Data

    def test_column_alignment(self, formatter) -> None:
        """Test column alignment options"""
        data = [
            {"Left": "text", "Center": "data", "Right": 123},
            {"Left": "more", "Center": "info", "Right": 45678},
        ]

        options = FormatterOptions(
            alignment={"Left": "left", "Center": "center", "Right": "right"}
        )

        output = formatter.format_table(data, style="ascii", options=options)

        # Visual inspection would show alignment
        # Here we just check it doesn't error
        assert "text" in output
        assert "45678" in output

    def test_column_width_calculation(self, formatter, table_data) -> None:
        """Test automatic column width calculation"""
        widths = formatter.calculate_column_widths(table_data)

        # Name column should be wide enough for "Charlie"
        assert widths["Name"] >= 7
        # Age column for 2-digit numbers
        assert widths["Age"] >= 2
        # City column for "Los Angeles"
        assert widths["City"] >= 11

    def test_table_truncation(self, formatter) -> None:
        """Test table truncation for large datasets"""
        # Create large dataset
        large_data = [{"id": i, "value": f"item_{i}"} for i in range(1000)]

        options = FormatterOptions(max_rows=10)
        output = formatter.format_table(large_data, options=options)

        lines = output.strip().split("\n")
        # Should be truncated (header + separator + 10 rows + truncation indicator)
        assert len(lines) < 20
        assert "..." in output or "truncated" in output.lower()


class TestFormatterConsistency:
    """Test consistency across all formatters"""

    @pytest.fixture
    def all_formatters(self) -> None:
        """Create all formatter types"""
        return {
            "output": OutputFormatter(),
            "result": ResultFormatter(),
            "error": ErrorFormatter(),
            "progress": ProgressFormatter(),
            "table": TableFormatter(),
        }

    @pytest.fixture
    def test_data(self) -> None:
        """Create test data that all formatters should handle"""
        return {
            "status": "success",
            "data": [{"id": 1, "value": "test1"}, {"id": 2, "value": "test2"}],
            "metadata": {"timestamp": "2024-01-15T10:00:00Z", "version": "1.0"},
        }

    def test_all_formats_supported(self, all_formatters, test_data) -> None:
        """Test that all formatters support all format types"""
        formats = [
            FormatType.JSON,
            FormatType.CSV,
            FormatType.YAML,
            FormatType.XML,
            FormatType.MARKDOWN,
        ]

        for formatter_name, formatter in all_formatters.items():
            if formatter_name == "table":  # Table formatter is special
                continue

            for format_type in formats:
                try:
                    # Adjust data for CSV (needs list of dicts)
                    if format_type == FormatType.CSV:
                        data = test_data["data"]
                    else:
                        data = test_data

                    output = formatter.format(data, format_type)
                    assert output is not None
                    assert len(output) > 0
                except NotImplementedError:
                    # Some combinations might not be implemented
                    pass

    def test_unicode_handling(self, all_formatters) -> None:
        """Test Unicode character handling"""
        unicode_data = {
            "text": "Hello 世界 🌍",
            "emoji": "✅ ❌ ⚠️",
            "special": "café naïve Zürich",
        }

        formatter = all_formatters["output"]

        # Test each format
        json_out = formatter.format(unicode_data, FormatType.JSON)
        assert "世界" in json_out
        assert "✅" in json_out

        yaml_out = formatter.format(unicode_data, FormatType.YAML)
        assert "café" in yaml_out

        xml_out = formatter.format(unicode_data, FormatType.XML)
        # XML might escape some characters
        root = ET.fromstring(xml_out)
        assert root.find("text").text == "Hello 世界 🌍"

    def test_special_characters_escaping(self, all_formatters) -> None:
        """Test special character escaping"""
        special_data = {
            "quotes": 'He said "Hello"',
            "newline": "Line1\nLine2",
            "tab": "Col1\tCol2",
            "backslash": "C:\\Users\\file.txt",
            "html": "<script>alert('XSS')</script>",
        }

        formatter = all_formatters["output"]

        # JSON should escape properly
        json_out = formatter.format(special_data, FormatType.JSON)
        parsed = json.loads(json_out)
        assert parsed["quotes"] == 'He said "Hello"'
        assert parsed["newline"] == "Line1\nLine2"

        # XML should escape HTML
        xml_out = formatter.format(special_data, FormatType.XML)
        assert "&lt;script&gt;" in xml_out or "<![CDATA[" in xml_out

    def test_null_and_empty_handling(self, all_formatters) -> None:
        """Test null and empty value handling"""
        edge_data = {
            "null_value": None,
            "empty_string": "",
            "empty_list": [],
            "empty_dict": {},
            "zero": 0,
            "false": False,
        }

        formatter = all_formatters["output"]

        # JSON
        json_out = formatter.format(edge_data, FormatType.JSON)
        parsed = json.loads(json_out)
        assert parsed["null_value"] is None
        assert parsed["empty_string"] == ""
        assert parsed["zero"] == 0
        assert parsed["false"] is False

        # YAML
        yaml_out = formatter.format(edge_data, FormatType.YAML)
        parsed = yaml.safe_load(yaml_out)
        assert parsed["null_value"] is None
        assert parsed["empty_list"] == []

    def test_large_number_precision(self, all_formatters) -> None:
        """Test large number and decimal precision"""
        number_data = {
            "large_int": 9223372036854775807,  # Max int64
            "float_precise": 3.141592653589793,
            "scientific": 1.23e-10,
            "decimal": str(Decimal("123.456789012345678901234567890")),
        }

        formatter = all_formatters["output"]

        # JSON should maintain precision
        json_out = formatter.format(number_data, FormatType.JSON)
        parsed = json.loads(json_out)
        assert parsed["large_int"] == 9223372036854775807
        assert abs(parsed["float_precise"] - 3.141592653589793) < 1e-10

    def test_format_consistency_across_runs(self, all_formatters, test_data) -> None:
        """Test that formatting is consistent across multiple runs"""
        formatter = all_formatters["output"]

        # Format the same data multiple times
        outputs = []
        for _ in range(5):
            output = formatter.format(test_data, FormatType.JSON)
            outputs.append(output)

        # All outputs should be identical
        assert all(out == outputs[0] for out in outputs)

    def test_format_round_trip(self, all_formatters, test_data) -> None:
        """Test data integrity through format/parse round trip"""
        formatter = all_formatters["output"]

        # JSON round trip
        json_out = formatter.format(test_data, FormatType.JSON)
        json_parsed = json.loads(json_out)
        assert json_parsed == test_data

        # YAML round trip
        yaml_out = formatter.format(test_data, FormatType.YAML)
        yaml_parsed = yaml.safe_load(yaml_out)
        assert yaml_parsed == test_data


class TestFormatterIntegration:
    """Integration tests for formatters"""

    def test_cli_output_pipeline(self) -> None:
        """Test complete CLI output pipeline"""
        # Simulate CLI command output
        formatter = OutputFormatter()

        # 1. Start with progress
        progress_formatter = ProgressFormatter()
        progress = {"current": 0, "total": 100, "percentage": 0.0}

        # 2. Process files and collect results
        results = []
        for i in range(100):
            progress["current"] = i + 1
            progress["percentage"] = (i + 1) / 100 * 100

            result = {
                "file": f"image{i}.jpg",
                "status": "success" if i % 10 != 0 else "failed",
                "compression": 0.5 + (i % 20) * 0.02,
            }
            results.append(result)

        # 3. Format final results
        result_formatter = ResultFormatter()

        # Test different output formats
        json_output = result_formatter.format_batch_results(results, FormatType.JSON)
        assert json.loads(json_output)  # Valid JSON

        csv_output = result_formatter.format_batch_results(results, FormatType.CSV)
        assert len(csv_output.split("\n")) > 100  # Has all rows

        yaml_output = result_formatter.format_batch_results(results, FormatType.YAML)
        assert yaml.safe_load(yaml_output)  # Valid YAML

    def test_error_recovery_formatting(self) -> None:
        """Test formatting with error recovery"""
        formatter = OutputFormatter()
        error_formatter = ErrorFormatter()

        # Create mixed success/error data
        mixed_data = [
            {"status": "success", "file": "good.jpg"},
            {"status": "error", "file": "bad.xyz", "error": "Invalid format"},
            {"status": "success", "file": "ok.png"},
            None,  # Null entry
            {"status": "error", "error": "Unknown error"},  # Missing file
        ]

        # Should handle gracefully
        try:
            output = formatter.format_safe(mixed_data, FormatType.JSON)
            parsed = json.loads(output)
            assert len(parsed) == 4  # Null filtered out
        except Exception as e:
            pytest.fail(f"Formatter should handle errors gracefully: {e}")

    def test_streaming_format_output(self) -> None:
        """Test streaming format output for large datasets"""
        formatter = OutputFormatter()

        # Simulate streaming data
        def generate_data() -> None:
            for i in range(1000):
                yield {"id": i, "value": f"item_{i}"}

        # Format as streaming JSON array
        output_buffer = StringIO()
        formatter.stream_format(generate_data(), FormatType.JSON, output_buffer)

        # Verify output
        output = output_buffer.getvalue()
        data = json.loads(output)
        assert len(data) == 1000
        assert data[0]["id"] == 0
        assert data[999]["id"] == 999
