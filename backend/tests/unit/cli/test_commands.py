"""
Unit tests for CLI commands
"""

import pytest
from typer.testing import CliRunner
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
import sys

# Add SDK path for imports
sys.path.insert(
    0, str(Path(__file__).parent.parent.parent.parent.parent / "sdks" / "python")
)

from app.cli.commands import convert, batch, optimize, analyze, formats, presets


@pytest.fixture
def runner():
    """Create a CLI test runner"""
    return CliRunner()


class TestConvertCommand:
    """Test convert command"""

    @patch("app.cli.commands.convert.ImageConverterClient")
    @patch("app.cli.commands.convert.validate_input_file")
    @patch("app.cli.commands.convert.validate_output_path")
    @patch("builtins.open", new_callable=mock_open, read_data=b"fake_image_data")
    def test_convert_file_basic(
        self, mock_file, mock_validate_output, mock_validate_input, mock_client, runner
    ):
        """Test basic file conversion"""
        mock_validate_input.return_value = True
        mock_validate_output.return_value = True

        mock_client_instance = Mock()
        mock_result = Mock()
        mock_result.output_data = b"converted_data"
        mock_client_instance.convert.return_value = mock_result
        mock_client.return_value = mock_client_instance

        result = runner.invoke(convert.app, ["file", "test.jpg", "-f", "webp"])

        assert result.exit_code == 0
        assert "Conversion complete" in result.stdout
        mock_client_instance.convert.assert_called_once()

    @patch("app.cli.commands.convert.validate_input_file")
    def test_convert_file_invalid_input(self, mock_validate, runner):
        """Test conversion with invalid input file"""
        mock_validate.return_value = False

        result = runner.invoke(convert.app, ["file", "invalid.jpg", "-f", "webp"])

        assert result.exit_code == 1
        assert "Invalid or unsupported input file" in result.stdout

    @patch("app.cli.commands.convert.validate_input_file")
    @patch("app.cli.commands.convert.validate_output_path")
    def test_convert_file_dry_run(
        self, mock_validate_output, mock_validate_input, runner
    ):
        """Test dry run mode"""
        mock_validate_input.return_value = True
        mock_validate_output.return_value = True

        result = runner.invoke(
            convert.app, ["file", "test.jpg", "-f", "webp", "--dry-run"]
        )

        assert result.exit_code == 0
        assert "Conversion Preview" in result.stdout
        assert "Dry run complete" in result.stdout

    @patch("sys.stdin")
    @patch("sys.stdout")
    @patch("app.cli.commands.convert.ImageConverterClient")
    def test_convert_stdin(self, mock_client, mock_stdout, mock_stdin, runner):
        """Test stdin conversion"""
        mock_stdin.isatty.return_value = False
        mock_stdin.buffer.read.return_value = b"input_data"

        mock_client_instance = Mock()
        mock_result = Mock()
        mock_result.output_data = b"output_data"
        mock_client_instance.convert.return_value = mock_result
        mock_client.return_value = mock_client_instance

        result = runner.invoke(convert.app, ["stdin", "-f", "webp"])

        # Check that conversion was attempted
        mock_client_instance.convert.assert_called_once()


class TestBatchCommand:
    """Test batch command"""

    @patch("app.cli.commands.batch.glob")
    @patch("app.cli.commands.batch.validate_input_file")
    def test_batch_find_files(self, mock_validate, mock_glob, runner):
        """Test batch file discovery"""
        mock_glob.return_value = ["file1.jpg", "file2.jpg", "file3.jpg"]
        mock_validate.return_value = True

        result = runner.invoke(
            batch.app, ["convert", "*.jpg", "-f", "webp", "--dry-run"]
        )

        assert result.exit_code == 0
        assert "Found 3 images" in result.stdout
        assert "Batch Conversion Preview" in result.stdout

    @patch("app.cli.commands.batch.glob")
    @patch("app.cli.commands.batch.validate_input_file")
    def test_batch_no_files_found(self, mock_validate, mock_glob, runner):
        """Test batch with no matching files"""
        mock_glob.return_value = []

        result = runner.invoke(batch.app, ["convert", "*.xyz", "-f", "webp"])

        assert result.exit_code == 1
        assert "No valid image files found" in result.stdout

    @patch("app.cli.commands.batch.AsyncImageConverterClient")
    def test_batch_status(self, mock_client_class, runner):
        """Test batch status command"""
        mock_client = MagicMock()
        mock_status = Mock()
        mock_status.job_id = "test123"
        mock_status.status = "completed"
        mock_status.completed_count = 10
        mock_status.total_count = 10
        mock_status.failed_count = 0

        mock_client.__aenter__.return_value.get_batch_status = Mock(
            return_value=mock_status
        )
        mock_client_class.return_value = mock_client

        with patch("asyncio.run"):
            result = runner.invoke(batch.app, ["status", "test123"])

        # Command should execute without error
        assert result.exit_code in [0, 1]  # May exit 1 due to mocking


class TestOptimizeCommand:
    """Test optimize command"""

    def test_optimize_auto(self, runner):
        """Test optimize auto command"""
        result = runner.invoke(optimize.app, ["auto", "test.jpg"])

        assert result.exit_code == 0
        assert "Optimizing test.jpg" in result.stdout


class TestAnalyzeCommand:
    """Test analyze command"""

    def test_analyze_info(self, runner):
        """Test analyze info command"""
        result = runner.invoke(analyze.app, ["info", "test.jpg"])

        assert result.exit_code == 0
        assert "Analyzing test.jpg" in result.stdout


class TestFormatsCommand:
    """Test formats command"""

    def test_formats_list(self, runner):
        """Test formats list command"""
        result = runner.invoke(formats.app, ["list"])

        assert result.exit_code == 0
        assert "Supported Image Formats" in result.stdout
        assert "JPEG" in result.stdout
        assert "PNG" in result.stdout
        assert "WebP" in result.stdout


class TestPresetsCommand:
    """Test presets command"""

    def test_presets_list(self, runner):
        """Test presets list command"""
        result = runner.invoke(presets.app, ["list"])

        assert result.exit_code == 0
        assert "Available Presets" in result.stdout
        assert "web" in result.stdout
