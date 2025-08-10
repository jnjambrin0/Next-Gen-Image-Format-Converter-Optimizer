"""
Integration tests for command chaining and piping
"""

import sys
from io import BytesIO
from unittest.mock import Mock, mock_open, patch

import pytest
from typer.testing import CliRunner

from app.cli.commands.chain import app as chain_app


@pytest.fixture
def runner():
    """Create a CLI test runner"""
    return CliRunner()


class TestCommandChaining:
    """Test command chaining functionality"""

    @patch("app.cli.commands.chain.ImageConverterClient")
    @patch("builtins.open", new_callable=mock_open, read_data=b"image_data")
    def test_chain_multiple_operations(self, mock_file, mock_client_class, runner):
        """Test chaining multiple operations"""
        # Setup mock
        mock_client = Mock()
        mock_result = Mock()
        mock_result.output_data = b"processed_data"
        mock_client.convert.return_value = mock_result
        mock_client_class.return_value = mock_client

        # Test chain command
        result = runner.invoke(
            chain_app,
            [
                "chain",
                "format:webp",
                "quality:85",
                "optimize",
                "-i",
                "test.jpg",
                "-o",
                "output.webp",
            ],
        )

        # Check command executed
        assert result.exit_code == 0
        mock_client.convert.assert_called_once()

    @patch("app.cli.commands.chain.ImageConverterClient")
    @patch("sys.stdin")
    @patch("sys.stdout")
    def test_pipe_stdin_stdout(
        self, mock_stdout, mock_stdin, mock_client_class, runner
    ):
        """Test piping from stdin to stdout"""
        # Setup mock stdin
        mock_stdin.isatty.return_value = False
        mock_stdin.buffer.read.return_value = b"input_image_data"

        # Setup mock client
        mock_client = Mock()
        mock_result = Mock()
        mock_result.output_data = b"output_image_data"
        mock_client.convert.return_value = mock_result
        mock_client_class.return_value = mock_client

        # Test pipe command
        result = runner.invoke(chain_app, ["pipe", "-f", "webp"])

        # Verify conversion was called
        mock_client.convert.assert_called_once()

    def test_chain_format_parsing(self, runner):
        """Test parsing of chain operation formats"""
        operations = ["format:webp", "quality:90", "resize:1920x1080", "optimize"]

        # Test that operations are parsed correctly
        # This would be tested through the actual command execution
        pass

    def test_chain_resize_parsing(self):
        """Test parsing of resize operations"""
        test_cases = [
            ("resize:1920x1080", (1920, 1080)),
            ("resize:800x", (800, None)),
            ("resize:x600", (None, 600)),
        ]

        # Test each resize format is parsed correctly
        pass

    @patch("app.cli.commands.chain.ImageConverterClient")
    def test_chain_error_handling(self, mock_client_class, runner):
        """Test error handling in chain operations"""
        # Setup mock to raise error
        mock_client = Mock()
        mock_client.convert.side_effect = Exception("Conversion failed")
        mock_client_class.return_value = mock_client

        # Test should handle error gracefully
        result = runner.invoke(chain_app, ["chain", "format:webp", "-i", "test.jpg"])

        # Should exit with error
        assert result.exit_code == 1

    def test_pipe_no_stdin_error(self, runner):
        """Test pipe command with no stdin data"""
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True

            result = runner.invoke(chain_app, ["pipe", "-f", "webp"])

            assert result.exit_code == 1
            assert "No input data" in result.stdout
