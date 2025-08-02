"""Unit tests for ExternalToolExecutor."""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
import subprocess

from app.core.conversion.tools import ExternalToolExecutor
from app.core.exceptions import ConversionFailedError


class TestExternalToolExecutor:
    """Test suite for ExternalToolExecutor."""
    
    def test_init_basic(self):
        """Test basic initialization."""
        executor = ExternalToolExecutor("test_tool")
        
        assert executor.tool_name == "test_tool"
        assert executor.tool_variants == ["test_tool"]
        assert executor.restricted_env["PATH"] == "/usr/bin:/bin:/usr/local/bin"
        assert executor.restricted_env["HOME"] == "/tmp"
        assert executor.restricted_env["LC_ALL"] == "C"
    
    def test_init_with_variants(self):
        """Test initialization with tool variants."""
        executor = ExternalToolExecutor(
            "mozjpeg",
            tool_variants=["cjpeg", "mozjpeg", "mozjpeg-cjpeg"]
        )
        
        assert executor.tool_name == "mozjpeg"
        assert executor.tool_variants == ["cjpeg", "mozjpeg", "mozjpeg-cjpeg"]
    
    def test_init_with_custom_env(self):
        """Test initialization with custom environment."""
        custom_env = {"CUSTOM_VAR": "test_value"}
        executor = ExternalToolExecutor("test_tool", custom_env=custom_env)
        
        assert executor.restricted_env["CUSTOM_VAR"] == "test_value"
        assert executor.restricted_env["PATH"] == "/usr/bin:/bin:/usr/local/bin"
    
    @patch("shutil.which")
    def test_find_tool_success(self, mock_which):
        """Test successful tool finding."""
        mock_which.return_value = "/usr/bin/test_tool"
        
        executor = ExternalToolExecutor("test_tool")
        
        assert executor.tool_path == "/usr/bin/test_tool"
        assert executor.is_available is True
        mock_which.assert_called_once_with("test_tool")
    
    @patch("shutil.which")
    def test_find_tool_with_variants(self, mock_which):
        """Test finding tool with variants."""
        mock_which.side_effect = [None, None, "/usr/local/bin/mozjpeg-cjpeg"]
        
        executor = ExternalToolExecutor(
            "mozjpeg",
            tool_variants=["cjpeg", "mozjpeg", "mozjpeg-cjpeg"]
        )
        
        assert executor.tool_path == "/usr/local/bin/mozjpeg-cjpeg"
        assert executor.is_available is True
        assert mock_which.call_count == 3
    
    @patch("shutil.which")
    def test_find_tool_not_found(self, mock_which):
        """Test when tool is not found."""
        mock_which.return_value = None
        
        executor = ExternalToolExecutor("nonexistent_tool")
        
        assert executor.tool_path is None
        assert executor.is_available is False
    
    @patch("subprocess.run")
    @patch("shutil.which")
    def test_check_version_success(self, mock_which, mock_run):
        """Test successful version check."""
        mock_which.return_value = "/usr/bin/test_tool"
        mock_run.return_value = MagicMock(
            stdout="Test Tool v1.2.3",
            stderr="",
            returncode=0
        )
        
        executor = ExternalToolExecutor("test_tool")
        version = executor.check_version()
        
        assert version == "Test Tool v1.2.3"
        mock_run.assert_called_once()
    
    @patch("subprocess.run")
    @patch("shutil.which")
    def test_check_version_from_stderr(self, mock_which, mock_run):
        """Test version check when output is on stderr."""
        mock_which.return_value = "/usr/bin/mozjpeg"
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="mozjpeg version 4.0.0",
            returncode=0
        )
        
        executor = ExternalToolExecutor("mozjpeg")
        version = executor.check_version()
        
        assert version == "mozjpeg version 4.0.0"
    
    @patch("shutil.which")
    def test_check_version_not_available(self, mock_which):
        """Test version check when tool not available."""
        mock_which.return_value = None
        
        executor = ExternalToolExecutor("test_tool")
        version = executor.check_version()
        
        assert version is None
    
    @patch("subprocess.run")
    @patch("shutil.which")
    def test_execute_success(self, mock_which, mock_run):
        """Test successful synchronous execution."""
        mock_which.return_value = "/usr/bin/test_tool"
        mock_run.return_value = MagicMock(
            stdout=b"output data",
            stderr=b"some warning",
            returncode=0
        )
        
        executor = ExternalToolExecutor("test_tool")
        result = executor.execute(["--arg1", "value1"], timeout=10)
        
        assert result.stdout == b"output data"
        assert result.stderr == "some warning"
        assert result.returncode == 0
        assert result.execution_time > 0
        
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["/usr/bin/test_tool", "--arg1", "value1"]
        assert call_args[1]["timeout"] == 10
        assert call_args[1]["env"] == executor.restricted_env
    
    @patch("subprocess.run")
    @patch("shutil.which")
    def test_execute_with_input_data(self, mock_which, mock_run):
        """Test execution with input data."""
        mock_which.return_value = "/usr/bin/test_tool"
        mock_run.return_value = MagicMock(
            stdout=b"processed output",
            stderr=b"",
            returncode=0
        )
        
        executor = ExternalToolExecutor("test_tool")
        input_data = b"test input data"
        result = executor.execute(["--process"], input_data=input_data)
        
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["input"] == input_data
    
    @patch("shutil.which")
    def test_execute_tool_not_available(self, mock_which):
        """Test execution when tool not available."""
        mock_which.return_value = None
        
        executor = ExternalToolExecutor("test_tool")
        
        with pytest.raises(ConversionFailedError) as exc_info:
            executor.execute(["--arg"])
        
        assert "not available" in str(exc_info.value)
    
    @patch("subprocess.run")
    @patch("shutil.which")
    def test_execute_timeout(self, mock_which, mock_run):
        """Test execution timeout."""
        mock_which.return_value = "/usr/bin/test_tool"
        mock_run.side_effect = subprocess.TimeoutExpired("test_tool", 5)
        
        executor = ExternalToolExecutor("test_tool")
        
        with pytest.raises(ConversionFailedError) as exc_info:
            executor.execute(["--slow"], timeout=5)
        
        assert "timed out" in str(exc_info.value)
    
    @patch("subprocess.run")
    @patch("shutil.which")
    def test_execute_failure(self, mock_which, mock_run):
        """Test execution with non-zero return code."""
        mock_which.return_value = "/usr/bin/test_tool"
        mock_run.return_value = MagicMock(
            stdout=b"",
            stderr=b"Error: Invalid argument",
            returncode=1
        )
        
        executor = ExternalToolExecutor("test_tool")
        result = executor.execute(["--invalid"])
        
        assert result.returncode == 1
        assert result.stderr == "Error: Invalid argument"
    
    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("shutil.which")
    async def test_execute_async_success(self, mock_which, mock_subprocess):
        """Test successful asynchronous execution."""
        mock_which.return_value = "/usr/bin/test_tool"
        
        # Mock process
        mock_process = MagicMock()
        async def mock_communicate(input=None):
            return (b"async output", b"async warning")
        mock_process.communicate = mock_communicate
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process
        
        executor = ExternalToolExecutor("test_tool")
        result = await executor.execute_async(["--async-arg"])
        
        assert result.stdout == b"async output"
        assert result.stderr == "async warning"
        assert result.returncode == 0
        assert result.execution_time > 0
    
    def test_validate_output_success(self):
        """Test output validation success."""
        executor = ExternalToolExecutor("test_tool")
        
        assert executor.validate_output(b"x" * 1000) is True
        assert executor.validate_output(b"x" * 100) is True
    
    def test_validate_output_empty(self):
        """Test output validation with empty data."""
        executor = ExternalToolExecutor("test_tool")
        
        assert executor.validate_output(b"") is False
        assert executor.validate_output(None) is False
    
    def test_validate_output_too_small(self):
        """Test output validation with small data."""
        executor = ExternalToolExecutor("test_tool")
        
        assert executor.validate_output(b"x" * 50, min_size=100) is False
        assert executor.validate_output(b"x" * 150, min_size=100) is True
    
    def test_repr(self):
        """Test string representation."""
        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/test_tool"
            executor = ExternalToolExecutor("test_tool")
            
            repr_str = repr(executor)
            assert "test_tool" in repr_str
            assert "available=True" in repr_str
            assert "/usr/bin/test_tool" in repr_str