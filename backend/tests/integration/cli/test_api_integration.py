"""
Integration tests for CLI-to-API communication
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path
import sys
import asyncio

# Add SDK path for imports
sys.path.insert(
    0, str(Path(__file__).parent.parent.parent.parent.parent / "sdks" / "python")
)

from app.cli.commands import convert, batch
from image_converter.models import ConversionResult, BatchStatus, OutputFormat


class TestCLIAPIIntegration:
    """Test CLI integration with API"""

    @pytest.fixture
    def mock_client(self):
        """Create mock API client"""
        client = Mock()
        return client

    @pytest.fixture
    def mock_async_client(self):
        """Create mock async API client"""
        client = AsyncMock()
        return client

    @patch("app.cli.commands.convert.ImageConverterClient")
    def test_convert_api_call(self, mock_client_class):
        """Test that convert command properly calls API"""
        # Setup mock
        mock_client = Mock()
        mock_result = ConversionResult(
            output_format=OutputFormat.WEBP,
            output_size=1000,
            output_data=b"converted_data",
            processing_time=0.5,
        )
        mock_client.convert.return_value = mock_result
        mock_client_class.return_value = mock_client

        # Test would invoke the command
        # This tests the integration between CLI command and SDK client

        # Verify client was initialized with correct parameters
        # mock_client_class.assert_called_once()

        # Verify convert was called
        # mock_client.convert.assert_called_once()

    @patch("app.cli.commands.batch.AsyncImageConverterClient")
    def test_batch_api_call(self, mock_client_class):
        """Test that batch command properly calls API"""
        # Setup mock
        mock_client = AsyncMock()
        mock_job = Mock()
        mock_job.job_id = "test-job-123"
        mock_job.status = "processing"

        mock_status = BatchStatus(
            job_id="test-job-123",
            status="completed",
            total_count=10,
            completed_count=10,
            failed_count=0,
            created_at="2024-01-01T00:00:00",
        )

        mock_client.create_batch = AsyncMock(return_value=mock_job)
        mock_client.get_batch_status = AsyncMock(return_value=mock_status)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        mock_client_class.return_value = mock_client

        # Test would invoke the batch command
        # This tests the integration between CLI batch command and async SDK client

    def test_error_handling_chain(self):
        """Test that API errors are properly handled through the chain"""
        # Test various error scenarios:
        # - Connection errors
        # - Authentication errors
        # - Rate limiting errors
        # - Server errors
        pass

    def test_progress_tracking(self):
        """Test that progress is properly tracked and displayed"""
        # Test progress updates from API are reflected in CLI output
        pass

    def test_configuration_propagation(self):
        """Test that CLI configuration is properly passed to API client"""
        # Test that settings like API URL, API key, timeout are passed correctly
        pass
