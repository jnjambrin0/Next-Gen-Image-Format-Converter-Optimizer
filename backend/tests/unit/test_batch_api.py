"""Unit tests for batch processing API endpoints."""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from fastapi import UploadFile, HTTPException
from fastapi.testclient import TestClient
from io import BytesIO
import uuid

from app.api.routes.batch import (
    validate_batch_request,
    router,
)
from app.core.batch.models import (
    BatchJob,
    BatchItem,
    BatchStatus,
    BatchItemStatus,
    BatchCreateResponse,
    BatchStatusResponse,
)
from app.config import settings
from app.main import app


class TestBatchValidation:
    """Test batch request validation."""

    def test_validate_batch_request_no_files(self):
        """Test validation fails with no files."""
        with pytest.raises(HTTPException) as exc_info:
            validate_batch_request([], "webp")
        
        assert exc_info.value.status_code == 400
        assert "No files provided" in str(exc_info.value.detail)

    def test_validate_batch_request_too_many_files(self):
        """Test validation fails with too many files."""
        files = [Mock(spec=UploadFile) for _ in range(settings.MAX_BATCH_SIZE + 1)]
        
        with pytest.raises(HTTPException) as exc_info:
            validate_batch_request(files, "webp")
        
        assert exc_info.value.status_code == 400
        assert f"Maximum {settings.MAX_BATCH_SIZE} files" in str(exc_info.value.detail)

    def test_validate_batch_request_invalid_format(self):
        """Test validation fails with invalid output format."""
        files = [Mock(spec=UploadFile)]
        
        with pytest.raises(HTTPException) as exc_info:
            validate_batch_request(files, "invalid_format")
        
        assert exc_info.value.status_code == 400
        assert "Invalid output format" in str(exc_info.value.detail)

    def test_validate_batch_request_file_too_large(self):
        """Test validation fails with file too large."""
        mock_file = Mock(spec=UploadFile)
        mock_file.filename = "test.jpg"
        mock_file.size = settings.max_file_size + 1
        
        with pytest.raises(HTTPException) as exc_info:
            validate_batch_request([mock_file], "webp")
        
        assert exc_info.value.status_code == 413
        assert "File too large" in str(exc_info.value.detail)

    def test_validate_batch_request_no_filename(self):
        """Test validation fails with missing filename."""
        mock_file = Mock(spec=UploadFile)
        mock_file.filename = None
        mock_file.size = 1000
        
        with pytest.raises(HTTPException) as exc_info:
            validate_batch_request([mock_file], "webp")
        
        assert exc_info.value.status_code == 400
        assert "has no filename" in str(exc_info.value.detail)

    def test_validate_batch_request_invalid_extension(self):
        """Test validation fails with invalid file extension."""
        mock_file = Mock(spec=UploadFile)
        mock_file.filename = "test.txt"
        mock_file.size = 1000
        
        with pytest.raises(HTTPException) as exc_info:
            validate_batch_request([mock_file], "webp")
        
        assert exc_info.value.status_code == 400
        assert "Unsupported file type" in str(exc_info.value.detail)

    def test_validate_batch_request_total_size_exceeded(self):
        """Test validation fails when total size exceeds limit."""
        # Create files that individually are OK but together exceed limit
        file_size = settings.max_file_size // 2
        num_files = (settings.MAX_BATCH_SIZE * settings.max_file_size // file_size) + 1
        
        files = []
        for i in range(min(num_files, settings.MAX_BATCH_SIZE)):
            mock_file = Mock(spec=UploadFile)
            mock_file.filename = f"test{i}.jpg"
            mock_file.size = file_size
            files.append(mock_file)
        
        with pytest.raises(HTTPException) as exc_info:
            validate_batch_request(files, "webp")
        
        assert exc_info.value.status_code == 413
        assert "Total batch size exceeds" in str(exc_info.value.detail)

    def test_validate_batch_request_success(self):
        """Test successful validation."""
        mock_file1 = Mock(spec=UploadFile)
        mock_file1.filename = "test1.jpg"
        mock_file1.size = 1000
        
        mock_file2 = Mock(spec=UploadFile)
        mock_file2.filename = "test2.png"
        mock_file2.size = 2000
        
        files = [mock_file1, mock_file2]
        
        # Should not raise any exception
        validate_batch_request(files, "webp")


class TestBatchAPIEndpoints:
    """Test batch API endpoints using TestClient."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    @pytest.mark.asyncio
    async def test_create_batch_job_endpoint(self, client):
        """Test batch job creation via API."""
        # Mock the batch service
        with patch('app.api.routes.batch.batch_service') as mock_service:
            # Create mock batch job
            mock_job = BatchJob(
                job_id="test-job-id",
                total_files=2,
                settings={"output_format": "webp"},
                items=[
                    BatchItem(file_index=0, filename="test1.jpg", status=BatchItemStatus.PENDING),
                    BatchItem(file_index=1, filename="test2.png", status=BatchItemStatus.PENDING)
                ]
            )
            mock_service.create_batch_job = AsyncMock(return_value=mock_job)
            
            # Create test files
            files = [
                ("files", ("test1.jpg", b"fake image 1", "image/jpeg")),
                ("files", ("test2.png", b"fake image 2", "image/png"))
            ]
            
            response = client.post(
                "/api/batch/",
                data={"output_format": "webp"},
                files=files
            )
            
            assert response.status_code == 202
            data = response.json()
            assert data["job_id"] == "test-job-id"
            assert data["total_files"] == 2
            assert data["status"] == "pending"
    
    @pytest.mark.asyncio
    async def test_get_batch_status_endpoint(self, client):
        """Test getting batch job status via API."""
        with patch('app.api.routes.batch.batch_service') as mock_service:
            # Create mock batch job
            mock_job = BatchJob(
                job_id="test-job-id",
                total_files=2,
                settings={"output_format": "webp"},
                status=BatchStatus.PROCESSING,
                completed_files=1,
                failed_files=0,
                items=[
                    BatchItem(file_index=0, filename="test1.jpg", status=BatchItemStatus.COMPLETED),
                    BatchItem(file_index=1, filename="test2.png", status=BatchItemStatus.PROCESSING)
                ]
            )
            mock_service.get_job = AsyncMock(return_value=mock_job)
            
            response = client.get("/api/batch/test-job-id/status")
            
            assert response.status_code == 200
            data = response.json()
            assert data["job_id"] == "test-job-id"
            assert data["status"] == "processing"
            assert data["completed_files"] == 1
    
    @pytest.mark.asyncio
    async def test_cancel_batch_job_endpoint(self, client):
        """Test cancelling batch job via API."""
        with patch('app.api.routes.batch.batch_service') as mock_service:
            # Create mock batch job
            mock_job = BatchJob(
                job_id="test-job-id",
                total_files=2,
                settings={"output_format": "webp"},
                status=BatchStatus.PROCESSING,
                items=[]
            )
            mock_service.get_job = AsyncMock(return_value=mock_job)
            mock_service.cancel_job = AsyncMock()
            
            response = client.delete("/api/batch/test-job-id")
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "cancelled"
            mock_service.cancel_job.assert_called_once_with("test-job-id")
    
    @pytest.mark.asyncio
    async def test_cancel_batch_item_endpoint(self, client):
        """Test cancelling specific item via API."""
        with patch('app.api.routes.batch.batch_service') as mock_service:
            # Create mock batch job
            mock_job = BatchJob(
                job_id="test-job-id",
                total_files=3,
                settings={"output_format": "webp"},
                items=[
                    BatchItem(file_index=0, filename="test1.jpg", status=BatchItemStatus.COMPLETED),
                    BatchItem(file_index=1, filename="test2.png", status=BatchItemStatus.PROCESSING),
                    BatchItem(file_index=2, filename="test3.jpg", status=BatchItemStatus.PENDING)
                ]
            )
            mock_service.get_job = AsyncMock(return_value=mock_job)
            mock_service.cancel_job_item = AsyncMock()
            
            response = client.delete("/api/batch/test-job-id/items/1")
            
            assert response.status_code == 200
            data = response.json()
            assert data["file_index"] == 1
            assert data["status"] == "cancelled"
            mock_service.cancel_job_item.assert_called_once_with("test-job-id", 1)
    
    @pytest.mark.asyncio
    async def test_download_batch_results_endpoint(self, client):
        """Test downloading batch results via API."""
        with patch('app.api.routes.batch.batch_service') as mock_service:
            # Create mock completed job
            mock_job = BatchJob(
                job_id="test-job-id",
                total_files=2,
                settings={"output_format": "webp"},
                status=BatchStatus.COMPLETED,
                completed_files=2,
                items=[]
            )
            mock_service.get_job = AsyncMock(return_value=mock_job)
            mock_service.get_download_zip = AsyncMock(return_value=b"fake zip content")
            
            response = client.get("/api/batch/test-job-id/download")
            
            assert response.status_code == 200
            assert response.headers["content-type"] == "application/zip"
            assert b"fake zip content" in response.content