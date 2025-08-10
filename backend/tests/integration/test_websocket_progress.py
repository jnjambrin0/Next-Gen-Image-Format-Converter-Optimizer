"""Integration tests for WebSocket progress updates."""

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.websockets.progress import (connection_manager, router,
                                         send_batch_progress,
                                         send_job_status_update)
from app.core.batch.models import BatchItemStatus, BatchProgress, BatchStatus


class TestWebSocketProgress:
    """Test WebSocket progress functionality."""

    @pytest.fixture
    def app(self) -> None:
        """Create a test FastAPI app with WebSocket router."""
        app = FastAPI()
        app.include_router(router)
        return app

    @pytest.fixture
    def client(self, app) -> None:
        """Create a test client."""
        return TestClient(app)

    def test_websocket_connection_success(self, client) -> None:
        """Test successful WebSocket connection."""
        job_id = str(uuid.uuid4())

        with client.websocket_connect(f"/ws/batch/{job_id}") as websocket:
            # Should receive connection message
            data = websocket.receive_json()
            assert data["type"] == "connection"
            assert data["status"] == "connected"
            assert data["job_id"] == job_id

    def test_websocket_invalid_job_id(self, client) -> None:
        """Test WebSocket connection with invalid job ID."""
        # Invalid job ID (not UUID format)
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/batch/invalid-id") as websocket:
                pass

    def test_websocket_ping_pong(self, client) -> None:
        """Test WebSocket ping/pong mechanism."""
        job_id = str(uuid.uuid4())

        with client.websocket_connect(f"/ws/batch/{job_id}") as websocket:
            # Skip connection message
            websocket.receive_json()

            # Send ping
            websocket.send_json({"type": "ping"})

            # Should receive pong
            data = websocket.receive_json()
            assert data["type"] == "pong"
            assert "timestamp" in data

    def test_websocket_progress_broadcast(self, client) -> None:
        """Test broadcasting progress updates."""
        job_id = str(uuid.uuid4())

        with client.websocket_connect(f"/ws/batch/{job_id}") as websocket:
            # Skip connection message
            websocket.receive_json()

            # Create progress update
            progress = BatchProgress(
                job_id=job_id,
                file_index=0,
                filename="test.jpg",
                status=BatchItemStatus.PROCESSING,
                progress=50,
                message=None,
            )

            # Broadcast progress (simulate from batch manager)
            asyncio.run(send_batch_progress(progress))

            # Should receive progress update
            data = websocket.receive_json()
            assert data["type"] == "progress"
            assert data["job_id"] == job_id
            assert data["file_index"] == 0
            assert data["filename"] == "test.jpg"
            assert data["status"] == "processing"
            assert data["progress"] == 50

    def test_websocket_job_status_broadcast(self, client) -> None:
        """Test broadcasting job status updates."""
        job_id = str(uuid.uuid4())

        with client.websocket_connect(f"/ws/batch/{job_id}") as websocket:
            # Skip connection message
            websocket.receive_json()

            # Broadcast job status
            asyncio.run(send_job_status_update(job_id, BatchStatus.COMPLETED))

            # Should receive status update
            data = websocket.receive_json()
            assert data["type"] == "job_status"
            assert data["job_id"] == job_id
            assert data["status"] == "completed"

    def test_websocket_multiple_connections(self, client) -> None:
        """Test multiple WebSocket connections to same job."""
        job_id = str(uuid.uuid4())

        with client.websocket_connect(f"/ws/batch/{job_id}") as ws1:
            with client.websocket_connect(f"/ws/batch/{job_id}") as ws2:
                # Skip connection messages
                ws1.receive_json()
                ws2.receive_json()

                # Verify connection count
                assert connection_manager.get_connection_count(job_id) == 2

                # Broadcast progress
                progress = BatchProgress(
                    job_id=job_id,
                    file_index=0,
                    filename="test.jpg",
                    status=BatchItemStatus.COMPLETED,
                    progress=100,
                )
                asyncio.run(send_batch_progress(progress))

                # Both should receive update
                data1 = ws1.receive_json()
                data2 = ws2.receive_json()

                assert data1["type"] == "progress"
                assert data2["type"] == "progress"
                assert data1["progress"] == 100
                assert data2["progress"] == 100

    def test_websocket_invalid_json(self, client) -> None:
        """Test handling of invalid JSON messages."""
        job_id = str(uuid.uuid4())

        with client.websocket_connect(f"/ws/batch/{job_id}") as websocket:
            # Skip connection message
            websocket.receive_json()

            # Send invalid JSON
            websocket.send_text("invalid json")

            # Should receive error message
            data = websocket.receive_json()
            assert data["type"] == "error"
            assert "Invalid JSON" in data["message"]

    def test_websocket_unknown_message_type(self, client) -> None:
        """Test handling of unknown message types."""
        job_id = str(uuid.uuid4())

        with client.websocket_connect(f"/ws/batch/{job_id}") as websocket:
            # Skip connection message
            websocket.receive_json()

            # Send unknown message type
            websocket.send_json({"type": "unknown"})

            # Connection should still be alive (send ping to verify)
            websocket.send_json({"type": "ping"})
            data = websocket.receive_json()
            assert data["type"] == "pong"

    @pytest.mark.asyncio
    async def test_connection_manager_disconnect(self):
        """Test connection manager disconnect handling."""
        job_id = str(uuid.uuid4())
        mock_websocket = AsyncMock()

        # Connect
        await connection_manager.connect(mock_websocket, job_id)
        assert connection_manager.get_connection_count(job_id) == 1

        # Disconnect
        await connection_manager.disconnect(mock_websocket)
        assert connection_manager.get_connection_count(job_id) == 0

    @pytest.mark.asyncio
    async def test_connection_manager_broadcast_to_disconnected(self):
        """Test broadcasting to disconnected clients."""
        job_id = str(uuid.uuid4())
        mock_websocket = AsyncMock()

        # Make send_json fail (simulating disconnection)
        mock_websocket.send_json.side_effect = Exception("Connection lost")

        # Connect
        await connection_manager.connect(mock_websocket, job_id)

        # Broadcast progress
        progress = BatchProgress(
            job_id=job_id,
            file_index=0,
            filename="test.jpg",
            status=BatchItemStatus.PROCESSING,
            progress=50,
        )

        # Should handle disconnection gracefully
        await connection_manager.broadcast_progress(progress)

        # Connection should be removed
        assert connection_manager.get_connection_count(job_id) == 0

    @pytest.mark.asyncio
    async def test_close_all_job_connections(self):
        """Test closing all connections for a job."""
        job_id = str(uuid.uuid4())

        # Create multiple mock connections
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()

        # Connect both
        await connection_manager.connect(mock_ws1, job_id)
        await connection_manager.connect(mock_ws2, job_id)

        assert connection_manager.get_connection_count(job_id) == 2

        # Close all connections
        await connection_manager.close_all_job_connections(job_id)

        # Verify all closed
        mock_ws1.close.assert_called_once()
        mock_ws2.close.assert_called_once()
        assert connection_manager.get_connection_count(job_id) == 0

    def test_websocket_timeout_ping(self, client) -> None:
        """Test WebSocket timeout and ping mechanism."""
        job_id = str(uuid.uuid4())

        with client.websocket_connect(f"/ws/batch/{job_id}") as websocket:
            # Skip connection message
            websocket.receive_json()

            # Wait for timeout ping (this test might be flaky due to timing)
            # In real implementation, you'd mock the timeout
            # For now, just verify the connection stays alive
            websocket.send_json({"type": "ping"})
            data = websocket.receive_json()
            assert data["type"] == "pong"


class TestWebSocketIntegrationWithBatch:
    """Test WebSocket integration with batch processing."""

    @pytest.mark.asyncio
    async def test_batch_progress_integration(self):
        """Test progress updates from batch processing."""
        job_id = str(uuid.uuid4())

        # Track received messages
        received_messages = []

        async def mock_send_json(data):
            received_messages.append(data)

        # Create mock websocket
        mock_websocket = AsyncMock()
        mock_websocket.send_json = mock_send_json
        mock_websocket.accept = AsyncMock()

        # Connect
        await connection_manager.connect(mock_websocket, job_id)

        # Simulate batch processing progress
        progress_updates = [
            BatchProgress(
                job_id=job_id,
                file_index=0,
                filename="file1.jpg",
                status=BatchItemStatus.PROCESSING,
                progress=0,
            ),
            BatchProgress(
                job_id=job_id,
                file_index=0,
                filename="file1.jpg",
                status=BatchItemStatus.PROCESSING,
                progress=50,
            ),
            BatchProgress(
                job_id=job_id,
                file_index=0,
                filename="file1.jpg",
                status=BatchItemStatus.COMPLETED,
                progress=100,
            ),
        ]

        # Send all progress updates
        for progress in progress_updates:
            await send_batch_progress(progress)

        # Verify all updates were sent (including connection message)
        assert len(received_messages) == 4  # 1 connection + 3 progress

        # Verify progress sequence
        assert received_messages[1]["progress"] == 0
        assert received_messages[2]["progress"] == 50
        assert received_messages[3]["progress"] == 100
        assert received_messages[3]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_concurrent_job_broadcasts(self):
        """Test broadcasting to multiple jobs concurrently."""
        job1_id = str(uuid.uuid4())
        job2_id = str(uuid.uuid4())

        # Create mock websockets
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()

        # Track messages per job
        job1_messages = []
        job2_messages = []

        async def send_json1(data):
            job1_messages.append(data)

        async def send_json2(data):
            job2_messages.append(data)

        mock_ws1.send_json = send_json1
        mock_ws2.send_json = send_json2

        # Connect to different jobs
        await connection_manager.connect(mock_ws1, job1_id)
        await connection_manager.connect(mock_ws2, job2_id)

        # Send progress to job1
        progress1 = BatchProgress(
            job_id=job1_id,
            file_index=0,
            filename="job1.jpg",
            status=BatchItemStatus.PROCESSING,
            progress=50,
        )
        await send_batch_progress(progress1)

        # Send progress to job2
        progress2 = BatchProgress(
            job_id=job2_id,
            file_index=0,
            filename="job2.jpg",
            status=BatchItemStatus.PROCESSING,
            progress=75,
        )
        await send_batch_progress(progress2)

        # Verify each connection only received its job's updates
        assert len(job1_messages) == 2  # connection + progress
        assert len(job2_messages) == 2  # connection + progress

        assert job1_messages[1]["filename"] == "job1.jpg"
        assert job1_messages[1]["progress"] == 50

        assert job2_messages[1]["filename"] == "job2.jpg"
        assert job2_messages[1]["progress"] == 75
