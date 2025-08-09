"""Unit tests for WebSocket security and authentication."""

from typing import Any
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.api.websockets.secure_progress import SecureConnectionManager
from app.core.batch.models import BatchItemStatus, BatchJob, BatchProgress


class TestSecureConnectionManager:
    """Test secure WebSocket connection management."""

    @pytest.fixture
    def manager(self) -> None:
        """Create a SecureConnectionManager instance."""
        return SecureConnectionManager()

    def test_generate_job_token(self, manager) -> None:
        """Test token generation."""
        job_id = "test-job-123"

        # Generate token
        token = manager.generate_job_token(job_id)

        # Verify token format
        assert isinstance(token, str)
        assert len(token) > 20  # URL-safe base64 encoded

        # Verify token is stored
        assert job_id in manager._job_tokens
        assert job_id in manager._token_expiry

        # Verify expiry is set correctly
        expiry = manager._token_expiry[job_id]
        assert expiry > datetime.utcnow()
        assert expiry < datetime.utcnow() + timedelta(hours=25)

    def test_verify_job_token_valid(self, manager) -> None:
        """Test verifying a valid token."""
        job_id = "test-job-123"

        # Generate token
        token = manager.generate_job_token(job_id)

        # Verify token
        assert manager.verify_job_token(job_id, token) is True

    def test_verify_job_token_invalid(self, manager) -> None:
        """Test verifying an invalid token."""
        job_id = "test-job-123"

        # Generate token
        manager.generate_job_token(job_id)

        # Try invalid token
        assert manager.verify_job_token(job_id, "invalid-token") is False
        assert manager.verify_job_token(job_id, None) is False
        assert manager.verify_job_token("wrong-job", "any-token") is False

    def test_verify_job_token_expired(self, manager) -> None:
        """Test verifying an expired token."""
        job_id = "test-job-123"

        # Generate token
        token = manager.generate_job_token(job_id)

        # Manually expire the token
        manager._token_expiry[job_id] = datetime.utcnow() - timedelta(hours=1)

        # Verify token is rejected
        assert manager.verify_job_token(job_id, token) is False

        # Verify token is cleaned up
        assert job_id not in manager._job_tokens
        assert job_id not in manager._token_expiry

    def test_check_rate_limit_within_limit(self, manager) -> None:
        """Test rate limiting within allowed limit."""
        client_ip = "192.168.1.100"

        # First 10 requests should be allowed
        for i in range(10):
            assert manager.check_rate_limit(client_ip) is True

        # 11th request should be denied
        assert manager.check_rate_limit(client_ip) is False

    def test_check_rate_limit_reset(self, manager) -> None:
        """Test rate limit reset after time window."""
        client_ip = "192.168.1.100"

        # Use up rate limit
        for i in range(10):
            manager.check_rate_limit(client_ip)

        # Manually expire the time window
        count, _ = manager._rate_limits[client_ip]
        manager._rate_limits[client_ip] = (
            count,
            datetime.utcnow() - timedelta(minutes=2),
        )

        # Should be allowed again
        assert manager.check_rate_limit(client_ip) is True

    @pytest.mark.asyncio
    async def test_connect_with_authentication(self, manager):
        """Test connecting with valid authentication."""
        job_id = "test-job-123"
        mock_websocket = Mock()
        mock_websocket.accept = AsyncMock()
        mock_websocket.send_json = AsyncMock()
        mock_websocket.close = AsyncMock()

        # Generate token
        token = manager.generate_job_token(job_id)

        # Mock batch service
        with patch("app.api.websockets.secure_progress.batch_service") as mock_service:
            mock_job = Mock(spec=BatchJob)
            mock_service.get_job = AsyncMock(return_value=mock_job)

            # Mock settings
            with patch("app.api.websockets.secure_progress.settings") as mock_settings:
                mock_settings.batch_websocket_auth_enabled = True

                # Connect should succeed
                result = await manager.connect(
                    mock_websocket, job_id, token, "192.168.1.100"
                )
                assert result is True
                mock_websocket.accept.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_invalid_token(self, manager):
        """Test connecting with invalid token."""
        job_id = "test-job-123"
        mock_websocket = Mock()
        mock_websocket.close = AsyncMock()

        # Mock batch service
        with patch("app.api.websockets.secure_progress.batch_service") as mock_service:
            mock_job = Mock(spec=BatchJob)
            mock_service.get_job = AsyncMock(return_value=mock_job)

            # Mock settings
            with patch("app.api.websockets.secure_progress.settings") as mock_settings:
                mock_settings.batch_websocket_auth_enabled = True

                # Connect should fail
                result = await manager.connect(
                    mock_websocket, job_id, "invalid-token", "192.168.1.100"
                )
                assert result is False
                mock_websocket.close.assert_called_once()

                # Check close reason
                call_args = mock_websocket.close.call_args
                assert call_args[1]["reason"] == "Invalid or expired token"

    @pytest.mark.asyncio
    async def test_connect_rate_limited(self, manager):
        """Test connecting when rate limited."""
        job_id = "test-job-123"
        client_ip = "192.168.1.100"

        # Use up rate limit
        for i in range(10):
            manager.check_rate_limit(client_ip)

        mock_websocket = Mock()
        mock_websocket.close = AsyncMock()

        # Connect should fail
        result = await manager.connect(mock_websocket, job_id, None, client_ip)
        assert result is False
        mock_websocket.close.assert_called_once()

        # Check close reason
        call_args = mock_websocket.close.call_args
        assert call_args[1]["reason"] == "Rate limit exceeded"

    @pytest.mark.asyncio
    async def test_connect_invalid_job(self, manager):
        """Test connecting to non-existent job."""
        job_id = "invalid-job"
        mock_websocket = Mock()
        mock_websocket.close = AsyncMock()

        # Mock batch service to return None
        with patch("app.api.websockets.secure_progress.batch_service") as mock_service:
            mock_service.get_job = AsyncMock(return_value=None)

            # Connect should fail
            result = await manager.connect(
                mock_websocket, job_id, None, "192.168.1.100"
            )
            assert result is False
            mock_websocket.close.assert_called_once()

            # Check close reason
            call_args = mock_websocket.close.call_args
            assert call_args[1]["reason"] == "Invalid job ID"

    @pytest.mark.asyncio
    async def test_connect_connection_limit(self, manager):
        """Test connection limit per job."""
        job_id = "test-job-123"
        manager._max_connections_per_job = 2

        # Mock batch service
        with patch("app.api.websockets.secure_progress.batch_service") as mock_service:
            mock_job = Mock(spec=BatchJob)
            mock_service.get_job = AsyncMock(return_value=mock_job)

            # Add 2 existing connections
            manager._connections[job_id] = {Mock(), Mock()}

            # Try to add third connection
            mock_websocket = Mock()
            mock_websocket.close = AsyncMock()

            result = await manager.connect(
                mock_websocket, job_id, None, "192.168.1.100"
            )
            assert result is False
            mock_websocket.close.assert_called_once()

            # Check close reason
            call_args = mock_websocket.close.call_args
            assert call_args[1]["reason"] == "Too many connections"

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens(self, manager):
        """Test cleaning up expired tokens."""
        # Create some tokens
        job1 = "job-1"
        job2 = "job-2"
        job3 = "job-3"

        manager.generate_job_token(job1)
        manager.generate_job_token(job2)
        manager.generate_job_token(job3)

        # Expire some tokens
        manager._token_expiry[job1] = datetime.utcnow() - timedelta(hours=1)
        manager._token_expiry[job3] = datetime.utcnow() - timedelta(minutes=1)

        # Run cleanup
        await manager.cleanup_expired_tokens()

        # Verify expired tokens are removed
        assert job1 not in manager._job_tokens
        assert job1 not in manager._token_expiry
        assert job3 not in manager._job_tokens
        assert job3 not in manager._token_expiry

        # Verify non-expired token remains
        assert job2 in manager._job_tokens
        assert job2 in manager._token_expiry

    @pytest.mark.asyncio
    async def test_broadcast_progress_with_auth(self, manager):
        """Test broadcasting progress updates."""
        job_id = "test-job-123"

        # Create mock connections
        ws1 = Mock()
        ws1.send_json = AsyncMock()
        ws2 = Mock()
        ws2.send_json = AsyncMock()

        manager._connections[job_id] = {ws1, ws2}

        # Create progress update
        progress = BatchProgress(
            job_id=job_id,
            file_index=0,
            filename="test.jpg",
            status=BatchItemStatus.PROCESSING,
            progress=50,
            message=None,
            timestamp=datetime.utcnow(),
        )

        # Broadcast
        await manager.broadcast_progress(progress)

        # Verify both connections received update
        ws1.send_json.assert_called_once()
        ws2.send_json.assert_called_once()

        # Verify message format
        call_args = ws1.send_json.call_args[0][0]
        assert call_args["type"] == "progress"
        assert call_args["job_id"] == job_id
        assert call_args["progress"] == 50
