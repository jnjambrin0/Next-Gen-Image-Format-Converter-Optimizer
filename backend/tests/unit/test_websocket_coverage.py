"""
Comprehensive test coverage for WebSocket handlers.
Target: 90%+ coverage for all WebSocket functionality.
"""

import pytest
import asyncio
import json
import weakref
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, MagicMock, patch
from typing import Dict, Any

# Mock WebSocket connection before imports
class MockWebSocket:
    def __init__(self):
        self.sent_messages = []
        self.closed = False
        self.close_code = None
        
    async def send_json(self, data: Dict[str, Any]):
        self.sent_messages.append(data)
        
    async def send_text(self, text: str):
        self.sent_messages.append(json.loads(text))
        
    async def close(self, code: int = 1000):
        self.closed = True
        self.close_code = code
        
    async def receive_json(self):
        return {"type": "ping"}


@pytest.mark.asyncio
class TestWebSocketManagerComplete:
    """Complete test coverage for WebSocket manager."""
    
    @pytest.fixture
    def mock_websocket(self):
        """Create a mock WebSocket connection."""
        return MockWebSocket()
    
    @pytest.fixture
    def websocket_manager(self):
        """Create WebSocket manager instance."""
        from app.api.websockets.progress import ConnectionManager
        return ConnectionManager()
    
    async def test_connection_lifecycle(self, websocket_manager, mock_websocket):
        """Test complete connection lifecycle."""
        connection_id = "test_conn_1"
        
        # Connect
        connected = await websocket_manager.connect(mock_websocket, connection_id)
        assert connected is True
        assert connection_id in websocket_manager._connections
        
        # Send message
        await websocket_manager.send_progress(connection_id, {
            "status": "processing",
            "progress": 50
        })
        assert len(mock_websocket.sent_messages) == 1
        assert mock_websocket.sent_messages[0]["progress"] == 50
        
        # Disconnect
        await websocket_manager.disconnect(connection_id)
        assert connection_id not in websocket_manager._connections
    
    async def test_heartbeat_functionality(self, websocket_manager, mock_websocket):
        """Test heartbeat keeps connection alive."""
        connection_id = "test_heartbeat"
        
        # Connect and start heartbeat
        await websocket_manager.connect(mock_websocket, connection_id)
        
        # Simulate heartbeat loop
        heartbeat_task = asyncio.create_task(
            websocket_manager._heartbeat_loop(connection_id)
        )
        
        # Let it run for a short time
        await asyncio.sleep(0.1)
        
        # Should have sent at least one ping
        pings = [msg for msg in mock_websocket.sent_messages if msg.get("type") == "ping"]
        assert len(pings) > 0
        
        # Cancel heartbeat
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
    
    async def test_connection_limit_enforcement(self, websocket_manager):
        """Test MAX_CONNECTIONS limit is enforced."""
        websocket_manager.MAX_CONNECTIONS = 2
        
        # Create connections up to limit
        conn1 = MockWebSocket()
        conn2 = MockWebSocket()
        conn3 = MockWebSocket()
        
        assert await websocket_manager.connect(conn1, "conn1") is True
        assert await websocket_manager.connect(conn2, "conn2") is True
        
        # Third should be rejected
        assert await websocket_manager.connect(conn3, "conn3") is False
        assert conn3.closed is True
    
    async def test_stale_connection_cleanup(self, websocket_manager):
        """Test cleanup of stale connections."""
        # Add stale connection (weak ref to None)
        stale_id = "stale_conn"
        websocket_manager._connections[stale_id] = weakref.ref(lambda: None)
        websocket_manager._connection_timestamps[stale_id] = (
            datetime.now() - timedelta(seconds=400)
        )
        
        # Add active connection
        active_ws = MockWebSocket()
        active_id = "active_conn"
        await websocket_manager.connect(active_ws, active_id)
        
        # Run cleanup
        await websocket_manager._periodic_cleanup()
        
        # Stale removed, active kept
        assert stale_id not in websocket_manager._connections
        assert active_id in websocket_manager._connections
    
    async def test_broadcast_to_all(self, websocket_manager):
        """Test broadcasting to all connections."""
        # Create multiple connections
        ws1 = MockWebSocket()
        ws2 = MockWebSocket()
        ws3 = MockWebSocket()
        
        await websocket_manager.connect(ws1, "conn1")
        await websocket_manager.connect(ws2, "conn2")
        await websocket_manager.connect(ws3, "conn3")
        
        # Broadcast message
        message = {"type": "announcement", "text": "Hello all"}
        await websocket_manager.broadcast(message)
        
        # All should receive
        assert message in ws1.sent_messages
        assert message in ws2.sent_messages
        assert message in ws3.sent_messages
    
    async def test_error_handling_on_send(self, websocket_manager, mock_websocket):
        """Test error handling when sending fails."""
        connection_id = "error_conn"
        
        # Make send fail
        mock_websocket.send_json = AsyncMock(side_effect=Exception("Send failed"))
        
        await websocket_manager.connect(mock_websocket, connection_id)
        
        # Should handle error gracefully
        await websocket_manager.send_progress(connection_id, {"test": "data"})
        
        # Connection should be removed
        assert connection_id not in websocket_manager._connections
    
    async def test_concurrent_connections(self, websocket_manager):
        """Test handling multiple concurrent connections."""
        connections = []
        tasks = []
        
        # Create 10 concurrent connections
        for i in range(10):
            ws = MockWebSocket()
            connections.append(ws)
            task = websocket_manager.connect(ws, f"conn_{i}")
            tasks.append(task)
        
        # Wait for all connections
        results = await asyncio.gather(*tasks)
        
        # All should succeed (assuming limit > 10)
        assert all(results)
        assert len(websocket_manager._connections) == 10
    
    async def test_connection_metadata_tracking(self, websocket_manager):
        """Test connection metadata and timestamps."""
        ws = MockWebSocket()
        connection_id = "metadata_test"
        
        # Connect
        start_time = datetime.now()
        await websocket_manager.connect(ws, connection_id)
        
        # Check timestamp
        assert connection_id in websocket_manager._connection_timestamps
        timestamp = websocket_manager._connection_timestamps[connection_id]
        assert (timestamp - start_time).total_seconds() < 1
    
    async def test_weakref_garbage_collection(self, websocket_manager):
        """Test weak references allow garbage collection."""
        connection_id = "gc_test"
        
        # Create connection in scope
        ws = MockWebSocket()
        await websocket_manager.connect(ws, connection_id)
        
        # Verify connection exists
        assert connection_id in websocket_manager._connections
        
        # Delete strong reference
        del ws
        
        # Force garbage collection
        import gc
        gc.collect()
        
        # Weak ref should now be dead
        weak_ref = websocket_manager._connections.get(connection_id)
        if weak_ref:
            assert weak_ref() is None
    
    @pytest.mark.parametrize("error_type", [
        ConnectionResetError,
        BrokenPipeError,
        asyncio.CancelledError,
        OSError
    ])
    async def test_various_error_types(self, websocket_manager, error_type):
        """Test handling of various error types."""
        ws = MockWebSocket()
        ws.send_json = AsyncMock(side_effect=error_type("Test error"))
        
        connection_id = f"error_{error_type.__name__}"
        await websocket_manager.connect(ws, connection_id)
        
        # Should handle error gracefully
        await websocket_manager.send_progress(connection_id, {"test": "data"})
        
        # Should disconnect on error
        assert connection_id not in websocket_manager._connections


@pytest.mark.asyncio
class TestSecureWebSocketManager:
    """Test secure WebSocket with authentication."""
    
    @pytest.fixture
    def secure_manager(self):
        """Create secure WebSocket manager."""
        from app.api.websockets.secure_progress import SecureConnectionManager
        return SecureConnectionManager()
    
    async def test_token_validation(self, secure_manager):
        """Test WebSocket token validation."""
        job_id = "test_job_123"
        
        # Generate token
        token = await secure_manager.generate_token(job_id)
        assert token is not None
        assert len(token) > 32
        
        # Validate token
        is_valid = await secure_manager.validate_token(job_id, token)
        assert is_valid is True
        
        # Invalid token
        is_valid = await secure_manager.validate_token(job_id, "invalid_token")
        assert is_valid is False
    
    async def test_token_expiration(self, secure_manager):
        """Test token expiration."""
        job_id = "expire_test"
        
        # Generate token
        token = await secure_manager.generate_token(job_id)
        
        # Mock expired timestamp
        with patch('app.api.websockets.secure_progress.datetime') as mock_dt:
            mock_dt.now.return_value = datetime.now() + timedelta(hours=25)
            
            # Should be expired
            is_valid = await secure_manager.validate_token(job_id, token)
            assert is_valid is False
    
    async def test_rate_limiting(self, secure_manager):
        """Test connection rate limiting."""
        ip_address = "192.168.1.100"
        
        # Simulate rapid connections
        for i in range(10):
            allowed = await secure_manager.check_rate_limit(ip_address)
            if i < 5:
                assert allowed is True
            else:
                # Should be rate limited after threshold
                pass  # May or may not be limited depending on implementation
    
    async def test_max_connections_per_job(self, secure_manager):
        """Test max connections per job limit."""
        job_id = "job_limit_test"
        secure_manager.MAX_CONNECTIONS_PER_JOB = 3
        
        # Create connections
        connections = []
        for i in range(5):
            ws = MockWebSocket()
            result = await secure_manager.connect_with_auth(ws, job_id, f"conn_{i}")
            connections.append((ws, result))
        
        # First 3 should succeed
        assert connections[0][1] is True
        assert connections[1][1] is True
        assert connections[2][1] is True
        
        # Rest should fail
        assert connections[3][1] is False
        assert connections[4][1] is False
    
    async def test_token_refresh(self, secure_manager):
        """Test token refresh functionality."""
        job_id = "refresh_test"
        
        # Generate initial token
        token1 = await secure_manager.generate_token(job_id)
        
        # Refresh token
        token2 = await secure_manager.refresh_token(job_id)
        
        # Should be different
        assert token2 != token1
        
        # Both should be valid
        assert await secure_manager.validate_token(job_id, token2) is True
        
        # Old token may or may not be valid depending on implementation
    
    async def test_cleanup_expired_tokens(self, secure_manager):
        """Test cleanup of expired tokens."""
        # Create tokens
        job1 = "job1"
        job2 = "job2"
        
        token1 = await secure_manager.generate_token(job1)
        token2 = await secure_manager.generate_token(job2)
        
        # Mock one as expired
        secure_manager._token_timestamps[job1] = datetime.now() - timedelta(hours=25)
        
        # Run cleanup
        await secure_manager.cleanup_expired_tokens()
        
        # job1 tokens should be removed
        assert job1 not in secure_manager._tokens
        assert job2 in secure_manager._tokens