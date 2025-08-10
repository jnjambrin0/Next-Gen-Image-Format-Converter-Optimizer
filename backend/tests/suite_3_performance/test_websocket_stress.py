"""
Ultra-realistic WebSocket stress tests with authentication and high concurrency.
Tests real-world scenarios with 100+ simultaneous connections.
"""

import pytest
import asyncio
import websockets
import json
import time
import random
import hashlib
from typing import List, Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch
import psutil

from app.api.websockets.secure_progress import SecureConnectionManager
from app.core.batch.models import BatchProgress, BatchItemStatus


class TestWebSocketStress:
    """Test WebSocket functionality under stress conditions."""

    @pytest.fixture
    def secure_manager(self):
        """Create SecureConnectionManager instance."""
        return SecureConnectionManager()

    @pytest.fixture
    async def mock_batch_job(self):
        """Create a mock batch job for testing."""
        return {
            "id": "test-batch-ws-001",
            "total_files": 100,
            "status": "processing",
            "created_at": time.time(),
        }

    async def create_websocket_client(
        self, url: str, token: str = None
    ) -> websockets.WebSocketClientProtocol:
        """Create a WebSocket client connection."""
        if token:
            url = f"{url}?token={token}"
        return await websockets.connect(url, ping_interval=None)

    @pytest.mark.performance
    @pytest.mark.slow
    async def test_100_concurrent_websocket_connections(
        self, secure_manager, mock_batch_job
    ):
        """
        Test handling 100 simultaneous WebSocket connections.

        Simulates: Large team monitoring same batch job simultaneously.
        """
        job_id = mock_batch_job["id"]
        connections = []
        connection_times = []

        # Generate tokens for all connections
        tokens = []
        for i in range(100):
            token = secure_manager.generate_job_token(job_id)
            tokens.append(token)

        # Track connection establishment time
        start_time = time.perf_counter()

        # Create 100 connections concurrently
        async def connect_client(client_id: int, token: str):
            """Connect a single client."""
            try:
                client_start = time.perf_counter()

                # Simulate WebSocket connection (mocked for test)
                ws_mock = AsyncMock()
                ws_mock.state = websockets.protocol.State.OPEN
                ws_mock.closed = asyncio.Future()

                # Register with manager
                if secure_manager.verify_job_token(job_id, token):
                    await secure_manager.connect(ws_mock, job_id, f"client_{client_id}")

                    connection_time = time.perf_counter() - client_start
                    return ws_mock, connection_time
                else:
                    return None, 0
            except Exception as e:
                print(f"Client {client_id} failed: {e}")
                return None, 0

        # Connect all clients
        tasks = [connect_client(i, tokens[i]) for i in range(100)]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Count successful connections
        successful_connections = 0
        for result in results:
            if not isinstance(result, Exception) and result[0] is not None:
                connections.append(result[0])
                connection_times.append(result[1])
                successful_connections += 1

        total_connection_time = time.perf_counter() - start_time

        # Assertions
        assert (
            successful_connections >= 95
        ), f"Too many connection failures: {successful_connections}/100"
        assert (
            total_connection_time < 10
        ), f"Connection establishment too slow: {total_connection_time:.2f}s"

        if connection_times:
            avg_connection_time = sum(connection_times) / len(connection_times)
            assert (
                avg_connection_time < 0.5
            ), f"Average connection time too high: {avg_connection_time:.2f}s"

        # Test broadcasting to all connections
        broadcast_start = time.perf_counter()

        progress = BatchProgress(
            job_id=job_id,
            total_files=100,
            completed_count=50,
            failed_count=2,
            in_progress_count=48,
            items=[],
        )

        # Broadcast progress update
        await secure_manager.broadcast_progress(progress)

        broadcast_time = time.perf_counter() - broadcast_start
        assert broadcast_time < 1.0, f"Broadcasting too slow: {broadcast_time:.2f}s"

        # Cleanup
        for conn in connections:
            if conn:
                await secure_manager.disconnect(conn)

    @pytest.mark.performance
    async def test_websocket_auth_token_validation_stress(self, secure_manager):
        """
        Test token validation under high load.

        Simulates: Many clients attempting to authenticate simultaneously.
        """
        job_ids = [f"job_{i}" for i in range(10)]

        # Generate many tokens
        tokens = {}
        for job_id in job_ids:
            tokens[job_id] = []
            for _ in range(50):  # 50 tokens per job
                token = secure_manager.generate_job_token(job_id)
                tokens[job_id].append(token)

        # Simulate concurrent validation attempts
        validation_tasks = []
        for job_id in job_ids:
            for token in tokens[job_id]:
                validation_tasks.append(
                    asyncio.create_task(
                        asyncio.to_thread(
                            secure_manager.verify_job_token, job_id, token
                        )
                    )
                )

        # Add some invalid token attempts
        for job_id in job_ids:
            for _ in range(10):
                invalid_token = hashlib.sha256(
                    f"invalid_{random.random()}".encode()
                ).hexdigest()
                validation_tasks.append(
                    asyncio.create_task(
                        asyncio.to_thread(
                            secure_manager.verify_job_token, job_id, invalid_token
                        )
                    )
                )

        # Execute all validations
        start_time = time.perf_counter()
        results = await asyncio.gather(*validation_tasks)
        validation_time = time.perf_counter() - start_time

        # Count results
        valid_count = sum(1 for r in results if r is True)
        invalid_count = sum(1 for r in results if r is False)

        # Assertions
        assert valid_count == 500, f"Wrong number of valid tokens: {valid_count}"
        assert invalid_count == 100, f"Wrong number of invalid tokens: {invalid_count}"
        assert validation_time < 5, f"Validation too slow: {validation_time:.2f}s"

    @pytest.mark.performance
    async def test_websocket_rate_limiting_effectiveness(self, secure_manager):
        """
        Test rate limiting prevents abuse.

        Simulates: Malicious client attempting rapid reconnections.
        """
        client_ips = ["192.168.1.100", "192.168.1.101", "10.0.0.50"]

        # Test each IP
        for client_ip in client_ips:
            allowed_count = 0
            blocked_count = 0

            # Attempt 20 connections rapidly
            for i in range(20):
                if secure_manager.check_rate_limit(client_ip):
                    allowed_count += 1
                else:
                    blocked_count += 1

                # Small delay to simulate real connection attempts
                await asyncio.sleep(0.01)

            # Should allow first 10, block the rest
            assert allowed_count == 10, f"Wrong number allowed: {allowed_count}"
            assert blocked_count == 10, f"Wrong number blocked: {blocked_count}"

        # Test rate limit reset
        await asyncio.sleep(61)  # Wait for rate limit window to expire

        # Should allow connections again
        for client_ip in client_ips:
            assert secure_manager.check_rate_limit(client_ip) is True

    @pytest.mark.performance
    @pytest.mark.slow
    async def test_websocket_message_throughput(self, secure_manager, mock_batch_job):
        """
        Test WebSocket message throughput under load.

        Simulates: Rapid progress updates during batch processing.
        """
        job_id = mock_batch_job["id"]

        # Create multiple mock connections
        connections = []
        for i in range(20):
            ws_mock = AsyncMock()
            ws_mock.state = websockets.protocol.State.OPEN
            ws_mock.closed = asyncio.Future()
            ws_mock.send = AsyncMock()

            token = secure_manager.generate_job_token(job_id)
            secure_manager.verify_job_token(job_id, token)
            await secure_manager.connect(ws_mock, job_id, f"client_{i}")
            connections.append(ws_mock)

        # Send many progress updates rapidly
        messages_sent = 0
        start_time = time.perf_counter()

        for i in range(100):  # 100 progress updates
            progress = BatchProgress(
                job_id=job_id,
                total_files=100,
                completed_count=i,
                failed_count=i // 20,
                in_progress_count=100 - i - (i // 20),
                items=[
                    {
                        "index": j,
                        "filename": f"file_{j}.jpg",
                        "status": (
                            BatchItemStatus.COMPLETED
                            if j < i
                            else BatchItemStatus.PENDING
                        ),
                    }
                    for j in range(min(10, i))  # Include last 10 items
                ],
            )

            await secure_manager.broadcast_progress(progress)
            messages_sent += len(connections)  # Each connection gets the message

            # Small delay between updates
            await asyncio.sleep(0.05)

        throughput_time = time.perf_counter() - start_time

        # Calculate throughput
        messages_per_second = messages_sent / throughput_time

        # Assertions
        assert (
            messages_per_second > 100
        ), f"Throughput too low: {messages_per_second:.1f} msg/s"
        assert throughput_time < 10, f"Updates took too long: {throughput_time:.2f}s"

        # Verify all messages were "sent"
        for conn in connections:
            assert conn.send.call_count >= 90, f"Too few messages sent to client"

    @pytest.mark.performance
    async def test_websocket_connection_cleanup(self, secure_manager):
        """
        Test proper cleanup of stale connections.

        Simulates: Clients disconnecting unexpectedly.
        """
        job_id = "cleanup-test-job"

        # Create connections
        connections = []
        for i in range(50):
            ws_mock = AsyncMock()
            ws_mock.state = websockets.protocol.State.OPEN
            ws_mock.closed = asyncio.Future()

            token = secure_manager.generate_job_token(job_id)
            secure_manager.verify_job_token(job_id, token)
            await secure_manager.connect(ws_mock, job_id, f"client_{i}")
            connections.append(ws_mock)

        # Simulate some connections closing unexpectedly
        for i in range(0, 50, 2):  # Every other connection
            connections[i].state = websockets.protocol.State.CLOSED
            connections[i].closed.set_result(None)

        # Trigger cleanup
        await secure_manager.cleanup_stale_connections()

        # Check active connections
        active_count = len(secure_manager.get_active_connections(job_id))
        assert active_count == 25, f"Wrong number of active connections: {active_count}"

        # Disconnect remaining
        for conn in connections[1::2]:  # Odd indices (still connected)
            await secure_manager.disconnect(conn)

        # Verify all cleaned up
        active_count = len(secure_manager.get_active_connections(job_id))
        assert active_count == 0, f"Connections not cleaned up: {active_count}"

    @pytest.mark.performance
    async def test_websocket_memory_stability(self, secure_manager, memory_monitor):
        """
        Test memory stability during extended WebSocket operations.

        Ensures no memory leaks with many connect/disconnect cycles.
        """
        memory_monitor.start()

        # Perform multiple connection cycles
        for cycle in range(10):
            job_id = f"memory-test-{cycle}"
            connections = []

            # Create 20 connections
            for i in range(20):
                ws_mock = AsyncMock()
                ws_mock.state = websockets.protocol.State.OPEN
                ws_mock.closed = asyncio.Future()
                ws_mock.send = AsyncMock()

                token = secure_manager.generate_job_token(job_id)
                secure_manager.verify_job_token(job_id, token)
                await secure_manager.connect(ws_mock, job_id, f"client_{i}")
                connections.append(ws_mock)

            # Send some messages
            for _ in range(10):
                progress = BatchProgress(
                    job_id=job_id,
                    total_files=10,
                    completed_count=5,
                    failed_count=0,
                    in_progress_count=5,
                    items=[],
                )
                await secure_manager.broadcast_progress(progress)

            # Disconnect all
            for conn in connections:
                await secure_manager.disconnect(conn)

            # Sample memory every 2 cycles
            if cycle % 2 == 0:
                memory_monitor.sample()

        # Check memory stability
        memory_monitor.assert_stable(max_growth_mb=30)

    @pytest.mark.performance
    async def test_websocket_reconnection_handling(self, secure_manager):
        """
        Test handling of client reconnections.

        Simulates: Clients with unstable connections reconnecting frequently.
        """
        job_id = "reconnect-test"
        client_id = "unstable-client"

        reconnection_times = []

        for attempt in range(20):  # 20 reconnection attempts
            start_time = time.perf_counter()

            # Generate new token for reconnection
            token = secure_manager.generate_job_token(job_id)

            # Verify token
            assert secure_manager.verify_job_token(job_id, token) is True

            # Create connection
            ws_mock = AsyncMock()
            ws_mock.state = websockets.protocol.State.OPEN
            ws_mock.closed = asyncio.Future()

            await secure_manager.connect(ws_mock, job_id, client_id)

            # Simulate some activity
            await asyncio.sleep(0.1)

            # Disconnect
            await secure_manager.disconnect(ws_mock)

            reconnection_time = time.perf_counter() - start_time
            reconnection_times.append(reconnection_time)

            # Small delay between reconnections
            await asyncio.sleep(0.05)

        # Verify all reconnections succeeded
        assert len(reconnection_times) == 20

        # Check reconnection performance
        avg_reconnection_time = sum(reconnection_times) / len(reconnection_times)
        assert (
            avg_reconnection_time < 0.5
        ), f"Reconnection too slow: {avg_reconnection_time:.3f}s"

    @pytest.mark.performance
    async def test_websocket_burst_traffic_handling(
        self, secure_manager, mock_batch_job
    ):
        """
        Test handling of burst traffic patterns.

        Simulates: Sudden spike in activity (e.g., batch job starts).
        """
        job_id = mock_batch_job["id"]

        # Create connections
        connections = []
        for i in range(30):
            ws_mock = AsyncMock()
            ws_mock.state = websockets.protocol.State.OPEN
            ws_mock.closed = asyncio.Future()
            ws_mock.send = AsyncMock()

            token = secure_manager.generate_job_token(job_id)
            secure_manager.verify_job_token(job_id, token)
            await secure_manager.connect(ws_mock, job_id, f"client_{i}")
            connections.append(ws_mock)

        # Simulate burst of updates
        burst_start = time.perf_counter()

        # Send 50 updates in rapid succession
        burst_tasks = []
        for i in range(50):
            progress = BatchProgress(
                job_id=job_id,
                total_files=100,
                completed_count=i * 2,
                failed_count=0,
                in_progress_count=100 - i * 2,
                items=[],
            )

            # Don't await, collect tasks
            task = asyncio.create_task(secure_manager.broadcast_progress(progress))
            burst_tasks.append(task)

        # Wait for all broadcasts to complete
        await asyncio.gather(*burst_tasks)

        burst_time = time.perf_counter() - burst_start

        # Should handle burst efficiently
        assert burst_time < 5, f"Burst handling too slow: {burst_time:.2f}s"

        # Verify all clients received messages
        for conn in connections:
            # Each client should have received most messages
            assert (
                conn.send.call_count >= 45
            ), f"Client missed too many messages during burst"
