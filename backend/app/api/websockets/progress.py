"""WebSocket endpoint for batch processing progress updates."""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, Optional, Set, Tuple

from fastapi import Query, WebSocket, WebSocketDisconnect, status
from fastapi.routing import APIRouter

from app.config import settings
from app.core.batch.models import BatchProgress, BatchStatus
from app.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for batch progress updates."""

    def __init__(self) -> None:
        """Initialize the connection manager."""
        # Map job_id to set of active connections
        self._connections: Dict[str, Set[WebSocket]] = {}
        # Map connection to job_id for cleanup
        self._connection_jobs: Dict[WebSocket, str] = {}
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

        self.logger = get_logger(__name__)

    async def connect(self, websocket: WebSocket, job_id: str) -> bool:
        """Accept a new WebSocket connection for a job.

        Args:
            websocket: WebSocket connection
            job_id: Batch job ID to subscribe to

        Returns:
            True if connected successfully
        """
        try:
            await websocket.accept()

            async with self._lock:
                # Add connection to job
                if job_id not in self._connections:
                    self._connections[job_id] = set()
                self._connections[job_id].add(websocket)

                # Track connection's job
                self._connection_jobs[websocket] = job_id

            self.logger.info(f"WebSocket connected for job {job_id}")

            # Send initial connection message
            await self._send_json(
                websocket,
                {
                    "type": "connection",
                    "status": "connected",
                    "job_id": job_id,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            return True

        except Exception as e:
            self.logger.error(f"Failed to connect WebSocket for job {job_id}: {e}")
            return False

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection.

        Args:
            websocket: WebSocket connection to remove
        """
        async with self._lock:
            # Get job ID for this connection
            job_id = self._connection_jobs.pop(websocket, None)

            if job_id and job_id in self._connections:
                self._connections[job_id].discard(websocket)

                # Clean up empty job entries
                if not self._connections[job_id]:
                    del self._connections[job_id]

        self.logger.info(f"WebSocket disconnected for job {job_id}")

    async def broadcast_progress(self, progress: BatchProgress) -> None:
        """Broadcast progress update to all connections for a job.

        Args:
            progress: Progress update to broadcast
        """
        job_id = progress.job_id

        # Get connections for this job
        async with self._lock:
            connections = self._connections.get(job_id, set()).copy()

        if not connections:
            return

        # Prepare message
        message = {
            "type": "progress",
            "job_id": progress.job_id,
            "file_index": progress.file_index,
            "filename": progress.filename,
            "status": progress.status.value,
            "progress": progress.progress,
            "message": progress.message,
            "timestamp": progress.timestamp.isoformat(),
        }

        # Send to all connections
        disconnected = []
        for websocket in connections:
            try:
                await self._send_json(websocket, message)
            except Exception as e:
                self.logger.warning(f"Failed to send progress to connection: {e}")
                disconnected.append(websocket)

        # Clean up disconnected connections
        for websocket in disconnected:
            await self.disconnect(websocket)

    async def broadcast_job_status(self, job_id: str, status: BatchStatus) -> None:
        """Broadcast job status update to all connections.

        Args:
            job_id: Job ID
            status: New job status
        """
        # Get connections for this job
        async with self._lock:
            connections = self._connections.get(job_id, set()).copy()

        if not connections:
            return

        # Prepare message
        message = {
            "type": "job_status",
            "job_id": job_id,
            "status": status.value,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Send to all connections
        disconnected = []
        for websocket in connections:
            try:
                await self._send_json(websocket, message)
            except Exception:
                disconnected.append(websocket)

        # Clean up disconnected connections
        for websocket in disconnected:
            await self.disconnect(websocket)

    async def _send_json(self, websocket: WebSocket, data: dict) -> None:
        """Send JSON data to a WebSocket connection.

        Args:
            websocket: WebSocket connection
            data: Data to send as JSON
        """
        await websocket.send_json(data)

    async def handle_client_message(self, websocket: WebSocket, message: dict) -> None:
        """Handle incoming message from client.

        Args:
            websocket: WebSocket connection
            message: Received message
        """
        msg_type = message.get("type")

        if msg_type == "ping":
            # Respond to ping with pong
            await self._send_json(
                websocket,
                {
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
        elif msg_type == "subscribe":
            # Client wants to subscribe to a different job
            new_job_id = message.get("job_id")
            if new_job_id:
                # Remove from current job
                await self.disconnect(websocket)
                # Add to new job
                await self.connect(websocket, new_job_id)
        else:
            self.logger.warning(f"Unknown message type: {msg_type}")

    def get_connection_count(self, job_id: str) -> int:
        """Get number of active connections for a job.

        Args:
            job_id: Job ID

        Returns:
            Number of active connections
        """
        return len(self._connections.get(job_id, set()))

    async def close_all_job_connections(self, job_id: str) -> None:
        """Close all connections for a specific job.

        Args:
            job_id: Job ID
        """
        async with self._lock:
            connections = self._connections.get(job_id, set()).copy()

        for websocket in connections:
            try:
                await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
            except Exception:
                pass
            await self.disconnect(websocket)


# Global connection manager instance
connection_manager = ConnectionManager()


async def _validate_job_id(websocket: WebSocket, job_id: str) -> bool:
    """Validate job ID format."""
    if not job_id or len(job_id) != 36:  # UUID format
        await websocket.close(code=status.WS_1003_UNSUPPORTED_DATA)
        return False
    return True


async def _setup_connection_manager(
    websocket: WebSocket, job_id: str, token: Optional[str]
) -> Optional[Tuple[Any, Any]]:
    """Setup appropriate connection manager based on auth settings."""
    if (
        hasattr(settings, "batch_websocket_auth_enabled")
        and settings.batch_websocket_auth_enabled
    ):
        # Import here to avoid circular imports
        from app.api.websockets.secure_progress import \
            secure_connection_manager

        # Get client IP for rate limiting
        client_ip = None
        if hasattr(websocket, "client") and websocket.client:
            client_ip = websocket.client.host

        # Use secure connection manager
        connected = await secure_connection_manager.connect(
            websocket, job_id, token, client_ip
        )
        if not connected:
            return None  # Connection already closed with appropriate error

        return (
            secure_connection_manager.disconnect,
            secure_connection_manager.handle_client_message,
        )
    else:
        # Use regular connection manager (backward compatibility)
        connected = await connection_manager.connect(websocket, job_id)
        if not connected:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
            return None

        return (
            connection_manager.disconnect,
            connection_manager.handle_client_message,
        )


async def _start_batch_processing(job_id: str) -> None:
    """Start batch processing for the job."""
    try:
        from app.services.batch_service import batch_service

        processing_started = await batch_service.batch_manager.start_processing(job_id)
        if processing_started:
            logger.info(
                f"Started batch processing for job {job_id} after WebSocket connection"
            )
        else:
            logger.warning(
                f"Could not start processing for job {job_id} - may already be processing"
            )
    except Exception as e:
        logger.error(f"Error starting batch processing for job {job_id}: {e}")
        # Clean up pending data on error
        try:
            await batch_service.batch_manager.cleanup_pending_job(job_id)
        except Exception as cleanup_error:
            logger.error(f"Error cleaning up job {job_id}: {cleanup_error}")


async def _handle_websocket_messages(
    websocket: WebSocket, message_handler: Any
) -> None:
    """Handle incoming WebSocket messages."""
    while True:
        try:
            # Wait for client messages with timeout
            data = await asyncio.wait_for(
                websocket.receive_text(), timeout=30.0  # 30 second timeout
            )

            # Parse and handle message
            try:
                message = json.loads(data)
                await message_handler(websocket, message)
            except json.JSONDecodeError:
                await websocket.send_json(
                    {
                        "type": "error",
                        "message": "Invalid JSON format",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

        except asyncio.TimeoutError:
            # Send ping to keep connection alive
            try:
                await websocket.send_json(
                    {
                        "type": "ping",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
            except Exception:
                break


@router.websocket("/ws/batch/{job_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    job_id: str,
    token: Optional[str] = Query(
        None, description="Authentication token for job access"
    ),
):
    """WebSocket endpoint for batch job progress updates.

    Args:
        websocket: WebSocket connection
        job_id: Batch job ID to subscribe to
        token: Optional[Any] authentication token
    """
    # Validate job_id format
    if not await _validate_job_id(websocket, job_id):
        return

    # Setup connection manager
    manager_handlers = await _setup_connection_manager(websocket, job_id, token)
    if not manager_handlers:
        return

    disconnect_handler, message_handler = manager_handlers

    # Start processing the batch job
    await _start_batch_processing(job_id)

    try:
        # Keep connection alive and handle incoming messages
        await _handle_websocket_messages(websocket, message_handler)

    except WebSocketDisconnect:
        logger.info(f"Client disconnected from job {job_id}")
    except Exception as e:
        logger.error(f"WebSocket error for job {job_id}: {e}")
    finally:
        # Clean up connection
        await disconnect_handler(websocket)


async def send_batch_progress(progress: BatchProgress) -> None:
    """Send batch progress update to all connected clients.

    This function is called by the BatchManager to broadcast progress.

    Args:
        progress: Progress update to send
    """
    # Broadcast to both managers if auth is enabled
    if (
        hasattr(settings, "batch_websocket_auth_enabled")
        and settings.batch_websocket_auth_enabled
    ):
        # Import here to avoid circular imports
        from app.api.websockets.secure_progress import \
            secure_connection_manager

        await secure_connection_manager.broadcast_progress(progress)
    else:
        await connection_manager.broadcast_progress(progress)


async def send_job_status_update(job_id: str, status: BatchStatus) -> None:
    """Send job status update to all connected clients.

    Args:
        job_id: Job ID
        status: New job status
    """
    # Broadcast to both managers if auth is enabled
    if (
        hasattr(settings, "batch_websocket_auth_enabled")
        and settings.batch_websocket_auth_enabled
    ):
        # Import here to avoid circular imports
        from app.api.websockets.secure_progress import \
            secure_connection_manager

        await secure_connection_manager.broadcast_job_status(job_id, status)
    else:
        await connection_manager.broadcast_job_status(job_id, status)
