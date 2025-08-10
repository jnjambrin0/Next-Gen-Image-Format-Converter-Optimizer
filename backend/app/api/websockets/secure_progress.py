"""Secure WebSocket endpoint for batch processing progress updates with authentication."""

import asyncio
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Set, Tuple

from fastapi import (
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    WebSocketException,
    status,
)
from fastapi.routing import APIRouter

from app.config import settings
from app.core.batch.models import BatchProgress, BatchStatus
from app.services.batch_service import batch_service
from app.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


class SecureConnectionManager:
    """Manages WebSocket connections for batch progress updates with authentication."""

    def __init__(self):
        """Initialize the connection manager."""
        # Map job_id to set of active connections
        self._connections: Dict[str, Set[WebSocket]] = {}
        # Map connection to job_id for cleanup
        self._connection_jobs: Dict[WebSocket, str] = {}
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

        # Authentication tokens for jobs (job_id -> token hash)
        self._job_tokens: Dict[str, str] = {}
        # Token expiry times
        self._token_expiry: Dict[str, datetime] = {}
        # Rate limiting: IP -> (count, reset_time)
        self._rate_limits: Dict[str, Tuple[int, datetime]] = {}
        # Connection limits per job
        self._max_connections_per_job = 10

        self.logger = get_logger(__name__)

    def generate_job_token(self, job_id: str) -> str:
        """Generate a secure token for job access.

        Args:
            job_id: Job ID to generate token for

        Returns:
            Generated token
        """
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        self._job_tokens[job_id] = token_hash
        self._token_expiry[job_id] = datetime.utcnow() + timedelta(hours=24)

        return token

    def verify_job_token(self, job_id: str, token: Optional[str]) -> bool:
        """Verify a job access token.

        Args:
            job_id: Job ID
            token: Token to verify

        Returns:
            True if token is valid
        """
        if not token:
            return False

        # Check if token exists and not expired
        if job_id not in self._job_tokens:
            return False

        if datetime.utcnow() > self._token_expiry.get(job_id, datetime.min):
            # Token expired
            del self._job_tokens[job_id]
            del self._token_expiry[job_id]
            return False

        # Verify token hash
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token_hash == self._job_tokens.get(job_id)

    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if client IP is within rate limits.

        Args:
            client_ip: Client IP address

        Returns:
            True if within limits, False if rate limited
        """
        now = datetime.utcnow()

        if client_ip in self._rate_limits:
            count, reset_time = self._rate_limits[client_ip]

            if now > reset_time:
                # Reset the counter
                self._rate_limits[client_ip] = (1, now + timedelta(minutes=1))
                return True

            if count >= 10:  # Max 10 connections per minute per IP
                return False

            # Increment counter
            self._rate_limits[client_ip] = (count + 1, reset_time)
        else:
            # First connection from this IP
            self._rate_limits[client_ip] = (1, now + timedelta(minutes=1))

        return True

    async def connect(
        self,
        websocket: WebSocket,
        job_id: str,
        token: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> bool:
        """Accept a new WebSocket connection for a job.

        Args:
            websocket: WebSocket connection
            job_id: Batch job ID to subscribe to
            token: Optional authentication token
            client_ip: Client IP address for rate limiting

        Returns:
            True if connected successfully
        """
        # Check rate limit
        if client_ip and not self.check_rate_limit(client_ip):
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION, reason="Rate limit exceeded"
            )
            self.logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return False

        # Verify job exists
        job = batch_service.get_job(job_id)
        if not job:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION, reason="Invalid job ID"
            )
            return False

        # Check connection limit per job
        async with self._lock:
            current_connections = len(self._connections.get(job_id, set()))
            if current_connections >= self._max_connections_per_job:
                await websocket.close(
                    code=status.WS_1008_POLICY_VIOLATION, reason="Too many connections"
                )
                self.logger.warning(f"Connection limit exceeded for job {job_id}")
                return False

        # Verify token if authentication is enabled
        if (
            hasattr(settings, "batch_websocket_auth_enabled")
            and settings.batch_websocket_auth_enabled
        ):
            if not self.verify_job_token(job_id, token):
                await websocket.close(
                    code=status.WS_1008_POLICY_VIOLATION,
                    reason="Invalid or expired token",
                )
                self.logger.warning(f"Invalid token for job {job_id}")
                return False

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
        elif msg_type == "pong":
            # Client responded to our ping, connection is alive
            pass  # No action needed, just acknowledge
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

    async def cleanup_expired_tokens(self) -> None:
        """Clean up expired authentication tokens."""
        now = datetime.utcnow()
        expired = []

        for job_id, expiry in self._token_expiry.items():
            if now > expiry:
                expired.append(job_id)

        for job_id in expired:
            self._job_tokens.pop(job_id, None)
            self._token_expiry.pop(job_id, None)


# Global secure connection manager instance
secure_connection_manager = SecureConnectionManager()


@router.post("/batch/{job_id}/websocket-token")
async def create_websocket_token(job_id: str) -> Dict[str, str]:
    """Create an authentication token for WebSocket access.

    Args:
        job_id: Batch job ID

    Returns:
        Authentication token
    """
    # Verify job exists
    job = batch_service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Batch job not found"
        )

    # Generate token
    token = secure_connection_manager.generate_job_token(job_id)

    return {
        "token": token,
        "expires_in": 86400,  # 24 hours
        "websocket_url": f"/ws/batch/{job_id}?token={token}",
    }


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
        token: Optional authentication token
    """
    # Validate job_id format
    if not job_id or len(job_id) != 36:  # UUID format
        await websocket.close(
            code=status.WS_1003_UNSUPPORTED_DATA, reason="Invalid job ID format"
        )
        return

    # Get client IP for rate limiting
    client_ip = None
    if hasattr(websocket, "client") and websocket.client:
        client_ip = websocket.client.host

    # Connect client with authentication
    connected = await secure_connection_manager.connect(
        websocket, job_id, token, client_ip
    )
    if not connected:
        return  # Connection already closed with appropriate error

    try:
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for client messages with timeout
                data = await asyncio.wait_for(
                    websocket.receive_text(), timeout=30.0  # 30 second timeout
                )

                # Parse and handle message
                try:
                    message = json.loads(data)
                    await secure_connection_manager.handle_client_message(
                        websocket, message
                    )
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

    except WebSocketDisconnect:
        logger.info(f"Client disconnected from job {job_id}")
    except Exception as e:
        logger.error(f"WebSocket error for job {job_id}: {e}")
    finally:
        # Clean up connection
        await secure_connection_manager.disconnect(websocket)


async def send_batch_progress(progress: BatchProgress) -> None:
    """Send batch progress update to all connected clients.

    This function is called by the BatchManager to broadcast progress.

    Args:
        progress: Progress update to send
    """
    await secure_connection_manager.broadcast_progress(progress)


async def send_job_status_update(job_id: str, status: BatchStatus) -> None:
    """Send job status update to all connected clients.

    Args:
        job_id: Job ID
        status: New job status
    """
    await secure_connection_manager.broadcast_job_status(job_id, status)


# Periodic cleanup task
async def cleanup_task():
    """Periodic task to clean up expired tokens."""
    while True:
        await asyncio.sleep(3600)  # Run every hour
        await secure_connection_manager.cleanup_expired_tokens()
