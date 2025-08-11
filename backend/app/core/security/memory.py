"""Secure memory management for image processing."""

import ctypes
import gc
import os
import resource
import threading
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple, Union

import structlog

from app.core.security.errors import SecurityError

logger = structlog.get_logger()


class MemoryError(SecurityError):
    """Exception raised for memory-related security violations."""

    def __init__(self, message: str, **details):
        super().__init__(
            category="sandbox",
            details={"reason": "memory_tracking", **details},
            message=message,
        )


class SecureMemoryManager:
    """Manages secure memory allocation and cleanup for image processing."""

    def __init__(self, max_memory_mb: int = 512):
        """
        Initialize secure memory manager.

        Args:
            max_memory_mb: Maximum memory limit in MB
        """
        self.max_memory_mb = max_memory_mb
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self._allocated_buffers: List[Union[bytes, bytearray]] = []
        self._lock = threading.Lock()
        self._locked_pages: List[Tuple[int, int]] = []

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup."""
        self.cleanup_all()

    def secure_allocate(self, size: int, lock_memory: bool = True) -> bytearray:
        """
        Securely allocate memory buffer with optional page locking.

        Args:
            size: Size in bytes to allocate
            lock_memory: Whether to lock memory pages to prevent swapping

        Returns:
            Allocated bytearray buffer

        Raises:
            MemoryError: If allocation would exceed limits or fails
        """
        if size <= 0:
            raise MemoryError("Invalid allocation size")

        if size > self.max_memory_bytes:
            raise MemoryError(
                f"Allocation size {size} exceeds maximum {self.max_memory_bytes}"
            )

        # Check current tracked buffer usage instead of system memory
        # to avoid conflicts with other processes
        with self._lock:
            current_tracked = sum(len(buf) for buf in self._allocated_buffers)
        if current_tracked + size > self.max_memory_bytes:
            raise MemoryError(
                f"Allocation would exceed memory limit: {current_tracked + size} > {self.max_memory_bytes}"
            )

        try:
            # Allocate buffer
            buffer = bytearray(size)

            # Try to lock memory pages if requested
            if lock_memory:
                self._lock_memory_pages(buffer)

            # Track the buffer
            with self._lock:
                self._allocated_buffers.append(buffer)

            logger.debug(
                "Secure memory allocated",
                size=size,
                locked=lock_memory,
                total_buffers=len(self._allocated_buffers),
            )

            return buffer

        except Exception as e:
            raise MemoryError(f"Failed to allocate secure memory: {e}")

    def secure_clear(self, buffer: Union[bytes, bytearray, memoryview]) -> None:
        """
        Securely clear memory buffer by overwriting with patterns.

        Args:
            buffer: Buffer to clear
        """
        if not buffer:
            return

        try:
            # Convert to mutable if needed
            if isinstance(buffer, (bytes, memoryview)):
                # Can't clear immutable bytes, but can clear the underlying data
                # if it's a bytearray
                if hasattr(buffer, "obj") and isinstance(buffer.obj, bytearray):
                    buffer = buffer.obj
                else:
                    logger.warning("Cannot securely clear immutable buffer")
                    return

            if isinstance(buffer, bytearray):
                size = len(buffer)

                # Multiple overwrite passes for security
                overwrite_patterns = [
                    0x00,  # All zeros
                    0xFF,  # All ones
                    0xAA,  # Alternating pattern
                    0x55,  # Alternating pattern (inverse)
                    0x00,  # Final zeros
                ]

                for pattern in overwrite_patterns:
                    for i in range(size):
                        buffer[i] = pattern

                logger.debug("Memory buffer securely cleared", size=size)

        except Exception as e:
            logger.error("Failed to securely clear buffer", error=str(e))

    def _lock_memory_pages(self, buffer: bytearray) -> None:
        """
        Lock memory pages to prevent swapping.

        Args:
            buffer: Buffer to lock in memory
        """
        try:
            # Get buffer address and size
            buffer_address = ctypes.addressof(
                (ctypes.c_char * len(buffer)).from_buffer(buffer)
            )
            buffer_size = len(buffer)

            # Try to lock using mlock (Unix-like systems)
            if os.name == "posix":
                try:
                    # Try different libc locations
                    libc_names = ["libc.so.6", "libc.dylib", "libc.so"]
                    libc = None

                    for name in libc_names:
                        try:
                            libc = ctypes.CDLL(name)
                            break
                        except OSError:
                            continue

                    if libc and hasattr(libc, "mlock"):
                        result = libc.mlock(buffer_address, buffer_size)
                        if result == 0:
                            self._locked_pages.append((buffer_address, buffer_size))
                            logger.debug(
                                "Memory pages locked",
                                address=hex(buffer_address),
                                size=buffer_size,
                            )
                        else:
                            logger.warning(
                                "Failed to lock memory pages", error_code=result
                            )
                    else:
                        logger.debug("mlock not available in libc")

                except Exception as libc_error:
                    logger.debug(
                        "Could not access libc for mlock", error=str(libc_error)
                    )
            else:
                logger.debug("Memory locking not available on this platform")

        except Exception as e:
            logger.warning("Failed to lock memory pages", error=str(e))

    def _unlock_memory_pages(self) -> None:
        """Unlock all locked memory pages."""
        if not self._locked_pages:
            return

        try:
            if os.name == "posix":
                # Try different libc locations
                libc_names = ["libc.so.6", "libc.dylib", "libc.so"]
                libc = None

                for name in libc_names:
                    try:
                        libc = ctypes.CDLL(name)
                        break
                    except OSError:
                        continue

                if libc and hasattr(libc, "munlock"):
                    for address, size in self._locked_pages:
                        libc.munlock(address, size)

                    logger.debug("Memory pages unlocked", count=len(self._locked_pages))

                self._locked_pages.clear()

        except Exception as e:
            logger.warning("Failed to unlock memory pages", error=str(e))

    def _get_current_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        try:
            # Get RSS (Resident Set Size) memory usage
            usage = resource.getrusage(resource.RUSAGE_SELF)
            # ru_maxrss is in KB on Linux, bytes on macOS
            if os.name == "posix":
                if hasattr(os, "uname") and os.uname().sysname == "Darwin":
                    # macOS: ru_maxrss is in bytes
                    return usage.ru_maxrss
                else:
                    # Linux: ru_maxrss is in KB
                    return usage.ru_maxrss * 1024
            else:
                # Fallback - sum up tracked buffer sizes
                with self._lock:
                    return sum(len(buf) for buf in self._allocated_buffers)

        except Exception as e:
            logger.debug("Failed to get memory usage", error=str(e))
            # Fallback to tracked buffers
            with self._lock:
                return sum(len(buf) for buf in self._allocated_buffers)

    def cleanup_all(self) -> None:
        """Clean up all allocated buffers and unlock memory."""
        with self._lock:
            # Securely clear all buffers
            for buffer in self._allocated_buffers:
                self.secure_clear(buffer)

            self._allocated_buffers.clear()

        # Unlock memory pages
        self._unlock_memory_pages()

        # Force garbage collection
        gc.collect()

        logger.debug("All secure memory cleaned up")

    def get_memory_stats(self) -> Dict[str, Any]:
        """Get current memory statistics."""
        with self._lock:
            allocated_count = len(self._allocated_buffers)
            allocated_size = sum(len(buf) for buf in self._allocated_buffers)

        current_usage = self._get_current_memory_usage()

        return {
            "max_memory_mb": self.max_memory_mb,
            "max_memory_bytes": self.max_memory_bytes,
            "current_usage_bytes": current_usage,
            "current_usage_mb": current_usage / (1024 * 1024),
            "allocated_buffers": allocated_count,
            "allocated_size_bytes": allocated_size,
            "locked_pages": len(self._locked_pages),
            "memory_utilization_percent": (current_usage / self.max_memory_bytes) * 100,
        }


@contextmanager
def secure_memory_context(max_memory_mb: int = 512, lock_memory: bool = True):
    """
    Context manager for secure memory operations.

    Args:
        max_memory_mb: Maximum memory limit in MB
        lock_memory: Whether to lock memory pages

    Yields:
        SecureMemoryManager instance
    """
    manager = SecureMemoryManager(max_memory_mb)
    try:
        yield manager
    finally:
        manager.cleanup_all()


def secure_allocate(
    size: int, max_memory_mb: int = 512, lock_memory: bool = True
) -> bytearray:
    """
    Allocate secure memory buffer.

    Args:
        size: Size in bytes to allocate
        max_memory_mb: Maximum memory limit
        lock_memory: Whether to lock memory pages

    Returns:
        Allocated bytearray buffer
    """
    manager = SecureMemoryManager(max_memory_mb)
    return manager.secure_allocate(size, lock_memory)


def secure_clear(buffer: Union[bytes, bytearray, memoryview]) -> None:
    """
    Securely clear memory buffer.

    Args:
        buffer: Buffer to clear
    """
    manager = SecureMemoryManager()
    manager.secure_clear(buffer)


def get_system_memory_info() -> Dict[str, Any]:
    """Get system memory information."""
    try:
        # Get memory info from /proc/meminfo on Linux
        if os.path.exists("/proc/meminfo"):
            memory_info = {}
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith(
                        ("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:")
                    ):
                        key, value = line.split(":")
                        # Extract numeric value (in kB)
                        memory_info[key.strip()] = (
                            int(value.strip().split()[0]) * 1024
                        )  # Convert to bytes

            return {
                "total_memory_bytes": memory_info.get("MemTotal", 0),
                "available_memory_bytes": memory_info.get("MemAvailable", 0),
                "total_swap_bytes": memory_info.get("SwapTotal", 0),
                "free_swap_bytes": memory_info.get("SwapFree", 0),
                "swap_in_use": (
                    memory_info.get("SwapTotal", 0) - memory_info.get("SwapFree", 0)
                )
                > 0,
            }
        else:
            # Fallback for non-Linux systems
            return {
                "total_memory_bytes": 0,
                "available_memory_bytes": 0,
                "total_swap_bytes": 0,
                "free_swap_bytes": 0,
                "swap_in_use": False,
            }

    except Exception as e:
        logger.debug("Failed to get system memory info", error=str(e))
        return {
            "total_memory_bytes": 0,
            "available_memory_bytes": 0,
            "total_swap_bytes": 0,
            "free_swap_bytes": 0,
            "swap_in_use": False,
        }
