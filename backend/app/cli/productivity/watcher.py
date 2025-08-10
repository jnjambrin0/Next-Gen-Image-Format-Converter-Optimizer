"""
Directory Watcher for Watch Mode
Monitor directories for changes and automatically process files
"""

import asyncio
import fnmatch
import hashlib
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Callable, Dict, List, Optional, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


class WatcherStatus(Enum):
    """Watcher status states"""

    IDLE = "idle"
    WATCHING = "watching"
    PROCESSING = "processing"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class ResourceLimits:
    """Resource limits for watch mode"""

    max_files: int = 100
    max_concurrent: int = 5
    max_memory_mb: int = 512
    max_cpu_percent: int = 80
    max_events_per_second: int = 10
    debounce_ms: int = 500
    timeout_seconds: int = 30


@dataclass
class WatcherStats:
    """Statistics for watch mode"""

    files_processed: int = 0
    files_failed: int = 0
    files_skipped: int = 0
    total_events: int = 0
    start_time: Optional[datetime] = None
    current_memory_mb: float = 0
    current_cpu_percent: float = 0
    last_event_time: Optional[datetime] = None

    def reset(self):
        """Reset statistics"""
        self.__init__()


@dataclass
class FileEvent:
    """Represents a file system event"""

    path: Path
    event_type: str
    timestamp: datetime
    size: int = 0
    checksum: Optional[str] = None


class RateLimiter:
    """Rate limiter for events"""

    def __init__(self, max_per_second: int):
        self.max_per_second = max_per_second
        self.events = []
        self.lock = threading.Lock()

    def should_allow(self) -> bool:
        """Check if event should be allowed"""
        with self.lock:
            now = time.time()
            # Remove events older than 1 second
            self.events = [t for t in self.events if now - t < 1.0]

            if len(self.events) < self.max_per_second:
                self.events.append(now)
                return True
            return False

    def reset(self):
        """Reset rate limiter"""
        with self.lock:
            self.events.clear()


class Debouncer:
    """Debounce rapid file changes"""

    def __init__(self, delay_ms: int):
        self.delay_ms = delay_ms
        self.pending_events: Dict[str, threading.Timer] = {}
        self.lock = threading.Lock()

    def debounce(self, key: str, callback: Callable, *args, **kwargs):
        """Debounce an event"""
        with self.lock:
            # Cancel existing timer for this key
            if key in self.pending_events:
                self.pending_events[key].cancel()

            # Create new timer
            timer = threading.Timer(
                self.delay_ms / 1000.0,
                self._execute_callback,
                args=(key, callback, args, kwargs),
            )
            self.pending_events[key] = timer
            timer.start()

    def _execute_callback(self, key: str, callback: Callable, args, kwargs):
        """Execute callback after debounce delay"""
        with self.lock:
            if key in self.pending_events:
                del self.pending_events[key]
        callback(*args, **kwargs)

    def cancel_all(self):
        """Cancel all pending events"""
        with self.lock:
            for timer in self.pending_events.values():
                timer.cancel()
            self.pending_events.clear()


class DirectoryWatcher:
    """Main directory watcher with resource management"""

    def __init__(
        self,
        directory: Path,
        filters: Optional[List[str]] = None,
        excludes: Optional[List[str]] = None,
        limits: Optional[ResourceLimits] = None,
        process_callback: Optional[Callable] = None,
    ):
        """
        Initialize directory watcher

        Args:
            directory: Directory to watch
            filters: File patterns to include (e.g., "*.jpg", "*.png")
            excludes: File patterns to exclude
            limits: Resource limits
            process_callback: Callback for processing files
        """
        self.directory = Path(directory).resolve()
        self.filters = filters or ["*"]
        self.excludes = excludes or []
        self.limits = limits or ResourceLimits()
        self.process_callback = process_callback

        # Components
        self.observer = Observer()
        self.event_handler = WatcherEventHandler(self)
        self.rate_limiter = RateLimiter(self.limits.max_events_per_second)
        self.debouncer = Debouncer(self.limits.debounce_ms)

        # Processing queue
        self.processing_queue = Queue(maxsize=self.limits.max_files)
        self.active_workers = 0
        self.worker_lock = threading.Lock()
        self.worker_semaphore = threading.Semaphore(self.limits.max_concurrent)

        # State
        self.status = WatcherStatus.IDLE
        self.stats = WatcherStats()
        self.processed_files: Set[str] = set()
        self.file_checksums: Dict[str, str] = {}

        # Control
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()

        # Resource monitoring
        self.resource_monitor = ResourceMonitor(self.limits)

    def should_process_file(self, path: Path) -> bool:
        """Check if file should be processed based on filters"""
        filename = path.name

        # Check excludes first
        for pattern in self.excludes:
            if fnmatch.fnmatch(filename, pattern):
                return False

        # Check includes
        for pattern in self.filters:
            if fnmatch.fnmatch(filename, pattern):
                return True

        return False

    def get_file_checksum(self, path: Path) -> Optional[str]:
        """Get file checksum for duplicate detection"""
        try:
            with open(path, "rb") as f:
                # Read in chunks for large files
                hasher = hashlib.sha256()
                while chunk := f.read(8192):
                    hasher.update(chunk)
                return hasher.hexdigest()
        except (IOError, OSError):
            return None

    def handle_file_event(self, event: FileSystemEvent):
        """Handle a file system event"""
        if self.status != WatcherStatus.WATCHING:
            return

        # Check rate limit
        if not self.rate_limiter.should_allow():
            self.stats.files_skipped += 1
            return

        path = Path(event.src_path)

        # Check if file should be processed
        if not self.should_process_file(path):
            return

        # Debounce the event
        self.debouncer.debounce(
            str(path), self._process_file_event, path, event.event_type
        )

    def _process_file_event(self, path: Path, event_type: str):
        """Process a debounced file event"""
        if not path.exists() or not path.is_file():
            return

        # Check for duplicates
        checksum = self.get_file_checksum(path)
        if checksum:
            if checksum in self.file_checksums.values():
                self.stats.files_skipped += 1
                return
            self.file_checksums[str(path)] = checksum

        # Create file event
        try:
            file_event = FileEvent(
                path=path,
                event_type=event_type,
                timestamp=datetime.now(),
                size=path.stat().st_size,
                checksum=checksum,
            )

            # Add to processing queue
            if not self.processing_queue.full():
                self.processing_queue.put(file_event, block=False)
                self.stats.total_events += 1
            else:
                self.stats.files_skipped += 1
        except (OSError, Exception):
            self.stats.files_failed += 1

    def start(self):
        """Start watching directory"""
        if self.status != WatcherStatus.IDLE:
            raise RuntimeError(f"Cannot start watcher in {self.status} state")

        self.status = WatcherStatus.WATCHING
        self.stats.reset()
        self.stats.start_time = datetime.now()

        # Start observer
        self.observer.schedule(self.event_handler, str(self.directory), recursive=True)
        self.observer.start()

        # Start processing workers
        for _ in range(self.limits.max_concurrent):
            worker = threading.Thread(target=self._process_worker)
            worker.daemon = True
            worker.start()

        # Start resource monitor
        self.resource_monitor.start(self._on_resource_exhaustion)

    def _process_worker(self):
        """Worker thread for processing file events"""
        while not self.stop_event.is_set():
            # Check pause state
            if self.pause_event.is_set():
                time.sleep(0.1)
                continue

            try:
                # Get event from queue with timeout
                file_event = self.processing_queue.get(timeout=1.0)

                # Acquire semaphore for processing
                with self.worker_semaphore:
                    with self.worker_lock:
                        self.active_workers += 1

                    try:
                        # Check resource limits
                        if self.resource_monitor.check_limits():
                            self._process_file(file_event)
                        else:
                            self.stats.files_skipped += 1
                    finally:
                        with self.worker_lock:
                            self.active_workers -= 1

            except Empty:
                continue
            except Exception:
                self.stats.files_failed += 1

    def _process_file(self, file_event: FileEvent):
        """Process a single file"""
        if self.process_callback:
            try:
                # Mark as processing
                self.status = WatcherStatus.PROCESSING

                # Call the callback (should be sandboxed)
                self.process_callback(file_event)

                self.stats.files_processed += 1
                self.processed_files.add(str(file_event.path))

                # Update status
                if self.processing_queue.empty() and self.active_workers == 1:
                    self.status = WatcherStatus.WATCHING
            except Exception:
                self.stats.files_failed += 1

    def _on_resource_exhaustion(self):
        """Handle resource exhaustion"""
        self.status = WatcherStatus.ERROR
        self.stop()

    def pause(self):
        """Pause processing"""
        if self.status == WatcherStatus.WATCHING:
            self.status = WatcherStatus.PAUSED
            self.pause_event.set()

    def resume(self):
        """Resume processing"""
        if self.status == WatcherStatus.PAUSED:
            self.status = WatcherStatus.WATCHING
            self.pause_event.clear()

    def stop(self):
        """Stop watching"""
        self.status = WatcherStatus.STOPPING

        # Stop accepting new events
        self.observer.stop()

        # Cancel pending debounced events
        self.debouncer.cancel_all()

        # Signal workers to stop
        self.stop_event.set()

        # Wait for observer to stop
        self.observer.join(timeout=5)

        # Stop resource monitor
        self.resource_monitor.stop()

        self.status = WatcherStatus.STOPPED

    def get_status(self) -> Dict[str, Any]:
        """Get current watcher status"""
        return {
            "status": self.status.value,
            "directory": str(self.directory),
            "stats": {
                "files_processed": self.stats.files_processed,
                "files_failed": self.stats.files_failed,
                "files_skipped": self.stats.files_skipped,
                "total_events": self.stats.total_events,
                "uptime": (
                    str(datetime.now() - self.stats.start_time)
                    if self.stats.start_time
                    else "0:00:00"
                ),
                "queue_size": self.processing_queue.qsize(),
                "active_workers": self.active_workers,
            },
            "resources": {
                "memory_mb": self.stats.current_memory_mb,
                "cpu_percent": self.stats.current_cpu_percent,
            },
        }


class WatcherEventHandler(FileSystemEventHandler):
    """Handle file system events"""

    def __init__(self, watcher: DirectoryWatcher):
        self.watcher = watcher

    def on_created(self, event):
        if not event.is_directory:
            self.watcher.handle_file_event(event)

    def on_modified(self, event):
        if not event.is_directory:
            self.watcher.handle_file_event(event)

    def on_moved(self, event):
        if not event.is_directory:
            self.watcher.handle_file_event(event)


class ResourceMonitor:
    """Monitor system resources"""

    def __init__(self, limits: ResourceLimits):
        self.limits = limits
        self.monitoring = False
        self.monitor_thread = None
        self.exhaustion_callback = None

    def start(self, exhaustion_callback: Callable):
        """Start monitoring resources"""
        self.monitoring = True
        self.exhaustion_callback = exhaustion_callback
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)

    def _monitor_loop(self):
        """Monitor resource usage with auto-shutdown on exhaustion"""
        import psutil

        consecutive_violations = 0
        max_violations = 3  # Allow brief spikes

        while self.monitoring:
            try:
                # Get current process
                process = psutil.Process()

                violation_detected = False

                # Check memory usage
                memory_mb = process.memory_info().rss / 1024 / 1024
                if memory_mb > self.limits.max_memory_mb:
                    violation_detected = True
                    consecutive_violations += 1

                # Check CPU usage (only if no memory violation)
                if not violation_detected:
                    cpu_percent = process.cpu_percent(interval=1)
                    if cpu_percent > self.limits.max_cpu_percent:
                        violation_detected = True
                        consecutive_violations += 1

                # Reset counter if no violations
                if not violation_detected:
                    consecutive_violations = 0

                # Trigger auto-shutdown if persistent violations
                if consecutive_violations >= max_violations:
                    if self.exhaustion_callback:
                        # Log reason for shutdown
                        import logging

                        logger = logging.getLogger(__name__)
                        logger.error(
                            f"Resource exhaustion detected: Memory={memory_mb:.1f}MB "
                            f"(limit={self.limits.max_memory_mb}MB), "
                            f"CPU={cpu_percent:.1f}% (limit={self.limits.max_cpu_percent}%)"
                        )
                        self.exhaustion_callback()
                    break

                # Check every 2 seconds for responsiveness
                time.sleep(2)
            except Exception as e:
                # Log error but continue monitoring
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(f"Resource monitoring error: {e}")
                time.sleep(5)

    def check_limits(self) -> bool:
        """Check if within resource limits"""
        try:
            import psutil

            process = psutil.Process()

            memory_mb = process.memory_info().rss / 1024 / 1024
            if memory_mb > self.limits.max_memory_mb:
                return False

            # Don't check CPU here as it's too expensive
            return True
        except Exception:
            return True  # Assume OK if can't check
