import pytest
import os
import tempfile
import time
import logging
from pathlib import Path
from app.utils.logging import setup_logging, cleanup_old_logs
from datetime import datetime, timedelta


class TestLogRotation:
    """Test log rotation and cleanup functionality."""
    
    def test_rotating_file_handler_setup(self, tmp_path):
        """Test that rotating file handler is properly configured."""
        log_dir = tmp_path / "logs"
        log_file = log_dir / "app.log"
        
        # Setup logging with file rotation
        setup_logging(
            log_level="INFO",
            json_logs=True,
            enable_file_logging=True,
            log_dir=str(log_dir),
            max_log_size_mb=1,  # Small size for testing
            backup_count=3,
            retention_hours=24
        )
        
        # Verify log directory was created
        assert log_dir.exists()
        
        # Get logger and write some logs
        logger = logging.getLogger("test")
        for i in range(100):
            logger.info(f"Test log message {i}")
        
        # Check that log file exists
        assert log_file.exists()
        
        # Clean up handlers
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
    
    def test_log_rotation_on_size(self, tmp_path):
        """Test that logs rotate when size limit is reached."""
        log_dir = tmp_path / "logs"
        
        # Setup logging with very small size limit
        setup_logging(
            log_level="INFO",
            json_logs=False,  # Plain text for predictable size
            enable_file_logging=True,
            log_dir=str(log_dir),
            max_log_size_mb=0.001,  # 1KB
            backup_count=3,
            retention_hours=24
        )
        
        logger = logging.getLogger("test_rotation")
        
        # Write enough data to trigger rotation
        large_message = "x" * 500  # 500 bytes per message
        for i in range(10):
            logger.info(f"Message {i}: {large_message}")
        
        # Force handlers to flush
        for handler in logging.getLogger().handlers:
            if hasattr(handler, 'flush'):
                handler.flush()
        
        # Check for rotated files
        log_files = list(log_dir.glob("app.log*"))
        assert len(log_files) > 1, "Log rotation should have created backup files"
        
        # Clean up handlers
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
    
    def test_paranoia_mode_disables_file_logging(self, tmp_path):
        """Test that paranoia mode (logging_enabled=False) prevents file logging."""
        log_dir = tmp_path / "logs"
        
        # Setup logging with paranoia mode
        setup_logging(
            log_level="INFO",
            json_logs=True,
            enable_file_logging=False,  # Paranoia mode
            log_dir=str(log_dir),
            max_log_size_mb=10,
            backup_count=3,
            retention_hours=24
        )
        
        logger = logging.getLogger("test_paranoia")
        logger.info("This should not be written to file")
        
        # Log directory should not be created in paranoia mode
        assert not log_dir.exists()
        
        # Only stderr handler should be present
        root_logger = logging.getLogger()
        file_handlers = [h for h in root_logger.handlers 
                        if isinstance(h, logging.handlers.RotatingFileHandler)]
        assert len(file_handlers) == 0, "No file handlers should exist in paranoia mode"
    
    def test_retention_with_mixed_files(self, tmp_path):
        """Test that cleanup only removes old log files, not other files."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        
        now = datetime.now()
        
        # Create various files
        files = {
            "old.log": now - timedelta(hours=48),
            "recent.log": now - timedelta(hours=12),
            "current.log": now,
            "old_data.txt": now - timedelta(hours=48),  # Non-log file
            "app.log.1": now - timedelta(hours=36),
            "app.log.2": now - timedelta(hours=6),
        }
        
        for filename, mtime in files.items():
            filepath = log_dir / filename
            filepath.write_text("test content")
            # Set modification time
            mtime_seconds = mtime.timestamp()
            os.utime(filepath, (mtime_seconds, mtime_seconds))
        
        # Run cleanup with 24-hour retention
        cleanup_old_logs(str(log_dir), retention_hours=24)
        
        # Check what remains
        remaining_files = set(f.name for f in log_dir.iterdir())
        
        # Old log files should be deleted
        assert "old.log" not in remaining_files
        assert "app.log.1" not in remaining_files
        
        # Recent log files should remain
        assert "recent.log" in remaining_files
        assert "current.log" in remaining_files
        assert "app.log.2" in remaining_files
        
        # Non-log files should remain
        assert "old_data.txt" in remaining_files
    
    def test_json_logging_format(self, tmp_path):
        """Test that JSON logging produces valid JSON."""
        import json
        
        log_dir = tmp_path / "logs"
        log_file = log_dir / "app.log"
        
        setup_logging(
            log_level="INFO",
            json_logs=True,
            enable_file_logging=True,
            log_dir=str(log_dir),
            max_log_size_mb=10,
            backup_count=3,
            retention_hours=24
        )
        
        logger = logging.getLogger("test_json")
        logger.info("Test message", extra={"user_id": "12345", "action": "convert"})
        
        # Force flush
        for handler in logging.getLogger().handlers:
            if hasattr(handler, 'flush'):
                handler.flush()
        
        # Read and parse log file
        if log_file.exists():
            with open(log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        # Should be valid JSON
                        log_entry = json.loads(line)
                        assert "message" in log_entry
                        assert "timestamp" in log_entry
                        # Privacy filtering should have removed user_id
                        if "user_id" in log_entry:
                            assert log_entry["user_id"] == "***REDACTED***"