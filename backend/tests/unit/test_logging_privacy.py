import pytest
from app.utils.logging import filter_sensitive_data, cleanup_old_logs
import os
import tempfile
from datetime import datetime, timedelta


class TestPrivacyFiltering:
    """Test privacy filtering in logging module."""
    
    def test_basic_sensitive_keys(self):
        """Test filtering of basic sensitive keys."""
        event_dict = {
            "message": "Processing image",
            "password": "secret123",
            "api_key": "sk-1234567890",
            "token": "bearer-token",
            "filename": "vacation.jpg",
            "file_path": "/home/user/photos/vacation.jpg",
            "email": "user@example.com",
            "user_id": "12345",
        }
        
        filtered = filter_sensitive_data(None, None, event_dict)
        
        assert filtered["message"] == "Processing image"
        assert filtered["password"] == "***REDACTED***"
        assert filtered["api_key"] == "***REDACTED***"
        assert filtered["token"] == "***REDACTED***"
        assert filtered["filename"] == "***REDACTED***"
        assert filtered["file_path"] == "***REDACTED***"
        assert filtered["email"] == "***REDACTED***"
        assert filtered["user_id"] == "***REDACTED***"
    
    def test_nested_sensitive_data(self):
        """Test filtering of nested sensitive data."""
        event_dict = {
            "request": {
                "headers": {
                    "authorization": "Bearer token123",
                    "content-type": "application/json"
                },
                "body": {
                    "username": "john_doe",
                    "image_path": "/uploads/photo.jpg"
                }
            },
            "metadata": {
                "exif": {"GPS": "40.7128,-74.0060"},
                "location": "New York"
            }
        }
        
        filtered = filter_sensitive_data(None, None, event_dict)
        
        assert filtered["request"]["headers"]["authorization"] == "***REDACTED***"
        assert filtered["request"]["headers"]["content-type"] == "application/json"
        assert filtered["request"]["body"]["username"] == "***REDACTED***"
        assert filtered["request"]["body"]["image_path"] == "***REDACTED***"
        # Entire metadata value is redacted when key contains "metadata"
        assert filtered["metadata"] == "***REDACTED***"
    
    def test_list_filtering(self):
        """Test filtering of sensitive data in lists."""
        event_dict = {
            "files": [
                {"name": "photo1.jpg", "size": 1024},
                {"name": "photo2.png", "size": 2048}
            ],
            "paths": ["/home/user/doc1.pdf", "/home/user/doc2.txt"]
        }
        
        filtered = filter_sensitive_data(None, None, event_dict)
        
        assert filtered["files"][0]["name"] == "***REDACTED***"
        assert filtered["files"][0]["size"] == 1024
        assert filtered["files"][1]["name"] == "***REDACTED***"
        assert len(filtered["files"]) == 2
        assert all(filtered["files"][i]["size"] in [1024, 2048] for i in range(2))
        assert filtered["paths"] == ["***PATH_REDACTED***", "***PATH_REDACTED***"]
    
    def test_pattern_detection(self):
        """Test pattern-based filtering."""
        event_dict = {
            "email_value": "test@example.com",
            "ip_value": "192.168.1.1",
            "unix_path": "/usr/local/bin/app",
            "windows_path": "C:\\Users\\John\\Documents",
            "network_path": "\\\\server\\share\\file.txt",
            "image_file": "my_photo.jpg",
            "regular_text": "This is just regular text"
        }
        
        filtered = filter_sensitive_data(None, None, event_dict)
        
        # Keys with "email", "ip", "path" in them get redacted entirely
        assert filtered["email_value"] == "***REDACTED***"
        assert filtered["ip_value"] == "***REDACTED***"
        assert filtered["unix_path"] == "***REDACTED***"
        assert filtered["windows_path"] == "***REDACTED***"
        assert filtered["network_path"] == "***REDACTED***"
        assert filtered["image_file"] == "***FILENAME_REDACTED***"
        assert filtered["regular_text"] == "This is just regular text"
    
    def test_case_insensitive_keys(self):
        """Test case-insensitive key matching."""
        event_dict = {
            "FileName": "document.pdf",
            "FILE_PATH": "/home/user/docs",
            "Email_Address": "user@test.com",
            "GPS_Location": "40.7128,-74.0060"
        }
        
        filtered = filter_sensitive_data(None, None, event_dict)
        
        assert filtered["FileName"] == "***REDACTED***"
        assert filtered["FILE_PATH"] == "***REDACTED***"
        assert filtered["Email_Address"] == "***REDACTED***"
        assert filtered["GPS_Location"] == "***REDACTED***"
    
    def test_metadata_filtering(self):
        """Test filtering of image metadata."""
        event_dict = {
            "image_metadata": {
                "exif": {
                    "Make": "Canon",
                    "GPS": {"Latitude": 40.7128, "Longitude": -74.0060}
                },
                "hash": "sha256:abcdef123456",
                "checksum": "md5:1234567890"
            },
            "content_hash": "sha1:fedcba0987654321"
        }
        
        filtered = filter_sensitive_data(None, None, event_dict)
        
        assert filtered["image_metadata"] == "***REDACTED***"
        assert filtered["content_hash"] == "***REDACTED***"
    
    def test_depth_limit_protection(self):
        """Test protection against deeply nested structures."""
        # Create deeply nested structure
        deep_dict = {"level": 0}
        current = deep_dict
        for i in range(15):
            current["nested"] = {"level": i + 1, "password": "secret"}
            current = current["nested"]
        
        event_dict = {"data": deep_dict}
        
        # Should not raise exception
        filtered = filter_sensitive_data(None, None, event_dict)
        
        # Check that depth limit was applied
        current = filtered["data"]
        depth = 0
        while "nested" in current and depth < 20:
            current = current["nested"]
            depth += 1
        
        assert depth <= 11  # Should stop at depth limit


class TestLogCleanup:
    """Test log cleanup functionality."""
    
    def test_cleanup_old_logs(self):
        """Test cleanup of old log files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test log files with different ages
            now = datetime.now()
            
            # Old file (should be deleted)
            old_file = os.path.join(temp_dir, "old.log")
            with open(old_file, "w") as f:
                f.write("old log content")
            # Set modification time to 48 hours ago
            old_time = (now - timedelta(hours=48)).timestamp()
            os.utime(old_file, (old_time, old_time))
            
            # Recent file (should be kept)
            recent_file = os.path.join(temp_dir, "recent.log")
            with open(recent_file, "w") as f:
                f.write("recent log content")
            
            # Non-log file (should be ignored)
            other_file = os.path.join(temp_dir, "data.txt")
            with open(other_file, "w") as f:
                f.write("other content")
            
            # Run cleanup
            cleanup_old_logs(temp_dir, retention_hours=24)
            
            # Check results
            assert not os.path.exists(old_file), "Old log file should be deleted"
            assert os.path.exists(recent_file), "Recent log file should be kept"
            assert os.path.exists(other_file), "Non-log file should be kept"
    
    def test_cleanup_nonexistent_directory(self):
        """Test cleanup with non-existent directory."""
        # Should not raise exception
        cleanup_old_logs("/nonexistent/directory", retention_hours=24)
    
    def test_cleanup_error_handling(self, monkeypatch):
        """Test cleanup handles errors gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, "test.log")
            with open(log_file, "w") as f:
                f.write("test content")
            
            # Mock os.remove to raise exception
            def mock_remove(path):
                raise PermissionError("Cannot delete file")
            
            monkeypatch.setattr(os, "remove", mock_remove)
            
            # Should not raise exception
            cleanup_old_logs(temp_dir, retention_hours=0)