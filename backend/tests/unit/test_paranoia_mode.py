import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from backend.app.main import app
from backend.app.config import settings


class TestParanoiaMode:
    """Test paranoia mode functionality."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    def test_get_logging_config(self, client):
        """Test retrieving current logging configuration."""
        response = client.get("/api/monitoring/logging/config")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "success"
        assert "log_level" in data["data"]
        assert "anonymize_logs" in data["data"]
        assert "paranoia_mode" in data["data"]
        assert "privacy_features" in data["data"]
        
        # Check privacy features
        privacy = data["data"]["privacy_features"]
        assert privacy["strip_metadata_default"] == settings.strip_metadata_default
        assert privacy["anonymize_logs"] == settings.anonymize_logs
    
    @patch('backend.app.api.routes.monitoring.settings')
    @patch('backend.app.api.routes.monitoring.setup_logging')
    def test_enable_paranoia_mode(self, mock_setup_logging, mock_settings, client):
        """Test enabling paranoia mode."""
        # Configure mock settings
        mock_settings.log_level = "INFO"
        mock_settings.logging_enabled = True
        
        response = client.put("/api/monitoring/logging/paranoia?enable=true")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "success"
        assert data["data"]["paranoia_mode"] is True
        assert data["data"]["logging_enabled"] is False
        assert "all file logging disabled" in data["data"]["message"]
        
        # Verify setup_logging was called with file logging disabled
        mock_setup_logging.assert_called_once_with(
            log_level="INFO",
            json_logs=True,
            enable_file_logging=False
        )
    
    @patch('backend.app.api.routes.monitoring.settings')
    @patch('backend.app.api.routes.monitoring.setup_logging')
    def test_disable_paranoia_mode(self, mock_setup_logging, mock_settings, client):
        """Test disabling paranoia mode."""
        # Configure mock settings
        mock_settings.log_level = "INFO"
        mock_settings.logging_enabled = False
        
        response = client.put("/api/monitoring/logging/paranoia?enable=false")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "success"
        assert data["data"]["paranoia_mode"] is False
        assert data["data"]["logging_enabled"] is True
        assert "logging resumed" in data["data"]["message"]
        
        # Verify setup_logging was called with file logging enabled
        mock_setup_logging.assert_called_once_with(
            log_level="INFO",
            json_logs=True,
            enable_file_logging=True
        )
    
    def test_paranoia_mode_in_memory_stats(self, client):
        """Test that stats collection works in paranoia mode (memory only)."""
        # Enable paranoia mode
        with patch('backend.app.api.routes.monitoring.settings') as mock_settings:
            mock_settings.logging_enabled = False
            
            # Stats should still work (they're in-memory)
            response = client.get("/api/monitoring/stats")
            
            assert response.status_code == 200
            data = response.json()
            
            assert data["status"] == "success"
            assert "current_hour" in data["data"]
            assert "current_day" in data["data"]
            assert "all_time" in data["data"]
            assert data["privacy_notice"] == "This data contains only aggregate statistics with no user information"
    
    @patch('backend.app.api.routes.monitoring.logger')
    def test_paranoia_mode_toggle_error_handling(self, mock_logger, client):
        """Test error handling when toggling paranoia mode fails."""
        # Make setup_logging raise an exception
        with patch('backend.app.api.routes.monitoring.setup_logging') as mock_setup:
            mock_setup.side_effect = Exception("Setup failed")
            
            response = client.put("/api/monitoring/logging/paranoia?enable=true")
            
            assert response.status_code == 500
            assert response.json()["detail"] == "Failed to toggle paranoia mode"
            
            # Verify error was logged
            mock_logger.error.assert_called_once()
    
    def test_paranoia_mode_environment_variable(self):
        """Test that paranoia mode can be set via environment variable."""
        import os
        from backend.app.config import Settings
        
        # Set environment variable
        os.environ["IMAGE_CONVERTER_LOGGING_ENABLED"] = "false"
        
        try:
            # Create new settings instance
            test_settings = Settings()
            assert test_settings.logging_enabled is False
            
            # This effectively enables paranoia mode
            assert not test_settings.logging_enabled
        finally:
            # Clean up
            del os.environ["IMAGE_CONVERTER_LOGGING_ENABLED"]
    
    def test_paranoia_mode_security_events(self, client):
        """Test that critical security events are still tracked in paranoia mode."""
        with patch('backend.app.api.routes.monitoring.settings') as mock_settings:
            mock_settings.logging_enabled = False  # Paranoia mode
            
            # Even in paranoia mode, the in-memory security event tracking should work
            # This is tested indirectly through stats which track security-related errors
            response = client.get("/api/monitoring/stats")
            
            assert response.status_code == 200
            data = response.json()
            
            # Check that error types can be tracked (including security violations)
            stats = data["data"]["current_hour"]
            assert "error_types" in stats  # Security violations would appear here