"""Integration tests for Image Converter Python SDK."""

import pytest
import os
from unittest.mock import Mock, patch, MagicMock
from image_converter import (
    ImageConverterClient,
    AsyncImageConverterClient,
    NetworkSecurityError,
    ValidationError,
    ServiceUnavailableError,
)


class TestClientSecurity:
    """Test security features of the client."""
    
    def test_localhost_only_enforcement(self):
        """Test that non-localhost connections are blocked."""
        # Should work with localhost
        client = ImageConverterClient(host="localhost")
        assert client is not None
        
        client = ImageConverterClient(host="127.0.0.1")
        assert client is not None
        
        # Should fail with external host
        with pytest.raises(NetworkSecurityError) as exc_info:
            ImageConverterClient(host="example.com")
        assert "blocked for security" in str(exc_info.value)
        
        with pytest.raises(NetworkSecurityError) as exc_info:
            ImageConverterClient(host="192.168.1.100")
        assert "blocked for security" in str(exc_info.value)
    
    def test_localhost_verification_can_be_disabled(self):
        """Test that localhost verification can be disabled (not recommended)."""
        # This should work but is dangerous
        client = ImageConverterClient(
            host="192.168.1.100",
            verify_localhost=False
        )
        assert client is not None
    
    def test_api_key_from_environment(self):
        """Test that API key is loaded from environment."""
        test_key = "ic_live_test123"
        with patch.dict(os.environ, {"IMAGE_CONVERTER_API_KEY": test_key}):
            client = ImageConverterClient()
            assert client._async_client.api_key == test_key


class TestAsyncClient:
    """Test async client functionality."""
    
    @pytest.mark.asyncio
    async def test_async_client_initialization(self):
        """Test async client can be initialized."""
        async with AsyncImageConverterClient() as client:
            assert client is not None
            assert client.base_url == "http://localhost:8080/api/v1"
    
    @pytest.mark.asyncio
    async def test_localhost_enforcement_async(self):
        """Test localhost enforcement in async client."""
        with pytest.raises(NetworkSecurityError):
            async with AsyncImageConverterClient(host="google.com"):
                pass


class TestErrorHandling:
    """Test error handling patterns."""
    
    def test_privacy_aware_errors(self):
        """Test that errors don't contain PII."""
        # File errors should not contain filenames
        from image_converter.exceptions import FileError
        
        error = FileError("File operation failed")
        assert "File operation failed" in str(error)
        assert "/" not in str(error)  # No paths
        assert "\\" not in str(error)  # No Windows paths
        
        # Validation errors should be generic
        error = ValidationError("Invalid request parameters")
        assert "Invalid request parameters" in str(error)
    
    def test_error_codes(self):
        """Test that error codes are properly set."""
        from image_converter.exceptions import (
            NetworkSecurityError,
            RateLimitError,
            SandboxError,
        )
        
        error = NetworkSecurityError()
        assert error.error_code == "network"
        
        error = RateLimitError()
        assert error.error_code == "rate_limit"
        
        error = SandboxError()
        assert error.error_code == "sandbox"


class TestSecureKeyManager:
    """Test secure API key management."""
    
    def test_key_generation(self):
        """Test API key generation."""
        from image_converter.auth import SecureAPIKeyManager
        
        key = SecureAPIKeyManager.generate_api_key()
        assert key.startswith("ic_live_")
        assert len(key) > 40  # Should be reasonably long
    
    def test_key_storage_and_retrieval(self):
        """Test storing and retrieving API keys."""
        from image_converter.auth import SecureAPIKeyManager
        
        manager = SecureAPIKeyManager()
        test_key = "ic_live_test_key_12345"
        
        # Store key
        success = manager.store_api_key("test", test_key)
        assert success
        
        # Retrieve key
        retrieved = manager.retrieve_api_key("test")
        assert retrieved == test_key
        
        # Delete key
        success = manager.delete_api_key("test")
        assert success
        
        # Should not retrieve deleted key
        retrieved = manager.retrieve_api_key("test")
        assert retrieved is None
    
    def test_key_obfuscation(self):
        """Test that keys are obfuscated in storage."""
        from image_converter.auth import SecureAPIKeyManager
        
        manager = SecureAPIKeyManager()
        test_value = "sensitive_api_key"
        
        # Obfuscate
        obfuscated = manager._obfuscate(test_value)
        assert obfuscated != test_value
        assert len(obfuscated) > 0
        
        # Deobfuscate
        deobfuscated = manager._deobfuscate(obfuscated)
        assert deobfuscated == test_value


@pytest.mark.integration
class TestAPIIntegration:
    """Test actual API integration (requires running server)."""
    
    @pytest.mark.skipif(
        not os.environ.get("RUN_INTEGRATION_TESTS"),
        reason="Integration tests require running API server"
    )
    def test_health_check(self):
        """Test health check endpoint."""
        client = ImageConverterClient()
        
        try:
            result = client.health_check()
            assert "status" in result
        except ServiceUnavailableError:
            pytest.skip("API server not running")
    
    @pytest.mark.skipif(
        not os.environ.get("RUN_INTEGRATION_TESTS"),
        reason="Integration tests require running API server"
    )
    def test_supported_formats(self):
        """Test getting supported formats."""
        client = ImageConverterClient()
        
        try:
            formats = client.get_supported_formats()
            assert len(formats) > 0
            
            # Check for expected formats
            format_names = [f.format for f in formats]
            assert "webp" in format_names
            assert "jpeg" in format_names
            assert "png" in format_names
        except ServiceUnavailableError:
            pytest.skip("API server not running")