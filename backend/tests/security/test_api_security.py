"""Security tests for API authentication and rate limiting."""

import pytest
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock

from app.main import app
from app.services.api_key_service import api_key_service
from app.models.database import Base
from app.core.security.rate_limiter import api_rate_limiter
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


class TestAuthenticationSecurity:
    """Security tests for authentication system."""
    
    @pytest.fixture(scope="function")
    def client(self):
        """Create test client with clean database."""
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        
        api_key_service.engine = engine
        api_key_service.SessionLocal = sessionmaker(bind=engine)
        
        with TestClient(app) as client:
            yield client
    
    @pytest.fixture
    def sample_api_key(self, client):
        """Create a sample API key for testing."""
        api_key_record, raw_key = api_key_service.create_api_key(
            name="Security Test Key",
            rate_limit_override=50
        )
        return api_key_record, raw_key
    
    def test_api_key_generation_entropy(self):
        """Test that API keys have sufficient entropy."""
        keys = set()
        
        # Generate multiple keys and ensure uniqueness
        for _ in range(100):
            key = api_key_service.generate_api_key()
            assert key not in keys, "Duplicate API key generated"
            keys.add(key)
            
            # Check minimum length (should be ~43 chars for 32 bytes base64)
            assert len(key) >= 40, "API key too short"
            
            # Check character set (URL-safe base64)
            valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')
            assert set(key).issubset(valid_chars), "Invalid characters in API key"
    
    def test_api_key_hashing_security(self):
        """Test that API key hashing is secure."""
        key = "test_api_key_12345"
        hash1 = api_key_service.hash_api_key(key)
        hash2 = api_key_service.hash_api_key(key)
        
        # Should be deterministic
        assert hash1 == hash2
        
        # Should be SHA-256
        assert len(hash1) == 64
        expected = hashlib.sha256(key.encode()).hexdigest()
        assert hash1 == expected
        
        # Different keys should produce different hashes
        different_key = "different_key_67890"
        different_hash = api_key_service.hash_api_key(different_key)
        assert hash1 != different_hash
        
        # Small changes should produce completely different hashes
        similar_key = "test_api_key_12346"  # Changed last char
        similar_hash = api_key_service.hash_api_key(similar_key)
        assert hash1 != similar_hash
    
    def test_api_key_storage_security(self, client):
        """Test that API keys are stored securely."""
        api_key_record, raw_key = api_key_service.create_api_key(name="Storage Test")
        
        # Raw key should never be stored
        with api_key_service.SessionLocal() as session:
            stored_key = session.get(type(api_key_record), api_key_record.id)
            
            # Only hash should be stored
            assert stored_key.key_hash != raw_key
            assert len(stored_key.key_hash) == 64  # SHA-256 hex length
            
            # Verify hash matches
            expected_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            assert stored_key.key_hash == expected_hash
    
    def test_timing_attack_resistance(self, client, sample_api_key):
        """Test resistance to timing attacks on API key verification."""
        _, valid_key = sample_api_key
        invalid_key = "invalid_key_" + secrets.token_urlsafe(20)
        
        # Measure verification times
        valid_times = []
        invalid_times = []
        
        for _ in range(10):
            # Time valid key verification
            start = time.perf_counter()
            api_key_service.verify_api_key(valid_key)
            valid_times.append(time.perf_counter() - start)
            
            # Time invalid key verification
            start = time.perf_counter()
            api_key_service.verify_api_key(invalid_key)
            invalid_times.append(time.perf_counter() - start)
        
        # Calculate averages
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        
        # Times should be similar (within reasonable threshold)
        # This test might be flaky on loaded systems
        time_ratio = max(avg_valid, avg_invalid) / min(avg_valid, avg_invalid)
        assert time_ratio < 2.0, f"Potential timing attack vector: {time_ratio:.2f}x difference"
    
    def test_sql_injection_resistance(self, client):
        """Test resistance to SQL injection in API key operations."""
        # Try SQL injection in various inputs
        malicious_inputs = [
            "'; DROP TABLE api_keys; --",
            "' OR '1'='1",
            "'; UPDATE api_keys SET is_active=0; --",
            "1' UNION SELECT * FROM api_keys --"
        ]
        
        for malicious_input in malicious_inputs:
            # Test in API key creation
            response = client.post("/api/auth/api-keys", json={"name": malicious_input})
            # Should either succeed (sanitized) or fail gracefully
            assert response.status_code in [200, 201, 400, 422]
            
            # Test in API key lookup
            response = client.get(f"/api/auth/api-keys/{malicious_input}")
            # Should return 404 (not found) or 400 (bad request)
            assert response.status_code in [400, 404]
            
            # Test in authentication header
            headers = {"Authorization": f"Bearer {malicious_input}"}
            response = client.get("/api/health", headers=headers)
            # Should work (unauthenticated) but not cause errors
            assert response.status_code == 200
    
    def test_xss_protection(self, client):
        """Test XSS protection in API responses."""
        # Try XSS payloads in API key name
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
        
        for payload in xss_payloads:
            response = client.post("/api/auth/api-keys", json={"name": payload})
            
            if response.status_code in [200, 201]:
                # If creation succeeded, check response doesn't contain executable script
                data = response.json()
                if "key_info" in data and "name" in data["key_info"]:
                    returned_name = data["key_info"]["name"]
                    # Should be properly escaped or sanitized
                    assert "<script>" not in returned_name.lower()
                    assert "javascript:" not in returned_name.lower()
                    assert "onerror=" not in returned_name.lower()
    
    def test_rate_limit_bypass_attempts(self, client, sample_api_key):
        """Test various rate limit bypass attempts."""
        _, raw_key = sample_api_key
        
        # Test with different header formats
        bypass_attempts = [
            {"Authorization": f"Bearer {raw_key}", "X-Forwarded-For": "127.0.0.1"},
            {"Authorization": f"Bearer {raw_key}", "X-Real-IP": "192.168.1.1"},
            {"Authorization": f"Bearer {raw_key}", "Client-IP": "10.0.0.1"},
            {"X-API-Key": raw_key, "X-Originating-IP": "172.16.0.1"}
        ]
        
        for headers in bypass_attempts:
            response = client.get("/api/health", headers=headers)
            
            # Should still be rate limited and not bypass
            assert response.status_code == 200
            assert "X-RateLimit-Remaining" in response.headers
            # Should use the API key's custom limit (50)
            assert response.headers["X-RateLimit-Limit"] == "50"
    
    def test_authentication_header_injection(self, client):
        """Test header injection attacks in authentication."""
        # Try various header injection payloads
        injection_payloads = [
            "Bearer valid_key\r\nX-Admin: true",
            "Bearer valid_key\nSet-Cookie: admin=true",
            "Bearer valid_key\r\n\r\nHTTP/1.1 200 OK",
            f"Bearer {'a' * 10000}",  # Extremely long header
        ]
        
        for payload in injection_payloads:
            try:
                headers = {"Authorization": payload}
                response = client.get("/api/health", headers=headers)
                
                # Should handle gracefully without crashes
                assert response.status_code in [200, 400, 401]
                
                # Should not have injected headers
                assert "X-Admin" not in response.headers
                assert "Set-Cookie" not in response.headers
                
            except Exception as e:
                # Server should handle gracefully, not crash
                assert "Internal Server Error" not in str(e)
    
    def test_api_key_enumeration_protection(self, client):
        """Test protection against API key enumeration."""
        # Try to enumerate API keys
        potential_keys = [
            "00000000000000000000000000000000",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "1234567890123456789012345678901234567890123",
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(32)
        ]
        
        response_times = []
        
        for key in potential_keys:
            headers = {"Authorization": f"Bearer {key}"}
            start = time.perf_counter()
            response = client.get("/api/health", headers=headers)
            elapsed = time.perf_counter() - start
            
            response_times.append(elapsed)
            
            # All should return 200 (optional auth) with similar timing
            assert response.status_code == 200
            assert response.headers["X-RateLimit-Limit"] == "60"  # Default limit
        
        # Response times should be similar (no timing-based enumeration)
        if len(response_times) > 1:
            max_time = max(response_times)
            min_time = min(response_times)
            if min_time > 0:
                time_ratio = max_time / min_time
                assert time_ratio < 3.0, f"Potential enumeration via timing: {time_ratio:.2f}x"
    
    def test_concurrent_authentication_safety(self, client, sample_api_key):
        """Test thread safety of authentication under concurrent load."""
        import threading
        import queue
        
        _, raw_key = sample_api_key
        results = queue.Queue()
        
        def make_request():
            try:
                headers = {"Authorization": f"Bearer {raw_key}"}
                response = client.get("/api/health", headers=headers)
                results.put(("success", response.status_code))
            except Exception as e:
                results.put(("error", str(e)))
        
        # Launch concurrent requests
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join(timeout=5)
        
        # Check results
        success_count = 0
        error_count = 0
        
        while not results.empty():
            result_type, result_value = results.get()
            if result_type == "success":
                success_count += 1
                assert result_value == 200
            else:
                error_count += 1
                print(f"Concurrent request error: {result_value}")
        
        # Most requests should succeed
        assert success_count >= 8, f"Too many concurrent failures: {error_count}"
    
    def test_api_key_lifecycle_security(self, client):
        """Test security throughout API key lifecycle."""
        # Create key
        response = client.post("/api/auth/api-keys", json={"name": "Lifecycle Test"})
        assert response.status_code == 201
        data = response.json()
        
        api_key = data["api_key"]
        key_id = data["key_info"]["id"]
        
        # Verify key works
        headers = {"Authorization": f"Bearer {api_key}"}
        response = client.get("/api/health", headers=headers)
        assert response.status_code == 200
        
        # Update key
        response = client.put(f"/api/auth/api-keys/{key_id}", json={"name": "Updated"})
        assert response.status_code == 200
        
        # Key should still work after update
        response = client.get("/api/health", headers=headers)
        assert response.status_code == 200
        
        # Revoke key
        response = client.delete(f"/api/auth/api-keys/{key_id}")
        assert response.status_code == 204
        
        # Key should no longer work
        response = client.get("/api/health", headers=headers)
        assert response.status_code == 200  # Still works (optional auth)
        # But should use default rate limit
        assert response.headers["X-RateLimit-Limit"] == "60"
    
    def test_privilege_escalation_protection(self, client, sample_api_key):
        """Test protection against privilege escalation."""
        api_key_record, raw_key = sample_api_key
        
        # Try to access admin endpoints with regular API key
        headers = {"Authorization": f"Bearer {raw_key}"}
        
        # These should work (no special privileges required)
        response = client.get("/api/health", headers=headers)
        assert response.status_code == 200
        
        # Try to access sensitive endpoints (these don't exist in our API, which is good)
        sensitive_endpoints = [
            "/api/admin/users",
            "/api/system/config",
            "/api/internal/secrets"
        ]
        
        for endpoint in sensitive_endpoints:
            response = client.get(endpoint, headers=headers)
            # Should return 404 (not found) - these endpoints don't exist
            assert response.status_code == 404
    
    def test_information_disclosure_protection(self, client):
        """Test protection against information disclosure."""
        # Try to get information through error messages
        disclosure_attempts = [
            "/api/auth/api-keys/../../../etc/passwd",
            "/api/auth/api-keys/{{7*7}}",  # Template injection
            "/api/auth/api-keys/%2e%2e%2f%2e%2e%2f",  # URL encoded path traversal
        ]
        
        for attempt in disclosure_attempts:
            response = client.get(attempt)
            
            # Should return appropriate error without disclosure
            assert response.status_code in [400, 404]
            
            if response.status_code != 404:
                data = response.json()
                
                # Error messages should not contain sensitive info
                error_text = str(data).lower()
                sensitive_patterns = [
                    "database",
                    "sql",
                    "traceback",
                    "exception",
                    "file system",
                    "internal server"
                ]
                
                for pattern in sensitive_patterns:
                    assert pattern not in error_text, f"Potential information disclosure: {pattern}"
    
    def test_rate_limiter_security(self, client):
        """Test rate limiter security features."""
        # Test that rate limiter prevents abuse
        start_time = time.time()
        response_codes = []
        
        # Make many requests quickly
        for i in range(20):
            response = client.get("/api/health")
            response_codes.append(response.status_code)
            
            # Check headers are present
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers
        
        elapsed = time.time() - start_time
        
        # Should complete quickly (rate limiter shouldn't add significant delay)
        assert elapsed < 5.0, f"Rate limiter causing excessive delay: {elapsed:.2f}s"
        
        # Most should succeed, but some might be rate limited
        success_count = sum(1 for code in response_codes if code == 200)
        rate_limited_count = sum(1 for code in response_codes if code == 429)
        
        # At least some should succeed
        assert success_count > 0
        
        # If any are rate limited, they should have proper error format
        if rate_limited_count > 0:
            # Make one more request to check rate limit response format
            response = client.get("/api/health")
            if response.status_code == 429:
                data = response.json()
                assert "error_code" in data
                assert "VAL429" in data["error_code"]
                assert "retry_after" in data
    
    def test_memory_safety(self, client):
        """Test memory safety in authentication operations."""
        # Test with various input sizes to check for buffer overflows
        test_sizes = [0, 1, 100, 1000, 10000, 100000]
        
        for size in test_sizes:
            try:
                # Test large API key
                large_key = "A" * size
                headers = {"Authorization": f"Bearer {large_key}"}
                response = client.get("/api/health", headers=headers)
                
                # Should handle gracefully
                assert response.status_code in [200, 400, 401]
                
                # Test large API key name
                if size <= 1000:  # Don't test extremely large payloads in name
                    payload = {"name": "X" * size}
                    response = client.post("/api/auth/api-keys", json=payload)
                    assert response.status_code in [200, 201, 400, 422]
                    
            except Exception as e:
                # Should not cause server crashes
                assert "Internal Server Error" not in str(e)
                assert "Memory" not in str(e)
    
    def test_cryptographic_security(self):
        """Test cryptographic aspects of the system."""
        # Test that we're using secure random for API key generation
        keys = []
        for _ in range(1000):
            key = api_key_service.generate_api_key()
            keys.append(key)
        
        # Basic randomness tests
        unique_keys = set(keys)
        assert len(unique_keys) == 1000, "API keys are not unique"
        
        # Test character distribution (should be roughly uniform for base64)
        all_chars = ''.join(keys)
        char_counts = {}
        for char in all_chars:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Should have reasonable distribution (not perfect, but not terrible)
        if char_counts:
            max_count = max(char_counts.values())
            min_count = min(char_counts.values())
            if min_count > 0:
                ratio = max_count / min_count
                assert ratio < 10, f"Poor character distribution in API keys: {ratio:.2f}"