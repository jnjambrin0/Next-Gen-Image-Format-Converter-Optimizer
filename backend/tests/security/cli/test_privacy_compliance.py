"""
Security tests for privacy compliance in CLI productivity features
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import re

from app.cli.productivity.autocomplete import (
    PrivacySanitizer,
    CommandLearner,
    AutocompleteEngine
)


class TestPrivacyCompliance:
    """Test that no PII is stored in learning data"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    def test_no_filenames_in_stored_data(self, temp_dir):
        """Test that filenames are never stored"""
        learner = CommandLearner(temp_dir)
        
        # Test various filename patterns
        test_commands = [
            "img convert MyPersonalPhoto.jpg -f webp",
            "img batch /Users/john/Documents/vacation/*.png",
            "img optimize C:\\Users\\Jane\\Pictures\\family.jpg",
            "img convert ~/private/data/scan.pdf -f png",
            "img analyze ./secret/financial_report.tiff"
        ]
        
        for command in test_commands:
            sanitized = PrivacySanitizer.sanitize(command)
            learner.learn(sanitized)
        
        learner._save_patterns()
        
        # Read the encrypted file and decrypt it
        with open(temp_dir / "patterns.json", 'rb') as f:
            encrypted_data = f.read()
            decrypted = learner.fernet.decrypt(encrypted_data)
            stored_data = json.loads(decrypted.decode())
        
        # Convert to string for searching
        data_str = json.dumps(stored_data)
        
        # Check that no personal information is present
        assert "MyPersonalPhoto" not in data_str
        assert "john" not in data_str
        assert "Jane" not in data_str
        assert "vacation" not in data_str
        assert "family" not in data_str
        assert "private" not in data_str
        assert "secret" not in data_str
        assert "financial_report" not in data_str
        assert "Users" not in data_str
        assert "Documents" not in data_str
        assert "Pictures" not in data_str
    
    def test_no_paths_in_stored_data(self, temp_dir):
        """Test that file paths are never stored"""
        learner = CommandLearner(temp_dir)
        
        # Test various path patterns
        test_paths = [
            "/home/user/photos",
            "C:\\Users\\Admin\\Desktop",
            "./my_files/personal",
            "../parent/directory",
            "~/Downloads/temp"
        ]
        
        for path in test_paths:
            command = f"img convert {path}/file.jpg -f webp"
            sanitized = PrivacySanitizer.sanitize(command)
            learner.learn(sanitized)
        
        learner._save_patterns()
        
        # Read and check stored data
        with open(temp_dir / "patterns.json", 'rb') as f:
            encrypted_data = f.read()
            decrypted = learner.fernet.decrypt(encrypted_data)
            stored_data = json.loads(decrypted.decode())
        
        data_str = json.dumps(stored_data)
        
        # Check that no paths are present
        for path in test_paths:
            # Remove special regex characters for literal search
            escaped_path = re.escape(path)
            assert path not in data_str
            assert escaped_path not in data_str
    
    def test_no_email_addresses_stored(self, temp_dir):
        """Test that email addresses are never stored"""
        learner = CommandLearner(temp_dir)
        
        emails = [
            "user@example.com",
            "john.doe@company.org",
            "admin@localhost"
        ]
        
        for email in emails:
            command = f"img convert photo.jpg --author {email}"
            sanitized = PrivacySanitizer.sanitize(command)
            learner.learn(sanitized)
        
        learner._save_patterns()
        
        # Check stored data
        with open(temp_dir / "patterns.json", 'rb') as f:
            encrypted_data = f.read()
            decrypted = learner.fernet.decrypt(encrypted_data)
            stored_data = json.loads(decrypted.decode())
        
        data_str = json.dumps(stored_data)
        
        for email in emails:
            assert email not in data_str
            assert email.split('@')[0] not in data_str  # Check username part
    
    def test_no_ip_addresses_stored(self, temp_dir):
        """Test that IP addresses are never stored"""
        learner = CommandLearner(temp_dir)
        
        ips = [
            "192.168.1.1",
            "10.0.0.100",
            "172.16.254.1"
        ]
        
        for ip in ips:
            command = f"img convert --server {ip} photo.jpg"
            sanitized = PrivacySanitizer.sanitize(command)
            learner.learn(sanitized)
        
        learner._save_patterns()
        
        # Check stored data
        with open(temp_dir / "patterns.json", 'rb') as f:
            encrypted_data = f.read()
            decrypted = learner.fernet.decrypt(encrypted_data)
            stored_data = json.loads(decrypted.decode())
        
        data_str = json.dumps(stored_data)
        
        for ip in ips:
            assert ip not in data_str
    
    def test_no_urls_stored(self, temp_dir):
        """Test that URLs are never stored"""
        learner = CommandLearner(temp_dir)
        
        urls = [
            "https://example.com/image.jpg",
            "http://private.server.com/data",
            "ftp://files.company.org/assets"
        ]
        
        for url in urls:
            command = f"img convert {url} -f webp"
            sanitized = PrivacySanitizer.sanitize(command)
            learner.learn(sanitized)
        
        learner._save_patterns()
        
        # Check stored data
        with open(temp_dir / "patterns.json", 'rb') as f:
            encrypted_data = f.read()
            decrypted = learner.fernet.decrypt(encrypted_data)
            stored_data = json.loads(decrypted.decode())
        
        data_str = json.dumps(stored_data)
        
        for url in urls:
            assert url not in data_str
            # Check domain names aren't stored
            assert "example.com" not in data_str
            assert "private.server.com" not in data_str
            assert "files.company.org" not in data_str
    
    def test_sanitizer_comprehensive_pii_removal(self):
        """Test comprehensive PII removal from complex commands"""
        complex_commands = [
            (
                'img convert "/Users/John Doe/My Documents/Personal Photos/family_2024.jpg" '
                '-o "C:\\Output\\Processed\\vacation memories.webp" --author "john.doe@email.com" '
                '--copyright "© 2024 John Doe" --comment "Taken at 123 Main St, Anytown"',
                
                # What should NOT be in sanitized version
                ["John Doe", "My Documents", "Personal Photos", "family_2024",
                 "vacation memories", "john.doe@email.com", "123 Main St", "Anytown"]
            ),
            (
                'img batch ~/Pictures/*.{jpg,png} --output-dir ../processed_images '
                '--watermark "Property of Jane Smith" --gps-coords "40.7128,-74.0060"',
                
                # What should NOT be in sanitized version
                ["Pictures", "processed_images", "Jane Smith", "40.7128", "74.0060"]
            )
        ]
        
        for command, forbidden_strings in complex_commands:
            sanitized = PrivacySanitizer.sanitize(command)
            
            for forbidden in forbidden_strings:
                assert forbidden not in sanitized, f"Found '{forbidden}' in sanitized command"
            
            # Check that command structure is preserved
            assert "img" in sanitized
            assert "--" in sanitized or "-" in sanitized
    
    def test_export_contains_no_pii(self, temp_dir):
        """Test that exported data contains no PII"""
        with patch('app.cli.productivity.autocomplete.get_config_dir') as mock_config:
            mock_config.return_value = temp_dir
            engine = AutocompleteEngine()
            
            # Record commands with PII
            engine.record_command("img convert /home/alice/photos/portrait.jpg -f webp")
            engine.record_command("img batch C:\\Users\\Bob\\Desktop\\*.png --author bob@example.com")
            engine.record_command("img optimize ~/Documents/scan_20240101.pdf")
            
            # Export data
            export_file = temp_dir / "export.json"
            success = engine.export_learning_data(export_file)
            assert success
            
            # Check exported content
            with open(export_file, 'r') as f:
                exported = json.load(f)
            
            exported_str = json.dumps(exported)
            
            # Verify no PII in export
            forbidden = [
                "alice", "bob", "portrait", "Desktop", "Documents",
                "scan_20240101", "example.com", "home", "Users"
            ]
            
            for item in forbidden:
                assert item not in exported_str.lower()
    
    def test_import_does_not_introduce_pii(self, temp_dir):
        """Test that import process doesn't introduce PII"""
        with patch('app.cli.productivity.autocomplete.get_config_dir') as mock_config:
            mock_config.return_value = temp_dir
            engine = AutocompleteEngine()
            
            # Create import file with attempted PII injection
            malicious_import = {
                "commands": {
                    "convert": 10,
                    "/etc/passwd": 100,  # Attempted path injection
                    "user@example.com": 50,  # Attempted email injection
                },
                "exported_at": "2025-01-01T00:00:00",
                "total_commands": 160
            }
            
            import_file = temp_dir / "import.json"
            with open(import_file, 'w') as f:
                json.dump(malicious_import, f)
            
            # Import data
            engine.import_learning_data(import_file)
            
            # Check that only valid commands were imported
            assert engine.learner.patterns["commands"]["convert"] == 10
            assert "/etc/passwd" not in engine.learner.patterns["commands"]
            assert "user@example.com" not in engine.learner.patterns["commands"]
    
    def test_file_permissions_are_restrictive(self, temp_dir):
        """Test that all created files have restrictive permissions"""
        learner = CommandLearner(temp_dir)
        learner.learn("img convert <FILE> -f webp")
        learner._save_patterns()
        
        # Check key file permissions
        key_file = temp_dir / ".key"
        assert key_file.exists()
        assert key_file.stat().st_mode & 0o777 == 0o600
        
        # Check patterns file permissions
        patterns_file = temp_dir / "patterns.json"
        assert patterns_file.exists()
        # File should be readable by owner only
        assert patterns_file.stat().st_mode & 0o077 == 0
    
    def test_encryption_is_always_enabled(self, temp_dir):
        """Test that learning data is always encrypted"""
        learner = CommandLearner(temp_dir)
        learner.learn("img convert <FILE> -f webp")
        learner._save_patterns()
        
        patterns_file = temp_dir / "patterns.json"
        
        # Try to read as plain JSON (should fail)
        with open(patterns_file, 'rb') as f:
            raw_data = f.read()
        
        # Should not be valid JSON (because it's encrypted)
        with pytest.raises(json.JSONDecodeError):
            json.loads(raw_data)
        
        # Should be decryptable with the key
        decrypted = learner.fernet.decrypt(raw_data)
        data = json.loads(decrypted.decode())
        assert "commands" in data
    
    def test_sanitizer_handles_edge_cases(self):
        """Test sanitizer with edge cases"""
        edge_cases = [
            ("", ""),  # Empty command
            ("img", "img"),  # Command only
            ("   img convert   ", "img convert"),  # Extra whitespace
            ("IMG CONVERT FILE.JPG", "IMG CONVERT <FILE>"),  # Uppercase
            ("img convert 日本語.jpg", "img convert <FILE>"),  # Unicode filename
            ("img convert file.jpg" * 100, None),  # Very long command
        ]
        
        for input_cmd, expected in edge_cases:
            sanitized = PrivacySanitizer.sanitize(input_cmd)
            
            if expected is not None:
                if expected == "":
                    assert sanitized == ""
                else:
                    # Just check that no filename patterns remain
                    assert not re.search(r'\.(jpg|jpeg|png|gif|webp)', sanitized, re.IGNORECASE)
            else:
                # For very long commands, just ensure they don't crash
                assert isinstance(sanitized, str)