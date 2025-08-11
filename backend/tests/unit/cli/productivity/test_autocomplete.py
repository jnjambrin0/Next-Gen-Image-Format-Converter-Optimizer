"""
Unit tests for the autocomplete engine
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from app.cli.productivity.autocomplete import (
    AutocompleteEngine,
    CommandLearner,
    PrivacySanitizer,
)


class TestPrivacySanitizer:
    """Test privacy sanitization functionality"""

    def test_sanitize_removes_unix_paths(self):
        """Test that Unix paths are removed"""
        command = "img convert /home/user/photos/vacation.jpg -f webp"
        sanitized = PrivacySanitizer.sanitize(command)
        assert "/home/user/photos/vacation.jpg" not in sanitized
        assert "<PATH>" in sanitized or "<FILE>" in sanitized

    def test_sanitize_removes_windows_paths(self):
        """Test that Windows paths are removed"""
        command = "img convert C:\\Users\\John\\Documents\\photo.png -f avif"
        sanitized = PrivacySanitizer.sanitize(command)
        assert "C:\\Users\\John\\Documents\\photo.png" not in sanitized
        assert "<PATH>" in sanitized or "<FILE>" in sanitized

    def test_sanitize_removes_relative_paths(self):
        """Test that relative paths are removed"""
        command = "img batch ./images/*.jpg --format webp"
        sanitized = PrivacySanitizer.sanitize(command)
        assert "./images/*.jpg" not in sanitized
        assert "<PATH>" in sanitized

    def test_sanitize_removes_filenames(self):
        """Test that filenames are removed"""
        command = "img convert photo.jpg output.webp -q 85"
        sanitized = PrivacySanitizer.sanitize(command)
        assert "photo.jpg" not in sanitized
        assert "output.webp" not in sanitized
        assert "<FILE>" in sanitized

    def test_sanitize_removes_email_addresses(self):
        """Test that email addresses are removed"""
        command = "img convert photo.jpg --author john.doe@example.com"
        sanitized = PrivacySanitizer.sanitize(command)
        assert "john.doe@example.com" not in sanitized
        assert "<EMAIL>" in sanitized

    def test_sanitize_removes_ip_addresses(self):
        """Test that IP addresses are removed"""
        command = "img convert --server 192.168.1.100 photo.jpg"
        sanitized = PrivacySanitizer.sanitize(command)
        assert "192.168.1.100" not in sanitized
        assert "<IP>" in sanitized

    def test_sanitize_removes_urls(self):
        """Test that URLs are removed"""
        command = "img convert https://example.com/image.jpg -f webp"
        sanitized = PrivacySanitizer.sanitize(command)
        assert "https://example.com/image.jpg" not in sanitized
        assert "<URL>" in sanitized

    def test_sanitize_removes_quoted_strings(self):
        """Test that quoted strings are removed"""
        command = 'img convert "My Personal Photo.jpg" -o "output file.webp"'
        sanitized = PrivacySanitizer.sanitize(command)
        assert "My Personal Photo.jpg" not in sanitized
        assert "output file.webp" not in sanitized
        assert '"<STRING>"' in sanitized

    def test_sanitize_preserves_command_structure(self):
        """Test that command structure is preserved"""
        command = "img convert photo.jpg -f webp -q 85 --preset web"
        sanitized = PrivacySanitizer.sanitize(command)
        assert "img convert" in sanitized
        assert "-f webp" in sanitized
        assert "-q 85" in sanitized
        assert "--preset web" in sanitized


class TestCommandLearner:
    """Test command learning functionality"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def learner(self, temp_dir):
        """Create CommandLearner instance"""
        return CommandLearner(temp_dir)

    def test_learner_creates_encryption_key(self, temp_dir):
        """Test that encryption key is created"""
        learner = CommandLearner(temp_dir)
        key_file = temp_dir / ".key"
        assert key_file.exists()
        assert key_file.stat().st_mode & 0o777 == 0o600

    def test_learner_loads_existing_key(self, temp_dir):
        """Test that existing key is loaded"""
        from cryptography.fernet import Fernet

        key_file = temp_dir / ".key"
        # Create a valid Fernet key
        valid_key = Fernet.generate_key()
        key_file.write_bytes(valid_key)

        learner1 = CommandLearner(temp_dir)
        learner2 = CommandLearner(temp_dir)

        # Both should load the same key
        assert learner1.encryption_key == learner2.encryption_key

    def test_learn_updates_command_frequency(self, learner):
        """Test that command frequency is updated"""
        learner.learn("img convert <FILE> -f webp")
        learner.learn("img convert <FILE> -f avif")
        learner.learn("img batch <PATH> -f webp")

        assert learner.patterns["commands"]["img"] == 3
        assert learner.patterns["commands"]["convert"] == 2
        assert learner.patterns["commands"]["batch"] == 1

    def test_learn_tracks_parameters(self, learner):
        """Test that parameters are tracked"""
        learner.learn("img convert <FILE> -f webp -q 85")
        learner.learn("img convert <FILE> -f avif -q 90")

        param_key = "img_params"
        assert learner.patterns["parameters"][param_key]["-f"] == 2
        assert learner.patterns["parameters"][param_key]["-q"] == 2

    def test_learn_tracks_sequences(self, learner):
        """Test that command sequences are tracked"""
        learner.learn("img convert <FILE>", previous_command="img")
        learner.learn("img batch <PATH>", previous_command="img")
        learner.learn("img optimize <FILE>", previous_command="img")

        assert learner.patterns["sequences"]["_sequences"]["img -> img"] == 3

    def test_learn_tracks_context(self, learner):
        """Test that context patterns are tracked"""
        learner.learn("img convert <FILE>", context="photo_dir")
        learner.learn("img optimize <FILE>", context="photo_dir")
        learner.learn("img batch <PATH>", context="document_dir")

        assert learner.patterns["contexts"]["photo_dir"]["img"] == 2
        assert learner.patterns["contexts"]["document_dir"]["img"] == 1

    def test_get_suggestions_basic(self, learner):
        """Test basic suggestion generation"""
        learner.learn("img convert <FILE>")
        learner.learn("img convert <FILE>")
        learner.learn("img batch <PATH>")
        learner.learn("img optimize <FILE>")

        suggestions = learner.get_suggestions("img", limit=3)
        assert "img" in suggestions

        suggestions = learner.get_suggestions("con", limit=3)
        assert any("convert" in s for s in suggestions)

    def test_get_suggestions_with_context(self, learner):
        """Test context-aware suggestions"""
        learner.learn("img convert <FILE>", context="photo_dir")
        learner.learn("img convert <FILE>", context="photo_dir")
        learner.learn("img batch <PATH>", context="document_dir")

        # Without context
        suggestions = learner.get_suggestions("img", limit=3)
        assert len(suggestions) > 0

        # With photo context - convert should be boosted
        suggestions = learner.get_suggestions("img", context="photo_dir", limit=3)
        assert len(suggestions) > 0

    def test_save_and_load_patterns(self, temp_dir):
        """Test that patterns are saved and loaded correctly"""
        learner1 = CommandLearner(temp_dir)
        learner1.learn("img convert <FILE>")
        learner1.learn("img batch <PATH>")
        learner1._save_patterns()

        # Create new learner that should load saved patterns
        learner2 = CommandLearner(temp_dir)
        assert learner2.patterns["commands"]["img"] == 2
        assert learner2.patterns["commands"]["convert"] == 1
        assert learner2.patterns["commands"]["batch"] == 1

    def test_cleanup_old_data(self, learner):
        """Test that old data is cleaned up"""
        from datetime import datetime, timedelta

        # Set old timestamp
        learner.patterns["last_updated"] = (
            datetime.now() - timedelta(days=10)
        ).isoformat()
        learner.patterns["commands"]["img"] = 5

        # Cleanup data older than 7 days
        learner.cleanup_old_data(days=7)

        # Patterns should be reset
        assert learner.patterns["commands"]["img"] == 0


class TestAutocompleteEngine:
    """Test the main autocomplete engine"""

    @pytest.fixture
    def engine(self):
        """Create AutocompleteEngine instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch(
                "app.cli.productivity.autocomplete.get_config_dir"
            ) as mock_config:
                mock_config.return_value = Path(tmpdir)
                yield AutocompleteEngine()

    def test_engine_initializes_components(self, engine):
        """Test that engine initializes all components"""
        assert engine.sanitizer is not None
        assert engine.learner is not None
        assert engine.command_registry is not None
        assert engine.previous_command is None

    def test_record_command_sanitizes_input(self, engine):
        """Test that commands are sanitized before learning"""
        with patch.object(engine.learner, "learn") as mock_learn:
            engine.record_command("img convert /home/user/photo.jpg -f webp")

            # Check that learn was called with sanitized command
            mock_learn.assert_called_once()
            args = mock_learn.call_args[0]
            assert "/home/user/photo.jpg" not in args[0]
            assert "<FILE>" in args[0] or "<PATH>" in args[0]

    def test_get_suggestions_for_commands(self, engine):
        """Test command suggestions"""
        suggestions = engine.get_suggestions("")
        assert len(suggestions) > 0
        assert any("convert" in s[0] for s in suggestions)
        assert any("batch" in s[0] for s in suggestions)
        assert any("optimize" in s[0] for s in suggestions)

    def test_get_suggestions_for_partial_commands(self, engine):
        """Test partial command suggestions"""
        suggestions = engine.get_suggestions("con")
        assert any("convert" in s[0] for s in suggestions)

        suggestions = engine.get_suggestions("ba")
        assert any("batch" in s[0] for s in suggestions)

    def test_get_suggestions_for_parameters(self, engine):
        """Test parameter suggestions"""
        suggestions = engine.get_suggestions("convert -")
        assert any("-f" in s[0] or "--format" in s[0] for s in suggestions)
        assert any("-q" in s[0] or "--quality" in s[0] for s in suggestions)

    def test_get_suggestions_filters_used_parameters(self, engine):
        """Test that used parameters are filtered"""
        suggestions = engine.get_suggestions("convert -f webp -")

        # -f should not be suggested again
        assert not any("-f" == s[0] for s in suggestions)
        # But other parameters should be suggested
        assert any("-q" in s[0] or "--quality" in s[0] for s in suggestions)

    def test_get_parameter_values(self, engine):
        """Test parameter value suggestions"""
        values = engine.get_parameter_values("convert", "-f")
        assert "webp" in values
        assert "avif" in values
        assert "jpeg" in values

        values = engine.get_parameter_values("convert", "-q")
        assert "85" in values
        assert "90" in values

        values = engine.get_parameter_values("convert", "--preset")
        assert "web" in values
        assert "print" in values

    def test_export_learning_data(self, engine):
        """Test export of learning data"""
        engine.record_command("img convert photo.jpg -f webp")
        engine.record_command("img batch *.png -f avif")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            export_path = Path(f.name)

        try:
            success = engine.export_learning_data(export_path)
            assert success

            # Check exported data
            with open(export_path, "r") as f:
                data = json.load(f)

            assert "commands" in data
            assert "exported_at" in data
            assert "total_commands" in data

            # Check that no PII is in exported data
            export_str = json.dumps(data)
            assert "photo.jpg" not in export_str
            assert "*.png" not in export_str
        finally:
            export_path.unlink(missing_ok=True)

    def test_import_learning_data(self, engine):
        """Test import of learning data"""
        import_data = {
            "commands": {"convert": 10, "batch": 5, "optimize": 3},
            "exported_at": "2025-01-01T00:00:00",
            "total_commands": 18,
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(import_data, f)
            import_path = Path(f.name)

        try:
            success = engine.import_learning_data(import_path)
            assert success

            # Check that commands were imported
            assert engine.learner.patterns["commands"]["convert"] == 10
            assert engine.learner.patterns["commands"]["batch"] == 5
            assert engine.learner.patterns["commands"]["optimize"] == 3
        finally:
            import_path.unlink(missing_ok=True)

    def test_import_rejects_invalid_commands(self, engine):
        """Test that import rejects commands not in registry"""
        import_data = {
            "commands": {
                "convert": 10,
                "malicious_command": 100,  # Not in registry
                "batch": 5,
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(import_data, f)
            import_path = Path(f.name)

        try:
            success = engine.import_learning_data(import_path)
            assert success

            # Valid commands should be imported
            assert engine.learner.patterns["commands"]["convert"] == 10
            assert engine.learner.patterns["commands"]["batch"] == 5

            # Invalid command should not be imported
            assert "malicious_command" not in engine.learner.patterns["commands"]
        finally:
            import_path.unlink(missing_ok=True)

    def test_command_registry_completeness(self, engine):
        """Test that command registry has all required commands"""
        required_commands = [
            "convert",
            "batch",
            "optimize",
            "analyze",
            "formats",
            "presets",
            "profile",
            "watch",
            "macro",
        ]

        for cmd in required_commands:
            assert cmd in engine.command_registry
            assert "params" in engine.command_registry[cmd]
            assert "description" in engine.command_registry[cmd]
            assert "requires_file" in engine.command_registry[cmd]
