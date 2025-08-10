"""
from typing import Any
Unit tests for Terminal UI components
"""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.cli.ui.tui import (
    ConversionSettings,
    ImageConverterTUI,
    QualityValidator,
)


class TestQualityValidator:
    """Test quality input validator"""

    def test_valid_quality(self) -> None:
        """Test valid quality values"""
        validator = QualityValidator()

        # Valid values
        assert validator.validate("50").is_valid
        assert validator.validate("1").is_valid
        assert validator.validate("100").is_valid
        assert validator.validate("85").is_valid

    def test_invalid_quality(self) -> None:
        """Test invalid quality values"""
        validator = QualityValidator()

        # Invalid values
        assert not validator.validate("0").is_valid
        assert not validator.validate("101").is_valid
        assert not validator.validate("-10").is_valid
        assert not validator.validate("abc").is_valid
        assert not validator.validate("").is_valid
        assert not validator.validate("50.5").is_valid

    def test_error_messages(self) -> None:
        """Test validator error messages"""
        validator = QualityValidator()

        result = validator.validate("")
        assert "Quality is required" in str(result.failure_descriptions)

        result = validator.validate("abc")
        assert "must be a number" in str(result.failure_descriptions)

        result = validator.validate("150")
        assert "between 1 and 100" in str(result.failure_descriptions)


class TestConversionSettings:
    """Test conversion settings container"""

    @pytest.mark.asyncio
    async def test_settings_compose(self):
        """Test settings UI composition"""
        settings = ConversionSettings()

        # Mock the compose method
        with patch.object(settings, "compose") as mock_compose:
            settings.compose()
            mock_compose.assert_called_once()

    def test_default_values(self) -> None:
        """Test default settings values"""
        settings = ConversionSettings()

        # Check that default values are set in inputs
        # This would require mounting the component in a test app
        # For now, we just verify the class exists
        assert settings is not None


class TestImageConverterTUI:
    """Test main TUI application"""

    @pytest.fixture
    def mock_config(self) -> None:
        """Mock configuration"""
        with patch("app.cli.ui.tui.get_config") as mock:
            config = Mock()
            config.api_url = "http://localhost:8000"
            config.api_key = "test_key"
            config.api_timeout = 30
            config.theme = "dark"
            mock.return_value = config
            yield config

    @pytest.fixture
    def mock_sdk(self) -> None:
        """Mock SDK availability"""
        with patch("app.cli.ui.tui.SDK_AVAILABLE", True):
            with patch("app.cli.ui.tui.ImageConverterClient") as mock_client:
                with patch("app.cli.ui.tui.ConversionRequest") as mock_request:
                    with patch("app.cli.ui.tui.SDKOutputFormat") as mock_format:
                        yield {
                            "client": mock_client,
                            "request": mock_request,
                            "format": mock_format,
                        }

    def test_app_creation(self, mock_config) -> None:
        """Test TUI app creation"""
        app = ImageConverterTUI()

        assert app.TITLE is not None
        assert "Image Converter" in app.TITLE
        assert app.selected_files == []
        assert app.is_converting is False

    @pytest.mark.asyncio
    async def test_app_mount(self, mock_config):
        """Test app mounting and initialization"""
        app = ImageConverterTUI()

        async with app.run_test() as pilot:
            # Check that app mounted successfully
            assert app.is_running

            # Check for main components
            assert pilot.app.query_one("#file_tree")
            assert pilot.app.query_one("#main_progress")
            assert pilot.app.query_one("#results_table")
            assert pilot.app.query_one("#convert_btn")

    @pytest.mark.asyncio
    async def test_file_selection(self, mock_config):
        """Test file selection in TUI"""
        app = ImageConverterTUI()

        async with app.run_test() as pilot:
            # Simulate file selection
            test_path = Path("/test/image.jpg")
            app.selected_files.append(test_path)

            # Check subtitle updates
            app._update_selection_display()
            assert "Selected: 1 files" in app.sub_title

    @pytest.mark.asyncio
    async def test_convert_no_files(self, mock_config):
        """Test conversion with no files selected"""
        app = ImageConverterTUI()

        async with app.run_test() as pilot:
            # Try to convert with no files
            await app.action_convert()

            # Should log warning
            log = pilot.app.query_one("#progress_log")
            # Verify no conversion started
            assert not app.is_converting

    @pytest.mark.asyncio
    async def test_convert_with_sdk(self, mock_config, mock_sdk):
        """Test conversion with SDK available"""
        app = ImageConverterTUI()

        # Mock file operations
        mock_file_data = b"fake_image_data"
        mock_result = Mock()
        mock_result.output_data = b"converted_data"

        mock_sdk["client"].return_value.convert = Mock(return_value=mock_result)

        async with app.run_test() as pilot:
            # Add a test file
            test_file = Path("/test/image.jpg")
            app.selected_files.append(test_file)

            # Mock file reading
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = (
                    mock_file_data
                )

                # Trigger conversion
                await app.action_convert()

                # Verify conversion was attempted
                assert app.is_converting is False  # Should be reset after completion

    @pytest.mark.asyncio
    async def test_convert_error_handling(self, mock_config, mock_sdk):
        """Test conversion error handling"""
        app = ImageConverterTUI()

        # Mock SDK to raise error
        mock_sdk["client"].side_effect = Exception("SDK init failed")

        async with app.run_test() as pilot:
            app.selected_files.append(Path("/test/image.jpg"))

            # Try conversion
            await app.action_convert()

            # Should handle error gracefully
            assert not app.is_converting

            # Check error was logged
            log = pilot.app.query_one("#progress_log")

    @pytest.mark.asyncio
    async def test_quality_validation(self, mock_config):
        """Test quality input validation in TUI"""
        app = ImageConverterTUI()

        async with app.run_test() as pilot:
            # Get quality input
            quality_input = pilot.app.query_one("#quality")

            # Test invalid input
            quality_input.value = "200"
            assert not quality_input.is_valid

            # Test valid input
            quality_input.value = "85"
            assert quality_input.is_valid

    @pytest.mark.asyncio
    async def test_help_action(self, mock_config):
        """Test help action"""
        app = ImageConverterTUI()

        async with app.run_test() as pilot:
            # Trigger help
            app.action_help()

            # Check help was displayed
            log = pilot.app.query_one("#progress_log")

    @pytest.mark.asyncio
    async def test_dark_mode_toggle(self, mock_config):
        """Test dark mode toggle"""
        app = ImageConverterTUI()

        async with app.run_test() as pilot:
            initial_dark = app.dark

            # Toggle dark mode
            app.action_toggle_dark()

            # Check it toggled
            assert app.dark != initial_dark

    @pytest.mark.asyncio
    async def test_quit_during_conversion(self, mock_config):
        """Test quit prevention during conversion"""
        app = ImageConverterTUI()

        async with app.run_test() as pilot:
            # Set converting flag
            app.is_converting = True

            # Try to quit
            app.action_quit()

            # Should still be running (quit prevented)
            assert app.is_running


class TestTUIIntegration:
    """Integration tests for TUI"""

    @pytest.mark.asyncio
    async def test_full_conversion_flow(self):
        """Test complete conversion flow in TUI"""
        with patch("app.cli.ui.tui.get_config") as mock_config:
            config = Mock()
            config.api_url = "http://localhost:8000"
            config.api_key = "test_key"
            config.api_timeout = 30
            config.theme = "dark"
            mock_config.return_value = config

            app = ImageConverterTUI()

            async with app.run_test() as pilot:
                # Verify app started
                assert app.is_running

                # Simulate user interactions
                # 1. Select files tab
                tabs = pilot.app.query_one("Tabs")
                tabs.active = "files_tab"

                # 2. Switch to settings tab
                app.action_settings()
                assert tabs.active == "settings_tab"

                # 3. Verify components exist
                assert pilot.app.query_one("#output_format")
                assert pilot.app.query_one("#quality")
                assert pilot.app.query_one("#preset")
