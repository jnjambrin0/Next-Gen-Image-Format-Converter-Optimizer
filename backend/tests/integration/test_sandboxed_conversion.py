"""Integration tests for sandboxed image conversions."""

import asyncio
import os
from io import BytesIO
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from PIL import Image

from app.config import settings
from app.core.conversion.manager import ConversionManager
from app.core.exceptions import ConversionError
from app.models.conversion import (ConversionRequest, ConversionSettings,
                                   OutputFormat)


class TestSandboxedConversion:
    """Integration tests for sandboxed image conversion pipeline."""

    @pytest.fixture
    def test_image_data(self) -> None:
        """Create test image data."""
        # Create a simple test image
        img = Image.new("RGB", (100, 100), color="red")
        buffer = BytesIO()
        img.save(buffer, format="JPEG")
        buffer.seek(0)
        return buffer.read()

    @pytest.fixture
    def conversion_manager(self) -> None:
        """Create ConversionManager instance with sandboxing enabled."""
        # Ensure sandboxing is enabled
        original_setting = settings.enable_sandboxing
        settings.enable_sandboxing = True

        manager = ConversionManager()

        # Restore original setting after test
        yield manager
        settings.enable_sandboxing = original_setting

    @pytest.fixture
    def conversion_request(self) -> None:
        """Create a test conversion request."""
        return ConversionRequest(
            output_format=OutputFormat.PNG,
            settings=ConversionSettings(quality=85, strip_metadata=True, optimize=True),
        )

    @pytest.mark.asyncio
    async def test_sandboxed_conversion_success(
        self, conversion_manager, test_image_data, conversion_request
    ):
        """Test successful sandboxed image conversion."""
        # Mock the actual convert command since it may not be installed
        with patch("subprocess.Popen") as mock_popen:
            # Create a mock output image
            output_img = Image.new("RGB", (100, 100), color="blue")
            output_buffer = BytesIO()
            output_img.save(output_buffer, format="PNG")
            output_data = output_buffer.getvalue()

            # Setup mock process
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_process.returncode = 0
            mock_process.pid = 12345
            mock_process.poll = Mock(return_value=0)
            mock_popen.return_value = mock_process

            # Mock file operations to simulate conversion output
            original_exists = os.path.exists
            original_open = open

            def mock_exists(path) -> None:
                if "_converted.png" in path:
                    return True
                return original_exists(path)

            def mock_open_func(path, mode="r") -> None:
                if "_converted.png" in path and "rb" in mode:
                    return BytesIO(output_data)
                return original_open(path, mode)

            with patch("os.path.exists", side_effect=mock_exists):
                with patch("builtins.open", side_effect=mock_open_func):
                    # Perform conversion
                    result = await conversion_manager.convert_image(
                        input_data=test_image_data,
                        input_format="jpeg",
                        request=conversion_request,
                    )

            # Verify result
            assert result.status.value == "completed"
            assert result.input_format.value == "jpeg"
            assert result.output_format.value == "png"
            assert result.processing_time > 0

            # Verify sandbox metrics were recorded
            assert "sandbox_execution_time" in result.quality_settings
            assert "sandbox_memory_used_mb" in result.quality_settings
            assert "sandbox_violations" in result.quality_settings
            assert result.quality_settings["sandbox_violations"] == 0

    @pytest.mark.asyncio
    async def test_sandboxed_conversion_with_security_violation(
        self, conversion_manager, test_image_data
    ):
        """Test sandboxed conversion handles security violations."""
        # Create request that would trigger security violation
        malicious_request = ConversionRequest(
            output_format=OutputFormat.PNG, settings=ConversionSettings()
        )

        # Mock security scan to fail
        with patch.object(
            conversion_manager.security_engine,
            "scan_file",
            return_value={
                "is_safe": False,
                "threats_found": ["Suspicious pattern detected: <script"],
            },
        ):
            with pytest.raises(ConversionError, match="Security scan failed"):
                await conversion_manager.convert_image(
                    input_data=test_image_data,
                    input_format="jpeg",
                    request=malicious_request,
                )

    @pytest.mark.asyncio
    async def test_sandboxed_conversion_resource_limit_exceeded(
        self, conversion_manager, test_image_data, conversion_request
    ):
        """Test sandboxed conversion handles resource limit violations."""
        with patch("subprocess.Popen") as mock_popen:
            # Setup mock process that exceeds memory limit
            mock_process = Mock()
            mock_process.communicate = AsyncMock(
                side_effect=MemoryError("Memory limit exceeded")
            )
            mock_process.returncode = -9
            mock_process.pid = 12345
            mock_process.poll = Mock(return_value=-9)
            mock_popen.return_value = mock_process

            with pytest.raises(MemoryError):
                await conversion_manager.convert_image(
                    input_data=test_image_data,
                    input_format="jpeg",
                    request=conversion_request,
                )

    @pytest.mark.asyncio
    async def test_sandboxed_conversion_timeout(
        self, conversion_manager, test_image_data, conversion_request
    ):
        """Test sandboxed conversion handles timeouts."""
        import subprocess

        with patch("subprocess.Popen") as mock_popen:
            # Setup mock process that times out
            mock_process = Mock()
            mock_process.communicate = AsyncMock(
                side_effect=subprocess.TimeoutExpired(cmd=["convert"], timeout=30)
            )
            mock_process.pid = 12345
            mock_process.poll = Mock(return_value=None)
            mock_process.kill = Mock()
            mock_popen.return_value = mock_process

            # Also mock killpg to avoid errors
            with patch("os.killpg"):
                with patch("os.getpgid", return_value=12345):
                    with pytest.raises(asyncio.TimeoutError):
                        await conversion_manager.convert_with_output(
                            input_data=test_image_data,
                            input_format="jpeg",
                            request=conversion_request,
                            timeout=0.1,  # Very short timeout
                        )

    @pytest.mark.asyncio
    async def test_sandboxed_conversion_cleanup(
        self, conversion_manager, test_image_data, conversion_request
    ):
        """Test that sandbox cleanup happens properly."""
        cleanup_called = False

        def mock_cleanup(conversion_id) -> None:
            nonlocal cleanup_called
            cleanup_called = True

        # Replace cleanup method
        original_cleanup = conversion_manager.security_engine.cleanup_sandbox
        conversion_manager.security_engine.cleanup_sandbox = mock_cleanup

        try:
            with patch("subprocess.Popen") as mock_popen:
                # Setup mock process that fails
                mock_process = Mock()
                mock_process.communicate = AsyncMock(
                    side_effect=Exception("Conversion failed")
                )
                mock_process.pid = 12345
                mock_popen.return_value = mock_process

                with pytest.raises(Exception):
                    await conversion_manager.convert_image(
                        input_data=test_image_data,
                        input_format="jpeg",
                        request=conversion_request,
                    )

            # Verify cleanup was called
            assert cleanup_called

        finally:
            # Restore original method
            conversion_manager.security_engine.cleanup_sandbox = original_cleanup

    @pytest.mark.asyncio
    async def test_sandbox_strictness_levels(self, conversion_manager):
        """Test different sandbox strictness levels."""
        # Test each strictness level
        for strictness in ["standard", "strict", "paranoid"]:
            settings.sandbox_strictness = strictness

            # Create sandbox
            sandbox = conversion_manager.security_engine.create_sandbox(
                conversion_id="test-123", strictness=strictness
            )

            # Verify resource limits match configuration
            limits = conversion_manager.security_engine._get_resource_limits(strictness)
            assert sandbox.config.max_memory_mb == limits["memory_mb"]
            assert sandbox.config.max_cpu_percent == limits["cpu_percent"]
            assert sandbox.config.timeout_seconds == limits["timeout_seconds"]
            assert sandbox.config.max_output_size_mb == limits["max_output_mb"]

    @pytest.mark.asyncio
    async def test_metadata_stripping(self, conversion_manager, test_image_data):
        """Test that metadata is properly stripped when requested."""
        request = ConversionRequest(
            output_format=OutputFormat.JPEG,
            settings=ConversionSettings(strip_metadata=True),
        )

        # Mock the strip_metadata method
        stripped_data = b"stripped_image_data"
        with patch.object(
            conversion_manager.security_engine,
            "strip_metadata",
            return_value=stripped_data,
        ) as mock_strip:
            with patch("subprocess.Popen") as mock_popen:
                # Setup successful conversion
                mock_process = Mock()
                mock_process.communicate = AsyncMock(return_value=(b"", b""))
                mock_process.returncode = 0
                mock_process.pid = 12345
                mock_process.poll = Mock(return_value=0)
                mock_popen.return_value = mock_process

                # Mock file operations
                with patch("os.path.exists", return_value=True):
                    with patch("builtins.open", mock_open(read_data=b"converted_data")):
                        result = await conversion_manager.convert_image(
                            input_data=test_image_data,
                            input_format="jpeg",
                            request=request,
                        )

            # Verify strip_metadata was called
            mock_strip.assert_called_once()


def mock_open(read_data=None) -> None:
    """Helper to create a mock file object."""
    m = Mock()
    m.__enter__ = Mock(return_value=BytesIO(read_data or b""))
    m.__exit__ = Mock(return_value=None)
    return Mock(return_value=m)
