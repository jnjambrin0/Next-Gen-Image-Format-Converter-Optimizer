"""Unit tests for the SecurityEngine."""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
import io
from PIL import Image

from app.core.security.engine import SecurityEngine
from app.core.exceptions import ConversionError


class TestSecurityEngine:
    """Test cases for SecurityEngine."""

    @pytest.fixture
    def security_engine(self):
        """Create SecurityEngine instance."""
        return SecurityEngine()

    @pytest.mark.asyncio
    async def test_scan_file_valid_jpeg(self, security_engine):
        """Test scanning a valid JPEG file."""
        # JPEG magic bytes + minimal valid data
        jpeg_data = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        
        report = await security_engine.scan_file(jpeg_data)
        
        assert report["is_safe"] is True
        assert len(report["threats_found"]) == 0
        assert report["detected_format"] == "JPEG"

    @pytest.mark.asyncio
    async def test_scan_file_valid_png(self, security_engine):
        """Test scanning a valid PNG file."""
        # PNG magic bytes
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        
        report = await security_engine.scan_file(png_data)
        
        assert report["is_safe"] is True
        assert len(report["threats_found"]) == 0
        assert report["detected_format"] == "PNG"

    @pytest.mark.asyncio
    async def test_scan_file_valid_webp(self, security_engine):
        """Test scanning a valid WebP file."""
        # WebP: RIFF header + WEBP fourcc
        webp_data = b"RIFF\x00\x00\x00\x00WEBPVP8 \x00\x00\x00\x00"
        
        report = await security_engine.scan_file(webp_data)
        
        assert report["is_safe"] is True
        assert len(report["threats_found"]) == 0
        assert report["detected_format"] == "WebP"

    @pytest.mark.asyncio
    async def test_scan_file_valid_avif(self, security_engine):
        """Test scanning a valid AVIF file."""
        # AVIF: ftyp box with 'avif' brand
        avif_data = b"\x00\x00\x00\x20ftypavif\x00\x00\x00\x00avifmif1miaf"
        
        report = await security_engine.scan_file(avif_data)
        
        assert report["is_safe"] is True
        assert len(report["threats_found"]) == 0
        assert report["detected_format"] == "AVIF"

    @pytest.mark.asyncio
    async def test_scan_file_valid_heif(self, security_engine):
        """Test scanning a valid HEIF file."""
        # HEIF: ftyp box with 'heic' brand
        heif_data = b"\x00\x00\x00\x20ftypheic\x00\x00\x00\x00heicmif1miaf"
        
        report = await security_engine.scan_file(heif_data)
        
        assert report["is_safe"] is True
        assert len(report["threats_found"]) == 0
        assert report["detected_format"] == "HEIF"

    @pytest.mark.asyncio
    async def test_scan_file_script_injection(self, security_engine):
        """Test detecting script injection."""
        malicious_data = b"<script>alert('xss')</script>"
        
        report = await security_engine.scan_file(malicious_data)
        
        assert report["is_safe"] is False
        assert len(report["threats_found"]) > 0
        assert "Suspicious pattern detected: <script" in report["threats_found"][0]

    @pytest.mark.asyncio
    async def test_scan_file_php_code(self, security_engine):
        """Test detecting PHP code."""
        malicious_data = b"<?php system($_GET['cmd']); ?>"
        
        report = await security_engine.scan_file(malicious_data)
        
        assert report["is_safe"] is False
        assert len(report["threats_found"]) > 0
        assert "Suspicious pattern detected: <?php" in report["threats_found"][0]

    @pytest.mark.asyncio
    async def test_scan_file_shell_script(self, security_engine):
        """Test detecting shell scripts."""
        malicious_data = b"#!/bin/bash\nrm -rf /"
        
        report = await security_engine.scan_file(malicious_data)
        
        assert report["is_safe"] is False
        assert len(report["threats_found"]) > 0
        assert "Suspicious pattern detected: #!/bin/" in report["threats_found"][0]

    @pytest.mark.asyncio
    async def test_scan_file_windows_executable(self, security_engine):
        """Test detecting Windows PE executable."""
        malicious_data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF"
        
        report = await security_engine.scan_file(malicious_data)
        
        assert report["is_safe"] is False
        assert len(report["threats_found"]) > 0

    @pytest.mark.asyncio
    async def test_scan_file_elf_executable(self, security_engine):
        """Test detecting Linux ELF executable."""
        malicious_data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        
        report = await security_engine.scan_file(malicious_data)
        
        assert report["is_safe"] is False
        assert len(report["threats_found"]) > 0

    @pytest.mark.asyncio
    async def test_scan_file_zip_archive(self, security_engine):
        """Test detecting ZIP archive."""
        malicious_data = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        
        report = await security_engine.scan_file(malicious_data)
        
        assert report["is_safe"] is False
        assert len(report["threats_found"]) > 0

    @pytest.mark.asyncio
    async def test_scan_file_too_small(self, security_engine):
        """Test file that's too small to be valid."""
        tiny_data = b"ABC"
        
        report = await security_engine.scan_file(tiny_data)
        
        assert report["is_safe"] is False
        assert "File too small to be a valid image" in report["threats_found"]

    @pytest.mark.asyncio
    async def test_scan_file_too_large(self, security_engine):
        """Test file that exceeds size limit."""
        with patch('app.config.settings.max_file_size', 100):
            large_data = b"x" * 200
            
            report = await security_engine.scan_file(large_data)
            
            assert report["is_safe"] is False
            assert any("exceeds maximum size" in threat for threat in report["threats_found"])

    @pytest.mark.asyncio
    async def test_scan_file_valid_with_null_bytes(self, security_engine):
        """Test valid image with null bytes (should pass)."""
        # Valid JPEG with null bytes in data
        jpeg_with_nulls = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xDB\x00\x43\x00\x08\x06\x06"
        
        report = await security_engine.scan_file(jpeg_with_nulls)
        
        assert report["is_safe"] is True
        assert len(report["threats_found"]) == 0

    @pytest.mark.asyncio
    async def test_scan_file_pil_fallback(self, security_engine):
        """Test PIL fallback for unrecognized format."""
        # Create a minimal valid image that doesn't match magic bytes
        img = Image.new('RGB', (1, 1), color='red')
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='BMP')
        img_data = img_buffer.getvalue()
        
        report = await security_engine.scan_file(img_data)
        
        assert report["is_safe"] is True

    @pytest.mark.asyncio
    async def test_scan_file_decompression_bomb(self, security_engine):
        """Test detection of decompression bomb."""
        # Mock PIL to raise DecompressionBombError
        with patch('PIL.Image.open') as mock_open:
            mock_img = MagicMock()
            mock_img.verify.side_effect = Image.DecompressionBombError("Potential bomb")
            mock_open.return_value = mock_img
            
            unknown_data = b"UNKNOWN_FORMAT_HEADER_12345678"
            report = await security_engine.scan_file(unknown_data)
            
            assert report["is_safe"] is False
            assert "Potential decompression bomb detected" in report["threats_found"]

    @pytest.mark.asyncio
    async def test_scan_file_unknown_format(self, security_engine):
        """Test handling of unknown format."""
        unknown_data = b"UNKNOWN_FORMAT_THAT_IS_NOT_AN_IMAGE_12345678"
        
        report = await security_engine.scan_file(unknown_data)
        
        assert report["is_safe"] is False
        assert "File does not appear to be a valid image format" in report["threats_found"]

    @pytest.mark.asyncio
    async def test_create_sandbox(self, security_engine):
        """Test sandbox creation."""
        sandbox = security_engine.create_sandbox("test-conversion-id", "standard")
        
        assert sandbox is not None
        assert "test-conversion-id" in security_engine._sandboxes

    @pytest.mark.asyncio
    async def test_strip_metadata(self, security_engine):
        """Test metadata stripping."""
        # Create a simple test image
        test_data = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        
        stripped_data, metadata = await security_engine.strip_metadata(
            test_data, "jpeg", preserve_metadata=False
        )
        
        assert stripped_data is not None
        assert metadata is not None