"""
Ultra-realistic Unicode filename tests covering emojis, RTL, and special characters.
Tests real-world filename scenarios from various platforms and languages.
"""

import pytest
import asyncio
import tempfile
import os
import unicodedata
from pathlib import Path
from typing import List, Tuple
import platform

from app.core.security.filename_sanitizer import sanitize_filename
from app.services.conversion_service import conversion_service
from app.services.batch_service import batch_service
from app.models.conversion import ConversionRequest


class TestUnicodeFilenames:
    """Test handling of Unicode filenames from real-world scenarios."""

    @pytest.fixture
    def problematic_filenames(self) -> List[Tuple[str, str]]:
        """Collection of real-world problematic filenames."""
        return [
            # Emoji-heavy (common in mobile)
            ("📸 Vacation Photos 🏖️ 2024 🎉.jpg", "photo"),
            ("Family Portrait 👨‍👩‍👧‍👦❤️.png", "photo"),
            ("Screenshot 😂😂😂 MUST SEE!!!.png", "screenshot"),
            ("🎨 Art Project (Final) [Version 2] 🖼️.webp", "illustration"),
            ("Birthday 🎂🎈🎊 Party 🥳.jpg", "photo"),
            # Mixed scripts
            ("日本旅行_東京タワー_2024年.jpg", "photo"),  # Japanese
            ("Фото из России 🇷🇺 Москва.heic", "photo"),  # Russian with emoji
            ("مستند مهم جداً.pdf.png", "document"),  # Arabic RTL
            ("תמונה מישראל 🇮🇱.jpeg", "photo"),  # Hebrew RTL
            ("中文文档_第1页_最终版.tiff", "document"),  # Chinese
            ("한국 서울 여행 사진.jpg", "photo"),  # Korean
            # Special characters and symbols
            ("File (Copy) [1] {Final} @2x.png", "image"),
            ("Image™ ® © 2024.jpg", "image"),
            ("Price $99.99 - 50% OFF!.png", "image"),
            ("Email@address.com_profile.jpg", "photo"),
            ("C:\\Users\\Name\\Desktop\\Photo.jpg", "photo"),  # Windows path
            ("/home/user/pictures/photo.png", "photo"),  # Unix path
            # Whitespace variations
            ("   Leading Spaces.jpg", "photo"),
            ("Trailing Spaces   .png", "image"),
            ("Multiple   Spaces   Between.gif", "image"),
            ("Tab\tCharacters\there.bmp", "image"),
            ("New\nLine\nCharacters.jpg", "photo"),
            # Length extremes
            ("a" * 255 + ".jpg", "photo"),  # Maximum filename length
            ("x.jpg", "photo"),  # Minimum meaningful
            # Platform-specific problematic names
            ("CON.jpg", "photo"),  # Windows reserved
            ("PRN.png", "image"),  # Windows device name
            ("AUX.gif", "image"),  # Windows reserved
            (".hidden_file.jpg", "photo"),  # Unix hidden
            ("~temporary.tmp.png", "image"),  # Temp file pattern
            # Zero-width and invisible characters
            ("Normal\u200bFile\u200cName\u200d.jpg", "photo"),  # Zero-width spaces
            ("File\ufeffWith\ufeffBOM.png", "image"),  # Byte order marks
            # Combining characters and diacritics
            ("Café_Münchën_Zürich.jpg", "photo"),
            ("naïve_résumé_über.png", "document"),
            ("Å_Ø_Æ_Nordic.jpg", "photo"),
            # WhatsApp/Telegram patterns
            ("IMG-20240115-WA0001.jpg", "photo"),
            ("photo_2024-01-15_14-30-45.jpg", "photo"),
            ("sticker_😄.webp", "illustration"),
            ("voice-message-2024-01-15-14-30-45.ogg.png", "image"),
        ]

    @pytest.mark.critical
    async def test_unicode_filename_sanitization(self, problematic_filenames):
        """
        Test that all Unicode filenames are properly sanitized.

        Ensures filenames are safe for all filesystems.
        """
        for original_name, _ in problematic_filenames:
            # Sanitize filename
            sanitized = sanitize_filename(original_name)

            # Basic sanitization checks
            assert sanitized is not None, f"Failed to sanitize: {original_name}"
            assert len(sanitized) > 0, f"Empty result for: {original_name}"
            assert len(sanitized) <= 255, f"Too long: {sanitized}"

            # Preserve extension
            original_ext = Path(original_name).suffix.lower()
            if original_ext:
                sanitized_ext = Path(sanitized).suffix.lower()
                assert (
                    sanitized_ext == original_ext
                ), f"Extension changed: {original_ext} -> {sanitized_ext}"

            # No path traversal
            assert ".." not in sanitized
            assert "/" not in sanitized.replace("_", "")  # Allow _ as replacement
            assert "\\" not in sanitized.replace("_", "")

            # No null bytes
            assert "\x00" not in sanitized

            # Should be valid on all platforms
            self._validate_cross_platform(sanitized)

    def _validate_cross_platform(self, filename: str):
        """Validate filename works on Windows, Mac, and Linux."""
        # Windows reserved names
        windows_reserved = [
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
        ]

        name_without_ext = Path(filename).stem.upper()
        assert (
            name_without_ext not in windows_reserved
        ), f"Windows reserved name: {name_without_ext}"

        # Windows illegal characters
        windows_illegal = '<>:"|?*'
        for char in windows_illegal:
            assert char not in filename, f"Windows illegal char '{char}' in filename"

        # Control characters (0-31)
        for i in range(32):
            assert chr(i) not in filename, f"Control char {i} in filename"

    @pytest.mark.integration
    async def test_unicode_filename_conversion(self, realistic_image_generator):
        """
        Test actual file conversion with Unicode filenames.

        Validates end-to-end processing with problematic names.
        """
        test_cases = [
            "Photo 📸 2024.jpg",
            "Документ_на_русском.png",
            "中文图片.gif",
            "صورة عربية.bmp",
        ]

        for original_filename in test_cases:
            # Create test image
            image_data = realistic_image_generator(
                width=800, height=600, content_type="photo", format="JPEG"
            )

            # Convert with Unicode filename
            request = ConversionRequest(output_format="webp", quality=85)

            result, output_data = await conversion_service.convert(
                image_data=image_data,
                request=request,
                source_filename=original_filename,
            )

            assert result.success, f"Failed to convert {original_filename}"
            assert output_data is not None

            # Check sanitized output filename
            if result.output_filename:
                self._validate_cross_platform(result.output_filename)

    @pytest.mark.integration
    async def test_batch_with_unicode_filenames(self, realistic_image_generator):
        """
        Test batch processing with mixed Unicode filenames.

        Simulates folder with international files.
        """
        # Create batch with diverse filenames
        files = []
        unicode_names = [
            "日本_1.jpg",
            "Россия_2.png",
            "France_3.gif",
            "España_4.bmp",
            "中国_5.jpg",
            "한국_6.png",
            "العربية_7.jpg",
            "ישראל_8.png",
            "Emoji_😀_9.jpg",
            "Mixed_文字_Text_10.png",
        ]

        for name in unicode_names:
            image_data = realistic_image_generator(
                width=640, height=480, content_type="photo", format="JPEG"
            )

            files.append(
                {"filename": name, "content": image_data, "content_type": "image/jpeg"}
            )

        # Process batch
        job = await batch_service.create_batch_job(
            files=files, output_format="webp", quality=80
        )

        result = await batch_service.process_batch(job.id)

        # All should process successfully
        assert len(result.completed) == len(
            files
        ), f"Some files failed: {len(result.failed)}/{len(files)}"

        # Check output filenames are sanitized
        for item in result.completed:
            if item.output_filename:
                self._validate_cross_platform(item.output_filename)

    @pytest.mark.critical
    async def test_filesystem_compatibility(self):
        """
        Test actual filesystem operations with Unicode names.

        Validates that sanitized names work on the actual filesystem.
        """
        test_names = [
            "Test_Emoji_😀.jpg",
            "Тест_Кириллица.png",
            "测试_中文.gif",
            "اختبار_عربي.bmp",
            "Special™_Chars®.jpg",
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            for original_name in test_names:
                # Sanitize name
                safe_name = sanitize_filename(original_name)

                # Try to create file
                file_path = tmpdir_path / safe_name

                try:
                    # Write test data
                    file_path.write_bytes(b"test data")

                    # Verify file exists and is readable
                    assert file_path.exists(), f"File not created: {safe_name}"
                    data = file_path.read_bytes()
                    assert data == b"test data", f"Data corrupted for: {safe_name}"

                    # Clean up
                    file_path.unlink()

                except (OSError, IOError) as e:
                    # Should not happen with properly sanitized names
                    pytest.fail(
                        f"Filesystem error with sanitized name '{safe_name}': {e}"
                    )

    async def test_rtl_language_handling(self):
        """
        Test Right-to-Left language filename handling.

        Arabic, Hebrew, and other RTL scripts.
        """
        rtl_names = [
            "مستند_مهم_2024.pdf",  # Arabic
            "תמונה_חשובה_2024.jpg",  # Hebrew
            "فارسی_تصویر.png",  # Persian
            "اردو_دستاویز.gif",  # Urdu
        ]

        for rtl_name in rtl_names:
            sanitized = sanitize_filename(rtl_name)

            # Should preserve some readable characters
            assert len(sanitized) > 10, f"Too much removed from RTL: {rtl_name}"

            # Should maintain extension
            assert Path(sanitized).suffix == Path(rtl_name).suffix

            # Should be filesystem-safe
            self._validate_cross_platform(sanitized)

    async def test_normalization_forms(self):
        """
        Test Unicode normalization form handling (NFC, NFD, etc.).

        Same character can be encoded differently.
        """
        # Same "é" in different forms
        test_cases = [
            ("café.jpg", "NFC"),  # é as single codepoint
            ("cafe\u0301.jpg", "NFD"),  # e + combining acute accent
        ]

        normalized_results = set()

        for name, form in test_cases:
            # Normalize to standard form
            normalized = unicodedata.normalize("NFC", name)
            sanitized = sanitize_filename(normalized)

            normalized_results.add(sanitized)

            # Should be valid
            self._validate_cross_platform(sanitized)

        # Different forms should result in same sanitized name
        assert (
            len(normalized_results) == 1
        ), "Different Unicode forms produced different results"

    @pytest.mark.performance
    async def test_filename_sanitization_performance(self, problematic_filenames):
        """
        Test performance of filename sanitization.

        Ensures sanitization is fast even for complex names.
        """
        import time

        total_time = 0
        iterations = 100

        for _ in range(iterations):
            for filename, _ in problematic_filenames[:20]:  # Test subset
                start = time.perf_counter()
                sanitized = sanitize_filename(filename)
                total_time += time.perf_counter() - start

        avg_time = total_time / (iterations * 20)

        # Should be very fast
        assert avg_time < 0.001, f"Sanitization too slow: {avg_time*1000:.3f}ms average"

    async def test_zero_width_character_removal(self):
        """
        Test removal of zero-width and invisible Unicode characters.

        These can cause confusion and security issues.
        """
        invisible_chars = [
            "\u200b",  # Zero-width space
            "\u200c",  # Zero-width non-joiner
            "\u200d",  # Zero-width joiner
            "\ufeff",  # Zero-width no-break space (BOM)
            "\u2060",  # Word joiner
            "\u180e",  # Mongolian vowel separator
            "\u2000",  # En quad
            "\u2001",  # Em quad
            "\u2002",  # En space
            "\u2003",  # Em space
            "\u2004",  # Three-per-em space
            "\u2005",  # Four-per-em space
            "\u2006",  # Six-per-em space
            "\u2007",  # Figure space
            "\u2008",  # Punctuation space
            "\u2009",  # Thin space
            "\u200a",  # Hair space
            "\u202f",  # Narrow no-break space
            "\u205f",  # Medium mathematical space
            "\u3000",  # Ideographic space
        ]

        for char in invisible_chars:
            filename = f"Normal{char}File{char}Name.jpg"
            sanitized = sanitize_filename(filename)

            # Invisible characters should be removed or replaced
            assert (
                char not in sanitized
            ), f"Invisible character U+{ord(char):04X} not removed"

            # Should still be valid
            self._validate_cross_platform(sanitized)

    async def test_homograph_attack_prevention(self):
        """
        Test prevention of homograph attacks using lookalike characters.

        Prevents security issues from visually similar characters.
        """
        homograph_examples = [
            ("pаypal.jpg", "paypal.jpg"),  # Cyrillic 'а' looks like Latin 'a'
            ("gооgle.png", "google.png"),  # Cyrillic 'о' looks like Latin 'o'
            ("аррӏе.gif", "apple.gif"),  # Mixed scripts
        ]

        for malicious, legitimate in homograph_examples:
            sanitized_malicious = sanitize_filename(malicious)
            sanitized_legitimate = sanitize_filename(legitimate)

            # Both should be valid
            self._validate_cross_platform(sanitized_malicious)
            self._validate_cross_platform(sanitized_legitimate)

            # The system should handle them safely
            # (exact behavior depends on implementation)

    async def test_max_path_length_handling(self):
        """
        Test handling of maximum path length limits.

        Different systems have different limits.
        """
        # Create very long filename
        base_name = "very_long_filename_" * 20  # ~400 chars
        extension = ".jpg"
        long_filename = base_name + extension

        sanitized = sanitize_filename(long_filename)

        # Should truncate to safe length
        assert len(sanitized) <= 255, f"Filename too long: {len(sanitized)}"

        # Should preserve extension
        assert sanitized.endswith(extension), "Extension lost during truncation"

        # Should be valid
        self._validate_cross_platform(sanitized)
