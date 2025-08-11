"""
Unit tests for image preview generation
"""

import io
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from PIL import Image

from app.cli.ui.preview import (
    ImagePreview,
    PreviewMode,
    create_ascii_preview,
    show_image_comparison,
)


class TestImagePreview:
    """Test ImagePreview class"""

    @pytest.fixture
    def mock_console(self):
        """Mock Rich console"""
        return Mock()

    @pytest.fixture
    def mock_detector(self):
        """Mock terminal detector"""
        with patch("app.cli.ui.preview.get_terminal_detector") as mock:
            detector = Mock()
            detector.supports_truecolor.return_value = True
            detector.supports_unicode.return_value = True
            detector.get_terminal_size.return_value = (80, 24)
            mock.return_value = detector
            yield detector

    @pytest.fixture
    def mock_image(self):
        """Create a mock image"""
        img = Image.new("RGB", (100, 100), color="red")
        return img

    @pytest.fixture
    def temp_image_file(self, tmp_path, mock_image):
        """Create a temporary image file"""
        img_path = tmp_path / "test_image.jpg"
        mock_image.save(img_path)
        return img_path

    def test_preview_init(self, mock_console, mock_detector):
        """Test preview generator initialization"""
        preview = ImagePreview(console=mock_console)

        assert preview.console == mock_console
        assert preview.detector is not None

    def test_preview_modes(self, mock_console, mock_detector):
        """Test all preview modes are available"""
        preview = ImagePreview(console=mock_console)

        # Check all modes exist
        assert PreviewMode.ASCII
        assert PreviewMode.ANSI
        assert PreviewMode.BRAILLE
        assert PreviewMode.BLOCKS
        assert PreviewMode.GRADIENT

    def test_generate_preview_file_not_found(self, mock_console, mock_detector):
        """Test preview generation with non-existent file"""
        preview = ImagePreview(console=mock_console)

        result = preview.generate_preview(Path("/nonexistent/file.jpg"))
        assert "Error: File not found" in result

    def test_generate_preview_file_too_large(
        self, mock_console, mock_detector, tmp_path
    ):
        """Test preview generation with oversized file"""
        preview = ImagePreview(console=mock_console)

        # Create a fake large file
        large_file = tmp_path / "large.jpg"
        large_file.touch()

        with patch.object(Path, "stat") as mock_stat:
            mock_stat.return_value.st_size = 60 * 1024 * 1024  # 60MB

            result = preview.generate_preview(large_file)
            assert "File too large for preview" in result

    def test_generate_preview_ascii(self, mock_console, mock_detector, temp_image_file):
        """Test ASCII preview generation"""
        preview = ImagePreview(console=mock_console)

        result = preview.generate_preview(
            temp_image_file,
            mode=PreviewMode.ASCII,
            width=20,
            height=10,
            show_info=False,
        )

        # Should return ASCII art
        assert isinstance(result, str)
        assert len(result) > 0
        # ASCII art should use ASCII characters
        assert any(c in result for c in ImagePreview.ASCII_CHARS)

    def test_generate_preview_blocks(
        self, mock_console, mock_detector, temp_image_file
    ):
        """Test block character preview generation"""
        preview = ImagePreview(console=mock_console)

        result = preview.generate_preview(
            temp_image_file,
            mode=PreviewMode.BLOCKS,
            width=20,
            height=10,
            show_info=False,
        )

        # Should return block art
        assert isinstance(result, str)
        assert len(result) > 0

    def test_generate_preview_with_info(
        self, mock_console, mock_detector, temp_image_file
    ):
        """Test preview with image info"""
        preview = ImagePreview(console=mock_console)

        with patch.object(preview, "_get_image_info") as mock_info:
            mock_info.return_value = "Image Info"

            result = preview.generate_preview(
                temp_image_file, mode=PreviewMode.ASCII, show_info=True
            )

            assert "Image Info" in result

    def test_generate_preview_invalid_image(
        self, mock_console, mock_detector, tmp_path
    ):
        """Test preview with corrupted image"""
        preview = ImagePreview(console=mock_console)

        # Create invalid image file
        invalid_file = tmp_path / "invalid.jpg"
        invalid_file.write_text("not an image")

        result = preview.generate_preview(invalid_file)
        assert "Error" in result

    def test_generate_preview_dimension_limits(
        self, mock_console, mock_detector, tmp_path
    ):
        """Test preview with oversized dimensions"""
        preview = ImagePreview(console=mock_console)

        # Mock opening an image with huge dimensions
        with patch("app.cli.ui.preview.Image.open") as mock_open:
            mock_img = Mock()
            mock_img.width = 15000
            mock_img.height = 15000
            mock_open.return_value = mock_img

            img_path = tmp_path / "huge.jpg"
            img_path.touch()

            result = preview.generate_preview(img_path)
            assert "dimensions too large" in result

    def test_resize_image(self, mock_console, mock_detector, mock_image):
        """Test image resizing logic"""
        preview = ImagePreview(console=mock_console)

        resized = preview._resize_image(mock_image, 50, 25)

        # Check dimensions are reasonable
        assert resized.width <= 50
        assert resized.height <= 25

    def test_generate_ansi_with_transparency(self, mock_console, mock_detector):
        """Test ANSI generation with RGBA image"""
        preview = ImagePreview(console=mock_console)

        # Create RGBA image with transparency
        img = Image.new("RGBA", (10, 10), (255, 0, 0, 128))

        with patch.object(preview.console, "capture") as mock_capture:
            mock_capture.return_value.__enter__.return_value.get.return_value = "output"

            result = preview._generate_ansi(img)

            assert isinstance(result, str)

    def test_generate_braille(self, mock_console, mock_detector, mock_image):
        """Test Braille pattern generation"""
        preview = ImagePreview(console=mock_console)

        # Convert to grayscale for Braille
        gray_img = mock_image.convert("L")

        result = preview._generate_braille(gray_img)

        assert isinstance(result, str)
        # Should contain Braille characters
        assert any(ord(c) >= 0x2800 and ord(c) <= 0x28FF for c in result if c != "\n")

    def test_create_side_by_side(self, mock_console, mock_detector, temp_image_file):
        """Test side-by-side preview creation"""
        preview = ImagePreview(console=mock_console)

        with patch.object(preview, "generate_preview") as mock_gen:
            mock_gen.return_value = "preview\nlines"

            result = preview.create_side_by_side(
                temp_image_file, temp_image_file, mode=PreviewMode.ASCII, width=40
            )

            # Should call generate_preview twice
            assert mock_gen.call_count == 2
            # Result should combine previews
            assert isinstance(result, str)

    def test_create_thumbnail_grid(self, mock_console, mock_detector, temp_image_file):
        """Test thumbnail grid creation"""
        preview = ImagePreview(console=mock_console)

        with patch.object(preview, "generate_preview") as mock_gen:
            mock_gen.return_value = "thumb"

            result = preview.create_thumbnail_grid(
                [temp_image_file, temp_image_file], columns=2, mode=PreviewMode.BLOCKS
            )

            assert mock_gen.call_count == 2
            assert isinstance(result, str)

    def test_memory_cleanup(self, mock_console, mock_detector, temp_image_file):
        """Test memory cleanup after preview generation"""
        preview = ImagePreview(console=mock_console)

        # Mock image close method
        with patch("app.cli.ui.preview.Image.open") as mock_open:
            mock_img = Mock()
            mock_img.mode = "RGB"
            mock_img.width = 100
            mock_img.height = 100
            mock_img.close = Mock()
            mock_open.return_value = mock_img

            with patch.object(preview, "_generate_ascii") as mock_gen:
                mock_gen.return_value = "preview"

                result = preview.generate_preview(temp_image_file)

                # Image should be closed
                mock_img.close.assert_called()


class TestPreviewHelpers:
    """Test preview helper functions"""

    def test_create_ascii_preview(self, tmp_path):
        """Test convenience function for ASCII preview"""
        img_path = tmp_path / "test.jpg"
        img = Image.new("RGB", (10, 10), "blue")
        img.save(img_path)

        result = create_ascii_preview(img_path, width=10, height=5, mode="ascii")

        assert isinstance(result, str)
        assert len(result) > 0

    @patch("app.cli.ui.preview.Console")
    def test_show_image_comparison(self, mock_console_class, tmp_path):
        """Test image comparison display"""
        mock_console = Mock()
        mock_console_class.return_value = mock_console

        # Create two test images
        img1 = tmp_path / "original.jpg"
        img2 = tmp_path / "converted.jpg"

        Image.new("RGB", (10, 10), "red").save(img1)
        Image.new("RGB", (10, 10), "blue").save(img2)

        with patch("app.cli.ui.preview.ImagePreview.create_side_by_side") as mock_side:
            mock_side.return_value = "comparison"

            show_image_comparison(img1, img2, console=mock_console)

            # Should create comparison and print it
            mock_side.assert_called_once()
            mock_console.print.assert_called()


class TestPreviewErrorHandling:
    """Test error handling in preview generation"""

    def test_fallback_to_ascii_on_error(self, tmp_path):
        """Test fallback to ASCII when preferred mode fails"""
        preview = ImagePreview()

        img_path = tmp_path / "test.jpg"
        Image.new("RGB", (10, 10)).save(img_path)

        # Mock ANSI generation to fail
        with patch.object(preview, "_generate_ansi") as mock_ansi:
            mock_ansi.side_effect = Exception("ANSI failed")

            with patch.object(preview, "_generate_ascii") as mock_ascii:
                mock_ascii.return_value = "ascii_fallback"

                result = preview.generate_preview(
                    img_path, mode=PreviewMode.ANSI, show_info=False
                )

                assert result == "ascii_fallback"

    def test_memory_error_handling(self, tmp_path):
        """Test handling of memory errors"""
        preview = ImagePreview()

        img_path = tmp_path / "test.jpg"
        img_path.touch()

        with patch("app.cli.ui.preview.Image.open") as mock_open:
            mock_open.side_effect = MemoryError("Out of memory")

            result = preview.generate_preview(img_path)
            assert "Insufficient memory" in result

    def test_mode_conversion_error(self, tmp_path):
        """Test handling of image mode conversion errors"""
        preview = ImagePreview()

        img_path = tmp_path / "test.jpg"
        Image.new("RGB", (10, 10)).save(img_path)

        with patch("app.cli.ui.preview.Image.open") as mock_open:
            mock_img = Mock()
            mock_img.mode = "CMYK"
            mock_img.width = 100
            mock_img.height = 100
            mock_img.convert.side_effect = Exception("Conversion failed")
            mock_open.return_value = mock_img

            result = preview.generate_preview(img_path)
            assert "Failed to convert image mode" in result
