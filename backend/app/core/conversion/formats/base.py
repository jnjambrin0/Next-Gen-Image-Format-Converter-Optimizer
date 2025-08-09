"""Base format handler interface."""

from abc import ABC, abstractmethod
from typing import Any, BinaryIO, Dict, Optional

from PIL import Image

from app.models.conversion import ConversionSettings, ImageMetadata


class BaseFormatHandler(ABC):
    """Abstract base class for format handlers."""

    def __init__(self) -> None:
        """Initialize format handler."""
        self.supported_formats: list[str] = []
        self.format_name: str = ""

    @abstractmethod
    def can_handle(self, format_name: str) -> bool:
        """Check if this handler can process the given format."""

    @abstractmethod
    def validate_image(self, image_data: bytes) -> bool:
        """Validate that the image data is valid for this format."""

    @abstractmethod
    def load_image(self, image_data: bytes) -> Image.Image:
        """Load image from bytes."""

    @abstractmethod
    def save_image(
        self, image: Image.Image, output_buffer: BinaryIO, settings: ConversionSettings
    ) -> None:
        """Save image to buffer with given settings."""

    def extract_metadata(
        self, image: Image.Image, strip_metadata: bool = True
    ) -> ImageMetadata:
        """Extract metadata from image."""
        return ImageMetadata(
            format=image.format or self.format_name,
            width=image.width,
            height=image.height,
            color_mode=image.mode,
            has_transparency=image.mode in ("RGBA", "LA", "P")
            and "transparency" in image.info,
            has_animation=hasattr(image, "is_animated") and image.is_animated,
            frame_count=(
                getattr(image, "n_frames", 1) if hasattr(image, "n_frames") else 1
            ),
            exif=self._extract_exif(image) if not strip_metadata else None,
        )

    def _extract_exif(self, image: Image.Image) -> Optional[Dict[str, Any]]:
        """Extract EXIF data from image."""
        try:
            # Prioritize public API method
            if hasattr(image, "getexif"):
                exif = image.getexif()
                if exif:
                    return dict(exif)
            # Fallback to private method for older Pillow versions
            elif hasattr(image, "_getexif") and image._getexif():
                return dict(image._getexif())
        except Exception:
            # Silently ignore EXIF extraction errors
            pass
        return None

    def get_quality_param(self, settings: ConversionSettings) -> Dict[str, Any]:
        """Get format-specific quality parameters."""
        return {"quality": settings.quality}

    def prepare_image(self, image: Image.Image) -> Image.Image:
        """Prepare image for conversion (e.g., convert color mode if needed)."""
        # Convert RGBA to RGB for formats that don't support transparency
        if image.mode == "RGBA" and not self._supports_transparency():
            # Create white background
            background = Image.new("RGB", image.size, (255, 255, 255))
            background.paste(image, mask=image.split()[3])  # Use alpha channel as mask
            return background

        # Convert other modes to RGB if needed
        if image.mode not in ("RGB", "RGBA") and not self._supports_mode(image.mode):
            return image.convert("RGB")

        return image

    def _supports_transparency(self) -> bool:
        """Check if format supports transparency."""
        # Override in subclasses
        return False

    def _supports_mode(self, mode: str) -> bool:
        """Check if format supports the given color mode."""
        # Override in subclasses
        return mode in ("RGB", "RGBA")
