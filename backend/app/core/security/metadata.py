"""Metadata stripping module for privacy protection."""

import asyncio
import io
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Tuple

import piexif
import structlog
from PIL import Image
from PIL.ExifTags import TAGS

logger = structlog.get_logger()

# Thread pool for blocking PIL operations to avoid blocking the event loop
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pil_worker")


class MetadataStripper:
    """
    Handles removal of metadata from images for privacy protection.

    This class provides comprehensive metadata stripping including:
    - EXIF data removal
    - XMP data removal
    - IPTC data removal
    - GPS location data removal
    - Embedded thumbnails removal
    - Format-specific metadata handling
    """

    async def _save_image_async(
        self, image: Image.Image, format: str, **save_kwargs
    ) -> bytes:
        """
        Save image to bytes in thread pool to avoid blocking event loop.

        Args:
            image: PIL Image object
            format: Output format
            **save_kwargs: Additional arguments for image.save()

        Returns:
            Saved image as bytes
        """
        loop = asyncio.get_event_loop()

        def save_sync() -> None:
            output_buffer = io.BytesIO()
            image.save(output_buffer, format=format, **save_kwargs)
            output_buffer.seek(0)
            return output_buffer.read()

        return await loop.run_in_executor(_executor, save_sync)

    # GPS tags that should always be removed unless explicitly preserved
    GPS_TAGS = {
        "GPSVersionID",
        "GPSLatitudeRef",
        "GPSLatitude",
        "GPSLongitudeRef",
        "GPSLongitude",
        "GPSAltitudeRef",
        "GPSAltitude",
        "GPSTimeStamp",
        "GPSSatellites",
        "GPSStatus",
        "GPSMeasureMode",
        "GPSDOP",
        "GPSSpeedRef",
        "GPSSpeed",
        "GPSTrackRef",
        "GPSTrack",
        "GPSImgDirectionRef",
        "GPSImgDirection",
        "GPSMapDatum",
        "GPSDestLatitudeRef",
        "GPSDestLatitude",
        "GPSDestLongitudeRef",
        "GPSDestLongitude",
        "GPSDestBearingRef",
        "GPSDestBearing",
        "GPSDestDistanceRef",
        "GPSDestDistance",
        "GPSProcessingMethod",
        "GPSAreaInformation",
        "GPSDateStamp",
        "GPSDifferential",
    }

    # Sensitive EXIF tags that may contain personal information
    SENSITIVE_EXIF_TAGS = {
        "ImageDescription",
        "Make",
        "Model",
        "Software",
        "DateTime",
        "Artist",
        "Copyright",
        "DateTimeOriginal",
        "DateTimeDigitized",
        "SubSecTime",
        "SubSecTimeOriginal",
        "SubSecTimeDigitized",
        "MakerNote",
        "UserComment",
        "RelatedSoundFile",
        "CameraOwnerName",
        "BodySerialNumber",
        "LensSerialNumber",
        "OwnerName",
        "SerialNumber",
        "CameraSerialNumber",
        "LensInfo",
        "LensMake",
        "LensModel",
    }

    def __init__(self) -> None:
        """Initialize the metadata stripper."""
        self.supported_formats = {
            "JPEG",
            "JPG",
            "PNG",
            "TIFF",
            "BMP",
            "WEBP",
            "HEIF",
            "HEIC",
            "AVIF",
        }

    async def analyze_and_strip_metadata(
        self,
        image_data: bytes,
        format: str,
        preserve_metadata: bool = False,
        preserve_gps: bool = False,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Analyze and optionally remove metadata from image based on settings.

        This method always analyzes what metadata exists in the image,
        then removes it according to the preservation settings.

        Args:
            image_data: Raw image data
            format: Image format
            preserve_metadata: If True, keep non-GPS metadata
            preserve_gps: If True, keep GPS data (only if preserve_metadata is also True)

        Returns:
            Tuple of (processed_image_data, metadata_summary)
        """
        format = format.upper()
        if format == "JPG":
            format = "JPEG"

        # Track what metadata was found/removed
        metadata_summary = {
            "had_exif": False,
            "had_gps": False,
            "had_xmp": False,
            "had_iptc": False,
            "had_thumbnail": False,
            "metadata_removed": [],
            "metadata_preserved": [],
            "gps_removed": False,
            "format": format,
        }

        try:
            # Load image in thread pool to avoid blocking event loop
            loop = asyncio.get_event_loop()
            image = await loop.run_in_executor(
                _executor, lambda: Image.open(io.BytesIO(image_data))
            )

            # Check what metadata exists
            metadata_summary.update(self._analyze_metadata(image))

            # If preserving all metadata, just return original
            if preserve_metadata and preserve_gps:
                metadata_summary["metadata_preserved"] = ["all"]
                return image_data, metadata_summary

            # Strip metadata based on format and settings
            if format in ["JPEG", "TIFF"]:
                stripped_data, summary = await self._strip_jpeg_tiff_metadata(
                    image, format, preserve_metadata, preserve_gps
                )
                metadata_summary.update(summary)

            elif format == "PNG":
                stripped_data, summary = await self._strip_png_metadata(
                    image, preserve_metadata
                )
                metadata_summary.update(summary)

            elif format == "WEBP":
                stripped_data, summary = await self._strip_webp_metadata(
                    image, preserve_metadata
                )
                metadata_summary.update(summary)

            elif format in ["HEIF", "HEIC", "AVIF"]:
                stripped_data, summary = await self._strip_heif_avif_metadata(
                    image, format, preserve_metadata
                )
                metadata_summary.update(summary)

            else:
                # For other formats, do basic stripping
                stripped_data = await self._basic_strip(image, format)
                metadata_summary["metadata_removed"] = ["all"]

            # Log summary (privacy-aware - no actual metadata values)
            logger.info(
                "Metadata stripping completed",
                format=format,
                had_exif=metadata_summary["had_exif"],
                had_gps=metadata_summary["had_gps"],
                gps_removed=metadata_summary["gps_removed"],
                metadata_types_removed=len(metadata_summary["metadata_removed"]),
                preserve_metadata=preserve_metadata,
                preserve_gps=preserve_gps,
            )

            return stripped_data, metadata_summary

        except Exception as e:
            logger.error(f"Failed to strip metadata: {e}")
            # Return original data if stripping fails
            return image_data, metadata_summary

    def _analyze_metadata(self, image: Image.Image) -> Dict[str, bool]:
        """Analyze what metadata is present in the image."""
        analysis = {
            "had_exif": False,
            "had_gps": False,
            "had_xmp": False,
            "had_iptc": False,
            "had_thumbnail": False,
        }

        # Check for EXIF
        if hasattr(image, "_getexif") and image._getexif():
            analysis["had_exif"] = True
            exif = image._getexif()

            # Check for GPS data (GPS IFD tag is 34853)
            if 34853 in exif:
                analysis["had_gps"] = True

        # Check for XMP
        if hasattr(image, "info") and "xmp" in image.info:
            analysis["had_xmp"] = True

        # Check for IPTC
        if hasattr(image, "info") and "iptc" in image.info:
            analysis["had_iptc"] = True

        # Check for thumbnail in EXIF
        if hasattr(image, "_getexif") and image._getexif():
            try:
                if hasattr(image, "info") and "exif" in image.info:
                    exif_dict = piexif.load(image.info["exif"])
                    if "1st" in exif_dict and exif_dict["1st"]:
                        analysis["had_thumbnail"] = True
            except:
                pass

        return analysis

    async def _strip_jpeg_tiff_metadata(
        self,
        image: Image.Image,
        format: str,
        preserve_metadata: bool,
        preserve_gps: bool,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Strip metadata from JPEG/TIFF images."""
        summary = {
            "metadata_removed": [],
            "metadata_preserved": [],
            "gps_removed": False,
        }

        try:
            # Get EXIF data if present
            exif_bytes = image.info.get("exif", b"")

            if exif_bytes and preserve_metadata:
                # Parse EXIF data
                exif_dict = piexif.load(exif_bytes)

                # Remove GPS data if not preserving it
                if not preserve_gps and "GPS" in exif_dict:
                    del exif_dict["GPS"]
                    summary["gps_removed"] = True
                    summary["metadata_removed"].append("GPS")

                # Remove sensitive tags
                for ifd in ["0th", "1st", "Exif"]:
                    if ifd in exif_dict:
                        for tag in list(exif_dict[ifd].keys()):
                            tag_name = TAGS.get(tag, tag)
                            if tag_name in self.SENSITIVE_EXIF_TAGS:
                                del exif_dict[ifd][tag]
                                if tag_name not in summary["metadata_removed"]:
                                    summary["metadata_removed"].append(tag_name)

                # Remove thumbnail
                if "1st" in exif_dict:
                    exif_dict["1st"] = {}
                    summary["metadata_removed"].append("thumbnail")

                # Rebuild EXIF
                exif_bytes = piexif.dump(exif_dict)
                summary["metadata_preserved"].append("basic_exif")

            else:
                # Remove all EXIF
                exif_bytes = b""
                summary["metadata_removed"].append("all_exif")
                if self._analyze_metadata(image)["had_gps"]:
                    summary["gps_removed"] = True

            # Prepare save kwargs
            save_kwargs = {
                "optimize": True,
                "progressive": format == "JPEG",
            }

            # Only JPEG supports quality="keep", others need numeric
            if format == "JPEG":
                save_kwargs["quality"] = "keep"

            if exif_bytes:
                save_kwargs["exif"] = exif_bytes

            # Remove other metadata
            if "xmp" in image.info and not preserve_metadata:
                summary["metadata_removed"].append("XMP")
            if "iptc" in image.info and not preserve_metadata:
                summary["metadata_removed"].append("IPTC")

            # Use async save to avoid blocking event loop
            saved_data = await self._save_image_async(image, format, **save_kwargs)
            return saved_data, summary

        except Exception as e:
            logger.error(f"Error stripping JPEG/TIFF metadata: {e}")
            return await self._basic_strip(image, format), summary

    async def _strip_png_metadata(
        self, image: Image.Image, preserve_metadata: bool
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Strip metadata from PNG images."""
        summary = {"metadata_removed": [], "metadata_preserved": []}

        # PNG metadata is in text chunks and other metadata
        metadata_keys = ["exif", "xmp", "icc_profile", "dpi", "pnginfo"]

        # Check for text metadata in pnginfo
        if hasattr(image, "info") and "pnginfo" in image.info:
            summary["metadata_removed"].append("pnginfo")

        # Check for other text chunks stored directly in info
        for key in image.info:
            if (
                isinstance(key, str)
                and key not in metadata_keys
                and key not in ["transparency", "gamma"]
            ):
                # These are likely PNG text chunks
                if key not in summary["metadata_removed"]:
                    summary["metadata_removed"].append(f"text:{key}")

        save_kwargs = {"optimize": True}

        if preserve_metadata:
            # Keep some metadata
            for key in metadata_keys:
                if key in image.info:
                    if key != "exif":  # Don't preserve EXIF in PNG
                        save_kwargs[key] = image.info[key]
                        summary["metadata_preserved"].append(key)
                    else:
                        summary["metadata_removed"].append(key)

            # Preserve text chunks if requested
            if "pnginfo" in image.info:
                save_kwargs["pnginfo"] = image.info["pnginfo"]
                if "pnginfo" in summary["metadata_removed"]:
                    summary["metadata_removed"].remove("pnginfo")
                summary["metadata_preserved"].append("pnginfo")
        else:
            # Remove all metadata - don't pass any metadata to save
            for key in metadata_keys:
                if key in image.info and key not in summary["metadata_removed"]:
                    summary["metadata_removed"].append(key)

        # Use async save to avoid blocking event loop
        saved_data = await self._save_image_async(image, "PNG", **save_kwargs)
        return saved_data, summary

    async def _strip_webp_metadata(
        self, image: Image.Image, preserve_metadata: bool
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Strip metadata from WebP images."""
        summary = {"metadata_removed": [], "metadata_preserved": []}

        # Check what metadata exists before conversion
        has_exif = "exif" in image.info
        has_xmp = "xmp" in image.info

        save_kwargs = {"optimize": True}

        # WebP can have EXIF and XMP
        if preserve_metadata:
            if has_exif:
                # Process EXIF to remove GPS
                # For now, remove all EXIF from WebP
                summary["metadata_removed"].append("exif")
            if has_xmp:
                save_kwargs["xmp"] = image.info["xmp"]
                summary["metadata_preserved"].append("xmp")
        else:
            # Remove all metadata by not passing it to save
            if has_exif:
                summary["metadata_removed"].append("exif")
            if has_xmp:
                summary["metadata_removed"].append("xmp")
            # Don't pass any metadata to save_kwargs

        # Use async save to avoid blocking event loop
        saved_data = await self._save_image_async(image, "WEBP", **save_kwargs)
        return saved_data, summary

    async def _strip_heif_avif_metadata(
        self, image: Image.Image, format: str, preserve_metadata: bool
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Strip metadata from HEIF/AVIF images."""
        # For now, use basic stripping as these formats need special handling
        summary = {"metadata_removed": ["all"], "metadata_preserved": []}

        return await self._basic_strip(image, format), summary

    async def _basic_strip(self, image: Image.Image, format: str) -> bytes:
        """Basic metadata stripping - creates new image without any metadata."""
        # Convert RGBA to RGB for JPEG
        if image.mode == "RGBA" and format in ["JPEG", "JPG"]:
            rgb_image = Image.new("RGB", image.size, (255, 255, 255))
            rgb_image.paste(
                image, mask=image.split()[3] if len(image.split()) == 4 else None
            )
            image = rgb_image

        save_kwargs = {
            "optimize": True,
        }

        # Add quality for JPEG
        if format in ["JPEG", "JPG"]:
            save_kwargs["quality"] = 85
            save_kwargs["progressive"] = True

        # Use async save to avoid blocking event loop
        format_name = format if format != "JPG" else "JPEG"
        return await self._save_image_async(image, format_name, **save_kwargs)

    def get_metadata_info(self, image_data: bytes, format: str) -> Dict[str, Any]:
        """
        Extract metadata information for logging/debugging.

        Returns summary of metadata without actual values for privacy.
        """
        try:
            image = Image.open(io.BytesIO(image_data))
            info = {
                "format": format,
                "has_exif": False,
                "has_gps": False,
                "exif_tags_count": 0,
                "has_xmp": False,
                "has_iptc": False,
                "has_thumbnail": False,
            }

            # Check EXIF
            if hasattr(image, "_getexif") and image._getexif():
                info["has_exif"] = True
                exif = image._getexif()
                info["exif_tags_count"] = len(exif)

                # Check for GPS (GPS IFD tag is 34853)
                if 34853 in exif:
                    info["has_gps"] = True

            # Check other metadata
            if hasattr(image, "info"):
                info["has_xmp"] = "xmp" in image.info
                info["has_iptc"] = "iptc" in image.info

            return info

        except Exception as e:
            logger.error(f"Error extracting metadata info: {e}")
            return {"error": str(e)}

    async def process_metadata_for_conversion(
        self,
        image_data: bytes,
        input_format: str,
        strip_metadata: bool,
        preserve_metadata: bool,
        preserve_gps: bool,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Process metadata for image conversion based on settings.

        This is a convenience method that handles the common logic of
        determining whether to strip metadata based on the flags.

        Args:
            image_data: Raw image data
            input_format: Input image format
            strip_metadata: If True, remove metadata (unless preserve_metadata overrides)
            preserve_metadata: If True, keep non-GPS metadata (overrides strip_metadata)
            preserve_gps: If True, keep GPS data (only if preserve_metadata is True)

        Returns:
            Tuple of (processed_image_data, metadata_summary)
        """
        # Determine if we should actually strip
        should_strip = strip_metadata and not preserve_metadata

        if not should_strip and not preserve_metadata:
            # No metadata handling requested, just analyze
            summary = self.get_metadata_info(image_data, input_format)
            return image_data, summary

        # Process metadata according to settings
        return await self.analyze_and_strip_metadata(
            image_data,
            input_format,
            preserve_metadata=preserve_metadata,
            preserve_gps=preserve_gps,
        )
