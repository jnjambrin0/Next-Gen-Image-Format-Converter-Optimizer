"""Constants and configuration values for the image converter."""

from typing import Any, TypedDict


# Type definitions for configuration dictionaries
class BlockedMessages(TypedDict):
    network: str
    dns: str
    udp: str
    p2p: str


class NetworkConfigType(TypedDict):
    violation_threshold: int
    termination_grace_period: int
    monitoring_interval: int
    monitoring_jitter: float
    check_timeout: int
    baseline_max_connections: int
    blocked_messages: BlockedMessages


# Security and Processing Limits
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_IMAGE_PIXELS = 178956970  # ~178MP (same as PIL default)
IMAGE_MAX_PIXELS = MAX_IMAGE_PIXELS  # Alias for compatibility

# Batch Processing Limits
MAX_BATCH_SIZE = 100  # Maximum files per batch
MAX_BATCH_WORKERS = 10  # Maximum concurrent workers for batch processing
BATCH_CHUNK_SIZE = 10  # Process files in chunks for memory efficiency
BATCH_RESULT_EXPIRY_SECONDS = 3600  # 1 hour to download results
BATCH_JOB_RETENTION_DAYS = 7  # Days to retain completed batch jobs

# Intelligence Engine Limits
INTELLIGENCE_MODEL_MAX_SIZE = 50 * 1024 * 1024  # 50MB max model size
INTELLIGENCE_TIMEOUT_MS = 500  # 500ms timeout for classification

# Sandbox Configuration
SANDBOX_TIMEOUTS = {"standard": 30, "strict": 20, "paranoid": 10}

SANDBOX_MEMORY_LIMITS = {
    "standard": 512,  # MB
    "strict": 256,  # MB
    "paranoid": 128,  # MB
}

SANDBOX_CPU_LIMITS = {
    "standard": 80,  # Percent
    "strict": 60,  # Percent
    "paranoid": 40,  # Percent
}

SANDBOX_OUTPUT_LIMITS = {
    "standard": 100,  # MB
    "strict": 50,  # MB
    "paranoid": 25,  # MB
}

# Supported Image Formats
SUPPORTED_INPUT_FORMATS = {
    "jpeg",
    "jpg",
    "png",
    "webp",
    "gif",
    "bmp",
    "tiff",
    "tif",
    "heif",
    "heic",
    "avif",
}

SUPPORTED_OUTPUT_FORMATS = {
    "jpeg",
    "jpg",
    "png",
    "webp",
    "gif",
    "bmp",
    "tiff",
    "tif",
    "heif",
    "heic",
    "avif",
    "jxl",
    "jpegxl",
    "jpeg_xl",
    "jp2",
    "jpeg2000",
    "webp2",
    "png_optimized",
    "jpeg_optimized",
}

# Format aliases mapping to canonical names
FORMAT_ALIASES = {
    # JPEG variants
    "jpg": "jpeg",
    "jpeg_optimized": "jpeg_opt",
    "jpg_optimized": "jpeg_opt",
    # PNG variants
    "png_optimized": "png_opt",
    # JPEG XL variants
    "jpegxl": "jxl",
    "jpeg_xl": "jxl",
    # JPEG 2000 variants
    "jpeg2000": "jp2",
    "j2k": "jp2",
    "jpf": "jp2",
    "jpx": "jp2",
    "jpm": "jp2",
    # TIFF variants
    "tif": "tiff",
    # HEIF variants
    "heic": "heif",
    "heix": "heif",
    "hevc": "heif",
    "hevx": "heif",
}

# Canonical format list (these are the primary format names)
CANONICAL_FORMATS = {
    # Basic formats
    "jpeg",
    "png",
    "webp",
    "gif",
    "bmp",
    "tiff",
    # Modern formats
    "heif",
    "avif",
    "jxl",
    "jp2",
    "webp2",
    # Optimized variants
    "jpeg_opt",
    "png_opt",
}

# Image Quality Defaults
DEFAULT_QUALITY = 85
MIN_QUALITY = 1
MAX_QUALITY = 100

# Format-specific settings
WEBP_METHOD = 4  # Good compression/speed tradeoff
PNG_COMPRESS_LEVEL = 9

# Error Codes
ERROR_CODES = {
    "ARGS_ERROR": "Missing or invalid arguments",
    "VALIDATION_ERROR": "Input validation failed",
    "SIZE_ERROR": "File size exceeds limits",
    "INPUT_ERROR": "Input data error",
    "INVALID_IMAGE": "Invalid image format or data",
    "DECOMPRESSION_BOMB": "Image exceeds decompression limits",
    "CONVERSION_ERROR": "Image conversion failed",
    "FORMAT_ERROR": "Unsupported format",
    "METADATA_ERROR": "Metadata processing failed",
    "SAVE_ERROR": "Failed to save output",
    "OUTPUT_ERROR": "Output validation failed",
    "SECURITY_VIOLATION": "Security policy violation detected",
    "UNEXPECTED_ERROR": "Unexpected system error",
}

# Magic bytes for format detection
IMAGE_MAGIC_BYTES = {
    # Common formats
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"RIFF": "WebP/RIFF",  # WebP starts with RIFF (needs further check)
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"II*\x00": "TIFF",
    b"MM\x00*": "TIFF",
    b"BM": "BMP",
    # Modern formats
    b"\x00\x00\x00\x0c\x6a\x50\x20\x20": "JPEG2000",  # JP2
    b"\x00\x00\x00\x20\x66\x74\x79\x70": "HEIF/AVIF",  # ftyp box (needs further check)
    b"\xff\x0a": "JPEG_XL",  # JPEG XL codestream
    b"\x00\x00\x00\x0c\x4a\x58\x4c\x20": "JPEG_XL_ISO",  # JPEG XL ISO container
    # Additional formats
    b"FORM": "IFF",  # IFF format
    b"\x00\x00\x01\x00": "ICO",  # Windows icon
    b"icns": "ICNS",  # macOS icon
}

# MIME Type Mappings
FORMAT_TO_MIME_TYPE = {
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "png": "image/png",
    "webp": "image/webp",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "tiff": "image/tiff",
    "tif": "image/tiff",
    "heif": "image/heif",
    "heic": "image/heic",
    "avif": "image/avif",
    "jxl": "image/jxl",
    "jpegxl": "image/jxl",
    "jp2": "image/jp2",
    "jpeg2000": "image/jp2",
    "webp2": "image/webp2",
    "ico": "image/x-icon",
    "icns": "image/icns",
}

# Allowed MIME types for upload validation
ALLOWED_UPLOAD_MIME_TYPES = [
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
    "image/gif",
    "image/bmp",
    "image/tiff",
    "image/heif",
    "image/heic",
    "image/avif",
    "image/jxl",
    "image/jp2",
    "application/octet-stream",  # Allow generic binary for files with unknown MIME
]

# Content types for API responses
FORMAT_TO_CONTENT_TYPE = {
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "png": "image/png",
    "webp": "image/webp",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "tiff": "image/tiff",
    "heif": "image/heif",
    "heic": "image/heic",
    "avif": "image/avif",
    "jxl": "image/jxl",
    "jp2": "image/jp2",
    "webp2": "image/webp2",
}

# Suspicious patterns for security scanning
SUSPICIOUS_PATTERNS = [
    # Script injections
    b"<script",  # JavaScript injection
    b"<?php",  # PHP code
    b"<% ",  # ASP/JSP injection
    b"<?xml",  # XML that could contain XXE
    # Shell/executable patterns
    b"#!/bin/",  # Shell scripts
    b"#!/usr/bin/",  # Shell scripts
    b"#!/usr/local/bin/",  # Shell scripts
    b"#!",  # Generic shebang (if at start)
    # Binary executables
    b"MZ\x90\x00",  # PE executable (Windows)
    b"\x7fELF",  # ELF executable (Linux)
    b"\xce\xfa\xed\xfe",  # Mach-O executable (macOS)
    b"\xfe\xed\xfa\xce",  # Mach-O executable (macOS, reverse)
    b"\xca\xfe\xba\xbe",  # Java class file
    # Archive formats that could contain executables
    b"PK\x03\x04",  # ZIP archive
    b"Rar!",  # RAR archive
    b"7z\xbc\xaf\x27\x1c",  # 7-Zip archive
]

# Container format detection
HEIF_AVIF_BRANDS = {
    b"avif": "AVIF",
    b"avis": "AVIF",
    b"heic": "HEIF",
    b"heix": "HEIF",
    b"hevc": "HEIF",
    b"hevx": "HEIF",
    b"mif1": "HEIF",
    b"msf1": "HEIF",
}

# Performance tuning
THREAD_POOL_SIZE = 4
PROCESS_POOL_SIZE = 2

# Monitoring and metrics
METRICS_ENABLED = True
HEALTH_CHECK_TIMEOUT = 5.0

# Network Security Configuration
NETWORK_CONFIG: NetworkConfigType = {
    "violation_threshold": 3,
    "termination_grace_period": 2,
    "monitoring_interval": 5,
    "monitoring_jitter": 0.1,
    "check_timeout": 1,
    "baseline_max_connections": 100,
    "blocked_messages": {
        "network": "Network access is disabled in sandboxed environment",
        "dns": "DNS resolution is disabled in sandboxed environment",
        "udp": "UDP sockets are disabled in sandboxed environment",
        "p2p": "P2P/WebRTC module '{}' is blocked in sandboxed environment",
    },
}

# Legacy constants for backward compatibility
NETWORK_VIOLATION_THRESHOLD = NETWORK_CONFIG["violation_threshold"]
PROCESS_TERMINATION_GRACE_PERIOD = NETWORK_CONFIG["termination_grace_period"]
DEFAULT_MONITORING_INTERVAL = NETWORK_CONFIG["monitoring_interval"]
MONITORING_JITTER_PERCENT = NETWORK_CONFIG["monitoring_jitter"]
NETWORK_CHECK_TIMEOUT = NETWORK_CONFIG["check_timeout"]
NETWORK_BASELINE_MAX_CONNECTIONS = NETWORK_CONFIG["baseline_max_connections"]
NETWORK_BLOCKED_MSG = NETWORK_CONFIG["blocked_messages"]["network"]
DNS_BLOCKED_MSG = NETWORK_CONFIG["blocked_messages"]["dns"]
UDP_BLOCKED_MSG = NETWORK_CONFIG["blocked_messages"]["udp"]
P2P_MODULE_BLOCKED_MSG = NETWORK_CONFIG["blocked_messages"]["p2p"]

# Rate Limiting Configuration
RATE_LIMIT_CONFIG = {
    "events_per_minute": 60,
    "events_per_hour": 1000,
    "burst_size": 10,
    "hour_burst_divisor": 10,
    "token_refill_amount": 1,
    "default_capacity": 100,
    "default_refill_rate": 10.0,
}

# Monitoring Configuration
MONITORING_CONFIG = {
    "default_hours": 24,
    "error_retention_days": 30,
    "security_retention_days": 90,
    "hourly_stats_hours": 168,  # 7 days
    "daily_stats_days": 90,
    "max_processing_times": 1000,
    "interval_seconds": 5.0,
    "jitter_seconds": 1.0,
    "connection_timeout": 2.0,
    "max_baseline_connections": 50,
}

# Legacy constants for backward compatibility
RATE_LIMIT_EVENTS_PER_MINUTE = RATE_LIMIT_CONFIG["events_per_minute"]
RATE_LIMIT_EVENTS_PER_HOUR = RATE_LIMIT_CONFIG["events_per_hour"]
RATE_LIMIT_BURST_SIZE = RATE_LIMIT_CONFIG["burst_size"]
RATE_LIMIT_HOUR_BURST_DIVISOR = RATE_LIMIT_CONFIG["hour_burst_divisor"]
RATE_LIMIT_TOKEN_REFILL_AMOUNT = RATE_LIMIT_CONFIG["token_refill_amount"]
DEFAULT_RATE_LIMIT_CAPACITY = RATE_LIMIT_CONFIG["default_capacity"]
DEFAULT_RATE_LIMIT_REFILL_RATE = RATE_LIMIT_CONFIG["default_refill_rate"]

DEFAULT_MONITORING_HOURS = MONITORING_CONFIG["default_hours"]
ERROR_RETENTION_DAYS = MONITORING_CONFIG["error_retention_days"]
SECURITY_EVENT_RETENTION_DAYS = MONITORING_CONFIG["security_retention_days"]
HOURLY_STATS_RETENTION_HOURS = MONITORING_CONFIG["hourly_stats_hours"]
DAILY_STATS_RETENTION_DAYS = MONITORING_CONFIG["daily_stats_days"]
MAX_PROCESSING_TIMES_MEMORY = MONITORING_CONFIG["max_processing_times"]
MONITORING_INTERVAL_SECONDS = MONITORING_CONFIG["interval_seconds"]
MONITORING_JITTER_SECONDS = MONITORING_CONFIG["jitter_seconds"]
CONNECTION_CHECK_TIMEOUT = MONITORING_CONFIG["connection_timeout"]
MAX_BASELINE_CONNECTIONS = MONITORING_CONFIG["max_baseline_connections"]

# Display Configuration
DISPLAY_CONFIG = {
    "max_top_errors": 20,
    "max_category_errors": 10,
    "max_recent_events": 10,
    "max_security_events": 100,
    "error_message_max_length": 200,
}

# Legacy constants for backward compatibility
MAX_TOP_ERRORS_DISPLAY = DISPLAY_CONFIG["max_top_errors"]
MAX_CATEGORY_ERRORS_DISPLAY = DISPLAY_CONFIG["max_category_errors"]
MAX_RECENT_EVENTS_DISPLAY = DISPLAY_CONFIG["max_recent_events"]
MAX_SECURITY_EVENTS = DISPLAY_CONFIG["max_security_events"]
ERROR_MESSAGE_MAX_LENGTH = DISPLAY_CONFIG["error_message_max_length"]
ERROR_SIGNATURE_HASH_LENGTH = 16

# Connection & Network Constants
MIN_CONNECTION_PARTS = 5
CONNECTION_PID_PARSE_START_INDEX = 6
DNS_TEST_PORT = 80
STAT_FIELD_UTIME_INDEX = 13
STAT_FIELD_STIME_INDEX = 14
DNS_TEST_DOMAINS = ["example.com", "google.com", "cloudflare.com"]
LOCALHOST_VARIANTS = ["127.0.0.1", "::1", "localhost"]

# Memory & Conversion Constants
KB_TO_BYTES_FACTOR = 1024
MB_TO_BYTES_FACTOR = 1024 * 1024
COMMAND_NAME_MAX_LENGTH = 255
STDERR_TRUNCATION_LENGTH = 500
MIN_VALIDATION_FILE_SIZE = 8
IMAGE_BUFFER_CHECK_LIMIT = 1024 * 1024  # 1MB

# Security Verification Constants
VERIFICATION_TIMEOUT_SECONDS = 5.0
MAX_MEMORY_VIOLATIONS = {"standard": 3, "strict": 2, "paranoid": 1}
MEMORY_CLEAR_PATTERNS = [
    0x00,
    0xFF,
    0xAA,
    0x55,
    0x00,
]  # Overwrite patterns for secure memory clearing

# Database & Event Storage
DB_CHECK_SAME_THREAD = False  # SQLite threading model
SECURITY_EVENT_TABLE_NAME = "security_events"
ERROR_EVENT_TABLE_NAME = "errors"

# Process Management
PROCESS_NICE_LEVEL = 10
MEMORY_CHECK_INTERVAL = 0.1  # seconds
STDERR_BUFFER_SIZE = 64 * 1024  # 64KB

# File Size Categories (for statistics)
FILE_SIZE_CATEGORIES = {
    "TINY": 1024,  # < 1KB
    "SMALL": 100 * 1024,  # < 100KB
    "MEDIUM": 1024 * 1024,  # < 1MB
    "LARGE": 10 * 1024 * 1024,  # < 10MB
    "HUGE": float("inf"),  # >= 10MB
}
