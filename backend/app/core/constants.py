"""Constants and configuration values for the image converter."""

# Security and Processing Limits
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_IMAGE_PIXELS = 178956970  # ~178MP (same as PIL default)

# Sandbox Configuration
SANDBOX_TIMEOUTS = {
    "standard": 30,
    "strict": 20, 
    "paranoid": 10
}

SANDBOX_MEMORY_LIMITS = {
    "standard": 512,  # MB
    "strict": 256,    # MB
    "paranoid": 128   # MB
}

SANDBOX_CPU_LIMITS = {
    "standard": 80,   # Percent
    "strict": 60,     # Percent
    "paranoid": 40    # Percent
}

SANDBOX_OUTPUT_LIMITS = {
    "standard": 100,  # MB
    "strict": 50,     # MB
    "paranoid": 25    # MB
}

# Supported Image Formats
SUPPORTED_INPUT_FORMATS = {
    'jpeg', 'jpg', 'png', 'webp', 'gif', 'bmp', 'tiff', 'tif', 'heif', 'heic', 'avif'
}

SUPPORTED_OUTPUT_FORMATS = {
    'jpeg', 'jpg', 'png', 'webp', 'gif', 'bmp', 'tiff', 'tif', 'heif', 'heic', 'avif'
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
    'ARGS_ERROR': 'Missing or invalid arguments',
    'VALIDATION_ERROR': 'Input validation failed',
    'SIZE_ERROR': 'File size exceeds limits',
    'INPUT_ERROR': 'Input data error',
    'INVALID_IMAGE': 'Invalid image format or data',
    'DECOMPRESSION_BOMB': 'Image exceeds decompression limits',
    'CONVERSION_ERROR': 'Image conversion failed',
    'FORMAT_ERROR': 'Unsupported format',
    'METADATA_ERROR': 'Metadata processing failed',
    'SAVE_ERROR': 'Failed to save output',
    'OUTPUT_ERROR': 'Output validation failed',
    'SECURITY_VIOLATION': 'Security policy violation detected',
    'UNEXPECTED_ERROR': 'Unexpected system error'
}

# Magic bytes for format detection
IMAGE_MAGIC_BYTES = {
    # Common formats
    b"\xFF\xD8\xFF": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"RIFF": "WebP/RIFF",  # WebP starts with RIFF (needs further check)
    b"GIF87a": "GIF",
    b"GIF89a": "GIF", 
    b"II*\x00": "TIFF",
    b"MM\x00*": "TIFF",
    b"BM": "BMP",
    # Modern formats
    b"\x00\x00\x00\x0C\x6A\x50\x20\x20": "JPEG2000",  # JP2
    b"\x00\x00\x00\x20\x66\x74\x79\x70": "HEIF/AVIF",  # ftyp box (needs further check)
    b"\xFF\x0A": "JPEG_XL",  # JPEG XL codestream
    b"\x00\x00\x00\x0C\x4A\x58\x4C\x20": "JPEG_XL_ISO",  # JPEG XL ISO container
    # Additional formats
    b"FORM": "IFF",  # IFF format
    b"\x00\x00\x01\x00": "ICO",  # Windows icon
    b"icns": "ICNS",  # macOS icon
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
    b"msf1": "HEIF"
}

# Performance tuning
THREAD_POOL_SIZE = 4
PROCESS_POOL_SIZE = 2

# Monitoring and metrics
METRICS_ENABLED = True
HEALTH_CHECK_TIMEOUT = 5.0

# Network Monitoring Constants
NETWORK_VIOLATION_THRESHOLD = 3  # Number of violations before process termination
PROCESS_TERMINATION_GRACE_PERIOD = 2  # seconds to wait before SIGKILL
DEFAULT_MONITORING_INTERVAL = 5  # seconds between connection checks
MONITORING_JITTER_PERCENT = 0.1  # 10% jitter to prevent thundering herd

# Network Blocking Messages
NETWORK_BLOCKED_MSG = "Network access is disabled in sandboxed environment"
DNS_BLOCKED_MSG = "DNS resolution is disabled in sandboxed environment"
UDP_BLOCKED_MSG = "UDP sockets are disabled in sandboxed environment"
P2P_MODULE_BLOCKED_MSG = "P2P/WebRTC module '{}' is blocked in sandboxed environment"

# Network Verification
NETWORK_CHECK_TIMEOUT = 1  # seconds for DNS resolution timeout
NETWORK_BASELINE_MAX_CONNECTIONS = 100  # Maximum baseline connections to track

# Rate Limiting Constants
RATE_LIMIT_EVENTS_PER_MINUTE = 60
RATE_LIMIT_EVENTS_PER_HOUR = 1000
RATE_LIMIT_BURST_SIZE = 10
RATE_LIMIT_HOUR_BURST_DIVISOR = 10
RATE_LIMIT_TOKEN_REFILL_AMOUNT = 1
DEFAULT_RATE_LIMIT_CAPACITY = 100
DEFAULT_RATE_LIMIT_REFILL_RATE = 10.0

# Monitoring & Retention Constants
DEFAULT_MONITORING_HOURS = 24
ERROR_RETENTION_DAYS = 30
SECURITY_EVENT_RETENTION_DAYS = 90
HOURLY_STATS_RETENTION_HOURS = 168  # 7 days
DAILY_STATS_RETENTION_DAYS = 90
MAX_PROCESSING_TIMES_MEMORY = 1000
MONITORING_INTERVAL_SECONDS = 5.0
MONITORING_JITTER_SECONDS = 1.0
CONNECTION_CHECK_TIMEOUT = 2.0
MAX_BASELINE_CONNECTIONS = 50

# Query & Display Limits
MAX_TOP_ERRORS_DISPLAY = 20
MAX_CATEGORY_ERRORS_DISPLAY = 10
MAX_RECENT_EVENTS_DISPLAY = 10
MAX_SECURITY_EVENTS = 100
ERROR_MESSAGE_MAX_LENGTH = 200
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
MEMORY_CLEAR_PATTERNS = [0x00, 0xFF, 0xAA, 0x55, 0x00]  # Overwrite patterns for secure memory clearing

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
    "TINY": 1024,           # < 1KB
    "SMALL": 100 * 1024,    # < 100KB
    "MEDIUM": 1024 * 1024,  # < 1MB
    "LARGE": 10 * 1024 * 1024,  # < 10MB
    "HUGE": float('inf')    # >= 10MB
}