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