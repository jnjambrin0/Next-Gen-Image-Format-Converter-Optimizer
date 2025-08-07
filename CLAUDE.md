# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**VERY IMPORTANT**: If during development you discover or learn something that would be important to add to this CLAUDE.md file, you must ask the user for confirmation before adding it. This ensures that important project knowledge stays updated and accessible.

## Project Overview

Next-Gen Image Format Converter & Optimizer - A privacy-focused, local-only image conversion tool with advanced optimization capabilities. All processing happens on the user's machine with no external network requests.

## Architecture Summary

- **Architecture Pattern**: Monolithic with modular internals
- **Backend**: FastAPI (Python 3.11+) running on port 8080
- **Frontend**: Vanilla JS with Vite build system
- **Core Modules**:
  - Conversion Manager: Orchestrates image processing
  - Security Engine: Process sandboxing and isolation
  - Intelligence Engine: ML-based content detection (ONNX Runtime)
  - Processing Engine: Image manipulation (Pillow/libvips)

## Critical Testing Pattern

**CRITICAL**: When testing with sample images, ALWAYS check actual format first:

```bash
# Many sample files have wrong extensions!
# Example: images_sample/heic/lofi_cat.heic is actually a PNG file

# Test with format detection to verify actual formats:
python test_format_detection.py
```

**Why**: The test images in `images_sample/` include intentionally misnamed files to test robustness. Never assume the extension matches the content.

## Development Commands

### Backend Setup and Development

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# CRITICAL: Run development server from backend/ directory
cd backend
uvicorn app.main:app --reload --port 8080

# Run tests (MUST be from backend/ directory)
cd backend
pytest

# Format code
black .

# Type checking (if mypy configured)
mypy .
```

### Frontend Development

```bash
# Navigate to frontend directory
cd frontend

# Setup environment variables
cp .env.example .env
# Edit .env to set backend port if different from 8080

# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Run linting
npm run lint

# Format code with Prettier
npm run format

# Run tests (Vitest)
npm run test
npm run test:coverage
```

#### Environment Configuration

The frontend uses environment variables for backend configuration:

- `VITE_API_PORT`: Backend API port (default: 8080)
- `VITE_API_HOST`: Backend API host (default: localhost)

See `frontend/ENV_CONFIG.md` for detailed configuration instructions.

### Testing

```bash
# IMPORTANT: Run pytest from backend/ directory, not project root
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/unit/test_conversion.py

# Run integration tests only
pytest tests/integration/

# Run security tests (requires Docker)
pytest tests/security/
```

### SDK Development

```bash
# Python SDK
cd sdks/python
pip install -e .  # Install in development mode
pip install keyring httpx pydantic  # Install dependencies
pytest tests/     # Run SDK tests

# JavaScript SDK
cd sdks/javascript
npm install       # Install dependencies
npm run build     # Build TypeScript
npm test          # Run tests (requires jest)

# Go SDK
cd sdks/go
go mod download   # Download dependencies
go test ./...     # Run all tests
go build ./...    # Build SDK
```

### CLI Usage (Story 6.1 & 6.2)

**CRITICAL**: The CLI exists at `backend/img.py` and uses the Python SDK with specific requirements:

1. **SDK Client Initialization**: Uses `host` and `port`, NOT `base_url`:
```python
# CORRECT - SDK expects separate host/port
client = ImageConverterClient(
    host=config.api_host,  # "localhost"
    port=config.api_port,  # 8080
    api_key=config.api_key
)

# WRONG - This will fail
client = ImageConverterClient(base_url="http://localhost:8080")
```

2. **SDK Methods Expect File Paths**: The SDK's `convert_image` expects file paths, not bytes:
```python
# CLI must use temp files for SDK
with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
    tmp.write(image_bytes)
    tmp_path = tmp.name

output_data, result = client.convert_image(
    image_path=tmp_path,  # File path, not bytes!
    output_format="webp"
)
```

3. **TUI Uses RichLog**: Textual's `TextLog` was removed, use `RichLog`:
```python
from textual.widgets import RichLog  # NOT TextLog
```

4. **CLI Command Structure**: Commands use subcommands pattern:
```bash
# CORRECT - Note the subcommand structure
img convert file input.jpg -f webp     # NOT: img convert input.jpg
img batch convert "*.png" -f avif      # NOT: img batch create
img optimize auto photo.jpg --preset web

# The pattern is: img <command> <subcommand> <args>
```

## Key Architecture Decisions

1. **Local-Only Processing**: No network requests, all ML models and processing happen locally
2. **Process Sandboxing**: Each conversion runs in isolated subprocess with restricted permissions
3. **Memory-Only Processing**: No temporary files on disk, all processing in RAM
4. **Format Support**:
   - Input: JPEG, PNG, WebP, HEIF/HEIC, BMP, TIFF, GIF, AVIF
   - Output: WebP, AVIF, JPEG XL, HEIF, PNG (optimized), JPEG (optimized), WebP2
5. **Content Detection**: Local ML model classifies images (photo/illustration/screenshot/document)
6. **Metadata Handling**: EXIF data removed by default for privacy

## Project Structure

```
/
├── backend/            # Backend API (FastAPI)
├── frontend/           # Frontend web UI
├── docs/               # Documentation
│   ├── architecture/   # Technical architecture docs
│   ├── prd/           # Product requirements
│   └── stories/       # User story files
├── backend/tests/      # Test suite
│   ├── unit/          # Unit tests
│   ├── integration/   # Integration tests
│   ├── security/      # Security tests
│   └── fixtures/      # Test images and data
├── sdks/               # Language SDKs (Story 5.3)
│   ├── python/        # Python SDK with async/sync support
│   ├── javascript/    # JavaScript/TypeScript SDK
│   └── go/           # Go SDK with idiomatic patterns
├── ml_models/         # Local ML models
└── scripts/           # Utility scripts
```

## Security Considerations

- All image processing happens in sandboxed subprocesses
- No network access from sandboxed processes
- Limited filesystem access (read input, write output only)
- Resource limits enforced (CPU, memory, time)
- Automatic EXIF/metadata removal by default
- Memory explicitly cleared after processing
- **Privacy-Aware Logging Rules**:
  - NEVER include filenames, file paths, or user-provided names in log messages or errors
  - Use generic messages like "Invalid filename" instead of including the actual filename
  - This applies to ALL error messages, debug logs, and system outputs

## Security Implementation Details

- **Sandbox Architecture**: Three-layer system with distinct responsibilities:
  - `SecurityEngine` - Orchestrates security operations, creates sandboxes, manages metadata
  - `SecuritySandbox` - Manages resource limits, memory tracking, process isolation  
  - `sandboxed_convert.py` - Isolated subprocess for actual image conversion
- **Strictness Levels**: Configurable via `IMAGE_CONVERTER_SANDBOX_STRICTNESS` (standard/strict/paranoid)
  - standard: 512MB RAM, 80% CPU, 30s timeout, 3 memory violations allowed, no memory locking
  - strict: 256MB RAM, 60% CPU, 20s timeout, 2 memory violations allowed, memory locking enabled
  - paranoid: 128MB RAM, 40% CPU, 10s timeout, 1 memory violation allowed, memory locking enabled
- **Privacy-Aware Logging**: Security audit logs contain no PII (filenames, paths, or content)
- **Resource Tracking**: Actual CPU/memory usage tracked per conversion with violation detection
- **Secure Memory Management**: 5-pass overwrite patterns (0x00, 0xFF, 0xAA, 0x55, 0x00) for clearing sensitive data
- **Memory Page Locking**: Cross-platform mlock() implementation with graceful fallbacks
- **Sandbox Control**: Enable/disable via `IMAGE_CONVERTER_ENABLE_SANDBOXING` env var

## Critical Implementation Details

### Image Conversion Architecture
- **NO ImageMagick Required**: The sandboxed conversion uses Python subprocess with PIL/Pillow
- **Sandboxed Script**: `app/core/conversion/sandboxed_convert.py` - standalone conversion script
- **Execution Method**: Must run with `python script.py` directly, NOT as module (`-m`) to avoid logging initialization
- **Error Format**: Sandboxed errors are returned as JSON on stderr:
  ```json
  {"error_code": "CODE", "message": "description", "type": "sandboxed_conversion_error"}
  ```

### Logging Configuration
- **CRITICAL**: Logging MUST use stderr, not stdout (`app/utils/logging.py:72`)
- Logging to stdout will contaminate subprocess output and break conversions
- Format: `stream=sys.stderr  # NOT sys.stdout`

### Key Configuration Files
- `app/core/constants.py` - All system constants (limits, formats, security patterns)
  - `MAX_BATCH_SIZE = 100` - Maximum files per batch
  - `MAX_BATCH_WORKERS = 10` - Maximum concurrent workers
  - `BATCH_CHUNK_SIZE = 10` - Process files in chunks
- `app/core/conversion/sandboxed_convert.py` - Isolated conversion subprocess
- `app/utils/logging.py` - Logging configuration (MUST use stderr)

## Critical Architectural Patterns

### 1. Metadata Processing MUST Happen Before Conversion
**CRITICAL**: Always process metadata (EXIF, GPS, etc.) on the INPUT image before format conversion, never on the output.

```python
# CORRECT: Process metadata before conversion
processed_input, metadata_summary = await security_engine.analyze_and_process_metadata(
    input_data, 
    input_format,  # Use INPUT format, not output
    ...
)
output_data = await convert_image(processed_input, ...)

# WRONG: Process metadata after conversion
output_data = await convert_image(input_data, ...)
# Metadata is already lost during conversion!
```

**Why**: Many format conversions (e.g., JPEG→WebP) automatically lose metadata during conversion. Processing after conversion gives incorrect results about what metadata existed in the original image.

### 2. Sandboxed Script Execution Pattern
**CRITICAL**: The sandboxed conversion script MUST be executed directly, NOT as a module:

```python
# CORRECT: Direct script execution
command = [sys.executable, "/path/to/sandboxed_convert.py", ...]

# WRONG: Module execution (will break due to logging initialization)
command = [sys.executable, "-m", "app.core.conversion.sandboxed_convert", ...]
```

**Why**: Module execution can trigger logging initialization that contaminates stdout with log messages, breaking binary data streams.

**Socket Blocking in Sandbox**: When implementing network blocking, NEVER replace `socket.socket` with a function:

```python
# CORRECT: Use a class that preserves inheritance
class BlockedSocket(original_socket):
    def __init__(self, *args, **kwargs):
        raise OSError("Network access disabled")
socket.socket = BlockedSocket

# WRONG: Replacing with function breaks SSL and other modules
socket.socket = lambda *args: raise OSError("Network disabled")
```

**Why**: Many Python modules (like SSL) expect `socket.socket` to be a class they can inherit from. Replacing it with a function causes `TypeError: function() argument 'code' must be code, not str`.

### 3. Privacy-Aware Logging Pattern
**CRITICAL**: Security and error messages MUST NEVER include filenames, paths, or user content:

```python
# CORRECT: Generic error messages without PII
raise SecurityError("Filename contains dangerous patterns")
logger.warning("Memory limit violation detected", current_mb=150, limit_mb=100)

# WRONG: Including filenames or paths (contains PII)
raise SecurityError(f"Invalid filename: {filename}")
logger.error(f"Failed to process file: {file_path}")
```

**Why**: Filenames and paths may contain Personally Identifiable Information (PII). All logging must be privacy-aware.

### 4. Secure Memory Management Pattern
**CRITICAL**: Memory allocated for image processing must be explicitly cleared with overwrite patterns:

```python
# CORRECT: Secure memory clearing
def secure_clear(buffer):
    if isinstance(buffer, bytearray):
        # Multiple overwrite passes for security
        patterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]
        for pattern in patterns:
            for i in range(len(buffer)):
                buffer[i] = pattern

# WRONG: Just setting to None (memory may persist)
buffer = None
```

**Why**: Image data may contain sensitive information. Secure clearing prevents memory-based data recovery attacks.

### 5. Database Initialization Pattern
**CRITICAL**: Database directories must exist before initializing trackers:

```python
# CORRECT: Ensure data directory exists in startup
import os
os.makedirs("./data", exist_ok=True)
# Then initialize trackers
security_tracker = SecurityEventTracker(db_path="./data/security.db")

# WRONG: Initialize without ensuring directory exists
security_tracker = SecurityEventTracker(db_path="./data/security.db")
# Will fail with "no such table" errors
```

**Why**: SQLite cannot create database files in non-existent directories. The trackers will fail silently and report "no such table" errors during operations.

### 6. Singleton Service Pattern
**CRITICAL**: To avoid circular imports, services must follow this pattern:

```python
# CORRECT: In service file (e.g., conversion_service.py)
class ConversionService:
    def __init__(self):
        self.stats_collector = None  # Will be injected
        
# Create singleton at module level
conversion_service = ConversionService()

# In main.py startup:
from app.services.conversion_service import conversion_service
from app.core.monitoring.stats import stats_collector
conversion_service.stats_collector = stats_collector

# WRONG: Direct import in __init__ causes circular dependency
class ConversionService:
    def __init__(self):
        from app.core.monitoring.stats import stats_collector  # Circular!
        self.stats_collector = stats_collector
```

**Why**: Direct imports in `__init__` can create circular dependencies. Use dependency injection pattern instead.

**IMPORTANT**: All new services with singleton pattern MUST be initialized in main.py during the lifespan startup. Example:
```python
# In main.py lifespan function:
from .services.new_service import new_service as svc_import, NewService
import app.services.new_service as svc_module
svc_module.new_service = NewService()
```

**Common Services Requiring Initialization**:
- `conversion_service` - Already initialized
- `intelligence_service` - Already initialized  
- `recommendation_service` - Story 3.4
- `optimization_service` - Story 3.5 (requires intelligence_engine and conversion_service)
- `batch_service` - Story 4.1 (requires conversion_service which also injects to internal BatchManager)
- Any future singleton services following this pattern

**Batch Service Special Initialization**:
```python
# CRITICAL: BatchService requires double injection
# In main.py lifespan function:
from app.services.batch_service import batch_service
batch_service.set_conversion_service(conversion_service)
# The BatchManager inside also needs conversion_service injected
```

**Optimization Service Special Initialization**:
```python
# In main.py lifespan function (AFTER other services):
from app.services.optimization_service import optimization_service
optimization_service.set_intelligence_engine(intelligence_service.engine)
optimization_service.set_conversion_service(conversion_service)
```


### 8. Format Detection Architecture
**CRITICAL**: The system uses content-based format detection, NOT extension-based:

```python
# CORRECT: Always detect format from content
from app.services.format_detection_service import format_detection_service
detected_format, confident = await format_detection_service.detect_format(image_data)
actual_format = detected_format  # Use this, not the file extension

# WRONG: Never trust file extensions
if filename.endswith('.jpg'):
    format = 'jpeg'  # WRONG! File could be misnamed
```

**Why**: Real-world files often have wrong extensions. The system detects formats using:
1. Magic bytes (most reliable)
2. PIL detection (fallback)
3. Extended structure analysis

**Key Service**: `app/services/format_detection_service.py` - Single source of truth for format detection.

### 9. Quality Analyzer Implementation Pattern
**CRITICAL**: The project uses a custom SSIM/PSNR implementation to avoid heavy dependencies:

```python
# Custom quality analyzer in app/core/optimization/quality_analyzer.py
# Implements real SSIM/PSNR calculations using numpy-based algorithms
# Avoids 200MB scikit-image dependency while providing accurate metrics
# Uses custom convolution for SSIM calculation (slower but dependency-free)
```

**Key Features**:
- Real perceptual quality metrics (not estimates)
- Pure Python/numpy implementation
- LRU cache for repeated calculations
- Automatic downsampling for large images (>2048px)

### 10. Critical Security Patterns (MUST KNOW)

#### Sandbox Path Validation
**CRITICAL**: The sandbox blocks ALL absolute paths for security:

```python
# WRONG: Absolute paths are rejected
sandbox.validate_path("/tmp/file.jpg")  # Raises SecurityError

# CORRECT: Use relative paths
sandbox.validate_path("output/file.jpg")  # OK
```

**Why**: Absolute paths could allow access to system files. The sandbox enforces relative paths only.

#### Blocked Commands in Sandbox
**CRITICAL**: The following commands are blocked in `SecuritySandbox.blocked_commands`:
- Programming languages: `python`, `perl`, `ruby`, `php`, `node`
- Shells: `bash`, `sh`, `zsh`, `fish`, `cmd`, `powershell`
- Network tools: `curl`, `wget`, `nc`, `netcat`, `telnet`, `ssh`, `ftp`
- Dangerous commands: `rm`, `dd`, `format`, `fdisk`, `mkfs`

#### Simplified Error System
**CRITICAL**: Use only 5 error categories, never expose PII:

```python
# CORRECT: Category-based errors without PII
raise create_sandbox_error(reason="timeout", timeout=30)
raise create_file_error(operation="access", reason="permission_denied")

# WRONG: Don't include filenames or paths
raise SecurityError(f"Cannot access {filename}")  # Exposes PII!
```

Categories: `network`, `sandbox`, `rate_limit`, `verification`, `file`

#### Architecture Constraint
**CRITICAL**: This is a **LOCAL-ONLY** application:
- **NEVER** add distributed features (Redis, distributed locks, etc.)
- **NEVER** add network functionality beyond localhost API
- **NEVER** add telemetry or external service calls
- All processing must work completely offline

#### SDK Localhost Enforcement Pattern (Story 5.3)
**CRITICAL**: All language SDKs enforce localhost-only connections:

```python
# Hardcoded in all SDKs (Python/JavaScript/Go):
allowed_hosts = ['localhost', '127.0.0.1', '::1', '[::1]']

# Connection attempts to external hosts are blocked:
if host not in allowed_hosts:
    raise NetworkSecurityError('Connection to non-localhost blocked')

# This can be disabled (NOT recommended) with:
verify_localhost=False  # Security risk!
```


## API Development Patterns

### API Versioning Strategy
**CRITICAL**: The API supports dual paths for backward compatibility:

```python
# Both legacy and versioned endpoints work simultaneously
# Legacy: /api/health
# Versioned: /api/v1/health
# All new endpoints should be added to both routers for compatibility
```

### Centralized Validation Utilities
**IMPORTANT**: Use these utilities from `app.api.utils.validation` to avoid code duplication:

```python
# File validation and reading
contents, file_size = await validate_uploaded_file(file, request, error_prefix="DET")

# Content type validation for uploads
if not validate_content_type(file):
    raise HTTPException(status_code=415, detail="Unsupported media type")

# Concurrency control with proper error handling
async with SemaphoreContextManager(semaphore, timeout, error_code, service_name, request):
    # Your code here

# Secure memory clearing (uses 5-pass overwrite)
secure_memory_clear(sensitive_data)
```

### Test Expectation Patterns
**IMPORTANT**: Validation middleware intercepts requests before FastAPI validation:

```python
# When testing missing file uploads:
# Expect 415 (Unsupported Media Type) from middleware, NOT 422 from FastAPI
assert response.status_code == 415  # Middleware catches it first

# When testing oversized files:
# Expect 413 with error_code "VAL413" from validation middleware
assert response.status_code == 413
assert data["error_code"] == "VAL413"
```

### Error Response Patterns
All API errors follow consistent structure with proper error codes:

```python
# Error codes match HTTP status patterns:
# DET503 - Detection service unavailable (503)
# REC422 - Recommendation validation error (422)
# VAL413 - Validation payload too large (413)
# CONV500 - Conversion internal error (500)
```

## API Endpoints

**IMPORTANT**: Form endpoints that accept presets still require the base parameters (e.g., `output_format`) even though presets will override them. This is due to FastAPI validation requirements.

### Core Endpoints (Available in both /api and /api/v1)
- `POST /api/convert` - Convert single image (requires `output_format` even with `preset_id`)
- `POST /api/batch` - Create batch conversion job (requires `output_format` even with `preset_id`)
- `GET /api/batch/{job_id}/status` - Get batch job status
- `DELETE /api/batch/{job_id}` - Cancel entire batch job
- `DELETE /api/batch/{job_id}/items/{file_index}` - Cancel specific file in batch
- `POST /api/batch/{job_id}/websocket-token` - Generate new WebSocket auth token
- `WebSocket /ws/batch/{job_id}` - Real-time progress updates for batch job
- `GET /api/health` - Health check with network isolation status
- `GET /api/formats` - List supported input/output formats

### Monitoring & Intelligence Endpoints
- `GET /api/monitoring/stats` - Conversion statistics
- `GET /api/monitoring/errors` - Recent errors
- `GET /api/security/status` - Security engine status
- `GET /api/intelligence/capabilities` - ML detection capabilities
- `GET /api/optimization/presets` - Available optimization presets

### Preset Management Endpoints
- `GET /api/presets` - List all presets (built-in and user-created)
- `POST /api/presets` - Create new user preset
- `PUT /api/presets/{preset_id}` - Update existing preset
- `DELETE /api/presets/{preset_id}` - Delete user preset
- `POST /api/presets/import` - Import presets from JSON
- `GET /api/presets/{preset_id}/export` - Export preset as JSON

### Detection Endpoints (New in v1)
- `POST /api/v1/detection/detect-format` - Detect image format from content
- `POST /api/v1/detection/recommend-format` - Get AI-powered format recommendations
- `GET /api/v1/detection/formats/compatibility` - Get format compatibility matrix

### Authentication Endpoints (Story 5.2)
- `POST /api/v1/auth/keys` - Create new API key (requires admin permissions)
- `GET /api/v1/auth/keys` - List all API keys
- `DELETE /api/v1/auth/keys/{key_id}` - Revoke specific API key
- `GET /api/v1/auth/verify` - Verify current API key validity

## Development Guidelines

1. Follow security-first principles - assume all input is potentially malicious
2. Write tests for all new functionality (80% coverage minimum)
3. Use type hints for all Python code
4. Document all API endpoints with OpenAPI
5. Keep dependencies minimal and audit regularly
6. Performance target: <2 seconds for 10MB images

## Code Quality and Formatting

### Frontend (JavaScript)

1. **ESLint Configuration**: The project uses ESLint with the following key rules:

   - `curly: ['error', 'all']` - Always use curly braces, even for single-line blocks
   - `no-console` warnings except for `console.warn` and `console.error`
   - `no-unused-vars` with `argsIgnorePattern: '^_'` for unused parameters
   - Prettier integration for consistent formatting

2. **Prettier Configuration**:

   - Automatically formats code on save (if configured in IDE)
   - Run `npm run format` to format all files
   - Prettier runs through ESLint for unified tooling

3. **Common Linting Fixes**:

   - Wrap case blocks with curly braces when declaring variables: `case 'value': { ... }`
   - Prefix unused function parameters with underscore: `(newState, _oldState) => {}`
   - Always use curly braces for if statements, even single-line
   - Use `import.meta.url` instead of `__dirname` in ES modules

4. **Test Environment Setup**:
   - Use `.eslintrc.cjs` (CommonJS format) for ESLint config
   - Add test globals in ESLint overrides for test files
   - Vitest provides `describe`, `it`, `expect`, `beforeEach`, `afterEach`, `vi` globals

5. **Frontend Memory Management Pattern**:
   **CRITICAL**: Always track and clean up blob URLs to prevent memory leaks:

   ```javascript
   // Track blob URLs in components that create them
   const testBlobUrls = { original: null, converted: null }

   // Clean up previous URLs before creating new ones
   if (testBlobUrls.original) {
       blobUrlManager.revokeUrl(testBlobUrls.original)
       testBlobUrls.original = null
   }

   // Store new URLs for cleanup
   testBlobUrls.original = blobUrlManager.createUrl(file)

   // Clean up on component removal, file selection, or reset
   // This prevents memory leaks in long-running sessions
   ```

   **Key Principles**:
   - Use `BlobUrlManager` for centralized URL lifecycle management
   - Track all created blob URLs in component state
   - Clean up before creating new URLs (prevents accumulation)
   - Clean up when components unmount or reset
   - Essential for features with preview/test functionality

### Backend (Python)

1. **Black Formatter**: Use `black .` for consistent Python formatting
2. **Type Hints**: Required for all function parameters and return values
3. **Docstrings**: Use Google-style docstrings for all public functions

## Important Note for Claude Code

When working on tasks or solving problems, if you discover important information that differs from or should be added to this CLAUDE.md file (such as new commands, architectural changes, or updated development workflows), you MUST:

1. Inform the user about the discrepancy or missing information
2. Suggest the specific modifications or additions needed for CLAUDE.md
3. After user confirmation, update this file accordingly

This ensures that future Claude Code instances always have the most accurate and up-to-date information about the project.


## Critical Intelligence Engine Security Requirements

### Input Validation (MANDATORY)
**CRITICAL**: ALL image processing MUST validate inputs to prevent DoS:

```python
# Required in ANY image processing function:
if not isinstance(image_data, bytes):
    raise create_file_error("invalid_input_type")
if len(image_data) == 0:
    raise create_file_error("empty_input")
if len(image_data) > 100 * 1024 * 1024:  # 100MB absolute max
    raise create_file_error("input_too_large")

# For PIL Images:
if image.width <= 0 or image.height <= 0:
    raise create_file_error("invalid_dimensions")
if image.width > 50000 or image.height > 50000:
    raise create_file_error("dimensions_too_large")
```

### Concurrency Protection (MANDATORY)
**CRITICAL**: Prevent resource exhaustion with semaphores:

```python
# Required for any resource-intensive operation:
MAX_CONCURRENT = 10
_semaphore = asyncio.Semaphore(MAX_CONCURRENT)

async with _semaphore:
    # Perform operation
```

### Cache Security Pattern
**CRITICAL**: NEVER return direct cache references:

```python
# CORRECT: Deep copy prevents cache poisoning
import copy
result_copy = copy.deepcopy(cached_result)
return result_copy

# WRONG: Allows external modification
return cached_result  # SECURITY VULNERABILITY!
```

### Performance Requirements
All image processing MUST meet:
- P99 latency < 500ms
- Memory stable (< 50MB growth per 1000 ops)
- Support 10+ concurrent requests
- Graceful degradation under load

### ContentClassification Model Attributes
**CRITICAL**: The ContentClassification model uses plural attribute names:

```python
# CORRECT: Use plural attributes (Story 3.5 update)
classification.face_regions  # List[BoundingBox] - face detection results
classification.text_regions  # List[BoundingBox] - text detection results

# WRONG: Singular names no longer exist
classification.faces  # AttributeError
classification.text   # AttributeError
```

**Integration Example**:
```python
# In region optimizer or any detection consumer:
if classification.face_regions:
    for face in classification.face_regions:
        bbox = (face.x, face.y, face.x + face.width, face.y + face.height)
```

## Non-Maximum Suppression Pattern

For detection algorithms, use distance-based grouping in addition to IoU:
```python
# Group if overlapping OR centers are close
if iou > 0.1 or center_dist < max_size * 2.0:
    # Merge detections using weighted average by confidence
```

### 10. Service Return Value Patterns
**CRITICAL**: The conversion_service.convert() method MUST return a tuple (result, output_data):

```python
# CORRECT: In conversion_service.py
async def convert(self, image_data: bytes, request: ConversionRequest, ...):
    result, output_data = await self.conversion_manager.convert_with_output(...)
    return result, output_data  # MUST return tuple

# In API routes:
result, output_data = await conversion_service.convert(...)  # Expects tuple

# WRONG: Returning only result causes ValueError
return result  # ValueError: too many values to unpack (expected 2)
```

**Why**: The API route expects both the ConversionResult object and the actual image bytes. Missing either causes runtime errors.

### 11. API Response Content-Type Pattern
**CRITICAL**: When using presets or any feature that changes output format, the response content-type MUST use the actual output format from the conversion result:

```python
# CORRECT: Use actual format from conversion result
actual_output_format = result.output_format.lower()
content_type = content_type_map.get(actual_output_format, "application/octet-stream")

# WRONG: Using form parameter when preset overrides it
content_type = content_type_map.get(output_format.lower(), "application/octet-stream")
```

**Why**: Presets and other features can override the requested output format. The response headers must reflect what was actually converted, not what was requested.

### 12. Server Execution Location
**CRITICAL**: The uvicorn server MUST be run from the backend/ directory:

```bash
# CORRECT: Run from backend directory
cd backend
uvicorn app.main:app --reload --port 8080

# WRONG: Running from project root
uvicorn backend.app.main:app  # ModuleNotFoundError: No module named 'app'
```

**Why**: The Python import paths are relative to the backend/ directory. Running from elsewhere breaks all imports.

### 13. Optimization Module Exports
**CRITICAL**: The optimization module must export all required classes:

```python
# In app/core/optimization/__init__.py
from .optimization_engine import OptimizationEngine, OptimizationMode
from .lossless_compressor import LosslessCompressor, CompressionLevel

__all__ = [
    # ... other exports ...
    "OptimizationMode",  # Required for performance tests
    "CompressionLevel",  # Required for performance tests
]
```

**Why**: Tests and other modules depend on these enums being accessible from the optimization package.

### 14. Realistic Test Mock Patterns
**CRITICAL**: When testing optimization features, use realistic compression curves:

```python
# CORRECT: Realistic exponential compression for mock conversion
async def mock_conversion_func(image_data, output_format, quality=85, **kwargs):
    base_size = 20000  # Base size for quality 100
    # Exponential curve - size decreases faster at lower qualities
    quality_factor = (quality / 100) ** 1.5
    new_size = int(base_size * quality_factor)
    new_size = max(new_size, 500)  # Minimum size
    return b'JPEG' + b'\x00' * (new_size - 4)

# WRONG: Linear reduction doesn't match real compression behavior
new_size = int(20000 * (quality / 100))  # Too simplistic
```

**Why**: Real image compression follows exponential curves, not linear. Tests with unrealistic mocks will fail or provide incorrect optimization results.

### 15. Batch Processing Architecture Pattern
**CRITICAL**: Batch processing follows these patterns:

- **Worker Pool Scaling**: Uses 80% of CPU cores (min 2, max 10 workers)
- **Queue Management**: asyncio.Queue with per-job semaphore limits
- **Memory Management**: File data temporarily stored in memory during processing
- **Progress Updates**: Real-time WebSocket updates via ConnectionManager
- **Cancellation Support**: Both job-level and item-level cancellation
- **Resource Cleanup**: Automatic cleanup of completed jobs after processing

```python
# Worker count calculation pattern
cpu_count = multiprocessing.cpu_count()
worker_count = max(2, int(cpu_count * 0.8))
worker_count = min(worker_count, MAX_BATCH_WORKERS)

# Progress callback pattern for WebSocket updates
async def progress_callback(progress: BatchProgress):
    await connection_manager.broadcast_progress(progress)
```

**Integration with Conversion Service**:
- BatchManager requires injection of conversion_service
- Each file processed through existing secure conversion pipeline
- Maintains all security sandboxing per individual file

**Memory Management Warning**:
```python
# CRITICAL: Batch results stored in-memory until cleanup
# BatchManager._job_results accumulates converted image data
# Must call cleanup_job_results() after download or timeout
# Risk example: 100 files × 5MB avg = 500MB per job
# With 10 concurrent jobs = 5GB RAM usage
# Mitigation: Automatic cleanup after download
# TODO: Consider disk storage for production scale
```

### 16. WebSocket Authentication Pattern for Batch Jobs
**CRITICAL**: Batch processing implements comprehensive WebSocket security:

```python
# When batch_websocket_auth_enabled = True (default):

# 1. Token generation on job creation
response = POST /api/batch
# Response includes: websocket_url with token parameter

# 2. WebSocket connection with authentication
ws://host/ws/batch/{job_id}?token={token}

# 3. Token refresh for expired/lost tokens
POST /api/batch/{job_id}/websocket-token
# Returns new token valid for 24 hours

# Security features:
# - SHA-256 token hashing (never store plaintext)
# - 24-hour expiration with automatic cleanup
# - Rate limiting: 10 connections/minute/IP
# - Max 10 concurrent connections per job
# - Graceful fallback when auth disabled
```

**SecureConnectionManager Implementation**:
- Located in `app/api/websockets/secure_progress.py`
- Manages tokens, rate limits, and connection limits
- Falls back to regular ConnectionManager when auth disabled
- Uses WebSocket close codes for different security violations

### 17. Frontend Component Memory Management Pattern
**CRITICAL**: All frontend components with event listeners MUST implement proper cleanup:

```javascript
// CORRECT: Store event handlers for cleanup
class Component {
  constructor() {
    this.eventHandlers = new Map()
  }
  
  attachEventListeners() {
    const handler = () => this.handleClick()
    element.addEventListener('click', handler)
    this.eventHandlers.set('element-click', { element, event: 'click', handler })
  }
  
  destroy() {
    // Clean up all event listeners
    this.eventHandlers.forEach(({ element, event, handler }) => {
      element?.removeEventListener(event, handler)
    })
    this.eventHandlers.clear()
  }
}

// WRONG: Anonymous functions can't be removed
element.addEventListener('click', () => this.handleClick())  // Memory leak!
```

**Why**: Event listeners with anonymous functions or direct method references can't be removed, causing memory leaks in single-page applications.

**Component Re-rendering Pattern**:
```javascript
// CRITICAL: If component uses render() method that recreates DOM
// MUST re-render after any setting change to update UI
updateSetting(key, value) {
  this.settings[key] = value
  this.render()  // CRITICAL: Without this, UI won't update!
  if (this.onChangeCallback) {
    this.onChangeCallback(this.getSettings())
  }
}
```

### 18. Batch Processing Simplified UI Pattern
**CRITICAL**: Batch processing uses automatic flow without modals:

- **NO BatchSummaryModal**: Removed intentionally for simplicity
- **Auto-download**: Files download automatically upon completion
- **Simple messages**: Only success/error messages, no complex popups

```python
# Frontend: Simplified flow in app.js
async function autoDownloadBatchResults() {
    const blob = await downloadBatchResults(currentBatchJobId)
    // Automatic download without user interaction
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `batch_${currentBatchJobId.substring(0, 8)}_results.zip`
    a.click()
}

# Backend: On-demand compilation in batch_service.py
async def get_download_zip(self, job_id: str):
    result = self._results_storage.get(job_id)
    if not result:
        # Automatically compile if not cached
        result = await self.get_results(job_id)
        if not result:
            return None
```

**Why**: User requirement: "debe ser simple, le das a convertir y luego se descargan solos" (must be simple, click convert and files download automatically)

**Important**: When modifying batch UI, maintain this simplicity principle - no unnecessary modals or user interactions

### 19. CLI Productivity Module Security Patterns (Story 6.3)
**CRITICAL**: When implementing CLI productivity features, these security patterns are MANDATORY:

#### Privacy-First Data Storage
```python
# NEVER store filenames, paths, or PII in autocomplete/history
class PrivacySanitizer:
    PATH_PATTERNS = [
        r'[/\\][\w\-\.]+(?:[/\\][\w\-\.]+)*',  # File paths
        r'[\w\.\-]+@[\w\.\-]+',  # Email addresses
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
    ]
    
    def sanitize(self, text: str) -> str:
        for pattern in self.PATH_PATTERNS:
            text = re.sub(pattern, '<REDACTED>', text)
        return text
```

#### Resource Limits for Watch Mode
- **Max Files**: 100 files per watch session
- **Concurrency**: Max 5 concurrent conversions
- **Memory**: 512MB RAM limit enforced
- **Rate Limiting**: 10 events/second with 500ms debouncing
- **Auto-shutdown**: On 3 consecutive resource violations

#### Macro Security Requirements
1. **Command Validation**: Block dangerous commands (rm, format, curl, etc.)
2. **Signature Verification**: HMAC-SHA256 for integrity
3. **Approval System**: User must approve before first execution
4. **Sandboxing**: Execute in restricted environment
5. **File Permissions**: Store with 0o600 (user read/write only)

### 20. Test Execution Critical Pattern
**CRITICAL**: Tests MUST be run from backend/ directory for imports to work:

```bash
# WRONG: Will cause import errors
/image_converter$ pytest backend/tests/

# CORRECT: Run from backend directory
/image_converter$ cd backend
/image_converter/backend$ pytest

# Run specific test categories
/image_converter/backend$ pytest tests/unit/
/image_converter/backend$ pytest tests/integration/
/image_converter/backend$ pytest tests/security/
```

**Why**: All test imports use `from app.` which requires backend/ as working directory. Running from project root will cause ModuleNotFoundError.

### 21. CLI Documentation Sandbox Security Pattern
**CRITICAL**: When implementing CLI tutorials, examples, or any interactive command execution, these security measures are MANDATORY:

#### Command Validation
```python
# Validate img subcommand structure, not just prefix
valid_subcommands = [
    'convert', 'batch', 'optimize', 'analyze', 'formats', 
    'presets', 'watch', 'chain', 'docs', 'tutorial', 'help',
    'config', 'version', '--help', '-h'
]
if not command.startswith('img '):
    raise ValueError("Only img commands allowed")
    
# Validate subcommand structure
img_parts = command[4:].strip().split()
if not img_parts:
    raise ValueError("Missing subcommand")
subcommand = img_parts[0].lower()
if subcommand not in valid_subcommands:
    raise ValueError(f"Invalid subcommand: {subcommand}")
```

#### Environment Isolation
```python
# MANDATORY environment for CLI sandbox execution
safe_env = {
    'PATH': '/usr/local/bin:/usr/bin:/bin',
    'HOME': str(sandbox_dir),
    'TMPDIR': str(sandbox_dir / 'tmp'),
    'IMAGE_CONVERTER_ENABLE_SANDBOXING': 'true',
    'IMAGE_CONVERTER_SANDBOX_STRICTNESS': 'paranoid',
    # Block all network access
    'http_proxy': 'http://127.0.0.1:1',
    'https_proxy': 'http://127.0.0.1:1',
    'no_proxy': '*',
}

# Execute with resource limits
result = subprocess.run(
    command,
    shell=True,
    cwd=sandbox_dir,
    env=safe_env,  # Use restricted environment
    timeout=10,    # 10 second timeout
    capture_output=True
)
```

#### Blocked Commands List (70+)
The sandbox MUST block these command categories:
- **Shells**: bash, sh, zsh, fish, ksh, csh, tcsh, powershell, cmd
- **Languages**: python, python3, perl, ruby, php, node, nodejs
- **Network**: curl, wget, nc, netcat, telnet, ssh, ftp, sftp, scp, rsync
- **System**: sudo, su, chmod, chown, kill, pkill, systemctl, mount
- **Dangerous**: rm, dd, format, fdisk, mkfs, shred, wipe
- **Editors**: vi, vim, nano, emacs (can escape sandbox)

**Why**: CLI documentation features that execute commands pose significant security risks. These patterns ensure complete isolation and prevent command injection, network access, and system manipulation.
