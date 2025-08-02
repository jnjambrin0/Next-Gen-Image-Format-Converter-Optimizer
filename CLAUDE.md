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

## Development Commands

### Backend Setup and Development

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (when available)
pip install -r requirements.txt

# Run development server
uvicorn app.main:app --reload --port 8080

# Run tests
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

# Install dependencies (when available)
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
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest backend/tests/unit/test_conversion.py

# Run integration tests only
pytest backend/tests/integration/

# Run security tests (requires Docker)
pytest backend/tests/security/
```

## Key Architecture Decisions

1. **Local-Only Processing**: No network requests, all ML models and processing happen locally
2. **Process Sandboxing**: Each conversion runs in isolated subprocess with restricted permissions
3. **Memory-Only Processing**: No temporary files on disk, all processing in RAM
4. **Format Support**:
   - Input: JPEG, PNG, WebP, HEIF/HEIC, BMP, TIFF, GIF, AVIF
   - Output: WebP, AVIF, JPEG XL, HEIF, PNG (optimized), JPEG (optimized), WebP2, JPEG 2000
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

### Quick Testing
```bash
# Test all format conversions
python test_conversion.py

# Test specific format
python test_conversion.py png
```

## API Endpoints (Planned)

- `POST /api/convert` - Convert single image
- `POST /api/batch` - Batch conversion
- `GET /api/health` - Health check
- `GET /api/formats` - Supported formats
- `POST /api/detect` - Content type detection
- `GET /api/presets` - Available presets

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
