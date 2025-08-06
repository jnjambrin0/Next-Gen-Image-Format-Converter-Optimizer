# Image Converter Python SDK

🔒 **Privacy-focused, local-only image conversion SDK for Python**

## 🚀 Features

- **100% Local Processing**: All conversions happen on your local machine
- **Security First**: Enforces localhost-only connections, no external network access
- **Secure API Key Storage**: OS keychain integration for API key management
- **Privacy-Aware**: No PII in logs or error messages
- **Async Support**: Both synchronous and asynchronous clients
- **Type Safety**: Full type hints for better IDE support
- **Comprehensive Format Support**: WebP, AVIF, JPEG, PNG, HEIF, JXL, WebP2

## 📦 Installation

```bash
pip install image-converter-sdk
```

For development:
```bash
pip install image-converter-sdk[dev]
```

## 🔒 Security Features

### Localhost-Only Enforcement
The SDK **only** connects to localhost addresses (127.0.0.1, localhost, ::1). Attempts to connect to external hosts will raise a `NetworkSecurityError`.

### Secure API Key Storage
API keys are stored securely using your OS keychain (macOS Keychain, Windows Credential Locker, Linux Secret Service). Fallback to encrypted local storage if keychain is unavailable.

### Privacy-Aware Error Handling
No filenames, paths, or user data in error messages. All errors use generic, privacy-safe messages.

## 🚦 Quick Start

### Simple Conversion

```python
from image_converter import ImageConverterClient

# Initialize client (localhost only)
client = ImageConverterClient(
    host="localhost",  # Only localhost allowed
    port=8080,
    api_key=None,  # Optional, will try env or secure storage
)

# Convert an image
converted_data, metadata = client.convert_image(
    image_path="photo.jpg",
    output_format="webp",
    quality=85,
    strip_metadata=True,  # Privacy-first: remove EXIF data
)

# Save the result
with open("photo.webp", "wb") as f:
    f.write(converted_data)

print(f"Compression ratio: {metadata.compression_ratio:.1%}")
```

### Async Client

```python
import asyncio
from image_converter import AsyncImageConverterClient

async def main():
    async with AsyncImageConverterClient() as client:
        # Concurrent conversions
        tasks = [
            client.convert_image(f"photo{i}.jpg", "webp")
            for i in range(5)
        ]
        results = await asyncio.gather(*tasks)
        
        for i, (data, metadata) in enumerate(results):
            with open(f"photo{i}.webp", "wb") as f:
                f.write(data)

asyncio.run(main())
```

### Batch Processing

```python
from image_converter import ImageConverterClient

client = ImageConverterClient()

# Create batch job
batch_status = client.create_batch(
    image_paths=["photo1.jpg", "photo2.png", "photo3.heic"],
    output_format="avif",
    quality=90,
    max_concurrent=5,
)

# Monitor progress
import time
while batch_status.status not in ["completed", "failed"]:
    time.sleep(2)
    batch_status = client.get_batch_status(batch_status.job_id)
    print(f"Progress: {batch_status.progress_percentage:.0f}%")

print(f"Completed: {batch_status.completed_files} files")
```

### Content Analysis & Recommendations

```python
from image_converter import ImageConverterClient

client = ImageConverterClient()

# Analyze image content
classification = client.analyze_image("photo.jpg")
print(f"Content type: {classification.content_type}")
print(f"Confidence: {classification.confidence:.1%}")

# Get format recommendations
recommendations = client.get_format_recommendations(
    content_classification=classification,
    original_format="jpeg",
    original_size_kb=1024,
    use_case="web",
    prioritize="quality",
)

for rec in recommendations.recommended_formats:
    print(f"Format: {rec['format']}, Score: {rec['score']}")
```

## 🔑 API Key Management

### Secure Storage

```python
from image_converter.auth import SecureAPIKeyManager

manager = SecureAPIKeyManager()

# Store API key securely
manager.store_api_key("my-app", "ic_live_abc123...")

# Retrieve API key
api_key = manager.retrieve_api_key("my-app")

# List stored keys (names only, not actual keys)
keys = manager.list_stored_keys()

# Delete API key
manager.delete_api_key("my-app")
```

### Environment Variable

```bash
export IMAGE_CONVERTER_API_KEY="ic_live_abc123..."
```

The SDK automatically checks for this environment variable.

## 🛡️ Error Handling

```python
from image_converter import ImageConverterClient
from image_converter.exceptions import (
    NetworkSecurityError,
    RateLimitError,
    ValidationError,
    ServiceUnavailableError,
)

client = ImageConverterClient()

try:
    # Attempt to connect to external host (blocked)
    client = ImageConverterClient(host="example.com")
except NetworkSecurityError as e:
    print(f"Security error: {e}")

try:
    result = client.convert_image("photo.jpg", "webp")
except RateLimitError as e:
    print(f"Rate limited. Retry after: {e.details.get('retry_after')} seconds")
except ValidationError as e:
    print(f"Invalid request: {e}")
except ServiceUnavailableError:
    print("Local service is not running")
```

## 🔧 Configuration

### Client Options

```python
client = ImageConverterClient(
    host="localhost",        # Must be localhost
    port=8080,              # API port
    api_key="ic_live_...",  # Optional API key
    api_version="v1",       # API version
    timeout=30.0,           # Request timeout (seconds)
    verify_localhost=True,  # Enforce localhost (recommended)
)
```

### Disable Localhost Verification (NOT RECOMMENDED)

```python
# ⚠️ WARNING: Only for testing. Never use in production!
client = ImageConverterClient(
    host="192.168.1.100",
    verify_localhost=False,  # Dangerous!
)
```

## 📚 Examples

See the `examples/` directory for complete examples:

- `convert_single.py` - Simple single image conversion
- `batch_convert.py` - Batch processing with progress tracking
- `async_example.py` - Async/await patterns
- `api_key_management.py` - Secure API key handling
- `content_analysis.py` - ML-powered content analysis

## 🧪 Testing

Run tests with pytest:

```bash
# Install dev dependencies
pip install -e .[dev]

# Run tests
pytest

# With coverage
pytest --cov=image_converter --cov-report=html
```

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All connections remain localhost-only
2. No PII in logs or error messages
3. API keys stored securely
4. Tests pass with 80%+ coverage
5. Type hints for all functions

## 📄 License

MIT License - see LICENSE file for details.

## 🔗 Links

- [API Documentation](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer)
- [Issue Tracker](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer/issues)
- [Release Notes](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer/releases)

## ⚠️ Security Notice

This SDK is designed for **local-only** operation. It will:
- ✅ Only connect to localhost/127.0.0.1
- ✅ Store API keys securely in OS keychain
- ✅ Remove metadata from images by default
- ❌ Never make external network calls
- ❌ Never log sensitive information
- ❌ Never transmit data outside your machine

For security issues, please report privately to security@imageconverter.local