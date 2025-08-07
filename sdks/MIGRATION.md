# Migration Guide

This guide helps you migrate between different versions of the Image Converter SDKs.

## Version Compatibility Matrix

| SDK Version | API Version | Breaking Changes | Migration Required |
| ----------- | ----------- | ---------------- | ------------------ |
| 1.0.x       | v1          | -                | No                 |
| 1.1.x       | v1          | No               | No                 |
| 1.2.x       | v1          | No               | No                 |
| 2.0.x       | v2          | Yes              | Yes                |

## Migrating from 1.x to 2.x (Future)

> **Note**: Version 2.x is not yet released. This section documents planned changes.

### Breaking Changes

#### All SDKs

- Minimum API version requirement: v2
- New error code system
- WebSocket connection changes

#### Python SDK

```python
# v1.x (Old)
from image_converter import ImageConverterClient
client = ImageConverterClient()

# v2.x (New)
from image_converter import Client  # Renamed
client = Client()
```

#### JavaScript SDK

```javascript
// v1.x (Old)
const client = new ImageConverterClient();

// v2.x (New)
const client = await ImageConverterClient.create(); // Async initialization
```

#### Go SDK

```go
// v1.x (Old)
client, err := ic.NewClient(nil)

// v2.x (New)
client, err := ic.NewClient(context.Background(), nil) // Context required
```

## Migrating from 0.x to 1.0

### Installation Changes

#### Python

```bash
# Old
pip install image-converter-beta

# New
pip install image-converter-sdk
```

#### JavaScript

```bash
# Old
npm install image-converter-client

# New
npm install @image-converter/sdk
```

#### Go

```bash
# Old
go get github.com/image-converter/client-go

# New
go get github.com/image-converter/image-converter-sdk-go
```

### API Changes

#### Error Handling

**Python - Old (0.x)**

```python
try:
    result = client.convert(image_path, "webp")
except Exception as e:
    print(f"Error: {e}")
```

**Python - New (1.0)**

```python
from image_converter.exceptions import (
    NetworkSecurityError,
    RateLimitError,
    ValidationError
)

try:
    result = client.convert_image(image_path, "webp")
except NetworkSecurityError as e:
    print(f"Security error: {e.error_code}")
except RateLimitError as e:
    print(f"Rate limited, retry after: {e.details.get('retry_after')}")
except ValidationError as e:
    print(f"Validation error: {e.message}")
```

#### Batch Processing

**JavaScript - Old (0.x)**

```javascript
// Synchronous batch processing
const results = client.batchConvert(images, "webp");
```

**JavaScript - New (1.0)**

```javascript
// Asynchronous with progress tracking
const batch = await client.createBatch(images, "webp");
while (batch.status !== "completed") {
  await sleep(2000);
  batch = await client.getBatchStatus(batch.jobId);
  console.log(`Progress: ${batch.progressPercentage}%`);
}
```

#### Security Enhancements

**Go - Old (0.x)**

```go
// No localhost enforcement
client := &Client{
    Host: "api.example.com", // Allowed
}
```

**Go - New (1.0)**

```go
// Localhost enforced by default
client, err := NewClient(&ClientOptions{
    Host: "api.example.com", // Error: NetworkSecurityError
})

// Must explicitly disable for non-localhost (not recommended)
client, err := NewClient(&ClientOptions{
    Host:            "192.168.1.100",
    VerifyLocalhost: false, // ⚠️ Security risk
})
```

## Feature Deprecations

### Deprecated in 1.0

#### Python SDK

- `client.set_api_key()` → Use `client.store_api_key()`
- `client.get_formats()` → Use `client.get_supported_formats()`

#### JavaScript SDK

- `client.formats` property → Use `client.getSupportedFormats()`
- Callback-based API → Use Promise/async-await

#### Go SDK

- `client.SetKey()` → Use `client.StoreAPIKey()`

### Removal Timeline

- Deprecated in: 1.0.0
- Warnings added: 1.1.0
- Removed in: 2.0.0

## Configuration Migration

### API Key Storage

**Old Method (0.x)**

```python
# Stored in plaintext config file
config = {
    "api_key": "ic_live_abc123..."
}
```

**New Method (1.0+)**

```python
# Secure OS keychain storage
from image_converter.auth import SecureAPIKeyManager

manager = SecureAPIKeyManager()
manager.store_api_key("production", "ic_live_abc123...")
```

### Environment Variables

**Old (0.x)**

```bash
export IC_API_KEY="abc123"
export IC_API_HOST="localhost"
export IC_API_PORT="8000"
```

**New (1.0+)**

```bash
export IMAGE_CONVERTER_API_KEY="ic_live_abc123..."
# Host and port now in client initialization
```

## Testing Your Migration

### Automated Migration Testing

**Python**

```python
# test_migration.py
import pytest
from image_converter import ImageConverterClient

def test_v1_compatibility():
    client = ImageConverterClient()
    assert client.verify_localhost == True
    assert client.base_url.startswith("http://localhost")

def test_security_enforcement():
    with pytest.raises(NetworkSecurityError):
        ImageConverterClient(host="external.com")
```

**JavaScript**

```javascript
// test-migration.js
const { ImageConverterClient } = require("@image-converter/sdk");

describe("Migration Tests", () => {
  test("v1 API compatibility", () => {
    const client = new ImageConverterClient();
    expect(client.verifyLocalhost).toBe(true);
  });

  test("Security enforcement", () => {
    expect(() => {
      new ImageConverterClient({ host: "external.com" });
    }).toThrow("Network access blocked");
  });
});
```

**Go**

```go
// migration_test.go
func TestV1Compatibility(t *testing.T) {
    client, err := NewClient(nil)
    assert.NoError(t, err)
    assert.True(t, client.verifyLocalhost)
}

func TestSecurityEnforcement(t *testing.T) {
    _, err := NewClient(&ClientOptions{
        Host: "external.com",
    })
    assert.Error(t, err)
    assert.IsType(t, &NetworkSecurityError{}, err)
}
```

## Migration Checklist

Before upgrading:

- [ ] Review breaking changes for your SDK
- [ ] Update import statements
- [ ] Migrate deprecated method calls
- [ ] Update error handling code
- [ ] Test localhost enforcement
- [ ] Migrate API key storage
- [ ] Update environment variables
- [ ] Run migration tests
- [ ] Update CI/CD pipelines
- [ ] Review security settings

## Rollback Procedure

If you need to rollback:

### Python

```bash
pip install image-converter-sdk==1.0.0  # Specific version
```

### JavaScript

```bash
npm install @image-converter/sdk@1.0.0
```

### Go

```bash
go get github.com/image-converter/image-converter-sdk-go@v1.0.0
```

## Getting Help

### Migration Support

- **Documentation**: Check the version-specific docs
- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/discussions)
- **Email**: support@imageconverter.local

### Common Migration Issues

#### Issue: "NetworkSecurityError: Connection blocked"

**Solution**: Ensure you're connecting to localhost only, or explicitly disable verification (not recommended).

#### Issue: "Module not found" after upgrade

**Solution**: Clear package cache and reinstall:

```bash
# Python
pip cache purge && pip install --upgrade image-converter-sdk

# JavaScript
npm cache clean --force && npm install @image-converter/sdk

# Go
go clean -cache && go get -u github.com/image-converter/image-converter-sdk-go
```

#### Issue: "API version mismatch"

**Solution**: Ensure your API server is running the compatible version. Check with:

```bash
curl http://localhost:8000/api/health
```

## Version Support Policy

| Version | Status      | Support Until | Security Updates |
| ------- | ----------- | ------------- | ---------------- |
| 1.2.x   | Current     | -             | Yes              |
| 1.1.x   | Maintenance | 2025-06-01    | Yes              |
| 1.0.x   | Maintenance | 2025-03-01    | Critical only    |
| 0.x     | End of Life | 2024-12-31    | No               |

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for detailed version history.
