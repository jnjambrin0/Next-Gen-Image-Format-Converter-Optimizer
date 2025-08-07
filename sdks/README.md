# Image Converter SDKs

🔒 **Privacy-focused, local-only image conversion SDKs for multiple languages**

## 📦 Available SDKs

### Python SDK

- **Package**: `image-converter-sdk`
- **Features**: Async/sync clients, type hints, secure key storage
- **Installation**: `pip install image-converter-sdk`
- [Documentation](./python/README.md)

### JavaScript/TypeScript SDK

- **Package**: `@image-converter/sdk`
- **Features**: TypeScript support, Node.js/browser compatible
- **Installation**: `npm install @image-converter/sdk`
- [Documentation](./javascript/README.md)

### Go SDK

- **Module**: `github.com/image-converter/image-converter-sdk-go`
- **Features**: Context support, idiomatic error handling
- **Installation**: `go get github.com/image-converter/image-converter-sdk-go`
- [Documentation](./go/README.md)

## 🔒 Security Features (All SDKs)

### Localhost-Only Enforcement

All SDKs enforce localhost-only connections by default. Attempts to connect to external hosts are blocked with security errors.

### Secure API Key Storage

- **Python**: OS keychain via `keyring` library
- **JavaScript**: Encrypted local storage
- **Go**: OS keychain via `go-keyring`

### Privacy-Aware Error Handling

No filenames, paths, or user data in error messages across all SDKs.

## 🚀 Quick Comparison

| Feature           | Python        | JavaScript    | Go               |
| ----------------- | ------------- | ------------- | ---------------- |
| Async Support     | ✅ asyncio    | ✅ Promises   | ✅ Context       |
| Type Safety       | ✅ Type hints | ✅ TypeScript | ✅ Static typing |
| Secure Storage    | ✅ keyring    | ✅ Encrypted  | ✅ keychain      |
| Browser Support   | ❌            | ✅            | ❌               |
| Concurrent Batch  | ✅            | ✅            | ✅               |
| WebSocket Support | ✅            | ✅            | ✅               |

## 🌟 Common Use Cases

### Single Image Conversion

```python
# Python
client = ImageConverterClient()
data, metadata = client.convert_image("photo.jpg", "webp")
```

```javascript
// JavaScript
const client = new ImageConverterClient();
const { data, metadata } = await client.convertImage("photo.jpg", "webp");
```

```go
// Go
client, _ := ic.NewClient(nil)
data, metadata, _ := client.ConvertImage(ctx, "photo.jpg", "webp", nil)
```

### Batch Processing

All SDKs support batch processing with progress tracking:

- Create batch job
- Monitor progress via polling or WebSocket
- Download results

### Content Analysis

ML-powered content analysis available in all SDKs:

- Detect content type (photo, screenshot, document, illustration)
- Face and text region detection
- Format recommendations based on content

## 🔧 Configuration

All SDKs use similar configuration patterns:

```yaml
Host: localhost # Must be localhost
Port: 8000 # API server port
API Key: (optional) # From env or secure storage
API Version: v1 # API version
Timeout: 30s # Request timeout
Verify Localhost: true # Security enforcement
```

## 🧪 Testing

Each SDK includes comprehensive tests:

```bash
# Python
pytest tests/

# JavaScript
npm test

# Go
go test ./...
```

## 📚 Documentation

- [API Reference](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer)
- [OpenAPI Specification](../openapi.json)
- [Security Guide](./SECURITY.md)
- [Migration Guide](./MIGRATION.md)
- [Distribution Guide](./DISTRIBUTION.md)

## 🤝 Contributing

When contributing to SDKs:

1. **Security First**: Maintain localhost-only enforcement
2. **Privacy**: No PII in logs or errors
3. **Consistency**: Follow language idioms
4. **Testing**: Maintain 80%+ coverage
5. **Documentation**: Update README and examples

## 📦 Publishing

### Python (PyPI)

```bash
cd python/
python setup.py sdist bdist_wheel
twine upload dist/*
```

### JavaScript (npm)

```bash
cd javascript/
npm run build
npm publish
```

### Go (Module)

```bash
cd go/
git tag v1.0.0
git push origin v1.0.0
```

## 🔐 Security Notice

These SDKs are designed for **local-only** operation:

- ✅ Only connect to localhost/127.0.0.1
- ✅ Secure API key storage
- ✅ Privacy-aware error handling
- ❌ No external network calls
- ❌ No telemetry or tracking
- ❌ No data transmission

## 📄 License

All SDKs are released under the MIT License.

## 🆘 Support

- [Issue Tracker](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer/issues)
- [Discussions](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer/discussions)
- Email: support@imageconverter.local
