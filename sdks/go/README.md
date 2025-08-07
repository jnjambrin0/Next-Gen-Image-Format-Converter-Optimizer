# Image Converter Go SDK

🔒 **Privacy-focused, local-only image conversion SDK for Go**

## 🚀 Features

- **100% Local Processing**: All conversions happen on your local machine
- **Security First**: Enforces localhost-only connections, no external network access
- **Idiomatic Go**: Context support, proper error handling, concurrent-safe
- **Secure API Key Storage**: OS keychain integration for API key management
- **Privacy-Aware**: No PII in logs or error messages
- **Comprehensive Format Support**: WebP, AVIF, JPEG, PNG, HEIF, JXL, WebP2

## 📦 Installation

```bash
go get github.com/image-converter/image-converter-sdk-go
```

## 🔒 Security Features

### Localhost-Only Enforcement

The SDK **only** connects to localhost addresses (127.0.0.1, localhost, ::1). Attempts to connect to external hosts will return a `NetworkSecurityError`.

### Secure API Key Storage

API keys are stored securely using OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service). Fallback to encrypted local storage if keychain is unavailable.

### Privacy-Aware Error Handling

No filenames, paths, or user data in error messages. All errors use generic, privacy-safe messages.

## 🚦 Quick Start

### Simple Conversion

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    ic "github.com/image-converter/image-converter-sdk-go"
)

func main() {
    // Initialize client (localhost only)
    client, err := ic.NewClient(&ic.ClientOptions{
        Host: "localhost",  // Only localhost allowed
        Port: 8000,
        // APIKey will be read from env or secure storage
    })
    if err != nil {
        log.Fatal(err)
    }

    // Convert an image
    ctx := context.Background()
    data, metadata, err := client.ConvertImage(
        ctx,
        "photo.jpg",
        string(ic.FormatWebP),
        &ic.ConversionOptions{
            Quality:       85,
            StripMetadata: true, // Privacy-first: remove EXIF data
        },
    )
    if err != nil {
        log.Fatal(err)
    }

    // Save the result
    err = os.WriteFile("photo.webp", data, 0644)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Compression ratio: %.1f%%\n", metadata.CompressionRatio*100)
}
```

### Concurrent Batch Processing

```go
package main

import (
    "context"
    "fmt"
    "log"
    "sync"

    ic "github.com/image-converter/image-converter-sdk-go"
)

func main() {
    client, err := ic.NewClient(nil) // Use defaults
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    images := []string{"photo1.jpg", "photo2.png", "photo3.heic"}

    // Create batch job
    batch, err := client.CreateBatch(
        ctx,
        images,
        string(ic.FormatAVIF),
        &ic.BatchOptions{
            Quality:       90,
            MaxConcurrent: 5,
        },
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Batch job created: %s\n", batch.JobID)

    // Monitor progress
    for batch.Status != "completed" && batch.Status != "failed" {
        time.Sleep(2 * time.Second)

        batch, err = client.GetBatchStatus(ctx, batch.JobID)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("Progress: %.0f%%\n", batch.ProgressPercentage)
    }

    fmt.Printf("Completed: %d files\n", batch.CompletedFiles)
}
```

### Content Analysis & Recommendations

```go
package main

import (
    "context"
    "fmt"
    "log"

    ic "github.com/image-converter/image-converter-sdk-go"
)

func main() {
    client, err := ic.NewClient(nil)
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Analyze image content
    classification, err := client.AnalyzeImage(ctx, "photo.jpg", false)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Content type: %s\n", classification.ContentType)
    fmt.Printf("Confidence: %.1f%%\n", classification.Confidence*100)

    // Handle face regions if detected
    if len(classification.FaceRegions) > 0 {
        fmt.Printf("Detected %d faces\n", len(classification.FaceRegions))
    }

    // Handle text regions if detected
    if len(classification.TextRegions) > 0 {
        fmt.Printf("Detected %d text regions\n", len(classification.TextRegions))
    }
}
```

## 🔑 API Key Management

### Secure Storage

```go
package main

import (
    "fmt"
    "log"

    ic "github.com/image-converter/image-converter-sdk-go"
)

func main() {
    client, err := ic.NewClient(nil)
    if err != nil {
        log.Fatal(err)
    }

    // Store API key securely
    err = client.StoreAPIKey("my-app", "ic_live_abc123...")
    if err != nil {
        log.Fatal(err)
    }

    // Retrieve API key
    apiKey, err := client.RetrieveAPIKey("my-app")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Retrieved key: %s...\n", apiKey[:10])

    // Generate new API key
    newKey := ic.GenerateAPIKey()
    fmt.Printf("Generated key: %s\n", newKey)
}
```

### Environment Variable

```bash
export IMAGE_CONVERTER_API_KEY="ic_live_abc123..."
```

The SDK automatically checks for this environment variable.

## 🛡️ Error Handling

```go
package main

import (
    "errors"
    "fmt"
    "log"

    ic "github.com/image-converter/image-converter-sdk-go"
)

func main() {
    // Attempt to connect to external host (blocked)
    _, err := ic.NewClient(&ic.ClientOptions{
        Host: "example.com",
    })

    var netErr *ic.NetworkSecurityError
    if errors.As(err, &netErr) {
        fmt.Println("Security error:", netErr)
    }

    // Use proper localhost client
    client, err := ic.NewClient(nil)
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()
    _, _, err = client.ConvertImage(ctx, "photo.jpg", "webp", nil)

    var rateErr *ic.RateLimitError
    var valErr *ic.ValidationError
    var svcErr *ic.ServiceUnavailableError

    if errors.As(err, &rateErr) {
        fmt.Printf("Rate limited. Retry after: %d seconds\n", rateErr.RetryAfter)
    } else if errors.As(err, &valErr) {
        fmt.Println("Invalid request:", valErr)
    } else if errors.As(err, &svcErr) {
        fmt.Println("Local service is not running")
    }
}
```

## 🔧 Configuration

### Client Options

```go
client, err := ic.NewClient(&ic.ClientOptions{
    Host:            "localhost",       // Must be localhost
    Port:            8000,              // API port
    APIKey:          "ic_live_...",    // Optional API key
    APIVersion:      "v1",              // API version
    Timeout:         30 * time.Second,  // Request timeout
    VerifyLocalhost: true,              // Enforce localhost (recommended)
})
```

### Context Support

All API methods accept a context for cancellation and timeouts:

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

data, metadata, err := client.ConvertImage(ctx, "photo.jpg", "webp", nil)
```

### Disable Localhost Verification (NOT RECOMMENDED)

```go
// ⚠️ WARNING: Only for testing. Never use in production!
client, err := ic.NewClient(&ic.ClientOptions{
    Host:            "192.168.1.100",
    VerifyLocalhost: false,  // Dangerous!
})
```

## 📚 Examples

See the `examples/` directory for complete examples:

- `simple/main.go` - Simple single image conversion
- `concurrent/main.go` - Concurrent batch processing
- `analysis/main.go` - Content analysis and recommendations
- `secure_keys/main.go` - API key management
- `microservice/main.go` - Integration with microservices

## 🧪 Testing

```bash
# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with race detection
go test -race ./...

# Benchmark tests
go test -bench=. ./...
```

## 🏗️ Building

```bash
# Build the package
go build

# Build with specific tags
go build -tags release

# Cross-compile for different platforms
GOOS=linux GOARCH=amd64 go build
GOOS=windows GOARCH=amd64 go build
GOOS=darwin GOARCH=arm64 go build
```

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All connections remain localhost-only
2. No PII in logs or error messages
3. API keys stored securely
4. Tests pass with 80%+ coverage
5. Idiomatic Go code with proper error handling

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
