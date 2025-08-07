# Image Converter JavaScript/TypeScript SDK

🔒 **Privacy-focused, local-only image conversion SDK for JavaScript/TypeScript**

## 🚀 Features

- **100% Local Processing**: All conversions happen on your local machine
- **Security First**: Enforces localhost-only connections, no external network access
- **TypeScript Support**: Full type definitions for better IDE experience
- **Universal**: Works in both Node.js and browser environments
- **Secure API Key Storage**: Encrypted local storage for API keys
- **Privacy-Aware**: No PII in logs or error messages
- **Comprehensive Format Support**: WebP, AVIF, JPEG, PNG, HEIF, JXL, WebP2

## 📦 Installation

```bash
npm install @image-converter/sdk
# or
yarn add @image-converter/sdk
# or
pnpm add @image-converter/sdk
```

## 🔒 Security Features

### Localhost-Only Enforcement
The SDK **only** connects to localhost addresses (127.0.0.1, localhost, ::1). Attempts to connect to external hosts will throw a `NetworkSecurityError`.

### Secure API Key Storage
API keys are stored securely using encrypted local storage. For production use with OS keychain support, consider adding `keytar` as a dependency.

### Privacy-Aware Error Handling
No filenames, paths, or user data in error messages. All errors use generic, privacy-safe messages.

## 🚦 Quick Start

### Simple Conversion (Node.js)

```javascript
const { ImageConverterClient } = require('@image-converter/sdk');

const client = new ImageConverterClient({
  host: 'localhost',  // Only localhost allowed
  port: 8000,
  apiKey: null,  // Optional, will try env or secure storage
});

// Convert an image
async function convertImage() {
  const { data, metadata } = await client.convertImage(
    'photo.jpg',
    'webp',
    {
      quality: 85,
      stripMetadata: true,  // Privacy-first: remove EXIF data
    }
  );

  // Save the result
  const fs = require('fs').promises;
  await fs.writeFile('photo.webp', data);

  console.log(`Compression ratio: ${(metadata.compressionRatio * 100).toFixed(1)}%`);
}

convertImage().catch(console.error);
```

### TypeScript

```typescript
import { ImageConverterClient, OutputFormat } from '@image-converter/sdk';

const client = new ImageConverterClient({
  host: 'localhost',
  port: 8000,
});

async function convert(): Promise<void> {
  const { data, metadata } = await client.convertImage(
    'photo.jpg',
    OutputFormat.WEBP,
    {
      quality: 90,
      stripMetadata: true,
    }
  );

  console.log(`Converted in ${metadata.processingTime}s`);
}
```

### Batch Processing

```javascript
const { ImageConverterClient } = require('@image-converter/sdk');

const client = new ImageConverterClient();

async function batchConvert() {
  // Create batch job
  const batchStatus = await client.createBatch(
    ['photo1.jpg', 'photo2.png', 'photo3.heic'],
    'avif',
    {
      quality: 90,
      maxConcurrent: 5,
    }
  );

  console.log(`Batch job created: ${batchStatus.jobId}`);

  // Monitor progress
  let status = batchStatus;
  while (!['completed', 'failed'].includes(status.status)) {
    await new Promise(resolve => setTimeout(resolve, 2000));
    status = await client.getBatchStatus(batchStatus.jobId);
    console.log(`Progress: ${status.progressPercentage.toFixed(0)}%`);
  }

  console.log(`Completed: ${status.completedFiles} files`);
}
```

### Content Analysis & Recommendations

```javascript
const { ImageConverterClient } = require('@image-converter/sdk');

const client = new ImageConverterClient();

async function analyzeAndRecommend() {
  // Analyze image content
  const classification = await client.analyzeImage('photo.jpg');
  console.log(`Content type: ${classification.contentType}`);
  console.log(`Confidence: ${(classification.confidence * 100).toFixed(1)}%`);

  // Get format recommendations
  const recommendations = await client.getFormatRecommendations(
    classification,
    'jpeg',
    1024,  // 1MB
    'web',
    'quality'
  );

  recommendations.recommendedFormats.forEach(rec => {
    console.log(`Format: ${rec.format}, Score: ${rec.score}`);
    console.log(`Reasons: ${rec.reasons.join(', ')}`);
  });
}
```

## 🔑 API Key Management

### Secure Storage

```javascript
const { SecureAPIKeyManager } = require('@image-converter/sdk');

const keyManager = new SecureAPIKeyManager();

// Store API key securely
await keyManager.store('my-app', 'ic_live_abc123...');

// Retrieve API key
const apiKey = keyManager.retrieve('my-app');

// List stored keys (names only, not actual keys)
const keys = await keyManager.listKeys();

// Delete API key
await keyManager.delete('my-app');

// Generate new API key
const newKey = SecureAPIKeyManager.generateApiKey();
```

### Environment Variable

```bash
export IMAGE_CONVERTER_API_KEY="ic_live_abc123..."
```

The SDK automatically checks for this environment variable.

## 🛡️ Error Handling

```javascript
const { 
  ImageConverterClient,
  NetworkSecurityError,
  RateLimitError,
  ValidationError,
  ServiceUnavailableError
} = require('@image-converter/sdk');

const client = new ImageConverterClient();

try {
  // Attempt to connect to external host (blocked)
  const badClient = new ImageConverterClient({ host: 'example.com' });
} catch (error) {
  if (error instanceof NetworkSecurityError) {
    console.error('Security error:', error.message);
  }
}

try {
  const result = await client.convertImage('photo.jpg', 'webp');
} catch (error) {
  if (error instanceof RateLimitError) {
    console.log(`Rate limited. Retry after: ${error.retryAfter} seconds`);
  } else if (error instanceof ValidationError) {
    console.log('Invalid request:', error.message);
  } else if (error instanceof ServiceUnavailableError) {
    console.log('Local service is not running');
  }
}
```

## 🔧 Configuration

### Client Options

```typescript
const client = new ImageConverterClient({
  host: 'localhost',        // Must be localhost
  port: 8000,              // API port
  apiKey: 'ic_live_...',   // Optional API key
  apiVersion: 'v1',        // API version
  timeout: 30000,          // Request timeout (ms)
  verifyLocalhost: true,   // Enforce localhost (recommended)
});
```

### Disable Localhost Verification (NOT RECOMMENDED)

```javascript
// ⚠️ WARNING: Only for testing. Never use in production!
const client = new ImageConverterClient({
  host: '192.168.1.100',
  verifyLocalhost: false,  // Dangerous!
});
```

## 🌐 Browser Usage

The SDK works in browsers with some limitations:

```html
<script type="module">
import { ImageConverterClient } from '@image-converter/sdk';

const client = new ImageConverterClient({
  host: 'localhost',
  port: 8000,
});

// Note: File reading is different in browser
async function convertFromBlob(blob) {
  // Browser implementation would need to handle file differently
  // This is a simplified example
  const formData = new FormData();
  formData.append('file', blob);
  formData.append('output_format', 'webp');
  
  const response = await fetch('http://localhost:8000/api/v1/convert', {
    method: 'POST',
    body: formData,
  });
  
  const convertedBlob = await response.blob();
  return convertedBlob;
}
</script>
```

## 📚 Examples

See the `examples/` directory for complete examples:

- `node-convert.js` - Node.js single image conversion
- `batch-processor.js` - Batch processing with progress
- `browser-app/` - Browser-based conversion app
- `typescript-example.ts` - TypeScript usage patterns
- `secure-keys.js` - API key management

## 🧪 Testing

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint

# Format code
npm run format
```

## 🏗️ Building

```bash
# Build for production
npm run build

# Development build with watch
npm run dev
```

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All connections remain localhost-only
2. No PII in logs or error messages
3. API keys stored securely
4. Tests pass with 80%+ coverage
5. TypeScript types are properly defined

## 📄 License

MIT License - see LICENSE file for details.

## 🔗 Links

- [API Documentation](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer)
- [Issue Tracker](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer/issues)
- [Release Notes](https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer/releases)

## ⚠️ Security Notice

This SDK is designed for **local-only** operation. It will:
- ✅ Only connect to localhost/127.0.0.1
- ✅ Store API keys securely with encryption
- ✅ Remove metadata from images by default
- ❌ Never make external network calls
- ❌ Never log sensitive information
- ❌ Never transmit data outside your machine

For security issues, please report privately to security@imageconverter.local