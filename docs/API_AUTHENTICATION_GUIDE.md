# API Authentication and Rate Limiting Guide

## Overview

The Image Converter API now supports optional API key authentication with per-key rate limiting, usage statistics, and comprehensive security features. All processing remains local-only.

## Features

- ✅ **Optional Authentication**: API works with or without API keys
- ✅ **Secure Key Management**: SHA-256 hashed storage, secure generation
- ✅ **Custom Rate Limits**: Per-API-key rate limit overrides
- ✅ **Usage Statistics**: Track API usage per key and overall
- ✅ **Privacy-Aware Logging**: No PII in logs, sanitized statistics
- ✅ **Localhost Whitelisting**: Trusted local access
- ✅ **Web UI Management**: Simple interface for key management

## Quick Start

### 1. Create an API Key

**Using the Web UI:**
1. Open the Image Converter web interface
2. Click the "API Keys" button in the header
3. Fill out the form and click "Create API Key"
4. **Important**: Copy the API key immediately - it won't be shown again

**Using the API:**
```bash
curl -X POST http://localhost:8080/api/auth/api-keys \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "rate_limit_override": 120,
    "expires_days": 90
  }'
```

### 2. Use Your API Key

**Bearer Token (Recommended):**
```bash
curl -X POST http://localhost:8080/api/convert \
  -H "Authorization: Bearer YOUR_API_KEY_HERE" \
  -F "file=@image.jpg" \
  -F "output_format=webp"
```

**X-API-Key Header:**
```bash
curl -X POST http://localhost:8080/api/convert \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -F "file=@image.jpg" \
  -F "output_format=webp"
```

**Query Parameter (Less Secure):**
```bash
curl -X POST "http://localhost:8080/api/convert?api_key=YOUR_API_KEY_HERE" \
  -F "file=@image.jpg" \
  -F "output_format=webp"
```

## API Endpoints

### Authentication Management

All endpoints are available at both `/api/auth/` and `/api/v1/auth/`.

#### Create API Key
```http
POST /api/auth/api-keys
Content-Type: application/json

{
  "name": "Optional key name",
  "rate_limit_override": 120,  // requests per minute (optional)
  "expires_days": 90           // expiration in days (optional)
}
```

**Response:**
```json
{
  "api_key": "abcd1234-your-actual-key-never-shown-again",
  "key_info": {
    "id": "uuid-of-key",
    "name": "Optional key name",
    "rate_limit_override": 120,
    "is_active": true,
    "created_at": "2025-08-05T10:00:00Z",
    "last_used_at": null,
    "expires_at": "2025-11-03T10:00:00Z"
  }
}
```

#### List API Keys
```http
GET /api/auth/api-keys?include_inactive=false
```

#### Get Specific API Key
```http
GET /api/auth/api-keys/{key_id}
```

#### Update API Key
```http
PUT /api/auth/api-keys/{key_id}
Content-Type: application/json

{
  "name": "New name",
  "rate_limit_override": 200,
  "expires_days": 60
}
```

#### Revoke API Key
```http
DELETE /api/auth/api-keys/{key_id}
```

#### Get Usage Statistics
```http
GET /api/auth/api-keys/{key_id}/usage?days=7
GET /api/auth/usage?days=7  // Overall statistics
```

**Response:**
```json
{
  "total_requests": 150,
  "unique_endpoints": 3,
  "avg_response_time_ms": 125.5,
  "status_codes": {
    "200": 140,
    "400": 8,
    "429": 2
  },
  "endpoints": {
    "/api/convert": 100,
    "/api/batch": 30,
    "/api/health": 20
  },
  "period_days": 7
}
```

## Rate Limiting

### Default Limits
- **Unauthenticated requests**: 60 requests/minute, 1000 requests/hour
- **Authenticated requests**: Custom limits or default if not specified

### Rate Limit Headers
All API responses include rate limiting information:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1691234567
X-RateLimit-Window: 60
```

### Custom Rate Limits
API keys can have custom rate limits:

```bash
# Create key with 200 requests/minute
curl -X POST http://localhost:8080/api/auth/api-keys \
  -H "Content-Type: application/json" \
  -d '{"rate_limit_override": 200}'
```

### Rate Limit Exceeded
When rate limited, you'll receive:

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1691234567

{
  "error_code": "VAL429",
  "message": "Rate limit exceeded: 60/60 requests per minute",
  "retry_after": 60
}
```

## Security Features

### Secure Storage
- API keys are stored as SHA-256 hashes, never in plain text
- Keys are generated using cryptographically secure random functions
- Database includes audit fields (created_at, last_used_at)

### Privacy Protection
- No filenames, paths, or user content in logs
- API keys in logs show only first 8 characters of hash
- Usage statistics sanitize endpoint paths (IDs replaced with placeholders)
- All logging is privacy-aware by design

### Localhost Whitelisting
Requests from localhost are automatically whitelisted:
- No authentication required for local development
- Applies to: 127.0.0.1, ::1, localhost
- Works with common tools: curl, wget, Postman, etc.

### Optional Authentication
The API continues to work without authentication:
- All endpoints accessible without API keys
- Default rate limits apply to unauthenticated requests
- Gradual adoption - add authentication when needed

## Error Handling

### Error Response Format
```json
{
  "error_code": "AUTH404",
  "message": "API key not found",
  "correlation_id": "uuid-for-tracing"
}
```

### Common Error Codes
- `AUTH400`: Validation error (empty name, invalid parameters)
- `AUTH401`: Invalid or expired API key (when required)
- `AUTH404`: API key not found
- `AUTH500`: Internal authentication error
- `VAL429`: Rate limit exceeded

## Integration Examples

### Python
```python
import requests

# With authentication
headers = {"Authorization": "Bearer YOUR_API_KEY"}
response = requests.post(
    "http://localhost:8080/api/convert",
    headers=headers,
    files={"file": open("image.jpg", "rb")},
    data={"output_format": "webp"}
)

# Check rate limits
print(f"Rate limit: {response.headers.get('X-RateLimit-Remaining')}/")
print(f"{response.headers.get('X-RateLimit-Limit')} remaining")
```

### JavaScript/Node.js
```javascript
const fetch = require('node-fetch');
const FormData = require('form-data');
const fs = require('fs');

const apiKey = 'YOUR_API_KEY';
const form = new FormData();
form.append('file', fs.createReadStream('image.jpg'));
form.append('output_format', 'webp');

fetch('http://localhost:8080/api/convert', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${apiKey}`
  },
  body: form
})
.then(response => {
  console.log(`Rate limit: ${response.headers.get('x-ratelimit-remaining')}/${response.headers.get('x-ratelimit-limit')}`);
  return response.blob();
})
.then(blob => {
  // Handle converted image
});
```

### cURL Examples
```bash
# Create API key
API_KEY=$(curl -s -X POST http://localhost:8080/api/auth/api-keys \
  -H "Content-Type: application/json" \
  -d '{"name":"CLI Tool"}' \
  | jq -r '.api_key')

# Use API key for conversion
curl -X POST http://localhost:8080/api/convert \
  -H "Authorization: Bearer $API_KEY" \
  -F "file=@image.jpg" \
  -F "output_format=webp" \
  --output converted.webp

# Check usage statistics
curl -H "Authorization: Bearer $API_KEY" \
  http://localhost:8080/api/auth/usage
```

## Monitoring and Analytics

### Usage Statistics
Track your API usage through the web UI or API:

```bash
# Get usage for specific key
curl http://localhost:8080/api/auth/api-keys/{key-id}/usage?days=30

# Get overall usage
curl http://localhost:8080/api/auth/usage?days=7
```

### Key Management
- Monitor key usage through `last_used_at` timestamps
- Set expiration dates for temporary access
- Revoke compromised keys immediately
- Use descriptive names to track key purposes

### Best Practices
1. **Rotate Keys Regularly**: Create new keys and revoke old ones
2. **Use Descriptive Names**: Track which application uses which key
3. **Set Appropriate Limits**: Configure rate limits based on expected usage
4. **Monitor Usage**: Check statistics regularly for unusual patterns
5. **Secure Storage**: Store API keys securely in your applications

## Migration Guide

### Existing Applications
No changes required! Existing applications continue to work without modification.

### Adding Authentication
1. Create API key through web UI or API
2. Add authentication header to requests
3. Handle rate limit responses appropriately
4. Monitor usage statistics

### Gradual Rollout
1. **Phase 1**: Deploy authentication (optional)
2. **Phase 2**: Create API keys for applications
3. **Phase 3**: Add authentication to applications
4. **Phase 4**: (Optional) Require authentication for specific endpoints

## Troubleshooting

### Common Issues

**API Key Not Working:**
- Check key hasn't expired (`expires_at`)
- Verify key is active (`is_active`)
- Ensure correct header format
- Check for typos in key

**Rate Limited:**
- Check `X-RateLimit-*` headers
- Wait for reset time or increase limits
- Consider upgrading to authenticated requests

**Statistics Not Updating:**
- Statistics are recorded asynchronously
- Check logs for recording errors
- Verify database connectivity

### Debug Mode
Enable debug logging to troubleshoot issues:

```bash
# Set environment variable
export IMAGE_CONVERTER_LOG_LEVEL=DEBUG

# Check logs for detailed authentication info
tail -f logs/app.log | grep -i auth
```

## API Reference

### Base URLs
- **Primary**: `http://localhost:8080/api/auth/`
- **Versioned**: `http://localhost:8080/api/v1/auth/`

### Authentication Methods
1. **Bearer Token**: `Authorization: Bearer {key}` (Recommended)
2. **Custom Header**: `X-API-Key: {key}`
3. **Query Parameter**: `?api_key={key}` (Less secure)

### Rate Limiting
- **Algorithm**: Token bucket with minute/hour windows
- **Headers**: Standard `X-RateLimit-*` format
- **Customizable**: Per-key overrides supported

### Security
- **Encryption**: SHA-256 hashing
- **Storage**: SQLite with proper indexing
- **Privacy**: No PII in logs or statistics
- **Optional**: Works with or without authentication

For more technical details, see the OpenAPI specification at `/api/docs`.