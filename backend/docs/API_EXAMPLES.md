# Image Converter API Examples

## Convert Image Endpoint

### Basic Conversion

Convert a JPEG image to WebP format with default quality (85):

```bash
curl -X POST http://localhost:8000/api/convert \
  -F "file=@image.jpg" \
  -F "output_format=webp" \
  -o converted.webp
```

### Conversion with Custom Quality

Convert with specific quality setting:

```bash
curl -X POST http://localhost:8000/api/convert \
  -F "file=@photo.jpg" \
  -F "output_format=avif" \
  -F "quality=90" \
  -o photo.avif
```

### Response Headers

The API returns useful information in response headers:

```bash
curl -X POST http://localhost:8000/api/convert \
  -F "file=@image.png" \
  -F "output_format=webp" \
  -F "quality=85" \
  -D - \
  -o output.webp
```

Response headers include:
- `X-Conversion-Id`: Unique ID for this conversion
- `X-Processing-Time`: Time taken to convert (seconds)
- `X-Compression-Ratio`: Output size / input size ratio
- `X-Correlation-ID`: Request tracking ID

### Error Responses

#### File Too Large (413)

```bash
# Attempt to upload file larger than 50MB
curl -X POST http://localhost:8000/api/convert \
  -F "file=@large_file.jpg" \
  -F "output_format=webp"
```

Response:
```json
{
  "detail": {
    "error_code": "CONV202",
    "message": "File size exceeds maximum allowed size of 50.0MB",
    "correlation_id": "abc123...",
    "details": {
      "file_size": 52428800,
      "max_size": 52428800
    }
  }
}
```

#### Invalid Format (422)

```bash
curl -X POST http://localhost:8000/api/convert \
  -F "file=@document.pdf" \
  -F "output_format=webp"
```

#### Service Unavailable (503)

When the service is at capacity:

```json
{
  "detail": {
    "error_code": "CONV251",
    "message": "Service temporarily unavailable due to high load",
    "correlation_id": "xyz789..."
  }
}
```

### Testing with Different Formats

#### PNG to AVIF

```bash
curl -X POST http://localhost:8000/api/convert \
  -F "file=@screenshot.png" \
  -F "output_format=avif" \
  -F "quality=80" \
  -o screenshot.avif
```

#### WebP to JPEG

```bash
curl -X POST http://localhost:8000/api/convert \
  -F "file=@image.webp" \
  -F "output_format=jpeg" \
  -F "quality=95" \
  -o image.jpg
```

### Debugging

To see the full request/response cycle:

```bash
curl -v -X POST http://localhost:8000/api/convert \
  -F "file=@test.jpg" \
  -F "output_format=webp" \
  -F "quality=85" \
  -o output.webp
```

### Health Check

```bash
curl http://localhost:8000/api/health
```

Response:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime": 3600.5,
  "timestamp": "2024-01-15T10:30:00Z"
}
```