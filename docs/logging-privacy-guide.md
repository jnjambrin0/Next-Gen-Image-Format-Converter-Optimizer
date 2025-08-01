# Privacy-Focused Logging and Monitoring Guide

## Overview

The Image Converter implements a comprehensive privacy-focused logging and monitoring system that ensures no personally identifiable information (PII) is ever logged or stored. All monitoring is done locally with aggregate statistics only.

## Core Privacy Principles

1. **No PII Logging**: Filenames, paths, user data, and image content are never logged
2. **Local-Only**: All logs and monitoring data stay on the user's machine
3. **Aggregate Statistics**: Only privacy-safe aggregates are collected
4. **Configurable Retention**: Automatic cleanup of old logs and data
5. **Paranoia Mode**: Complete logging disable option for maximum privacy

## What We Log

### Allowed Log Fields

- **Timestamps**: When events occurred (ISO format)
- **Log Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Event Types**: Generic operation names (e.g., "conversion", "validation")
- **Error Categories**: Privacy-safe categories (e.g., "timeout", "memory_limit")
- **Aggregate Counts**: Total operations, success rates
- **Performance Metrics**: Processing times (no correlation to specific files)
- **Correlation IDs**: Random UUIDs for request tracking (no user data)

### Example Privacy-Safe Log Entry

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "message": "Image conversion completed",
  "correlation_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "input_format": "jpeg",
  "output_format": "webp",
  "size_category": "medium",
  "processing_time": 1.23,
  "success": true
}
```

## What We Don't Log

### Never Logged (Automatically Filtered)

- **Filenames**: All filenames are filtered out
- **File Paths**: Complete paths are replaced with `***PATH_REDACTED***`
- **User Information**: User IDs, emails, usernames
- **IP Addresses**: Replaced with `***IP_REDACTED***`
- **Image Content**: No image data or content hashes
- **EXIF/Metadata**: GPS coordinates, camera info, timestamps
- **System Paths**: Home directories, user folders

### Privacy Filter Examples

| Original | Filtered |
|----------|----------|
| `/home/user/photos/vacation.jpg` | `***PATH_REDACTED***` |
| `user@example.com` | `***EMAIL_REDACTED***` |
| `192.168.1.100` | `***IP_REDACTED***` |
| `IMG_20240115_123456.jpg` | `***FILENAME_REDACTED***` |

## Configuration Options

### Environment Variables

```bash
# Enable/disable file logging (false = paranoia mode)
IMAGE_CONVERTER_LOGGING_ENABLED=true

# Log retention settings
IMAGE_CONVERTER_LOG_DIR=./logs
IMAGE_CONVERTER_LOG_RETENTION_HOURS=24
IMAGE_CONVERTER_MAX_LOG_SIZE_MB=10
IMAGE_CONVERTER_LOG_BACKUP_COUNT=3

# Log level (DEBUG only in development)
IMAGE_CONVERTER_LOG_LEVEL=INFO

# Privacy settings
IMAGE_CONVERTER_ANONYMIZE_LOGS=true
```

### Paranoia Mode

Enable paranoia mode to disable all file logging:

```bash
# Via environment variable
IMAGE_CONVERTER_LOGGING_ENABLED=false

# Via API
curl -X PUT http://localhost:8080/api/monitoring/logging/paranoia?enable=true
```

In paranoia mode:
- No log files are created
- Only stderr output (can be redirected to /dev/null)
- In-memory statistics still work
- Critical security events tracked in memory only

## Monitoring Endpoints

### Aggregate Statistics

```bash
# Get current statistics (privacy-safe aggregates only)
GET /api/monitoring/stats

# Response example:
{
  "current_hour": {
    "total_conversions": 150,
    "success_rate": 95.3,
    "format_counts": {
      "jpeg->webp": 75,
      "png->avif": 50
    },
    "size_distribution": {
      "small": 30,
      "medium": 100,
      "large": 20
    }
  }
}
```

### Error Reporting

```bash
# Get error summary (no PII)
GET /api/monitoring/errors/report?hours=24

# Response example:
{
  "unique_errors": 5,
  "total_occurrences": 23,
  "errors_by_category": {
    "timeout": 10,
    "memory_limit": 8,
    "format_error": 5
  },
  "most_frequent": [
    {
      "error_type": "TimeoutError",
      "category": "timeout",
      "count": 10,
      "sanitized_message": "Operation timed out"
    }
  ]
}
```

### Logging Configuration

```bash
# Check current logging configuration
GET /api/monitoring/logging/config

# Toggle paranoia mode
PUT /api/monitoring/logging/paranoia?enable=true
```

## Security Event Tracking

Security events are tracked separately with enhanced privacy:

```sql
-- Security events table schema
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY,
    event_type TEXT,  -- 'violation', 'scan', 'sandbox_create'
    severity TEXT,    -- 'info', 'warning', 'critical'
    details TEXT,     -- JSON with no PII
    timestamp TIMESTAMP
);
```

Example security event (no PII):
```json
{
  "event_type": "sandbox_violation",
  "severity": "warning",
  "details": {
    "violation_type": "memory_limit_exceeded",
    "limit_mb": 256,
    "attempted_mb": 512
  }
}
```

## Log Rotation and Cleanup

### Automatic Rotation

- Logs rotate when reaching size limit (default: 10MB)
- Keeps specified number of backups (default: 3)
- Automatic compression of rotated logs

### Scheduled Cleanup

- Runs hourly to remove old logs
- Configurable retention period (default: 24 hours)
- Cleans both file logs and database records

### Manual Cleanup

```bash
# Clean up old statistics
POST /api/monitoring/stats/cleanup?hourly_retention=168&daily_retention=30

# Clean up old error reports
POST /api/monitoring/errors/cleanup?retention_days=7
```

## Privacy-Safe Error Handling

### Error Sanitization Process

1. **Message Filtering**: Remove all paths, emails, IPs
2. **Stack Trace Hashing**: Hash stack traces for deduplication
3. **Context Sanitization**: Filter any provided context
4. **Categorization**: Map to privacy-safe categories

### Error Categories

- `timeout`: Operation timeouts
- `memory_limit`: Memory constraints
- `format_error`: Unsupported formats
- `validation`: Input validation failures
- `permission`: Access control issues
- `sandbox_violation`: Security sandbox violations
- `general_error`: Other errors

## Best Practices for Developers

### Do's

```python
# Good: Generic messages
logger.info("Conversion completed", 
    input_format="jpeg", 
    output_format="webp",
    duration_seconds=1.23
)

# Good: Privacy-safe categories
logger.error("Validation failed",
    error_type="invalid_dimensions",
    max_allowed=4096,
    dimension="width"
)
```

### Don'ts

```python
# Bad: Including filenames
logger.info(f"Processing {filename}")  # NEVER DO THIS

# Bad: Including paths
logger.error(f"Failed to read {file_path}")  # NEVER DO THIS

# Bad: Including user data
logger.warning(f"User {email} exceeded limit")  # NEVER DO THIS
```

## Troubleshooting with Privacy-Safe Logs

### Debugging Conversions

Use correlation IDs to track requests:
```bash
# Search logs for correlation ID (no grep on filenames!)
grep "correlation_id.*a1b2c3d4" logs/app.log
```

### Performance Analysis

Analyze aggregate metrics:
```python
# Get hourly performance stats
GET /api/monitoring/stats/hourly?hours=24

# Identify bottlenecks by format
{
  "format_performance": {
    "jpeg->webp": {"avg_time": 1.2, "p95_time": 2.5},
    "png->avif": {"avg_time": 3.4, "p95_time": 5.0}
  }
}
```

### Error Investigation

Track errors by category:
```bash
# Get errors by category
GET /api/monitoring/errors/report?hours=1

# Investigate specific error type
GET /api/monitoring/errors/{error_id}
```

## Compliance and Auditing

### GDPR Compliance

- No personal data collected or logged
- No user tracking or profiling
- All data is local to user's machine
- No data retention beyond configured limits

### Security Auditing

- Security events logged without PII
- Aggregate violation counts only
- No correlation between events and users
- Audit logs auto-expire

### Data Retention

| Data Type | Default Retention | Configurable |
|-----------|------------------|--------------|
| Log Files | 24 hours | Yes |
| Error Reports | 30 days | Yes |
| Statistics (Hourly) | 7 days | Yes |
| Statistics (Daily) | 90 days | Yes |
| Security Events | 90 days | Yes |

## Network Isolation Verification

The application includes built-in network isolation checking:

```python
# Startup check output example
Network Isolation Report
========================
✓ Application appears properly isolated
API Binding: 127.0.0.1
No telemetry packages detected
No external connections configured
```

### Verified No Telemetry

The following packages have been verified to have no telemetry:
- structlog: Local logging only
- FastAPI: No analytics or tracking
- Pillow: No network features
- pytest: Telemetry plugins not installed

## Summary

The privacy-focused logging system ensures:

1. **Zero PII Exposure**: Comprehensive filtering at multiple levels
2. **Local-Only Operation**: No external services or cloud logging
3. **Minimal Data Collection**: Only aggregates necessary for operations
4. **User Control**: Paranoia mode and configurable retention
5. **Transparency**: Clear documentation of what is/isn't logged

For maximum privacy, enable paranoia mode and redirect stderr to /dev/null:
```bash
IMAGE_CONVERTER_LOGGING_ENABLED=false python -m app.main 2>/dev/null
```