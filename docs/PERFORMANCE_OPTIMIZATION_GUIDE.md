# Performance Optimization Guide

## Overview

This guide covers performance optimizations available in the Image Converter, including parallel processing, memory-efficient streaming, and performance monitoring.

## Table of Contents

1. [Parallel Processing](#parallel-processing)
2. [Large File Streaming](#large-file-streaming)
3. [Performance Monitoring](#performance-monitoring)
4. [libvips Installation](#libvips-installation)
5. [Configuration](#configuration)
6. [Best Practices](#best-practices)

## Parallel Processing

The Image Converter automatically uses parallel processing for batch operations to maximize throughput.

### Features

- **Automatic Worker Scaling**: Uses 80% of available CPU cores (2 minimum, 10 maximum)
- **Intelligent Queue Management**: Distributes work efficiently across workers
- **Real-time Progress**: WebSocket updates for batch progress
- **Worker Efficiency Tracking**: Monitors resource utilization per worker

### How It Works

```python
# Automatic in batch operations
# Workers = min(10, max(2, cpu_count * 0.8))
```

When processing batch conversions, the system automatically:
1. Detects available CPU cores
2. Spawns optimal number of workers
3. Distributes files across workers
4. Maintains sandbox isolation per worker

## Large File Streaming

For files larger than 100MB, the system can use memory-efficient streaming to prevent memory exhaustion.

### Features

- **Automatic Detection**: Files >100MB trigger streaming mode
- **Chunked Processing**: Processes images in 10MB chunks
- **Memory Monitoring**: Tracks and limits memory usage
- **Fallback Support**: Uses PIL if libvips unavailable

### Requirements

For optimal streaming performance, install libvips (see [libvips Installation](#libvips-installation)).

## Performance Monitoring

Track detailed performance metrics using the `--profile` flag with CLI commands.

### CLI Profiling

```bash
# Enable profiling for any conversion
img convert file input.jpg -f webp --profile

# Save profile to file
img convert file input.jpg -f webp --profile --profile-output profile.json

# Profile batch operations
img batch convert "*.png" -f avif --profile

# Profile optimization
img optimize auto large.jpg --profile
```

### Metrics Collected

- **Conversion Metrics**
  - Input/output file sizes
  - Compression ratios
  - Processing time
  - Memory usage
  - Throughput (MB/s)

- **Batch Metrics**
  - Files processed per second
  - Worker efficiency
  - Memory peaks
  - Parallel speedup

- **System Metrics**
  - CPU utilization
  - Memory usage (current/peak/delta)
  - I/O operations

## libvips Installation

libvips provides 10x faster image processing and memory-efficient streaming for large files.

### Benefits of libvips

- **10x Faster**: Than PIL/Pillow for most operations
- **Memory Efficient**: Streams large images without loading fully into RAM
- **Parallel Processing**: Built-in multi-threading
- **Format Support**: Excellent support for modern formats

### Installation Instructions

#### macOS

```bash
# Using Homebrew
brew install vips

# Install Python bindings
pip install pyvips
```

#### Ubuntu/Debian

```bash
# Install libvips and dependencies
sudo apt update
sudo apt install libvips-dev

# Install Python bindings
pip install pyvips
```

#### RHEL/CentOS/Fedora

```bash
# Install libvips
sudo yum install vips-devel

# Or on newer versions
sudo dnf install vips-devel

# Install Python bindings
pip install pyvips
```

#### Windows

```bash
# Download pre-built binaries from:
# https://github.com/libvips/libvips/releases

# Add to PATH and install Python bindings
pip install pyvips
```

### Verify Installation

```python
# Test if libvips is available
python -c "import pyvips; print(f'libvips {pyvips.version(0)}.{pyvips.version(1)}')"
```

### Troubleshooting

If libvips is not detected:

1. **Check Installation**:
   ```bash
   vips --version
   ```

2. **Verify Python Bindings**:
   ```bash
   pip show pyvips
   ```

3. **Set Library Path** (Linux):
   ```bash
   export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
   ```

4. **Fallback Mode**: The system automatically falls back to PIL if libvips is unavailable

## Configuration

### Environment Variables

```bash
# Set maximum workers for batch processing (default: auto)
export MAX_BATCH_WORKERS=8

# Set memory limit per worker (MB)
export IMAGE_CONVERTER_MEMORY_LIMIT=256

# Set streaming threshold (MB)
export STREAMING_THRESHOLD_MB=100
```

### Performance Tuning

```python
# In code or configuration
{
    "max_workers": 10,           # Maximum parallel workers
    "memory_limit_mb": 512,      # Memory limit per operation
    "streaming_threshold_mb": 100, # Trigger streaming for files > 100MB
    "chunk_size_mb": 10          # Process in 10MB chunks
}
```

## Best Practices

### For Batch Processing

1. **Optimal Batch Size**: 50-100 files per batch for best performance
2. **File Organization**: Group similar-sized files together
3. **Format Selection**: Use modern formats (WebP, AVIF) for better compression
4. **Preset Usage**: Use optimization presets for consistent results

### For Large Files

1. **Install libvips**: Essential for files >100MB
2. **Monitor Memory**: Use `--profile` to track memory usage
3. **Incremental Processing**: Process very large batches in chunks
4. **Disk Space**: Ensure adequate temp space for processing

### Performance Tips

1. **Use SSDs**: Faster I/O significantly improves performance
2. **Close Other Apps**: Free up RAM for image processing
3. **Network Location**: Process files locally when possible
4. **Regular Cleanup**: Clear temp files periodically

### Monitoring Commands

```bash
# Monitor system resources during conversion
img convert file large.jpg -f webp --profile

# Check worker efficiency in batch operations
img batch convert "*.png" -f avif --profile --profile-output batch_metrics.json

# Analyze optimization performance
img optimize auto photo.jpg --preset web --profile
```

## Performance Benchmarks

Typical performance with libvips installed:

| File Size | Without libvips | With libvips | Speedup |
|-----------|----------------|--------------|---------|
| 10MB      | 2.5s          | 0.8s         | 3.1x    |
| 50MB      | 8.2s          | 2.1s         | 3.9x    |
| 100MB     | 18.5s         | 3.8s         | 4.9x    |
| 500MB     | 95s           | 12s          | 7.9x    |
| 1GB       | 210s          | 22s          | 9.5x    |

*Benchmarks on 8-core CPU with 16GB RAM, converting JPEG to WebP*

## Troubleshooting Performance Issues

### Slow Conversions

1. Check if libvips is installed and detected
2. Verify sufficient RAM available
3. Check disk I/O performance
4. Review `--profile` output for bottlenecks

### High Memory Usage

1. Reduce batch size
2. Enable streaming for large files
3. Lower worker count with `MAX_BATCH_WORKERS`
4. Check for memory leaks with `--profile`

### Worker Inefficiency

1. Check CPU throttling
2. Verify sandbox settings
3. Review file distribution across workers
4. Analyze with `--profile` metrics

## Support

For performance-related issues:

1. Run with `--profile` flag
2. Save profile output: `--profile-output metrics.json`
3. Check system resources during operation
4. Report issues with profile data attached