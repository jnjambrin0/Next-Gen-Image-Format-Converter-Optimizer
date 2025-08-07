# Multi-stage Dockerfile for Image Converter Backend
# Optimized for production with development support

# ============================================
# Stage 1: Build dependencies
# ============================================
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    cmake \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# ============================================
# Stage 2: Production runtime
# ============================================
FROM python:3.11-slim AS production

# Install runtime dependencies for image processing
RUN apt-get update && apt-get install -y --no-install-recommends \
    libvips42 \
    libheif1 \
    libde265-0 \
    libjpeg62-turbo \
    libpng16-16 \
    libwebp7 \
    libwebpmux3 \
    libwebpdemux2 \
    libtiff5 \
    libexif12 \
    libglib2.0-0 \
    libexpat1 \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/app:$PYTHONPATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create non-root user with specific UID/GID for consistency
RUN groupadd -g 1000 appuser && \
    useradd -r -u 1000 -g appuser -m -d /home/appuser -s /bin/bash appuser

# Create necessary directories with proper permissions
RUN mkdir -p /app /app/data /app/logs /app/ml_models /tmp/image-converter && \
    chown -R appuser:appuser /app /tmp/image-converter

WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser app/ ./app/
COPY --chown=appuser:appuser ml_models/ ./ml_models/

# Create empty data directory structure
RUN mkdir -p data && \
    touch data/.gitkeep && \
    chown -R appuser:appuser data

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Expose port
EXPOSE 8000

# Default command for production
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--loop", "uvloop", \
     "--access-log"]

# ============================================
# Stage 3: Development runtime
# ============================================
FROM production AS development

# Switch to root to install dev tools
USER root

# Install development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    nano \
    htop \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install development Python packages
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir \
    ipython \
    ipdb \
    pytest-watch \
    black \
    flake8 \
    mypy

# Switch back to non-root user
USER appuser

# Development command with hot-reload
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--reload", \
     "--reload-dir", "/app", \
     "--log-level", "debug"]

# ============================================
# Stage 4: Testing runtime
# ============================================
FROM production AS testing

# Copy test files
COPY --chown=appuser:appuser tests/ ./tests/
COPY --chown=appuser:appuser pytest.ini ./
COPY --chown=appuser:appuser .coveragerc ./

# Install test dependencies
ENV PATH="/opt/venv/bin:$PATH"
USER root
RUN pip install --no-cache-dir \
    pytest-cov \
    pytest-mock \
    pytest-asyncio \
    pytest-timeout \
    hypothesis

USER appuser

# Run tests by default
CMD ["pytest", "-v", "--cov=app", "--cov-report=term-missing"]