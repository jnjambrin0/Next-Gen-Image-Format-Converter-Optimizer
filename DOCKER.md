# 🐳 Docker Setup Guide for Image Converter

This guide provides comprehensive instructions for running the Image Converter application using Docker, covering both development and production environments.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Development Environment](#development-environment)
- [Production Deployment](#production-deployment)
- [Architecture Overview](#architecture-overview)
- [Configuration](#configuration)
- [Scripts Reference](#scripts-reference)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)
- [Security Considerations](#security-considerations)

## Prerequisites

- Docker Engine 20.10+ ([Install Docker](https://docs.docker.com/get-docker/))
- Docker Compose 2.0+ (included with Docker Desktop)
- 4GB+ RAM available for Docker
- 10GB+ free disk space

## 🚀 Quick Start

### Development Environment

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/image-converter.git
cd image-converter

# 2. Copy environment configuration
cp .env.docker .env

# 3. Start development environment
./scripts/docker-dev.sh start

# Access the application
# Frontend: http://localhost:5173
# Backend API: http://localhost:8000
# API Documentation: http://localhost:8000/api/docs
```

### Production Deployment

```bash
# 1. Copy and configure production environment
cp .env.production .env.production
# Edit .env.production and set SECRET_KEY

# 2. Deploy to production
./scripts/docker-deploy.sh deploy

# Access the application
# Frontend: http://localhost (port 80)
# Backend API: http://localhost:8000
```

## 🔧 Development Environment

### Starting Development

```bash
# Start with hot-reload enabled
./scripts/docker-dev.sh start

# Or using docker-compose directly
docker-compose up -d
```

### Development Features

- **Hot Reload**: Code changes automatically reload the application
- **Debug Mode**: Full error traces and debug logging
- **Volume Mounts**: Direct code editing without rebuilding
- **Development Tools**: Includes ipython, black, pytest-watch

### Common Development Tasks

```bash
# View logs
./scripts/docker-dev.sh logs

# Run tests
./scripts/docker-dev.sh test

# Format code
./scripts/docker-dev.sh format

# Access backend shell
./scripts/docker-dev.sh shell backend

# Access frontend shell
./scripts/docker-dev.sh shell frontend

# Restart services
./scripts/docker-dev.sh restart

# Stop services
./scripts/docker-dev.sh stop
```

## 🏭 Production Deployment

### Deployment Strategies

#### 1. Standard Deployment
```bash
./scripts/docker-deploy.sh deploy
```

#### 2. Rolling Deployment (Zero Downtime)
```bash
./scripts/docker-deploy.sh rolling
```

#### 3. Blue-Green Deployment
```bash
./scripts/docker-deploy.sh blue-green
```

### Production Features

- **Multi-stage Builds**: Optimized image sizes (50% smaller)
- **Security Hardening**: Non-root users, read-only filesystems
- **Health Checks**: Automatic container health monitoring
- **Resource Limits**: CPU and memory constraints
- **Log Management**: Centralized logging with rotation
- **Automatic Backups**: Data backup before deployments

### Production Commands

```bash
# Check deployment status
./scripts/docker-deploy.sh status

# View production logs
./scripts/docker-deploy.sh logs

# Create backup
./scripts/docker-deploy.sh backup

# Rollback to previous version
./scripts/docker-deploy.sh rollback

# Stop production
./scripts/docker-deploy.sh stop
```

## 🏗️ Architecture Overview

### Container Structure

```
┌─────────────────────────────────────────┐
│            nginx (Frontend)              │
│         Port 80/443 (Production)         │
│          Port 5173 (Development)         │
└─────────────┬───────────────────────────┘
              │
              │ Proxy /api, /ws
              │
┌─────────────▼───────────────────────────┐
│         FastAPI (Backend)                │
│            Port 8000                     │
│   - Image Processing                     │
│   - ML Models                           │
│   - WebSocket Support                   │
└─────────────────────────────────────────┘
              │
              │ Volumes
              │
┌─────────────▼───────────────────────────┐
│          Persistent Storage              │
│   - SQLite Database                     │
│   - ML Models                           │
│   - Logs                                │
│   - Temporary Files                     │
└─────────────────────────────────────────┘
```

### Multi-Stage Build Strategy

#### Backend Dockerfile Stages:
1. **Builder**: Compiles dependencies
2. **Production**: Minimal runtime
3. **Development**: Includes dev tools
4. **Testing**: Test runner environment

#### Frontend Dockerfile Stages:
1. **Dependencies**: Production npm packages
2. **Builder**: Builds static assets
3. **Production**: nginx server
4. **Development**: Vite dev server

## ⚙️ Configuration

### Environment Variables

Key environment variables for Docker deployment:

```bash
# Application
IMAGE_CONVERTER_ENV=development|production
IMAGE_CONVERTER_DEBUG=true|false
IMAGE_CONVERTER_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR

# API Configuration
IMAGE_CONVERTER_API_PORT=8000
IMAGE_CONVERTER_API_WORKERS=2
IMAGE_CONVERTER_CORS_ORIGINS=http://localhost:5173

# Security
IMAGE_CONVERTER_SECRET_KEY=your-secret-key
IMAGE_CONVERTER_ENABLE_SANDBOXING=true
IMAGE_CONVERTER_SANDBOX_STRICTNESS=standard|strict|paranoid

# Performance
IMAGE_CONVERTER_MAX_CONCURRENT_CONVERSIONS=10
IMAGE_CONVERTER_MEMORY_LIMIT_MB=512
IMAGE_CONVERTER_CPU_LIMIT_PERCENT=80

# Database
IMAGE_CONVERTER_DATABASE_URL=sqlite:///./data/app.db

# ML Models
IMAGE_CONVERTER_ML_MODELS_PATH=/app/ml_models
IMAGE_CONVERTER_ENABLE_AI_FEATURES=true
```

### Volume Mounts

#### Development Volumes:
- `./backend/app:/app/app` - Backend source code
- `./frontend:/app` - Frontend source code
- `./ml_models:/app/ml_models` - ML models

#### Production Volumes:
- `backend_data:/app/data` - Database persistence
- `backend_logs:/app/logs` - Application logs
- `./ml_models:/app/ml_models:ro` - ML models (read-only)

## 📜 Scripts Reference

### docker-build.sh
Builds Docker images with proper tagging:
```bash
# Build for production
./scripts/docker-build.sh production

# Build for development
./scripts/docker-build.sh development

# Build with custom version
VERSION=1.2.3 ./scripts/docker-build.sh production
```

### docker-dev.sh
Development environment management:
```bash
./scripts/docker-dev.sh [command] [options]

Commands:
  start|up       Start development environment
  stop|down      Stop development environment
  restart        Restart all services
  logs [service] Show logs
  exec <service> <cmd>  Execute command
  shell [service]  Open shell
  test           Run tests
  format         Format code
  status         Show status
  clean [level]  Clean up (soft|hard|full)
  rebuild        Rebuild from scratch
```

### docker-deploy.sh
Production deployment management:
```bash
./scripts/docker-deploy.sh [command] [options]

Commands:
  check          Check prerequisites
  backup         Create backup
  deploy         Standard deployment
  rolling        Rolling deployment
  blue-green     Blue-green deployment
  status         Show status
  rollback       Rollback deployment
  stop           Stop production
  logs [service] Show logs
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Port Already in Use
```bash
# Check what's using the port
lsof -i :8000
lsof -i :5173

# Stop conflicting service or change ports in .env
```

#### 2. Permission Denied
```bash
# Fix script permissions
chmod +x scripts/*.sh

# Fix volume permissions
sudo chown -R 1000:1000 ./data ./logs
```

#### 3. Container Won't Start
```bash
# Check logs
docker-compose logs backend
docker-compose logs frontend

# Rebuild from scratch
./scripts/docker-dev.sh rebuild
```

#### 4. Out of Memory
```bash
# Increase Docker memory limit
# Docker Desktop > Settings > Resources > Memory

# Or adjust container limits in docker-compose.yml
```

#### 5. Slow Performance
```bash
# Check resource usage
docker stats

# Adjust resource limits in docker-compose files
```

### Debug Commands

```bash
# Inspect container
docker inspect image_converter_backend

# Check network
docker network ls
docker network inspect image_converter_app_network

# Clean up everything
docker system prune -a --volumes

# Check disk usage
docker system df
```

## 🚀 Performance Tuning

### Optimization Tips

1. **Image Size Optimization**
   - Multi-stage builds reduce image size by 50%
   - Production images: ~300MB (backend), ~50MB (frontend)

2. **Build Cache Optimization**
   - Dependencies installed before code copy
   - Leverage Docker build cache

3. **Resource Allocation**
   ```yaml
   # Adjust in docker-compose files
   deploy:
     resources:
       limits:
         cpus: '2'
         memory: 2G
       reservations:
         cpus: '1'
         memory: 1G
   ```

4. **Concurrent Processing**
   ```bash
   # Increase workers for production
   IMAGE_CONVERTER_API_WORKERS=4
   IMAGE_CONVERTER_MAX_CONCURRENT_CONVERSIONS=20
   ```

## 🔒 Security Considerations

### Security Best Practices

1. **Non-Root Users**
   - All containers run as non-root user (UID 1000)
   - Reduces privilege escalation risks

2. **Read-Only Filesystems**
   - Production frontend uses read-only root
   - Temporary files use tmpfs mounts

3. **Network Isolation**
   - Custom bridge network with isolated subnet
   - No external network access for backend

4. **Secret Management**
   ```bash
   # Generate secure secret key
   openssl rand -hex 32
   
   # Store in .env.production (never commit!)
   IMAGE_CONVERTER_SECRET_KEY=<generated-key>
   ```

5. **Security Headers**
   - nginx configured with security headers
   - CORS properly configured

6. **Resource Limits**
   - CPU and memory limits prevent DoS
   - Request size limits configured

7. **Sandboxing**
   - Image processing runs in sandboxed environment
   - Configurable strictness levels

### Security Checklist

- [ ] Change default SECRET_KEY
- [ ] Configure CORS_ORIGINS for your domain
- [ ] Enable HTTPS in production
- [ ] Set up firewall rules
- [ ] Regular security updates
- [ ] Monitor logs for suspicious activity
- [ ] Backup data regularly
- [ ] Test disaster recovery

## 📊 Monitoring

### Health Checks

Backend health endpoint: `http://localhost:8000/api/health`

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "network_isolated": true,
  "sandbox_enabled": true
}
```

### Metrics Collection

```bash
# View container metrics
docker stats

# Export metrics (if Prometheus configured)
curl http://localhost:9090/metrics
```

### Log Management

```bash
# View logs with timestamps
docker-compose logs -f --timestamps

# Export logs
docker-compose logs > logs_$(date +%Y%m%d).txt

# Log rotation configured in production
```

## 🔄 Updates and Maintenance

### Updating the Application

```bash
# 1. Pull latest code
git pull origin main

# 2. Rebuild images
./scripts/docker-build.sh production

# 3. Deploy with zero downtime
./scripts/docker-deploy.sh rolling
```

### Backup and Recovery

```bash
# Manual backup
./scripts/docker-deploy.sh backup

# Automatic backups before deployment
# Configured in deployment script

# Restore from backup
./scripts/docker-deploy.sh rollback
```

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [FastAPI Docker Guide](https://fastapi.tiangolo.com/deployment/docker/)
- [nginx Docker Guide](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-docker/)

## 💡 Tips and Tricks

1. **Use Docker BuildKit** for faster builds:
   ```bash
   export DOCKER_BUILDKIT=1
   docker-compose build
   ```

2. **Prune regularly** to save disk space:
   ```bash
   docker system prune -a --volumes
   ```

3. **Use .dockerignore** to speed up builds

4. **Monitor disk usage**:
   ```bash
   docker system df
   ```

5. **Use Docker secrets** for sensitive data in production

---

For issues or questions, please refer to the main project documentation or create an issue on GitHub.