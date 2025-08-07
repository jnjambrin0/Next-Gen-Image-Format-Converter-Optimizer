# Multi-stage Dockerfile for Image Converter Frontend
# Optimized for production with nginx

# ============================================
# Stage 1: Build dependencies
# ============================================
FROM node:20-alpine AS dependencies

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies with clean install for production
RUN npm ci --only=production

# ============================================
# Stage 2: Build application
# ============================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files and install all dependencies (including dev)
COPY package*.json ./
RUN npm ci

# Copy application source
COPY . .

# Build the application
RUN npm run build

# ============================================
# Stage 3: Production runtime with nginx
# ============================================
FROM nginx:alpine AS production

# Install curl for health checks
RUN apk add --no-cache curl

# Remove default nginx config
RUN rm -rf /etc/nginx/conf.d/*

# Copy custom nginx configuration
COPY --from=builder /app/nginx.conf /etc/nginx/conf.d/default.conf

# Copy built application from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy environment configuration script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Create non-root user for nginx
RUN addgroup -g 1000 -S appuser && \
    adduser -u 1000 -S appuser -G appuser && \
    chown -R appuser:appuser /usr/share/nginx/html && \
    chown -R appuser:appuser /var/cache/nginx && \
    chown -R appuser:appuser /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown appuser:appuser /var/run/nginx.pid

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

# Expose port 80
EXPOSE 80

# Use custom entrypoint to inject environment variables
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]

# ============================================
# Stage 4: Development runtime
# ============================================
FROM node:20-alpine AS development

WORKDIR /app

# Install development tools
RUN apk add --no-cache \
    git \
    vim \
    curl

# Copy package files
COPY package*.json ./

# Install all dependencies
RUN npm ci

# Copy application source
COPY . .

# Expose development server port
EXPOSE 5173

# Start development server with hot-reload
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]