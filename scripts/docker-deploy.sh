#!/bin/bash

# Docker Production Deployment Script
# Deploys the application to production

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env.production"
BACKUP_DIR="./backups"
DEPLOYMENT_MODE="${1:-rolling}"

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking deployment prerequisites..."
    
    # Check Docker
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running"
        exit 1
    fi
    
    # Check environment file
    if [ ! -f "$ENV_FILE" ]; then
        print_error "Production environment file not found: $ENV_FILE"
        print_warn "Please create $ENV_FILE with production settings"
        exit 1
    fi
    
    # Check SECRET_KEY is set
    if ! grep -q "SECRET_KEY=" "$ENV_FILE" || grep -q "SECRET_KEY=\${SECRET_KEY}" "$ENV_FILE"; then
        print_error "SECRET_KEY is not set in $ENV_FILE"
        print_info "Generate a secret key with: openssl rand -hex 32"
        exit 1
    fi
    
    # Create necessary directories
    mkdir -p data/backend logs/backend "$BACKUP_DIR"
    
    print_info "Prerequisites check passed"
}

# Function to backup data
backup_data() {
    print_info "Creating backup..."
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_name="backup_${timestamp}"
    local backup_path="${BACKUP_DIR}/${backup_name}"
    
    mkdir -p "$backup_path"
    
    # Backup database
    if [ -f "./data/backend/app.db" ]; then
        cp -r ./data/backend/* "$backup_path/"
        print_info "Database backed up to $backup_path"
    fi
    
    # Backup environment file
    cp "$ENV_FILE" "$backup_path/.env.production.backup"
    
    # Create tar archive
    tar -czf "${backup_path}.tar.gz" -C "$BACKUP_DIR" "$backup_name"
    rm -rf "$backup_path"
    
    print_info "Backup created: ${backup_path}.tar.gz"
    
    # Keep only last 5 backups
    ls -t "${BACKUP_DIR}"/backup_*.tar.gz | tail -n +6 | xargs -r rm
}

# Function to perform health check
health_check() {
    local max_attempts=30
    local attempt=1
    
    print_info "Performing health check..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:8000/api/health > /dev/null 2>&1; then
            print_info "Health check passed"
            return 0
        fi
        
        print_warn "Health check attempt $attempt/$max_attempts failed"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    print_error "Health check failed after $max_attempts attempts"
    return 1
}

# Function for blue-green deployment
blue_green_deployment() {
    print_info "Starting blue-green deployment..."
    
    # Build new images
    ./scripts/docker-build.sh production
    
    # Start new containers with different names
    docker-compose -f "$COMPOSE_FILE" -p image_converter_green up -d
    
    # Wait for health check
    if health_check; then
        print_info "New deployment is healthy"
        
        # Stop old deployment
        docker-compose -f "$COMPOSE_FILE" -p image_converter_blue down
        
        # Rename green to blue for next deployment
        docker-compose -f "$COMPOSE_FILE" -p image_converter_green down
        docker-compose -f "$COMPOSE_FILE" -p image_converter_blue up -d
        
        print_info "Blue-green deployment completed"
    else
        print_error "New deployment failed health check"
        docker-compose -f "$COMPOSE_FILE" -p image_converter_green down
        exit 1
    fi
}

# Function for rolling deployment
rolling_deployment() {
    print_info "Starting rolling deployment..."
    
    # Build new images
    ./scripts/docker-build.sh production
    
    # Update services one by one
    docker-compose -f "$COMPOSE_FILE" up -d --no-deps --build backend
    sleep 10
    
    if health_check; then
        docker-compose -f "$COMPOSE_FILE" up -d --no-deps --build frontend
        print_info "Rolling deployment completed"
    else
        print_error "Backend deployment failed"
        exit 1
    fi
}

# Function for standard deployment
standard_deployment() {
    print_info "Starting standard deployment..."
    
    # Build and start all services
    docker-compose -f "$COMPOSE_FILE" up -d --build
    
    if health_check; then
        print_info "Standard deployment completed"
    else
        print_error "Deployment failed health check"
        exit 1
    fi
}

# Function to show deployment status
show_status() {
    print_info "Deployment status:"
    docker-compose -f "$COMPOSE_FILE" ps
    
    print_info "\nService health:"
    docker-compose -f "$COMPOSE_FILE" exec -T backend curl -s http://localhost:8000/api/health | jq '.' 2>/dev/null || echo "Backend: Unable to get health status"
}

# Function to rollback deployment
rollback() {
    print_warn "Starting rollback..."
    
    # Find latest backup
    local latest_backup=$(ls -t "${BACKUP_DIR}"/backup_*.tar.gz 2>/dev/null | head -n 1)
    
    if [ -z "$latest_backup" ]; then
        print_error "No backup found for rollback"
        exit 1
    fi
    
    print_info "Rolling back to: $latest_backup"
    
    # Stop current deployment
    docker-compose -f "$COMPOSE_FILE" down
    
    # Extract backup
    tar -xzf "$latest_backup" -C "$BACKUP_DIR"
    local backup_name=$(basename "$latest_backup" .tar.gz)
    
    # Restore data
    cp -r "${BACKUP_DIR}/${backup_name}"/* ./data/backend/
    cp "${BACKUP_DIR}/${backup_name}/.env.production.backup" "$ENV_FILE"
    
    # Restart services
    docker-compose -f "$COMPOSE_FILE" up -d
    
    # Clean up extracted backup
    rm -rf "${BACKUP_DIR}/${backup_name}"
    
    print_info "Rollback completed"
}

# Main script
print_info "Image Converter Production Deployment"
print_info "Deployment mode: $DEPLOYMENT_MODE"

case $DEPLOYMENT_MODE in
    prereq|check)
        check_prerequisites
        print_info "All prerequisites met"
        ;;
    
    backup)
        backup_data
        ;;
    
    deploy|standard)
        check_prerequisites
        backup_data
        standard_deployment
        show_status
        ;;
    
    rolling)
        check_prerequisites
        backup_data
        rolling_deployment
        show_status
        ;;
    
    blue-green)
        check_prerequisites
        backup_data
        blue_green_deployment
        show_status
        ;;
    
    status)
        show_status
        ;;
    
    rollback)
        rollback
        show_status
        ;;
    
    stop)
        print_info "Stopping production deployment..."
        docker-compose -f "$COMPOSE_FILE" down
        print_info "Production deployment stopped"
        ;;
    
    logs)
        SERVICE=${2:-}
        if [ -z "$SERVICE" ]; then
            docker-compose -f "$COMPOSE_FILE" logs -f
        else
            docker-compose -f "$COMPOSE_FILE" logs -f "$SERVICE"
        fi
        ;;
    
    help)
        echo "Docker Production Deployment Script"
        echo ""
        echo "Usage: $0 [command] [options]"
        echo ""
        echo "Commands:"
        echo "  check|prereq    Check deployment prerequisites"
        echo "  backup          Create backup of current data"
        echo "  deploy|standard Standard deployment (default)"
        echo "  rolling         Rolling deployment (zero downtime)"
        echo "  blue-green      Blue-green deployment"
        echo "  status          Show deployment status"
        echo "  rollback        Rollback to previous deployment"
        echo "  stop            Stop production deployment"
        echo "  logs [service]  Show logs"
        echo "  help            Show this help message"
        ;;
    
    *)
        print_error "Unknown command: $DEPLOYMENT_MODE"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac