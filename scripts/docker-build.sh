#!/bin/bash

# Docker Build Script for Image Converter
# Builds all Docker images with proper tagging

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="image-converter"
REGISTRY="${DOCKER_REGISTRY:-}"
VERSION="${VERSION:-latest}"
BUILD_TARGET="${1:-production}"

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

# Function to build an image
build_image() {
    local service=$1
    local dockerfile=$2
    local context=$3
    local target=$4
    
    print_info "Building $service image (target: $target)..."
    
    local image_name="${PROJECT_NAME}-${service}"
    if [ -n "$REGISTRY" ]; then
        image_name="${REGISTRY}/${image_name}"
    fi
    
    docker build \
        --target "$target" \
        --tag "${image_name}:${VERSION}" \
        --tag "${image_name}:latest" \
        --file "$dockerfile" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VERSION="$VERSION" \
        --build-arg VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
        "$context"
    
    if [ $? -eq 0 ]; then
        print_info "Successfully built ${image_name}:${VERSION}"
    else
        print_error "Failed to build $service image"
        exit 1
    fi
}

# Main script
print_info "Starting Docker build process..."
print_info "Build target: $BUILD_TARGET"
print_info "Version: $VERSION"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Build backend image
build_image "backend" "./backend/Dockerfile" "./backend" "$BUILD_TARGET"

# Build frontend image
if [ "$BUILD_TARGET" == "production" ]; then
    build_image "frontend" "./frontend/Dockerfile" "./frontend" "production"
else
    build_image "frontend" "./frontend/Dockerfile" "./frontend" "development"
fi

# List built images
print_info "Built images:"
docker images | grep "$PROJECT_NAME"

# Option to push to registry
if [ -n "$REGISTRY" ] && [ "$PUSH_TO_REGISTRY" == "true" ]; then
    print_info "Pushing images to registry..."
    docker push "${REGISTRY}/${PROJECT_NAME}-backend:${VERSION}"
    docker push "${REGISTRY}/${PROJECT_NAME}-frontend:${VERSION}"
    print_info "Images pushed successfully"
fi

print_info "Docker build completed successfully!"

# Option to save images as tar files
if [ "$SAVE_IMAGES" == "true" ]; then
    print_info "Saving images as tar files..."
    mkdir -p ./docker-images
    docker save -o "./docker-images/backend-${VERSION}.tar" "${PROJECT_NAME}-backend:${VERSION}"
    docker save -o "./docker-images/frontend-${VERSION}.tar" "${PROJECT_NAME}-frontend:${VERSION}"
    print_info "Images saved to ./docker-images/"
fi