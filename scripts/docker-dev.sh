#!/bin/bash

# Docker Development Environment Script
# Starts the development environment with hot-reload

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"

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

print_cmd() {
    echo -e "${BLUE}[CMD]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    
    # Check for .env file
    if [ ! -f "$ENV_FILE" ]; then
        print_warn ".env file not found. Creating from .env.docker..."
        cp .env.docker .env
    fi
    
    # Create necessary directories
    mkdir -p data/backend logs/backend
    
    print_info "Prerequisites check passed"
}

# Function to stop containers
stop_containers() {
    print_info "Stopping containers..."
    docker-compose -f "$COMPOSE_FILE" down
}

# Function to clean up
cleanup() {
    local clean_level=$1
    
    case $clean_level in
        "soft")
            print_info "Performing soft cleanup (keeping volumes)..."
            docker-compose -f "$COMPOSE_FILE" down
            ;;
        "hard")
            print_info "Performing hard cleanup (removing volumes)..."
            docker-compose -f "$COMPOSE_FILE" down -v
            ;;
        "full")
            print_info "Performing full cleanup (removing everything)..."
            docker-compose -f "$COMPOSE_FILE" down -v --rmi all
            ;;
        *)
            print_error "Invalid cleanup level: $clean_level"
            exit 1
            ;;
    esac
}

# Function to show logs
show_logs() {
    local service=$1
    if [ -z "$service" ]; then
        docker-compose -f "$COMPOSE_FILE" logs -f
    else
        docker-compose -f "$COMPOSE_FILE" logs -f "$service"
    fi
}

# Function to execute command in container
exec_container() {
    local service=$1
    shift
    local cmd="$@"
    
    print_cmd "Executing in $service: $cmd"
    docker-compose -f "$COMPOSE_FILE" exec "$service" $cmd
}

# Function to show status
show_status() {
    print_info "Container status:"
    docker-compose -f "$COMPOSE_FILE" ps
    
    print_info "\nResource usage:"
    docker stats --no-stream $(docker-compose -f "$COMPOSE_FILE" ps -q)
}

# Parse command line arguments
COMMAND=${1:-start}
shift || true

# Main script
case $COMMAND in
    start|up)
        check_prerequisites
        print_info "Starting development environment..."
        docker-compose -f "$COMPOSE_FILE" up -d --build
        print_info "Development environment started!"
        print_info "Backend API: http://localhost:8000"
        print_info "Frontend: http://localhost:5173"
        print_info "API Docs: http://localhost:8000/api/docs"
        ;;
    
    stop|down)
        stop_containers
        print_info "Development environment stopped"
        ;;
    
    restart)
        stop_containers
        check_prerequisites
        print_info "Restarting development environment..."
        docker-compose -f "$COMPOSE_FILE" up -d --build
        print_info "Development environment restarted"
        ;;
    
    logs)
        show_logs "$@"
        ;;
    
    exec)
        exec_container "$@"
        ;;
    
    shell)
        SERVICE=${1:-backend}
        print_info "Opening shell in $SERVICE container..."
        exec_container "$SERVICE" /bin/bash
        ;;
    
    test)
        print_info "Running tests in backend container..."
        exec_container backend pytest -v
        ;;
    
    format)
        print_info "Formatting code..."
        exec_container backend black /app
        print_info "Code formatted"
        ;;
    
    status|ps)
        show_status
        ;;
    
    clean)
        LEVEL=${1:-soft}
        cleanup "$LEVEL"
        print_info "Cleanup completed"
        ;;
    
    rebuild)
        print_info "Rebuilding containers..."
        docker-compose -f "$COMPOSE_FILE" build --no-cache
        docker-compose -f "$COMPOSE_FILE" up -d
        print_info "Containers rebuilt"
        ;;
    
    help)
        echo "Docker Development Environment Helper"
        echo ""
        echo "Usage: $0 [command] [options]"
        echo ""
        echo "Commands:"
        echo "  start|up       Start the development environment"
        echo "  stop|down      Stop the development environment"
        echo "  restart        Restart the development environment"
        echo "  logs [service] Show logs (optionally for specific service)"
        echo "  exec <service> <command>  Execute command in container"
        echo "  shell [service]  Open shell in container (default: backend)"
        echo "  test           Run tests in backend container"
        echo "  format         Format code with Black"
        echo "  status|ps      Show container status"
        echo "  clean [level]  Clean up (soft|hard|full)"
        echo "  rebuild        Rebuild containers from scratch"
        echo "  help           Show this help message"
        ;;
    
    *)
        print_error "Unknown command: $COMMAND"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac