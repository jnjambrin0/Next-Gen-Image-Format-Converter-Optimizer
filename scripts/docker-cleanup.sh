#!/bin/bash

# ============================================
# DOCKER CLEANUP SCRIPT - ELIMINACIÓN COMPLETA
# ============================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="image-converter"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOG_FILE="${SCRIPT_DIR}/cleanup_log_$(date +%Y%m%d_%H%M%S).txt"
DRY_RUN=false

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

print_section() {
    echo -e "\n${MAGENTA}═══════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}  $1${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════${NC}\n"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            echo "MODO DRY-RUN: Solo se mostrará lo que se eliminaría"
            shift
            ;;
        --help)
            echo "Uso: $0 [--dry-run] [--help]"
            echo "  --dry-run  Muestra qué se eliminaría sin hacerlo"
            echo "  --help     Muestra esta ayuda"
            exit 0
            ;;
        *)
            echo "Opción desconocida: $1"
            echo "Usa --help para ver las opciones disponibles"
            exit 1
            ;;
    esac
done

# Logging function
log_action() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] $1"
    echo "$message" >> "$LOG_FILE"
    [[ "$DRY_RUN" = true ]] && message="[DRY-RUN] $message"
    echo "$message"
}

# Safe execution function
safe_execute() {
    local command="$1"
    local description="$2"
    
    if [ "$DRY_RUN" = true ]; then
        log_action "[DRY-RUN] Ejecutaría: $description"
        return 0
    else
        log_action "Ejecutando: $description"
        eval "$command" 2>/dev/null || {
            log_action "Advertencia: Falló '$description' (continuando...)"
            return 0
        }
    fi
}

# Verify current directory
verify_directory() {
    # Go to parent directory where docker-compose.yml should be
    cd "$SCRIPT_DIR/.." || exit 1
    
    if [ ! -f "docker-compose.yml" ] && [ ! -f "docker-compose.prod.yml" ]; then
        print_error "No se encontró docker-compose.yml en el directorio del proyecto"
        echo "Directorio actual: $(pwd)"
        read -p "¿Es este el directorio correcto del proyecto? (s/N): " confirm
        if [[ ! "$confirm" =~ ^[Ss]$ ]]; then
            log_action "Abortado: directorio incorrecto"
            exit 1
        fi
    fi
}

# Backup function
create_backup() {
    if [ "$DRY_RUN" = true ]; then
        log_action "[DRY-RUN] Se crearía backup de volúmenes"
        return 0
    fi
    
    read -p "¿Crear backup de los volúmenes antes de eliminar? (s/N): " do_backup
    if [[ "$do_backup" =~ ^[Ss]$ ]]; then
        BACKUP_DIR="${SCRIPT_DIR}/backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        log_action "Creando backup en: $BACKUP_DIR"
        
        # Export volumes
        for volume in $(docker volume ls -q | grep -E "^${PROJECT_NAME}_|^image_converter_"); do
            log_action "Respaldando volumen: $volume"
            docker run --rm \
                -v "${volume}:/data:ro" \
                -v "${BACKUP_DIR}:/backup" \
                alpine tar czf "/backup/${volume}.tar.gz" -C /data . 2>/dev/null || \
                log_action "No se pudo respaldar: $volume"
        done
        
        log_action "Backup completado en: $BACKUP_DIR"
        echo "Backup guardado en: $BACKUP_DIR"
    fi
}

# Improved container cleanup with precise filtering
cleanup_containers() {
    print_section "1. Deteniendo y eliminando contenedores"
    
    # Get containers with exact project label match
    local containers=$(docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" -q)
    
    if [ -n "$containers" ]; then
        for container in $containers; do
            local name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null || echo "unknown")
            safe_execute "docker stop '$container'" "Deteniendo contenedor: $name"
            safe_execute "docker rm -f '$container'" "Eliminando contenedor: $name"
        done
    fi
    
    # Also check by name pattern (more restrictive)
    local pattern_containers=$(docker ps -a --format "{{.ID}} {{.Names}}" | \
        grep -E "^[[:alnum:]]+[[:space:]]+[[:alnum:]_-]*${PROJECT_NAME}" | \
        awk '{print $1}')
    
    if [ -n "$pattern_containers" ]; then
        for container in $pattern_containers; do
            safe_execute "docker rm -f '$container'" "Eliminando contenedor por patrón: $container"
        done
    fi
    
    log_action "Contenedores eliminados completamente"
}

# Check if user really wants to proceed
confirm_cleanup() {
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    ⚠️  ADVERTENCIA ⚠️                         ║${NC}"
    echo -e "${RED}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║  Este script eliminará COMPLETAMENTE:                        ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║  • Todos los contenedores de Image Converter                ║${NC}"
    echo -e "${RED}║  • Todas las imágenes Docker del proyecto                   ║${NC}"
    echo -e "${RED}║  • Todos los volúmenes (incluidos datos)                    ║${NC}"
    echo -e "${RED}║  • Todas las redes Docker del proyecto                      ║${NC}"
    echo -e "${RED}║  • Cache de Docker build                                    ║${NC}"
    echo -e "${RED}║  • Directorios locales de datos y logs                      ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║  Esta acción NO se puede deshacer                           ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    read -p "¿Estás seguro de que quieres eliminar TODO? (escribe 'SI ELIMINAR' para confirmar): " confirmation
    
    if [ "$confirmation" != "SI ELIMINAR" ]; then
        print_warn "Limpieza cancelada"
        exit 0
    fi
}

# Function to remove images
cleanup_images() {
    print_section "2. Eliminando imágenes Docker"
    
    print_info "Eliminando imágenes del proyecto..."
    
    # Remove project images
    docker images | grep -E "$PROJECT_NAME|image_converter" | awk '{print $3}' | xargs -r docker rmi -f 2>/dev/null || true
    
    # Remove dangling images
    docker images -f "dangling=true" -q | xargs -r docker rmi -f 2>/dev/null || true
    
    print_info "✓ Imágenes eliminadas"
}

# Function to remove volumes
cleanup_volumes() {
    print_section "3. Eliminando volúmenes Docker"
    
    print_info "Eliminando volúmenes del proyecto..."
    
    # Remove named volumes
    docker volume ls | grep -E "$PROJECT_NAME|image_converter" | awk '{print $2}' | xargs -r docker volume rm -f 2>/dev/null || true
    
    # Remove specific volumes
    for volume in "backend_data" "backend_logs" "backend_tmp" "node_modules"; do
        docker volume rm -f "${PROJECT_NAME}_${volume}" 2>/dev/null || true
        docker volume rm -f "image_converter_${volume}" 2>/dev/null || true
        docker volume rm -f "${volume}" 2>/dev/null || true
    done
    
    print_info "✓ Volúmenes eliminados"
}

# Function to remove networks
cleanup_networks() {
    print_section "4. Eliminando redes Docker"
    
    print_info "Eliminando redes del proyecto..."
    
    # Remove project networks
    docker network ls | grep -E "$PROJECT_NAME|image_converter|app_network" | awk '{print $2}' | xargs -r docker network rm 2>/dev/null || true
    
    print_info "✓ Redes eliminadas"
}

# Function to clean build cache
cleanup_build_cache() {
    print_section "5. Limpiando cache de Docker build"
    
    print_info "Eliminando cache de build..."
    
    # Prune build cache
    docker builder prune -f --filter "label=project=$PROJECT_NAME" 2>/dev/null || true
    
    print_info "✓ Cache de build eliminado"
}

# Function to clean local directories
cleanup_local_directories() {
    print_section "6. Eliminando directorios locales"
    
    print_info "Eliminando directorios de datos y logs..."
    
    # Remove data directories
    rm -rf ./data 2>/dev/null || true
    rm -rf ./logs 2>/dev/null || true
    rm -rf ./backups 2>/dev/null || true
    rm -rf ./docker-images 2>/dev/null || true
    
    # Remove backend specific
    rm -rf ./backend/data 2>/dev/null || true
    rm -rf ./backend/logs 2>/dev/null || true
    rm -rf ./backend/__pycache__ 2>/dev/null || true
    rm -rf ./backend/.pytest_cache 2>/dev/null || true
    rm -rf ./backend/*.egg-info 2>/dev/null || true
    
    # Remove frontend specific
    rm -rf ./frontend/node_modules 2>/dev/null || true
    rm -rf ./frontend/dist 2>/dev/null || true
    rm -rf ./frontend/.vite 2>/dev/null || true
    
    # Remove .env files (keep examples)
    rm -f .env 2>/dev/null || true
    
    print_info "✓ Directorios locales eliminados"
}

# Function to show Docker disk usage
show_docker_usage() {
    print_section "7. Uso de disco de Docker"
    
    docker system df 2>/dev/null || print_warn "No se pudo obtener información de uso de disco"
}

# Function for complete Docker system prune (optional)
optional_system_prune() {
    print_section "8. Limpieza completa del sistema Docker (OPCIONAL)"
    
    echo -e "${YELLOW}¿Quieres hacer una limpieza COMPLETA del sistema Docker?${NC}"
    echo -e "${YELLOW}Esto eliminará:${NC}"
    echo -e "${YELLOW}  • TODOS los contenedores detenidos (de todos los proyectos)${NC}"
    echo -e "${YELLOW}  • TODAS las imágenes no utilizadas${NC}"
    echo -e "${YELLOW}  • TODOS los volúmenes no utilizados${NC}"
    echo -e "${YELLOW}  • TODAS las redes no utilizadas${NC}"
    echo -e "${YELLOW}  • TODO el cache de build${NC}"
    echo ""
    
    read -p "¿Realizar limpieza completa del sistema? (s/N): " do_prune
    
    if [[ "$do_prune" =~ ^[Ss]$ ]]; then
        print_warn "Ejecutando limpieza completa del sistema Docker..."
        docker system prune -a --volumes -f
        print_info "✓ Limpieza completa del sistema realizada"
    else
        print_info "Limpieza del sistema omitida"
    fi
}

# Main function with all improvements
main() {
    print_section "SCRIPT DE LIMPIEZA COMPLETA - IMAGE CONVERTER"
    
    log_action "Iniciando script de limpieza (DRY_RUN=$DRY_RUN)"
    
    # Check Docker
    if ! docker info > /dev/null 2>&1; then
        log_action "Error: Docker no está en ejecución"
        print_error "Docker no está en ejecución. Por favor, inicia Docker primero."
        exit 1
    fi
    
    # Verify directory
    verify_directory
    
    # Confirm if not in dry-run mode
    if [ "$DRY_RUN" = false ]; then
        confirm_cleanup
        create_backup
    fi
    
    # Execute cleanup
    cleanup_containers
    cleanup_images
    cleanup_volumes
    cleanup_networks
    cleanup_build_cache
    cleanup_local_directories
    
    if [ "$DRY_RUN" = false ]; then
        show_docker_usage
        optional_system_prune
    fi
    
    # Final summary
    print_section "✅ LIMPIEZA COMPLETADA"
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}Esto fue una ejecución DRY-RUN. No se eliminó nada realmente.${NC}"
        echo -e "${YELLOW}Ejecuta sin --dry-run para realizar la limpieza real.${NC}"
    else
        echo -e "${GREEN}Limpieza completada. Ver log en: $LOG_FILE${NC}"
    fi
    
    log_action "Script finalizado exitosamente"
}

# Run with all arguments
main "$@"