from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Any

from .config import settings
from .api.routes import api_router, api_v1_router
from .api.middleware import (
    error_handler_middleware,
    setup_exception_handlers,
    logging_middleware,
)
from .api.middleware.validation import validation_middleware
from .utils.logging import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    setup_logging(
        log_level=settings.log_level, 
        json_logs=settings.env == "production",
        enable_file_logging=getattr(settings, "logging_enabled", True),
        log_dir=getattr(settings, "log_dir", "./logs"),
        max_log_size_mb=getattr(settings, "max_log_size_mb", 10),
        backup_count=getattr(settings, "log_backup_count", 3),
        retention_hours=getattr(settings, "log_retention_hours", 24)
    )
    print(f"Starting {settings.app_name} API on port {settings.api_port}")
    
    # Initialize stats collector and inject into conversion service
    from .core.monitoring.stats import stats_collector
    from .services.conversion_service import conversion_service
    conversion_service.stats_collector = stats_collector
    
    # Initialize intelligence service
    from .services.intelligence_service import intelligence_service
    intelligence_service.stats_collector = stats_collector
    await intelligence_service.initialize()
    
    # Initialize recommendation service (CRITICAL: Must be initialized for Story 3.4)
    from .services.recommendation_service import recommendation_service as rec_service_import, RecommendationService
    import app.services.recommendation_service as rec_module
    rec_module.recommendation_service = RecommendationService()
    
    # Initialize optimization service (Story 3.5)
    from .services.optimization_service import optimization_service
    optimization_service.stats_collector = stats_collector
    optimization_service.set_intelligence_engine(intelligence_service.engine)
    # Set conversion service
    optimization_service.set_conversion_service(conversion_service)
    
    # Initialize batch service (Story 4.1)
    from .services.batch_service import batch_service
    batch_service.set_conversion_service(conversion_service)
    
    # Initialize preset service (Story 4.2)
    from .services.preset_service import preset_service
    await preset_service.initialize()
    
    # Inject preset service into conversion service
    conversion_service.set_preset_service(preset_service)
    
    # Ensure data directory exists for database files
    import os
    os.makedirs("./data", exist_ok=True)
    
    # Run enhanced network isolation verification
    if settings.network_verification_enabled:
        from .core.security.network_verifier import NetworkStrictness, verify_network_at_startup
        from .core.monitoring.security_events import SecurityEventTracker
        
        # Map string to enum
        strictness_map = {
            "standard": NetworkStrictness.STANDARD,
            "strict": NetworkStrictness.STRICT,
            "paranoid": NetworkStrictness.PARANOID
        }
        strictness = strictness_map.get(
            settings.network_verification_strictness, 
            NetworkStrictness.STANDARD
        )
        
        # Initialize security tracker if needed
        security_tracker = None
        if strictness != NetworkStrictness.STANDARD:
            security_tracker = SecurityEventTracker(
                db_path=settings.database_url.replace("sqlite:///", "")
                if settings.database_url.startswith("sqlite:///")
                else None
            )
        
        # Perform network verification
        network_status = await verify_network_at_startup(strictness, security_tracker)
        
        # Store status for later access
        app.state.network_status = network_status
        
        # Log results
        if not network_status["isolated"]:
            print(f"WARNING: Network isolation issues detected: {network_status['warnings']}")
        else:
            print(f"Network isolation verified ({strictness.value} mode)")
    else:
        # Basic check from original implementation
        from .core.monitoring.network_check import startup_network_check
        startup_network_check()
        app.state.network_status = {"isolated": True, "verified": False}
    
    # Schedule periodic log cleanup
    if getattr(settings, "logging_enabled", True):
        import asyncio
        from .utils.logging import cleanup_old_logs
        
        async def periodic_log_cleanup():
            while True:
                await asyncio.sleep(3600)  # Run every hour
                try:
                    cleanup_old_logs(
                        log_dir=getattr(settings, "log_dir", "./logs"),
                        retention_hours=getattr(settings, "log_retention_hours", 24)
                    )
                except Exception as e:
                    print(f"Log cleanup error: {e}")
        
        # Start background task
        cleanup_task = asyncio.create_task(periodic_log_cleanup())
    
    # Schedule periodic batch job cleanup (Story 4.1)
    async def periodic_batch_cleanup():
        while True:
            await asyncio.sleep(86400)  # Run once per day
            try:
                from .services.batch_history_service import batch_history_service
                deleted_count = await batch_history_service.cleanup_old_jobs()
                if deleted_count > 0:
                    print(f"Cleaned up {deleted_count} old batch jobs")
            except Exception as e:
                print(f"Batch cleanup error: {e}")
    
    # Start batch cleanup task
    batch_cleanup_task = asyncio.create_task(periodic_batch_cleanup())
    
    yield
    
    # Shutdown
    print(f"Shutting down {settings.app_name} API")
    
    # Shutdown intelligence service
    from .services.intelligence_service import intelligence_service
    await intelligence_service.shutdown()
    
    if getattr(settings, "logging_enabled", True) and 'cleanup_task' in locals():
        cleanup_task.cancel()
    
    # Cancel batch cleanup task
    if 'batch_cleanup_task' in locals():
        batch_cleanup_task.cancel()


app = FastAPI(
    title="Image Converter API",
    description="Privacy-focused local image conversion service with advanced optimization capabilities",
    version="0.1.0",
    openapi_url="/api/openapi.json",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add validation middleware (first - should run before others)
app.middleware("http")(validation_middleware)

# Add logging middleware
app.middleware("http")(logging_middleware)

# Add error handling middleware
app.middleware("http")(error_handler_middleware)

# Setup exception handlers
setup_exception_handlers(app)


def custom_openapi() -> Dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Enhanced metadata for better API documentation
    openapi_schema["info"].update({
        "version": "1.0.0",
        "title": "Image Converter API",
        "description": """
        Privacy-focused local image conversion service with advanced optimization capabilities.
        
        ## Features
        - Local-only processing (no external network requests)
        - Advanced format support (WebP, AVIF, JPEG XL, HEIF, etc.)
        - Batch processing with real-time progress updates
        - Smart content detection and optimization recommendations
        - Preset management for consistent conversion settings
        - Comprehensive metadata handling with privacy controls
        
        ## Security
        - All processing happens in sandboxed environments
        - Automatic metadata removal for privacy
        - No data leaves your machine
        
        ## API Versions
        - v1: Current stable API with full feature support
        - legacy: Backward compatibility endpoints (deprecated)
        """,
        "contact": {
            "name": "Image Converter API Support",
            "url": "https://github.com/your-repo/image-converter",
        },
        "license": {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT",
        },
        "x-logo": {
            "url": "/api/logo.png",
            "altText": "Image Converter Logo",
        },
    })

    # Enhanced server configuration
    openapi_schema["servers"] = [
        {
            "url": f"http://localhost:{settings.api_port}/api/v1",
            "description": "Local development server (v1 API)",
        },
        {
            "url": f"http://localhost:{settings.api_port}/api",
            "description": "Local development server (legacy endpoints)",
        }
    ]

    # Add reusable components
    openapi_schema["components"] = openapi_schema.get("components", {})
    
    # Enhanced security schemes for future authentication
    openapi_schema["components"]["securitySchemes"] = {
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key for authenticated access (future feature)"
        },
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token authentication (future feature)"
        }
    }
    
    # Add common response schemas
    openapi_schema["components"]["schemas"] = openapi_schema["components"].get("schemas", {})
    openapi_schema["components"]["schemas"].update({
        "ErrorResponse": {
            "type": "object",
            "required": ["error_code", "message", "correlation_id"],
            "properties": {
                "error_code": {
                    "type": "string",
                    "description": "Unique error code for programmatic handling",
                    "example": "CONV201"
                },
                "message": {
                    "type": "string",
                    "description": "Human-readable error message",
                    "example": "File size exceeds maximum allowed size"
                },
                "correlation_id": {
                    "type": "string",
                    "description": "Request correlation ID for tracking",
                    "example": "abc123-def456-ghi789"
                },
                "details": {
                    "type": "object",
                    "description": "Additional error context",
                    "additionalProperties": True
                },
                "timestamp": {
                    "type": "string",
                    "format": "date-time",
                    "description": "When the error occurred"
                }
            }
        },
        "ValidationError": {
            "type": "object",
            "properties": {
                "loc": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Location of the validation error"
                },
                "msg": {
                    "type": "string",
                    "description": "Validation error message"
                },
                "type": {
                    "type": "string",
                    "description": "Type of validation error"
                }
            }
        }
    })

    # Add common parameters
    openapi_schema["components"]["parameters"] = {
        "CorrelationId": {
            "name": "X-Correlation-ID",
            "in": "header",
            "description": "Optional correlation ID for request tracking",
            "required": False,
            "schema": {"type": "string"}
        },
        "AcceptVersion": {
            "name": "Accept-Version",
            "in": "header",
            "description": "API version preference",
            "required": False,
            "schema": {
                "type": "string",
                "enum": ["v1"],
                "default": "v1"
            }
        }
    }

    # Add tags for better organization
    openapi_schema["tags"] = [
        {
            "name": "conversion",
            "description": "Single image conversion operations"
        },
        {
            "name": "batch",
            "description": "Batch processing operations"
        },
        {
            "name": "detection",
            "description": "Format detection and analysis"
        },
        {
            "name": "presets",
            "description": "Preset management"
        },
        {
            "name": "monitoring",
            "description": "System monitoring and statistics"
        },
        {
            "name": "health",
            "description": "Health check and system status"
        }
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Include API routers
app.include_router(api_router)  # Legacy endpoints for backward compatibility
app.include_router(api_v1_router)  # Current v1 API endpoints

# Include WebSocket routers
from .api.websockets.progress import router as websocket_router
app.include_router(websocket_router)

# Include secure WebSocket routes if authentication is enabled
if settings.batch_websocket_auth_enabled:
    from .api.websockets.secure_progress import router as secure_websocket_router
    app.include_router(secure_websocket_router, prefix="/api")

# Static file serving for production
if settings.env == "production":
    # Mount static files
    frontend_build_path = Path(__file__).parent.parent.parent / "frontend" / "dist"
    if frontend_build_path.exists():
        app.mount(
            "/assets",
            StaticFiles(directory=str(frontend_build_path / "assets")),
            name="assets",
        )

        # Serve index.html for all non-API routes (SPA fallback)
        @app.get("/{full_path:path}")
        async def serve_spa(full_path: str):
            # Don't catch API routes
            if full_path.startswith("api/"):
                return {"detail": "Not Found"}, 404

            index_path = frontend_build_path / "index.html"
            if index_path.exists():
                return FileResponse(str(index_path))

            return {"detail": "Frontend not built"}, 404

else:

    @app.get("/")
    async def root():
        return {"message": "Image Converter API", "version": "0.1.0"}
