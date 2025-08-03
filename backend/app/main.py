from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Any

from .config import settings
from .api.routes import api_router
from .api.middleware import (
    error_handler_middleware,
    setup_exception_handlers,
    logging_middleware,
)
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
    
    yield
    
    # Shutdown
    print(f"Shutting down {settings.app_name} API")
    
    # Shutdown intelligence service
    from .services.intelligence_service import intelligence_service
    await intelligence_service.shutdown()
    
    if getattr(settings, "logging_enabled", True) and 'cleanup_task' in locals():
        cleanup_task.cancel()


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

    # Add custom schema modifications
    openapi_schema["info"]["x-logo"] = {
        "url": "/api/logo.png",
        "altText": "Image Converter Logo",
    }

    openapi_schema["servers"] = [
        {
            "url": f"http://localhost:{settings.api_port}/api",
            "description": "Local development server",
        }
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Include API routers
app.include_router(api_router)

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
