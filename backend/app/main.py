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
    setup_logging(log_level=settings.log_level, json_logs=settings.env == "production")
    print(f"Starting {settings.app_name} API on port {settings.api_port}")
    yield
    # Shutdown
    print(f"Shutting down {settings.app_name} API")


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
