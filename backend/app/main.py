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
    auth_middleware,
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
        retention_hours=getattr(settings, "log_retention_hours", 24),
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
    from .services.recommendation_service import (
        recommendation_service as rec_service_import,
        RecommendationService,
    )
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

    # Initialize API key service (Story 5.2)
    from .services.api_key_service import api_key_service

    # Ensure data directory exists for database files
    import os

    os.makedirs("./data", exist_ok=True)

    # Run enhanced network isolation verification
    if settings.network_verification_enabled:
        from .core.security.network_verifier import (
            NetworkStrictness,
            verify_network_at_startup,
        )
        from .core.monitoring.security_events import SecurityEventTracker

        # Map string to enum
        strictness_map = {
            "standard": NetworkStrictness.STANDARD,
            "strict": NetworkStrictness.STRICT,
            "paranoid": NetworkStrictness.PARANOID,
        }
        strictness = strictness_map.get(
            settings.network_verification_strictness, NetworkStrictness.STANDARD
        )

        # Initialize security tracker if needed
        security_tracker = None
        if strictness != NetworkStrictness.STANDARD:
            security_tracker = SecurityEventTracker(
                db_path=(
                    settings.database_url.replace("sqlite:///", "")
                    if settings.database_url.startswith("sqlite:///")
                    else None
                )
            )

        # Perform network verification
        network_status = await verify_network_at_startup(strictness, security_tracker)

        # Store status for later access
        app.state.network_status = network_status

        # Log results
        if not network_status["isolated"]:
            print(
                f"WARNING: Network isolation issues detected: {network_status['warnings']}"
            )
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
                        retention_hours=getattr(settings, "log_retention_hours", 24),
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

    if getattr(settings, "logging_enabled", True) and "cleanup_task" in locals():
        cleanup_task.cancel()

    # Cancel batch cleanup task
    if "batch_cleanup_task" in locals():
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

# Add authentication middleware (runs after validation)
app.middleware("http")(auth_middleware)

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
    openapi_schema["info"].update(
        {
            "version": "1.0.0",
            "title": "Image Converter API",
            "description": """
        Privacy-focused local image conversion service with advanced optimization capabilities.
        
        ## 🚀 Features
        
        ### Core Conversion
        - **Universal Format Support**: JPEG, PNG, WebP, AVIF, HEIF/HEIC, JPEG XL, WebP2, BMP, TIFF, GIF
        - **Smart Format Detection**: Content-based detection, not relying on file extensions
        - **Quality Optimization**: Adaptive quality settings based on content analysis
        - **Metadata Privacy**: Automatic EXIF/GPS removal with granular control
        
        ### Batch Processing
        - **Concurrent Processing**: Multi-threaded batch conversion with progress tracking
        - **Real-time Updates**: WebSocket and Server-Sent Events for live progress
        - **Flexible Cancellation**: Cancel entire jobs or individual items
        - **Result Management**: Automatic ZIP packaging and download
        
        ### Intelligence Features
        - **Content Analysis**: AI-powered detection of photos, illustrations, screenshots, documents
        - **Smart Recommendations**: Format suggestions based on content type and optimization goals
        - **Quality Metrics**: SSIM/PSNR quality analysis for optimization validation
        - **Performance Profiling**: Detailed conversion statistics and metrics
        
        ### Preset Management
        - **Version Control**: Full version history with rollback capabilities
        - **Advanced Search**: Fuzzy matching, filtering, and ranking
        - **Import/Export**: Portable preset sharing with validation
        - **Usage Analytics**: Track preset performance and adoption
        
        ## 🔒 Security & Privacy
        
        ### Local-Only Processing
        - **Network Isolation**: No external API calls or data transmission
        - **Sandboxed Execution**: All conversions run in isolated environments
        - **Memory Security**: Secure memory clearing with overwrite patterns
        - **Resource Limits**: CPU, memory, and time constraints prevent abuse
        
        ### Privacy Controls
        - **Metadata Removal**: EXIF, GPS, and camera data stripped by default
        - **Filename Sanitization**: Path traversal and security validation
        - **Privacy-Aware Logging**: No PII or sensitive data in logs
        - **Audit Trail**: Security event tracking without data exposure
        
        ## 📊 API Versions
        
        ### Current API (v1)
        - **REST Endpoints**: Full CRUD operations with standardized error handling
        - **Real-time Updates**: WebSocket and SSE support for live progress
        - **Comprehensive Filtering**: Advanced search, pagination, and sorting
        - **Version Management**: Preset versioning and rollback capabilities
        
        ### Legacy API (deprecated)
        - **Backward Compatibility**: Maintained for existing integrations
        - **Migration Path**: Automated migration tools and guides available
        - **Sunset Timeline**: Legacy endpoints will be removed in v2.0
        
        ## 🔧 Development
        
        ### Error Handling
        - **Standardized Errors**: Consistent error codes and correlation IDs
        - **Detailed Context**: Rich error details for debugging
        - **Rate Limiting**: Built-in protection against abuse
        - **Validation**: Comprehensive input validation with helpful messages
        
        ### Performance
        - **Concurrent Limits**: Configurable concurrency for optimal resource usage
        - **Memory Management**: Automatic cleanup and garbage collection
        - **Caching**: Intelligent caching for repeated operations
        - **Monitoring**: Built-in metrics and health checks
        
        ## 📚 Documentation
        
        - **Interactive API Docs**: This Swagger UI with live testing
        - **Code Examples**: Complete examples in multiple languages
        - **Integration Guides**: Step-by-step integration tutorials
        - **Performance Tips**: Optimization recommendations and best practices
        """,
            "contact": {
                "name": "Image Converter API Support",
                "url": "https://github.com/jnjambrin0/Next-Gen-Image-Format-Converter-Optimizer",
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT",
            },
            "x-logo": {
                "url": "/api/logo.png",
                "altText": "Image Converter Logo",
            },
        }
    )

    # Enhanced server configuration with environment detection
    openapi_schema["servers"] = [
        {
            "url": f"http://localhost:{settings.api_port}/api/v1",
            "description": "Local development server (v1 API - Current)",
            "variables": {
                "port": {
                    "default": str(settings.api_port),
                    "description": "API server port",
                }
            },
        },
        {
            "url": f"http://localhost:{settings.api_port}/api",
            "description": "Local development server (Legacy endpoints - Deprecated)",
            "variables": {
                "port": {
                    "default": str(settings.api_port),
                    "description": "API server port",
                }
            },
        },
        {
            "url": "http://127.0.0.1:8080/api/v1",
            "description": "Alternative localhost (v1 API)",
        },
    ]

    # Add reusable components
    openapi_schema["components"] = openapi_schema.get("components", {})

    # Enhanced security schemes for future authentication
    openapi_schema["components"]["securitySchemes"] = {
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key for authenticated access (future feature)",
        },
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token authentication (future feature)",
        },
    }

    # Add comprehensive response schemas and examples
    openapi_schema["components"]["schemas"] = openapi_schema["components"].get(
        "schemas", {}
    )
    openapi_schema["components"]["schemas"].update(
        {
            "ErrorResponse": {
                "type": "object",
                "required": ["error_code", "message", "correlation_id"],
                "properties": {
                    "error_code": {
                        "type": "string",
                        "description": "Unique error code for programmatic handling",
                        "example": "CONV201",
                        "enum": [
                            "CONV201",
                            "CONV400",
                            "CONV413",
                            "CONV415",
                            "CONV422",
                            "CONV500",
                            "BAT201",
                            "BAT400",
                            "BAT404",
                            "BAT500",
                            "DET400",
                            "DET413",
                            "DET503",
                            "PRE400",
                            "PRE403",
                            "PRE404",
                            "PRE409",
                            "PRE500",
                        ],
                    },
                    "message": {
                        "type": "string",
                        "description": "Human-readable error message",
                        "example": "File size exceeds maximum allowed size",
                    },
                    "correlation_id": {
                        "type": "string",
                        "description": "Request correlation ID for tracking",
                        "example": "abc123-def456-ghi789",
                        "pattern": "^[a-f0-9-]+$",
                    },
                    "details": {
                        "type": "object",
                        "description": "Additional error context",
                        "additionalProperties": True,
                        "example": {
                            "file_size": 52428800,
                            "max_allowed": 50331648,
                            "size_mb": 50.0,
                        },
                    },
                    "timestamp": {
                        "type": "string",
                        "format": "date-time",
                        "description": "When the error occurred",
                        "example": "2024-01-15T10:30:00Z",
                    },
                },
                "example": {
                    "error_code": "CONV413",
                    "message": "File size exceeds maximum allowed size",
                    "correlation_id": "abc123-def456-ghi789",
                    "details": {
                        "file_size": 52428800,
                        "max_allowed": 50331648,
                        "size_mb": 50.0,
                    },
                    "timestamp": "2024-01-15T10:30:00Z",
                },
            },
            "ValidationError": {
                "type": "object",
                "properties": {
                    "loc": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Location of the validation error",
                        "example": ["body", "quality"],
                    },
                    "msg": {
                        "type": "string",
                        "description": "Validation error message",
                        "example": "ensure this value is greater than or equal to 1",
                    },
                    "type": {
                        "type": "string",
                        "description": "Type of validation error",
                        "example": "value_error.number.not_ge",
                    },
                },
                "example": {
                    "loc": ["body", "quality"],
                    "msg": "ensure this value is greater than or equal to 1",
                    "type": "value_error.number.not_ge",
                },
            },
            "SupportedFormat": {
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "description": "Format identifier",
                        "example": "webp",
                    },
                    "mime_type": {
                        "type": "string",
                        "description": "MIME type",
                        "example": "image/webp",
                    },
                    "extensions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "File extensions",
                        "example": [".webp"],
                    },
                    "supports_transparency": {
                        "type": "boolean",
                        "description": "Whether format supports transparency",
                        "example": True,
                    },
                    "supports_animation": {
                        "type": "boolean",
                        "description": "Whether format supports animation",
                        "example": True,
                    },
                },
            },
            "ConversionResult": {
                "type": "object",
                "description": "Conversion result metadata (returned in response headers)",
                "properties": {
                    "conversion_id": {
                        "type": "string",
                        "description": "Unique conversion identifier",
                        "example": "conv_abc123def456",
                    },
                    "processing_time": {
                        "type": "number",
                        "description": "Processing time in seconds",
                        "example": 0.234,
                    },
                    "compression_ratio": {
                        "type": "number",
                        "description": "Output/input size ratio",
                        "example": 0.65,
                    },
                    "input_format": {
                        "type": "string",
                        "description": "Detected input format",
                        "example": "jpeg",
                    },
                    "output_format": {
                        "type": "string",
                        "description": "Actual output format",
                        "example": "webp",
                    },
                    "input_size": {
                        "type": "integer",
                        "description": "Original file size in bytes",
                        "example": 1048576,
                    },
                    "output_size": {
                        "type": "integer",
                        "description": "Converted file size in bytes",
                        "example": 681574,
                    },
                    "quality_used": {
                        "type": "integer",
                        "description": "Quality setting applied",
                        "example": 85,
                    },
                    "metadata_removed": {
                        "type": "boolean",
                        "description": "Whether metadata was stripped",
                        "example": True,
                    },
                },
            },
        }
    )

    # Add comprehensive common parameters
    openapi_schema["components"]["parameters"] = {
        "CorrelationId": {
            "name": "X-Correlation-ID",
            "in": "header",
            "description": "Optional correlation ID for request tracking and debugging",
            "required": False,
            "schema": {
                "type": "string",
                "pattern": "^[a-f0-9-]+$",
                "example": "abc123-def456-ghi789",
            },
        },
        "AcceptVersion": {
            "name": "Accept-Version",
            "in": "header",
            "description": "API version preference for backward compatibility",
            "required": False,
            "schema": {"type": "string", "enum": ["v1"], "default": "v1"},
        },
        "ContentType": {
            "name": "Content-Type",
            "in": "header",
            "description": "Content type for file uploads",
            "required": True,
            "schema": {
                "type": "string",
                "enum": ["multipart/form-data"],
                "example": "multipart/form-data",
            },
        },
        "CacheControl": {
            "name": "Cache-Control",
            "in": "header",
            "description": "Cache control for converted images",
            "required": False,
            "schema": {
                "type": "string",
                "example": "no-cache, no-store, must-revalidate",
            },
        },
        "PaginationLimit": {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of items to return",
            "required": False,
            "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
        },
        "PaginationOffset": {
            "name": "offset",
            "in": "query",
            "description": "Number of items to skip",
            "required": False,
            "schema": {"type": "integer", "minimum": 0, "default": 0},
        },
    }

    # Add comprehensive tags for better organization
    openapi_schema["tags"] = [
        {
            "name": "conversion",
            "description": "Single image conversion operations with format detection and optimization",
            "externalDocs": {
                "description": "Conversion Guide",
                "url": "/api/docs/conversion-guide",
            },
        },
        {
            "name": "batch",
            "description": "Batch processing operations with real-time progress tracking",
            "externalDocs": {
                "description": "Batch Processing Guide",
                "url": "/api/docs/batch-guide",
            },
        },
        {
            "name": "detection",
            "description": "Format detection, analysis, and intelligent recommendations",
            "externalDocs": {
                "description": "Detection API Reference",
                "url": "/api/docs/detection-guide",
            },
        },
        {
            "name": "presets",
            "description": "Preset management with versioning, search, and advanced filtering",
            "externalDocs": {
                "description": "Preset Management Guide",
                "url": "/api/docs/preset-guide",
            },
        },
        {
            "name": "monitoring",
            "description": "System monitoring, statistics, and performance metrics",
            "externalDocs": {
                "description": "Monitoring Guide",
                "url": "/api/docs/monitoring-guide",
            },
        },
        {
            "name": "health",
            "description": "Health checks, system status, and network isolation verification",
            "externalDocs": {
                "description": "Health Check Guide",
                "url": "/api/docs/health-guide",
            },
        },
        {
            "name": "intelligence",
            "description": "AI-powered content analysis and optimization recommendations",
            "externalDocs": {
                "description": "Intelligence Engine Guide",
                "url": "/api/docs/intelligence-guide",
            },
        },
        {
            "name": "optimization",
            "description": "Advanced optimization features and quality analysis",
            "externalDocs": {
                "description": "Optimization Guide",
                "url": "/api/docs/optimization-guide",
            },
        },
    ]

    # Add comprehensive examples for common operations
    openapi_schema["components"]["examples"] = {
        "SimpleConversion": {
            "summary": "Basic image conversion",
            "description": "Convert a JPEG image to WebP format with default settings",
            "value": {"file": "@photo.jpg", "output_format": "webp", "quality": 85},
        },
        "HighQualityConversion": {
            "summary": "High-quality conversion",
            "description": "Convert with maximum quality and metadata preservation",
            "value": {
                "file": "@photo.jpg",
                "output_format": "avif",
                "quality": 95,
                "preserve_metadata": True,
                "strip_metadata": False,
            },
        },
        "BatchConversion": {
            "summary": "Batch processing",
            "description": "Convert multiple images with consistent settings",
            "value": {
                "files": ["@photo1.jpg", "@photo2.png", "@photo3.heic"],
                "output_format": "webp",
                "quality": 80,
                "optimization_mode": "size",
            },
        },
        "PresetConversion": {
            "summary": "Using presets",
            "description": "Convert using a predefined preset configuration",
            "value": {
                "file": "@photo.jpg",
                "output_format": "webp",
                "preset_id": "550e8400-e29b-41d4-a716-446655440000",
            },
        },
        "ErrorResponse400": {
            "summary": "Validation error",
            "description": "Example of a validation error response",
            "value": {
                "error_code": "CONV400",
                "message": "Invalid quality setting",
                "correlation_id": "abc123-def456-ghi789",
                "details": {"provided_quality": 150, "valid_range": "1-100"},
                "timestamp": "2024-01-15T10:30:00Z",
            },
        },
        "ErrorResponse413": {
            "summary": "File too large",
            "description": "Example of a file size error response",
            "value": {
                "error_code": "CONV413",
                "message": "File size exceeds maximum allowed size",
                "correlation_id": "def456-ghi789-jkl012",
                "details": {
                    "file_size": 52428800,
                    "max_allowed": 50331648,
                    "size_mb": 50.0,
                },
                "timestamp": "2024-01-15T10:31:00Z",
            },
        },
    }

    # Add comprehensive request/response examples
    openapi_schema["components"]["requestBodies"] = {
        "ImageConversion": {
            "description": "Image file with conversion parameters",
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["file", "output_format"],
                        "properties": {
                            "file": {
                                "type": "string",
                                "format": "binary",
                                "description": "Image file to convert",
                            },
                            "output_format": {
                                "type": "string",
                                "enum": [
                                    "webp",
                                    "avif",
                                    "jpeg",
                                    "png",
                                    "jxl",
                                    "heif",
                                    "webp2",
                                ],
                                "description": "Target output format",
                            },
                            "quality": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100,
                                "default": 85,
                                "description": "Output quality (1-100)",
                            },
                            "strip_metadata": {
                                "type": "boolean",
                                "default": True,
                                "description": "Remove EXIF and metadata",
                            },
                            "preserve_metadata": {
                                "type": "boolean",
                                "default": False,
                                "description": "Preserve non-GPS metadata",
                            },
                            "preserve_gps": {
                                "type": "boolean",
                                "default": False,
                                "description": "Preserve GPS location data",
                            },
                            "preset_id": {
                                "type": "string",
                                "format": "uuid",
                                "description": "UUID of preset to apply",
                            },
                        },
                    },
                    "examples": {
                        "simple": {"$ref": "#/components/examples/SimpleConversion"},
                        "high_quality": {
                            "$ref": "#/components/examples/HighQualityConversion"
                        },
                        "with_preset": {
                            "$ref": "#/components/examples/PresetConversion"
                        },
                    },
                }
            },
        },
        "BatchConversion": {
            "description": "Multiple image files with batch conversion settings",
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["files", "output_format"],
                        "properties": {
                            "files": {
                                "type": "array",
                                "items": {"type": "string", "format": "binary"},
                                "minItems": 1,
                                "maxItems": 100,
                                "description": "Array of image files to convert",
                            },
                            "output_format": {
                                "type": "string",
                                "enum": [
                                    "webp",
                                    "avif",
                                    "jpeg",
                                    "png",
                                    "jxl",
                                    "heif",
                                    "webp2",
                                ],
                                "description": "Target output format for all files",
                            },
                            "quality": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100,
                                "default": 85,
                            },
                            "optimization_mode": {
                                "type": "string",
                                "enum": ["size", "quality", "balanced", "lossless"],
                                "default": "balanced",
                            },
                            "preserve_metadata": {"type": "boolean", "default": False},
                            "preset_id": {"type": "string", "format": "uuid"},
                        },
                    },
                    "example": {"$ref": "#/components/examples/BatchConversion"},
                }
            },
        },
    }

    # Add response headers documentation
    openapi_schema["components"]["headers"] = {
        "X-Conversion-Id": {
            "description": "Unique identifier for the conversion operation",
            "schema": {"type": "string", "example": "conv_abc123def456"},
        },
        "X-Processing-Time": {
            "description": "Time taken to process the conversion (seconds)",
            "schema": {"type": "number", "example": 0.234},
        },
        "X-Compression-Ratio": {
            "description": "Ratio of output size to input size",
            "schema": {"type": "number", "example": 0.65},
        },
        "X-Input-Format": {
            "description": "Detected input image format",
            "schema": {"type": "string", "example": "jpeg"},
        },
        "X-Output-Format": {
            "description": "Actual output format used",
            "schema": {"type": "string", "example": "webp"},
        },
        "X-Correlation-ID": {
            "description": "Request correlation ID for tracking",
            "schema": {"type": "string", "example": "abc123-def456-ghi789"},
        },
        "X-API-Version": {
            "description": "API version used for the request",
            "schema": {"type": "string", "example": "v1"},
        },
        "X-Total-Items": {
            "description": "Total number of items available (pagination)",
            "schema": {"type": "integer", "example": 150},
        },
        "X-Has-More": {
            "description": "Whether more items are available (pagination)",
            "schema": {"type": "boolean", "example": True},
        },
    }

    # Add webhook/callback documentation for future extensibility
    openapi_schema["components"]["callbacks"] = {
        "conversionComplete": {
            "{$request.body#/callback_url}": {
                "post": {
                    "summary": "Conversion completion notification",
                    "description": "Called when a conversion operation completes (future feature)",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "conversion_id": {"type": "string"},
                                        "status": {
                                            "type": "string",
                                            "enum": ["completed", "failed"],
                                        },
                                        "result": {
                                            "$ref": "#/components/schemas/ConversionResult"
                                        },
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Callback acknowledged"}},
                }
            }
        }
    }

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
