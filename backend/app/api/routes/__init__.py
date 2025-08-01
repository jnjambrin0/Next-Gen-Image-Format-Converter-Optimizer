from fastapi import APIRouter
from .health import router as health_router
from .conversion import router as conversion_router
from .monitoring import router as monitoring_router

api_router = APIRouter(prefix="/api")

# Include all routers
api_router.include_router(health_router, tags=["health"])
api_router.include_router(conversion_router, tags=["conversion"])
api_router.include_router(monitoring_router, tags=["monitoring"])

__all__ = ["api_router"]
