from fastapi import APIRouter
from .health import router as health_router

api_router = APIRouter(prefix="/api")

# Include all routers
api_router.include_router(health_router, tags=["health"])

__all__ = ["api_router"]
