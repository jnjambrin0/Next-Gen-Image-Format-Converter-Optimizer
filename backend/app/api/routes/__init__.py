from fastapi import APIRouter
from .health import router as health_router
from .conversion import router as conversion_router
from .monitoring import router as monitoring_router
from .security import router as security_router
from .intelligence import router as intelligence_router
from .optimization import router as optimization_router
from .batch import router as batch_router

api_router = APIRouter(prefix="/api")

# Include all routers
api_router.include_router(health_router, tags=["health"])
api_router.include_router(conversion_router, tags=["conversion"])
api_router.include_router(monitoring_router, tags=["monitoring"])
api_router.include_router(security_router, tags=["security"])
api_router.include_router(intelligence_router, tags=["intelligence"])
api_router.include_router(optimization_router, tags=["optimization"])
api_router.include_router(batch_router, tags=["batch"])

__all__ = ["api_router"]
