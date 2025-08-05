from fastapi import APIRouter
from .health import router as health_router
from .conversion import router as conversion_router
from .monitoring import router as monitoring_router
from .security import router as security_router
from .intelligence import router as intelligence_router
from .optimization import router as optimization_router
from .batch import router as batch_router
from .presets import router as presets_router
from .detection import router as detection_router

# Legacy API router (backward compatibility)
api_router = APIRouter(prefix="/api")

# Include all routers for legacy endpoints
api_router.include_router(health_router, tags=["health"])
api_router.include_router(conversion_router, tags=["conversion"])
api_router.include_router(monitoring_router, tags=["monitoring"])
api_router.include_router(security_router, tags=["security"])
api_router.include_router(intelligence_router, tags=["intelligence"])
api_router.include_router(optimization_router, tags=["optimization"])
api_router.include_router(batch_router, tags=["batch"])
api_router.include_router(presets_router, tags=["presets"])
api_router.include_router(detection_router, tags=["detection"])

# V1 API router (current stable version)
api_v1_router = APIRouter(prefix="/api/v1")

# Include all routers for v1 endpoints with enhanced tags
api_v1_router.include_router(health_router, tags=["v1-health"])
api_v1_router.include_router(conversion_router, tags=["v1-conversion"])
api_v1_router.include_router(monitoring_router, tags=["v1-monitoring"])
api_v1_router.include_router(security_router, tags=["v1-security"])
api_v1_router.include_router(intelligence_router, tags=["v1-intelligence"])
api_v1_router.include_router(optimization_router, tags=["v1-optimization"])
api_v1_router.include_router(batch_router, tags=["v1-batch"])
api_v1_router.include_router(presets_router, tags=["v1-presets"])
api_v1_router.include_router(detection_router, tags=["v1-detection"])

__all__ = ["api_router", "api_v1_router"]
