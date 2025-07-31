from fastapi import APIRouter
from typing import Dict

router = APIRouter()


@router.get("/health", response_model=Dict[str, str])
async def health_check() -> Dict[str, str]:
    """
    Health check endpoint to verify API is running.

    Returns:
        Dict with status information
    """
    return {"status": "healthy"}
