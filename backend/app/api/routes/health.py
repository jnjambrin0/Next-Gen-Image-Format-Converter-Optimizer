from typing import Any, Dict

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health", response_model=Dict[str, Any])
async def health_check(request: Request) -> Dict[str, Any]:
    """
    Health check endpoint to verify API is running.
    Includes network isolation status.

    Returns:
        Dict with status information including network isolation
    """
    response = {
        "status": "healthy",
        "network_isolated": True,
        "network_status": "unknown",
    }

    # Include network isolation status if available
    if hasattr(request.app.state, "network_status"):
        network_status = request.app.state.network_status
        response["network_isolated"] = network_status.get("isolated", True)
        response["network_status"] = (
            "isolated" if network_status.get("isolated", True) else "not_isolated"
        )
        response["network_verification"] = {
            "verified": network_status.get("verified", False),
            "strictness": network_status.get("strictness", "unknown"),
            "checks_passed": len(network_status.get("checks_passed", [])),
            "checks_failed": len(network_status.get("checks_failed", [])),
            "warning_count": len(network_status.get("warnings", [])),
        }

    return response
