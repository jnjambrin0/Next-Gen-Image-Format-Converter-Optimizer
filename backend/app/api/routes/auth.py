"""API routes for authentication and API key management."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.exceptions import ValidationError
from app.services.api_key_service import api_key_service
from app.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# Request/Response Models
class ApiKeyCreateRequest(BaseModel):
    """Request model for creating an API key."""

    name: Optional[str] = Field(
        None, max_length=100, description="Optional name for the API key"
    )
    rate_limit_override: Optional[int] = Field(
        None, ge=1, le=1000, description="Custom rate limit per minute (1-1000)"
    )
    expires_days: Optional[int] = Field(
        None, ge=1, le=365, description="Expiration in days (1-365)"
    )


class ApiKeyResponse(BaseModel):
    """Response model for API key information."""

    id: str
    name: Optional[str]
    rate_limit_override: Optional[int]
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True


class ApiKeyCreateResponse(BaseModel):
    """Response model for API key creation."""

    api_key: str = Field(..., description="The generated API key (only shown once)")
    key_info: ApiKeyResponse


class ApiKeyUpdateRequest(BaseModel):
    """Request model for updating an API key."""

    name: Optional[str] = Field(
        None, max_length=100, description="New name for the API key"
    )
    rate_limit_override: Optional[int] = Field(
        None, ge=1, le=1000, description="New rate limit per minute"
    )
    expires_days: Optional[int] = Field(
        None, ge=1, le=365, description="New expiration in days from now"
    )


class UsageStatsResponse(BaseModel):
    """Response model for usage statistics."""

    total_requests: int
    unique_endpoints: int
    avg_response_time_ms: float
    status_codes: Dict[int, int]
    endpoints: Dict[str, int]
    period_days: int


@router.post(
    "/api-keys",
    response_model=ApiKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    request: ApiKeyCreateRequest, http_request: Request
) -> ApiKeyCreateResponse:
    """Create a new API key.

    Args:
        request: API key creation request
        http_request: HTTP request for logging

    Returns:
        Created API key information including the raw key
    """
    try:
        # Validate request
        if request.name and len(request.name.strip()) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "AUTH400",
                    "message": "API key name cannot be empty",
                },
            )

        # Create the API key
        api_key_record, raw_key = api_key_service.create_api_key(
            name=request.name,
            rate_limit_override=request.rate_limit_override,
            expires_days=request.expires_days,
        )

        # Log creation (privacy-aware)
        logger.info(
            "API key created via endpoint",
            key_id=api_key_record.id,
            has_name=request.name is not None,
            has_custom_rate_limit=request.rate_limit_override is not None,
            has_expiration=request.expires_days is not None,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )

        return ApiKeyCreateResponse(
            api_key=raw_key, key_info=ApiKeyResponse.from_orm(api_key_record)
        )

    except ValidationError as e:
        logger.warning(
            "API key creation validation failed",
            error=str(e),
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "AUTH400", "message": str(e)},
        )
    except Exception as e:
        logger.error(
            "Failed to create API key",
            error=str(e),
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_code": "AUTH500", "message": "Failed to create API key"},
        )


@router.get("/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    include_inactive: bool = False, http_request: Request = None
) -> List[ApiKeyResponse]:
    """List all API keys.

    Args:
        include_inactive: Whether to include inactive keys
        http_request: HTTP request for logging

    Returns: List[Any] of API key information
    """
    try:
        api_keys = api_key_service.list_api_keys(include_inactive=include_inactive)

        logger.info(
            "API keys listed",
            count=len(api_keys),
            include_inactive=include_inactive,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request and http_request.client
                else "unknown"
            ),
        )

        return [ApiKeyResponse.from_orm(key) for key in api_keys]

    except Exception as e:
        logger.error(
            "Failed to list API keys",
            error=str(e),
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request and http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_code": "AUTH500", "message": "Failed to list API keys"},
        )


@router.get("/api-keys/{key_id}", response_model=ApiKeyResponse)
async def get_api_key(key_id: str, http_request: Request) -> ApiKeyResponse:
    """Get a specific API key by ID.

    Args:
        key_id: The API key ID
        http_request: HTTP request for logging

    Returns:
        API key information
    """
    try:
        api_key = api_key_service.get_api_key_by_id(key_id)

        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error_code": "AUTH404", "message": "API key not found"},
            )

        logger.info(
            "API key retrieved",
            key_id=key_id,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )

        return ApiKeyResponse.from_orm(api_key)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get API key",
            error=str(e),
            key_id=key_id,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_code": "AUTH500", "message": "Failed to retrieve API key"},
        )


@router.put("/api-keys/{key_id}", response_model=ApiKeyResponse)
async def update_api_key(
    key_id: str, request: ApiKeyUpdateRequest, http_request: Request
) -> ApiKeyResponse:
    """Update an API key.

    Args:
        key_id: The API key ID
        request: Update request
        http_request: HTTP request for logging

    Returns:
        Updated API key information
    """
    try:
        # Validate request
        if request.name is not None and len(request.name.strip()) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "AUTH400",
                    "message": "API key name cannot be empty",
                },
            )

        # Update the API key
        updated_key = api_key_service.update_api_key(
            key_id=key_id,
            name=request.name,
            rate_limit_override=request.rate_limit_override,
            expires_days=request.expires_days,
        )

        if not updated_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error_code": "AUTH404", "message": "API key not found"},
            )

        logger.info(
            "API key updated",
            key_id=key_id,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )

        return ApiKeyResponse.from_orm(updated_key)

    except HTTPException:
        raise
    except ValidationError as e:
        logger.warning(
            "API key update validation failed",
            error=str(e),
            key_id=key_id,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error_code": "AUTH400", "message": str(e)},
        )
    except Exception as e:
        logger.error(
            "Failed to update API key",
            error=str(e),
            key_id=key_id,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_code": "AUTH500", "message": "Failed to update API key"},
        )


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(key_id: str, http_request: Request) -> None:
    """Revoke (deactivate) an API key.

    Args:
        key_id: The API key ID
        http_request: HTTP request for logging
    """
    try:
        success = api_key_service.revoke_api_key(key_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error_code": "AUTH404", "message": "API key not found"},
            )

        logger.info(
            "API key revoked via endpoint",
            key_id=key_id,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to revoke API key",
            error=str(e),
            key_id=key_id,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_code": "AUTH500", "message": "Failed to revoke API key"},
        )


@router.get("/api-keys/{key_id}/usage", response_model=UsageStatsResponse)
async def get_api_key_usage(
    key_id: str, days: int = 7, http_request: Request = None
) -> UsageStatsResponse:
    """Get usage statistics for a specific API key.

    Args:
        key_id: The API key ID
        days: Number of days to look back (1-30)
        http_request: HTTP request for logging

    Returns:
        Usage statistics
    """
    try:
        # Validate days parameter
        if not 1 <= days <= 30:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "AUTH400",
                    "message": "Days parameter must be between 1 and 30",
                },
            )

        # Verify API key exists
        api_key = api_key_service.get_api_key_by_id(key_id)
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error_code": "AUTH404", "message": "API key not found"},
            )

        # Get usage statistics
        stats = api_key_service.get_usage_stats(api_key_id=key_id, days=days)

        logger.info(
            "API key usage retrieved",
            key_id=key_id,
            days=days,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request and http_request.client
                else "unknown"
            ),
        )

        return UsageStatsResponse(**stats)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get API key usage",
            error=str(e),
            key_id=key_id,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request and http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": "AUTH500",
                "message": "Failed to retrieve usage statistics",
            },
        )


@router.get("/usage", response_model=UsageStatsResponse)
async def get_overall_usage(
    days: int = 7, http_request: Request = None
) -> UsageStatsResponse:
    """Get overall usage statistics for all API keys.

    Args:
        days: Number of days to look back (1-30)
        http_request: HTTP request for logging

    Returns:
        Overall usage statistics
    """
    try:
        # Validate days parameter
        if not 1 <= days <= 30:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "AUTH400",
                    "message": "Days parameter must be between 1 and 30",
                },
            )

        # Get overall usage statistics
        stats = api_key_service.get_usage_stats(days=days)

        logger.info(
            "Overall usage statistics retrieved",
            days=days,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request and http_request.client
                else "unknown"
            ),
        )

        return UsageStatsResponse(**stats)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get overall usage statistics",
            error=str(e),
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request and http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": "AUTH500",
                "message": "Failed to retrieve usage statistics",
            },
        )


@router.post("/cleanup-expired", status_code=status.HTTP_200_OK)
async def cleanup_expired_keys(http_request: Request) -> Dict[str, Any]:
    """Clean up expired API keys.

    Args:
        http_request: HTTP request for logging

    Returns:
        Cleanup results
    """
    try:
        cleaned_count = api_key_service.cleanup_expired_keys()

        logger.info(
            "Expired API keys cleaned up",
            count=cleaned_count,
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )

        return {
            "message": f"Cleaned up {cleaned_count} expired API keys",
            "count": cleaned_count,
        }

    except Exception as e:
        logger.error(
            "Failed to cleanup expired API keys",
            error=str(e),
            client_ip=(
                getattr(http_request.client, "host", "unknown")
                if http_request.client
                else "unknown"
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error_code": "AUTH500",
                "message": "Failed to cleanup expired keys",
            },
        )
