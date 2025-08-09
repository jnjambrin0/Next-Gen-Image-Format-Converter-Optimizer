"""API Key service for managing authentication keys."""

import hashlib
import json
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models.database import ApiKey, ApiUsageStats, Base
from app.utils.logging import get_logger

logger = get_logger(__name__)


class ApiKeyService:
    """Service for managing API keys."""

    def __init__(self, db_path: str = "./data/api_keys.db") -> None:
        """Initialize the API key service.

        Args:
            db_path: Path to SQLite database
        """
        self.engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.logger = get_logger(__name__)

    def generate_api_key(self) -> str:
        """Generate a secure API key.

        Returns:
            Generated API key string
        """
        # Use secrets for cryptographically secure random generation
        # 32 bytes = 256 bits of entropy, URL-safe base64 encoded
        return secrets.token_urlsafe(32)

    def hash_api_key(self, api_key: str) -> str:
        """Hash an API key using SHA-256.

        Args:
            api_key: The API key to hash

        Returns:
            SHA-256 hash of the API key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()

    def create_api_key(
        self,
        name: Optional[str] = None,
        permissions: Optional[Dict] = None,
        rate_limit_override: Optional[int] = None,
        expires_days: Optional[int] = None,
    ) -> Tuple[ApiKey, str]:
        """Create a new API key.

        Args:
            name: Optional[Any] name for the API key
            permissions: Optional[Any] permissions dict (for future use)
            rate_limit_override: Optional[Any] custom rate limit per minute
            expires_days: Optional[Any] expiration in days from now

        Returns:
            Tuple of (ApiKey model, raw API key string)
        """
        # Generate the API key
        raw_key = self.generate_api_key()
        key_hash = self.hash_api_key(raw_key)

        # Calculate expiration if specified
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)

        # Create the database record
        api_key = ApiKey(
            key_hash=key_hash,
            name=name,
            permissions=json.dumps(permissions) if permissions else None,
            rate_limit_override=rate_limit_override,
            expires_at=expires_at,
        )

        # Save to database
        with self.SessionLocal() as session:
            session.add(api_key)
            session.commit()
            session.refresh(api_key)

        self.logger.info(
            "API key created",
            key_id=api_key.id,
            name=name,
            has_expiration=expires_at is not None,
            has_custom_rate_limit=rate_limit_override is not None,
        )

        return api_key, raw_key

    def verify_api_key(self, api_key: str) -> Optional[ApiKey]:
        """Verify an API key and return the associated record.

        Args:
            api_key: The raw API key to verify

        Returns:
            ApiKey record if valid, None if invalid/expired/inactive
        """
        if not api_key:
            return None

        key_hash = self.hash_api_key(api_key)

        with self.SessionLocal() as session:
            # Find the API key
            result = session.execute(
                select(ApiKey).where(
                    ApiKey.key_hash == key_hash, ApiKey.is_active == True
                )
            )
            api_key_record = result.scalar_one_or_none()

            if not api_key_record:
                return None

            # Check expiration
            if (
                api_key_record.expires_at
                and datetime.utcnow() > api_key_record.expires_at
            ):
                self.logger.warning(
                    "Expired API key used",
                    key_id=api_key_record.id,
                    expired_at=api_key_record.expires_at,
                )
                return None

            # Update last used timestamp
            session.execute(
                update(ApiKey)
                .where(ApiKey.id == api_key_record.id)
                .values(last_used_at=datetime.utcnow())
            )
            session.commit()

            return api_key_record

    def list_api_keys(self, include_inactive: bool = False) -> List[ApiKey]:
        """List all API keys.

        Args:
            include_inactive: Whether to include inactive keys

        Returns: List[Any] of ApiKey records
        """
        with self.SessionLocal() as session:
            query = select(ApiKey)
            if not include_inactive:
                query = query.where(ApiKey.is_active == True)

            query = query.order_by(ApiKey.created_at.desc())
            result = session.execute(query)
            return result.scalars().all()

    def get_api_key_by_id(self, key_id: str) -> Optional[ApiKey]:
        """Get an API key by ID.

        Args:
            key_id: The API key ID

        Returns:
            ApiKey record if found, None otherwise
        """
        with self.SessionLocal() as session:
            result = session.execute(select(ApiKey).where(ApiKey.id == key_id))
            return result.scalar_one_or_none()

    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke (deactivate) an API key.

        Args:
            key_id: The API key ID to revoke

        Returns:
            True if key was revoked, False if not found
        """
        with self.SessionLocal() as session:
            result = session.execute(
                update(ApiKey).where(ApiKey.id == key_id).values(is_active=False)
            )
            session.commit()

            if result.rowcount > 0:
                self.logger.info("API key revoked", key_id=key_id)
                return True

            return False

    def update_api_key(
        self,
        key_id: str,
        name: Optional[str] = None,
        rate_limit_override: Optional[int] = None,
        expires_days: Optional[int] = None,
    ) -> Optional[ApiKey]:
        """Update an API key's metadata.

        Args:
            key_id: The API key ID
            name: New name (None to keep current)
            rate_limit_override: New rate limit (None to keep current)
            expires_days: New expiration days from now (None to keep current)

        Returns:
            Updated ApiKey record if found, None otherwise
        """
        with self.SessionLocal() as session:
            # Get current record
            result = session.execute(select(ApiKey).where(ApiKey.id == key_id))
            api_key = result.scalar_one_or_none()

            if not api_key:
                return None

            # Build update values
            update_values = {}
            if name is not None:
                update_values["name"] = name
            if rate_limit_override is not None:
                update_values["rate_limit_override"] = rate_limit_override
            if expires_days is not None:
                update_values["expires_at"] = datetime.utcnow() + timedelta(
                    days=expires_days
                )

            if update_values:
                session.execute(
                    update(ApiKey).where(ApiKey.id == key_id).values(**update_values)
                )
                session.commit()

                # Refresh the record
                session.refresh(api_key)

                self.logger.info(
                    "API key updated",
                    key_id=key_id,
                    updated_fields=list(update_values.keys()),
                )

            return api_key

    def cleanup_expired_keys(self) -> int:
        """Clean up expired API keys by marking them inactive.

        Returns:
            Number of keys cleaned up
        """
        with self.SessionLocal() as session:
            result = session.execute(
                update(ApiKey)
                .where(ApiKey.expires_at < datetime.utcnow(), ApiKey.is_active == True)
                .values(is_active=False)
            )
            session.commit()

            cleaned_count = result.rowcount
            if cleaned_count > 0:
                self.logger.info("Cleaned up expired API keys", count=cleaned_count)

            return cleaned_count

    def get_rate_limit_for_key(self, api_key: ApiKey) -> int:
        """Get the rate limit for an API key.

        Args:
            api_key: The API key record

        Returns:
            Rate limit per minute
        """
        if api_key.rate_limit_override:
            return api_key.rate_limit_override
        return settings.max_requests_per_minute

    def record_usage(
        self,
        api_key_id: Optional[str],
        endpoint: str,
        method: str,
        status_code: int,
        response_time_ms: int,
    ) -> None:
        """Record API usage statistics.

        Args:
            api_key_id: API key ID (None for unauthenticated requests)
            endpoint: API endpoint path
            method: HTTP method
            status_code: Response status code
            response_time_ms: Response time in milliseconds
        """
        try:
            usage_stat = ApiUsageStats(
                api_key_id=api_key_id,
                endpoint=endpoint,
                method=method,
                status_code=status_code,
                response_time_ms=response_time_ms,
            )

            with self.SessionLocal() as session:
                session.add(usage_stat)
                session.commit()

        except Exception as e:
            # Don't let usage tracking failures break the API
            self.logger.warning(
                "Failed to record API usage",
                error=str(e),
                endpoint=endpoint,
                method=method,
            )

    def get_usage_stats(self, api_key_id: Optional[str] = None, days: int = 7) -> Dict:
        """Get usage statistics.

        Args:
            api_key_id: Specific API key ID (None for all keys)
            days: Number of days to look back

        Returns:
            Dictionary with usage statistics
        """
        since = datetime.utcnow() - timedelta(days=days)

        with self.SessionLocal() as session:
            query = select(ApiUsageStats).where(ApiUsageStats.timestamp >= since)

            if api_key_id:
                query = query.where(ApiUsageStats.api_key_id == api_key_id)

            result = session.execute(query)
            stats = result.scalars().all()

            # Aggregate statistics
            total_requests = len(stats)
            unique_endpoints = len(set(stat.endpoint for stat in stats))
            avg_response_time = sum(stat.response_time_ms for stat in stats) / max(
                total_requests, 1
            )

            status_codes = {}
            endpoints = {}
            for stat in stats:
                status_codes[stat.status_code] = (
                    status_codes.get(stat.status_code, 0) + 1
                )
                endpoints[stat.endpoint] = endpoints.get(stat.endpoint, 0) + 1

            return {
                "total_requests": total_requests,
                "unique_endpoints": unique_endpoints,
                "avg_response_time_ms": round(avg_response_time, 2),
                "status_codes": status_codes,
                "endpoints": endpoints,
                "period_days": days,
            }


# Global service instance
api_key_service = ApiKeyService()
