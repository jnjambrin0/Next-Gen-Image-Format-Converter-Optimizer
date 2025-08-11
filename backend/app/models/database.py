"""Database models for the Image Converter application."""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class UserPreset(Base):
    """Model for storing user-defined and built-in conversion presets."""

    __tablename__ = "user_presets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    settings = Column(Text, nullable=False)  # JSON stored as text
    is_builtin = Column(Boolean, default=False, nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("name", name="uq_preset_name"),
        Index("idx_presets_builtin", "is_builtin"),
    )

    def __repr__(self):
        return f"<UserPreset(id={self.id}, name={self.name}, is_builtin={self.is_builtin})>"


class ApiKey(Base):
    """Model for storing API keys for authentication."""

    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key_hash = Column(String(256), nullable=False, unique=True)  # SHA-256 hash
    name = Column(String(100), nullable=True)  # Optional key name
    permissions = Column(Text, nullable=True)  # JSON permissions (future use)
    rate_limit_override = Column(Integer, nullable=True)  # Custom rate limit per minute
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Optional expiration

    __table_args__ = (
        Index("idx_api_keys_hash", "key_hash"),
        Index("idx_api_keys_active", "is_active"),
        Index("idx_api_keys_expires", "expires_at"),
    )

    def __repr__(self):
        return f"<ApiKey(id={self.id}, name={self.name}, is_active={self.is_active})>"


class ApiUsageStats(Base):
    """Model for storing API usage statistics."""

    __tablename__ = "api_usage_stats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    api_key_id = Column(
        String(36), ForeignKey("api_keys.id"), nullable=True
    )  # Nullable for unauthenticated requests
    endpoint = Column(String(200), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer, nullable=False)
    response_time_ms = Column(Integer, nullable=False)
    timestamp = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_usage_api_key", "api_key_id"),
        Index("idx_usage_endpoint", "endpoint"),
        Index("idx_usage_timestamp", "timestamp"),
        Index("idx_usage_status", "status_code"),
    )

    def __repr__(self):
        return f"<ApiUsageStats(id={self.id}, endpoint={self.endpoint}, method={self.method}, status={self.status_code})>"
