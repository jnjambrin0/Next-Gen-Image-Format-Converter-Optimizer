"""Database models for the Image Converter application."""

from sqlalchemy import Column, String, Boolean, DateTime, Text, Index, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import uuid

Base = declarative_base()


class UserPreset(Base):
    """Model for storing user-defined and built-in conversion presets."""
    
    __tablename__ = "user_presets"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    settings = Column(Text, nullable=False)  # JSON stored as text
    is_builtin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    __table_args__ = (
        UniqueConstraint('name', name='uq_preset_name'),
        Index('idx_presets_builtin', 'is_builtin'),
    )
    
    def __repr__(self):
        return f"<UserPreset(id={self.id}, name={self.name}, is_builtin={self.is_builtin})>"