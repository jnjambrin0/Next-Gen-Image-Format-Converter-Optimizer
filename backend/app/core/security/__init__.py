"""Security module for image converter application."""

from typing import Any

from app.core.security.engine import SecurityEngine
from app.core.security.errors import SecurityError
from app.core.security.sandbox import (
    SandboxConfig,
    SecuritySandbox,
)


# Backward compatibility - create_sandbox function
def create_sandbox(*args, **kwargs) -> None:
    """Create a security sandbox (backward compatibility)."""
    return SecuritySandbox(*args, **kwargs)


__all__ = [
    "SecuritySandbox",
    "SandboxConfig",
    "SecurityError",
    "SecurityEngine",
    "create_sandbox",
]
