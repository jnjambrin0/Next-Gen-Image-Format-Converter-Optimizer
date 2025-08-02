"""Security module for image converter application."""

from app.core.security.sandbox import (
    SecuritySandbox,
    SandboxConfig,
)
from app.core.security.engine import SecurityEngine
from app.core.security.errors import (
    SecurityError,
    SandboxSecurityError,
    NetworkSecurityError,
    SecurityErrorCode,
)

# Backward compatibility - create_sandbox function
def create_sandbox(*args, **kwargs):
    """Create a security sandbox (backward compatibility)."""
    return SecuritySandbox(*args, **kwargs)

__all__ = [
    "SecuritySandbox",
    "SandboxConfig",
    "SecurityError",
    "SandboxSecurityError",
    "NetworkSecurityError",
    "SecurityErrorCode",
    "SecurityEngine",
    "create_sandbox",
]
