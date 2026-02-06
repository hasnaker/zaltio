"""
Zalt Auth Python SDK
@zalt/auth-python

A Python SDK for Zalt.io Authentication Platform with async support,
automatic token refresh, and framework integrations (FastAPI, Flask).

Security: RS256 JWT, Argon2id passwords, TOTP/WebAuthn MFA
"""

from .client import ZaltClient, ZaltAsyncClient, create_zalt_client, create_async_zalt_client
from .types import (
    ZaltConfig,
    TokenStorage,
    User,
    UserProfile,
    AuthResult,
    TokenResult,
    MFAResult,
    RegisterData,
    LoginCredentials,
    ProfileUpdateData,
    PasswordChangeData,
    MFASetupResult,
    MFAVerifyResult,
    MFAStatus,
)
from .errors import (
    ZaltError,
    NetworkError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    RateLimitError,
    TokenRefreshError,
    ConfigurationError,
    MFARequiredError,
    is_zalt_error,
    is_retryable_error,
)
from .storage import MemoryStorage, FileStorage

__version__ = "1.0.0"
__all__ = [
    # Clients
    "ZaltClient",
    "ZaltAsyncClient",
    "create_zalt_client",
    "create_async_zalt_client",
    # Types
    "ZaltConfig",
    "TokenStorage",
    "User",
    "UserProfile",
    "AuthResult",
    "TokenResult",
    "MFAResult",
    "RegisterData",
    "LoginCredentials",
    "ProfileUpdateData",
    "PasswordChangeData",
    "MFASetupResult",
    "MFAVerifyResult",
    "MFAStatus",
    # Errors
    "ZaltError",
    "NetworkError",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "RateLimitError",
    "TokenRefreshError",
    "ConfigurationError",
    "MFARequiredError",
    "is_zalt_error",
    "is_retryable_error",
    # Storage
    "MemoryStorage",
    "FileStorage",
]
