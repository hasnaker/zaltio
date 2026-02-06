"""
HSD Auth Python SDK
Validates: Requirements 4.2, 4.4, 4.5

A Python SDK for HSD Auth Platform authentication operations
with automatic token refresh and retry mechanisms.
"""

from .client import HSDAuthClient, create_hsd_auth_client
from .types import (
    HSDAuthConfig,
    TokenStorage,
    User,
    UserProfile,
    AuthResult,
    TokenResult,
    RegisterData,
    LoginCredentials,
    ProfileUpdateData,
    PasswordChangeData,
)
from .errors import (
    HSDAuthError,
    NetworkError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    RateLimitError,
    TokenRefreshError,
    ConfigurationError,
    is_hsd_auth_error,
    is_retryable_error,
)
from .storage import MemoryStorage

__version__ = "0.1.0"
__all__ = [
    # Client
    "HSDAuthClient",
    "create_hsd_auth_client",
    # Types
    "HSDAuthConfig",
    "TokenStorage",
    "User",
    "UserProfile",
    "AuthResult",
    "TokenResult",
    "RegisterData",
    "LoginCredentials",
    "ProfileUpdateData",
    "PasswordChangeData",
    # Errors
    "HSDAuthError",
    "NetworkError",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "RateLimitError",
    "TokenRefreshError",
    "ConfigurationError",
    "is_hsd_auth_error",
    "is_retryable_error",
    # Storage
    "MemoryStorage",
]
