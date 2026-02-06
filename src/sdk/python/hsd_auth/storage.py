"""
HSD Auth SDK Token Storage Implementations
Validates: Requirements 4.3 (automatic token refresh)

Storage implementations consistent with TypeScript SDK.
"""

import time
from typing import Optional


class MemoryStorage:
    """
    In-memory token storage (default).
    Suitable for server-side applications and testing.
    """
    
    def __init__(self) -> None:
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._expires_at: float = 0
    
    def get_access_token(self) -> Optional[str]:
        """Get the stored access token."""
        return self._access_token
    
    def get_refresh_token(self) -> Optional[str]:
        """Get the stored refresh token."""
        return self._refresh_token
    
    def set_tokens(self, access_token: str, refresh_token: str, expires_in: int) -> None:
        """Store tokens with expiration."""
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_at = time.time() + expires_in
    
    def clear_tokens(self) -> None:
        """Clear all stored tokens."""
        self._access_token = None
        self._refresh_token = None
        self._expires_at = 0
    
    def get_expires_at(self) -> float:
        """Get token expiration timestamp."""
        return self._expires_at
    
    def is_expired(self) -> bool:
        """Check if access token is expired."""
        return time.time() >= self._expires_at
    
    def will_expire_soon(self, threshold_seconds: int) -> bool:
        """Check if token will expire within threshold."""
        return time.time() >= self._expires_at - threshold_seconds
