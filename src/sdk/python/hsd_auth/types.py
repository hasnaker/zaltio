"""
HSD Auth SDK Type Definitions
Validates: Requirements 4.2 (Python SDK for backend service integration)

Type definitions consistent with TypeScript SDK for cross-SDK API consistency.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Literal, Optional, Protocol


@dataclass
class HSDAuthConfig:
    """SDK Configuration options - consistent with TypeScript SDK."""
    
    # API base URL (e.g., https://api.auth.hsdcore.com)
    base_url: str
    # Realm ID for multi-tenant isolation
    realm_id: str
    # Request timeout in seconds (default: 10)
    timeout: float = 10.0
    # Number of retry attempts for failed requests (default: 3)
    retry_attempts: int = 3
    # Delay between retries in seconds (default: 1.0)
    retry_delay: float = 1.0
    # Enable automatic token refresh (default: True)
    auto_refresh: bool = True
    # Token refresh threshold in seconds before expiry (default: 300)
    refresh_threshold: int = 300
    # Custom storage for tokens (default: None, uses MemoryStorage)
    storage: Optional["TokenStorage"] = None


class TokenStorage(Protocol):
    """Token storage interface for custom implementations."""
    
    def get_access_token(self) -> Optional[str]:
        """Get the stored access token."""
        ...
    
    def get_refresh_token(self) -> Optional[str]:
        """Get the stored refresh token."""
        ...
    
    def set_tokens(self, access_token: str, refresh_token: str, expires_in: int) -> None:
        """Store tokens with expiration."""
        ...
    
    def clear_tokens(self) -> None:
        """Clear all stored tokens."""
        ...


@dataclass
class UserProfile:
    """User profile information."""
    
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar_url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        result: Dict[str, Any] = {}
        if self.first_name is not None:
            result["first_name"] = self.first_name
        if self.last_name is not None:
            result["last_name"] = self.last_name
        if self.avatar_url is not None:
            result["avatar_url"] = self.avatar_url
        if self.metadata:
            result["metadata"] = self.metadata
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserProfile":
        """Create from dictionary."""
        return cls(
            first_name=data.get("first_name"),
            last_name=data.get("last_name"),
            avatar_url=data.get("avatar_url"),
            metadata=data.get("metadata", {}),
        )


UserStatus = Literal["active", "suspended", "pending_verification"]


@dataclass
class User:
    """User data returned from API."""
    
    id: str
    realm_id: str
    email: str
    email_verified: bool
    profile: UserProfile
    created_at: str
    updated_at: str
    last_login: str
    status: UserStatus
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Create from dictionary."""
        profile_data = data.get("profile", {})
        return cls(
            id=data["id"],
            realm_id=data["realm_id"],
            email=data["email"],
            email_verified=data.get("email_verified", False),
            profile=UserProfile.from_dict(profile_data) if profile_data else UserProfile(),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            last_login=data.get("last_login", ""),
            status=data.get("status", "active"),
        )


@dataclass
class AuthResult:
    """Authentication result containing tokens and user data."""
    
    user: User
    access_token: str
    refresh_token: str
    expires_in: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthResult":
        """Create from dictionary."""
        return cls(
            user=User.from_dict(data["user"]),
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_in=data["expires_in"],
        )


@dataclass
class TokenResult:
    """Token refresh result."""
    
    access_token: str
    refresh_token: str
    expires_in: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenResult":
        """Create from dictionary."""
        return cls(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_in=data["expires_in"],
        )


@dataclass
class RegisterData:
    """User registration data."""
    
    email: str
    password: str
    profile: Optional[UserProfile] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        result: Dict[str, Any] = {
            "email": self.email,
            "password": self.password,
        }
        if self.profile:
            result["profile"] = self.profile.to_dict()
        return result


@dataclass
class LoginCredentials:
    """User login credentials."""
    
    email: str
    password: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        return {
            "email": self.email,
            "password": self.password,
        }


@dataclass
class ProfileUpdateData:
    """Profile update data."""
    
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar_url: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        result: Dict[str, Any] = {}
        if self.first_name is not None:
            result["first_name"] = self.first_name
        if self.last_name is not None:
            result["last_name"] = self.last_name
        if self.avatar_url is not None:
            result["avatar_url"] = self.avatar_url
        if self.metadata is not None:
            result["metadata"] = self.metadata
        return result


@dataclass
class PasswordChangeData:
    """Password change data."""
    
    current_password: str
    new_password: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        return {
            "current_password": self.current_password,
            "new_password": self.new_password,
        }
