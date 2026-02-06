"""
Zalt Auth SDK Type Definitions

Type definitions consistent with TypeScript SDK for cross-SDK API consistency.
Supports both sync and async clients.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Protocol, runtime_checkable
import re


# API Key format validation
PUBLISHABLE_KEY_REGEX = re.compile(r'^pk_(live|test)_[A-Za-z0-9]{32}$')


def is_valid_publishable_key(key: str) -> bool:
    """Validate publishable key format."""
    return bool(PUBLISHABLE_KEY_REGEX.match(key))


def is_test_key(key: str) -> bool:
    """Check if key is for test environment."""
    return key.startswith('pk_test_')


@runtime_checkable
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
class ZaltConfig:
    """SDK Configuration options - consistent with TypeScript SDK."""
    
    # Publishable API key (pk_live_xxx or pk_test_xxx)
    publishable_key: str
    # Optional realm ID for multi-tenant isolation
    realm_id: Optional[str] = None
    # API base URL (default: https://api.zalt.io)
    base_url: str = "https://api.zalt.io"
    # Request timeout in seconds (default: 30)
    timeout: float = 30.0
    # Number of retry attempts for failed requests (default: 3)
    retry_attempts: int = 3
    # Delay between retries in seconds (default: 1.0)
    retry_delay: float = 1.0
    # Enable automatic token refresh (default: True)
    auto_refresh: bool = True
    # Token refresh threshold in seconds before expiry (default: 60)
    refresh_threshold: int = 60
    # Custom storage for tokens (default: None, uses MemoryStorage)
    storage: Optional[TokenStorage] = None
    # Enable debug logging (default: False)
    debug: bool = False
    # Custom headers to include in requests
    headers: Optional[Dict[str, str]] = None


@dataclass
class UserProfile:
    """User profile information."""
    
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar_url: Optional[str] = None
    phone_number: Optional[str] = None
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
        if self.phone_number is not None:
            result["phone_number"] = self.phone_number
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
            phone_number=data.get("phone_number"),
            metadata=data.get("metadata", {}),
        )


UserStatus = Literal["active", "suspended", "pending_verification"]


@dataclass
class MFAStatus:
    """MFA status for a user."""
    enabled: bool
    methods: List[str]
    backup_codes_remaining: int = 0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MFAStatus":
        return cls(
            enabled=data.get("enabled", False),
            methods=data.get("methods", []),
            backup_codes_remaining=data.get("backup_codes_remaining", 0),
        )


@dataclass
class TenantMembership:
    """User's membership in a tenant."""
    tenant_id: str
    tenant_name: str
    role: str
    permissions: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TenantMembership":
        return cls(
            tenant_id=data["tenant_id"],
            tenant_name=data.get("tenant_name", ""),
            role=data.get("role", "member"),
            permissions=data.get("permissions", []),
        )


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
    last_login: Optional[str]
    status: UserStatus
    mfa_enabled: bool = False
    tenants: List[TenantMembership] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Create from dictionary."""
        profile_data = data.get("profile", {})
        tenants_data = data.get("tenants", [])
        return cls(
            id=data["id"],
            realm_id=data.get("realm_id", ""),
            email=data["email"],
            email_verified=data.get("email_verified", False),
            profile=UserProfile.from_dict(profile_data) if profile_data else UserProfile(),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            last_login=data.get("last_login"),
            status=data.get("status", "active"),
            mfa_enabled=data.get("mfa_enabled", False),
            tenants=[TenantMembership.from_dict(t) for t in tenants_data],
        )


@dataclass
class TokenResult:
    """Token result from auth operations."""
    
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenResult":
        """Create from dictionary."""
        # Handle nested tokens structure
        tokens = data.get("tokens", data)
        return cls(
            access_token=tokens.get("access_token", ""),
            refresh_token=tokens.get("refresh_token", ""),
            expires_in=tokens.get("expires_in", 900),
            token_type=tokens.get("token_type", "Bearer"),
        )


@dataclass
class AuthResult:
    """Authentication result containing tokens and user data."""
    
    user: User
    tokens: TokenResult
    mfa_required: bool = False
    mfa_session_id: Optional[str] = None
    mfa_methods: List[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthResult":
        """Create from dictionary."""
        user_data = data.get("user", {})
        tokens_data = data.get("tokens", data)
        return cls(
            user=User.from_dict(user_data) if user_data else User(
                id="", realm_id="", email="", email_verified=False,
                profile=UserProfile(), created_at="", updated_at="",
                last_login=None, status="active"
            ),
            tokens=TokenResult.from_dict(tokens_data),
            mfa_required=data.get("mfa_required", False),
            mfa_session_id=data.get("mfa_session_id"),
            mfa_methods=data.get("mfa_methods", []),
        )


@dataclass
class MFAResult:
    """MFA verification result."""
    success: bool
    user: Optional[User] = None
    tokens: Optional[TokenResult] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MFAResult":
        user_data = data.get("user")
        tokens_data = data.get("tokens")
        return cls(
            success=data.get("success", False),
            user=User.from_dict(user_data) if user_data else None,
            tokens=TokenResult.from_dict(tokens_data) if tokens_data else None,
        )


@dataclass
class MFASetupResult:
    """MFA setup result with secret and backup codes."""
    secret: str
    qr_code: str
    backup_codes: List[str]
    recovery_key: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MFASetupResult":
        return cls(
            secret=data.get("secret", ""),
            qr_code=data.get("qr_code", data.get("qrCode", "")),
            backup_codes=data.get("backup_codes", data.get("backupCodes", [])),
            recovery_key=data.get("recovery_key", data.get("recoveryKey")),
        )


@dataclass
class MFAVerifyResult:
    """MFA verification result."""
    success: bool
    user: Optional[User] = None
    tokens: Optional[TokenResult] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MFAVerifyResult":
        user_data = data.get("user")
        tokens_data = data.get("tokens")
        return cls(
            success=data.get("success", True),
            user=User.from_dict(user_data) if user_data else None,
            tokens=TokenResult.from_dict(tokens_data) if tokens_data else None,
        )


@dataclass
class RegisterData:
    """User registration data."""
    
    email: str
    password: str
    profile: Optional[UserProfile] = None
    device_fingerprint: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        result: Dict[str, Any] = {
            "email": self.email,
            "password": self.password,
        }
        if self.profile:
            result["profile"] = self.profile.to_dict()
        if self.device_fingerprint:
            result["device_fingerprint"] = self.device_fingerprint
        return result


@dataclass
class LoginCredentials:
    """User login credentials."""
    
    email: str
    password: str
    device_fingerprint: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        result: Dict[str, Any] = {
            "email": self.email,
            "password": self.password,
        }
        if self.device_fingerprint:
            result["device_fingerprint"] = self.device_fingerprint
        return result


@dataclass
class ProfileUpdateData:
    """Profile update data."""
    
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar_url: Optional[str] = None
    phone_number: Optional[str] = None
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
        if self.phone_number is not None:
            result["phone_number"] = self.phone_number
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


@dataclass
class PasswordResetRequest:
    """Password reset request data."""
    email: str


@dataclass
class PasswordResetConfirm:
    """Password reset confirmation data."""
    token: str
    new_password: str
