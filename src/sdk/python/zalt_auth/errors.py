"""
Zalt Auth SDK Error Classes

Error classes consistent with TypeScript SDK for cross-SDK API consistency.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class ZaltError(Exception):
    """Base error class for Zalt Auth SDK."""
    
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.request_id = request_id
        self.timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    @classmethod
    def from_api_response(
        cls, response: Dict[str, Any], status_code: int
    ) -> "ZaltError":
        """Create error from API response."""
        error = response.get("error", {})
        return cls(
            code=error.get("code", "UNKNOWN_ERROR"),
            message=error.get("message", f"HTTP {status_code}"),
            status_code=status_code,
            details=error.get("details"),
            request_id=error.get("request_id"),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/serialization."""
        return {
            "name": self.__class__.__name__,
            "code": self.code,
            "message": self.message,
            "status_code": self.status_code,
            "details": self.details,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
        }
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code={self.code!r}, message={self.message!r})"


class NetworkError(ZaltError):
    """Network error (connection issues, timeouts)."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None, retryable: bool = True):
        super().__init__("NETWORK_ERROR", message, 0, details)
        self.retryable = retryable


class AuthenticationError(ZaltError):
    """Authentication error (invalid credentials, expired tokens)."""
    
    def __init__(
        self,
        message: str,
        code: str = "AUTHENTICATION_FAILED",
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(code, message, 401, details, request_id)


class AuthorizationError(ZaltError):
    """Authorization error (insufficient permissions)."""
    
    def __init__(
        self,
        message: str,
        code: str = "FORBIDDEN",
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(code, message, 403, details, request_id)


class ValidationError(ZaltError):
    """Validation error (invalid input)."""
    
    def __init__(
        self,
        message: str,
        code: str = "VALIDATION_ERROR",
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(code, message, 400, details, request_id)


class RateLimitError(ZaltError):
    """Rate limit error."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(
            "RATE_LIMITED",
            message,
            429,
            {"retry_after": retry_after} if retry_after else None,
            request_id,
        )
        self.retry_after = retry_after


class TokenRefreshError(ZaltError):
    """Token refresh error."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__("TOKEN_REFRESH_FAILED", message, 401, details)


class ConfigurationError(ZaltError):
    """Configuration error."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__("CONFIGURATION_ERROR", message, 0, details)


class MFARequiredError(ZaltError):
    """MFA verification required error."""
    
    def __init__(
        self,
        mfa_session_id: str,
        mfa_methods: Optional[List[str]] = None,
        message: str = "MFA verification required",
    ):
        super().__init__(
            "MFA_REQUIRED",
            message,
            403,
            {
                "mfa_session_id": mfa_session_id,
                "mfa_methods": mfa_methods or [],
            },
        )
        self.mfa_session_id = mfa_session_id
        self.mfa_methods = mfa_methods or []


def is_zalt_error(error: Any) -> bool:
    """Check if error is a ZaltError."""
    return isinstance(error, ZaltError)


def is_retryable_error(error: Any) -> bool:
    """Check if error is retryable."""
    if isinstance(error, NetworkError):
        return error.retryable
    if isinstance(error, RateLimitError):
        return True
    if isinstance(error, ZaltError):
        # Retry on server errors (5xx)
        return 500 <= error.status_code < 600
    return False
