"""
HSD Auth SDK Error Classes
Validates: Requirements 4.5 (proper error handling)

Error classes consistent with TypeScript SDK for cross-SDK API consistency.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional


class HSDAuthError(Exception):
    """Base error class for HSD Auth SDK."""
    
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
    ) -> "HSDAuthError":
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


class NetworkError(HSDAuthError):
    """Network error (connection issues, timeouts)."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__("NETWORK_ERROR", message, 0, details)


class AuthenticationError(HSDAuthError):
    """Authentication error (invalid credentials, expired tokens)."""
    
    def __init__(
        self,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(code, message, 401, details, request_id)


class AuthorizationError(HSDAuthError):
    """Authorization error (insufficient permissions)."""
    
    def __init__(
        self,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(code, message, 403, details, request_id)


class ValidationError(HSDAuthError):
    """Validation error (invalid input)."""
    
    def __init__(
        self,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(code, message, 400, details, request_id)


class RateLimitError(HSDAuthError):
    """Rate limit error."""
    
    def __init__(
        self,
        message: str,
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


class TokenRefreshError(HSDAuthError):
    """Token refresh error."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__("TOKEN_REFRESH_FAILED", message, 401, details)


class ConfigurationError(HSDAuthError):
    """Configuration error."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__("CONFIGURATION_ERROR", message, 0, details)


def is_hsd_auth_error(error: Any) -> bool:
    """Check if error is an HSDAuthError."""
    return isinstance(error, HSDAuthError)


def is_retryable_error(error: Any) -> bool:
    """Check if error is retryable."""
    if isinstance(error, NetworkError):
        return True
    if isinstance(error, HSDAuthError):
        # Retry on server errors (5xx) except for specific cases
        return 500 <= error.status_code < 600
    return False
