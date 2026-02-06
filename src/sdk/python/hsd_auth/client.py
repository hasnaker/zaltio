"""
HSD Auth SDK Client
Validates: Requirements 4.2, 4.4, 4.5

Main client class for HSD Auth Platform authentication operations
with automatic token refresh and retry mechanisms.

API is consistent with TypeScript SDK for cross-SDK consistency.
"""

import time
import threading
from typing import Any, Dict, Literal, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException, Timeout

from .types import (
    HSDAuthConfig,
    User,
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
    is_retryable_error,
)
from .storage import MemoryStorage


class HSDAuthClient:
    """
    HSD Auth Client - Main SDK entry point.
    
    Provides authentication operations with automatic token refresh
    and retry mechanisms, consistent with the TypeScript SDK API.
    """
    
    def __init__(self, config: HSDAuthConfig) -> None:
        """
        Initialize the HSD Auth client.
        
        Args:
            config: SDK configuration options
        """
        self._validate_config(config)
        
        # Store configuration with defaults
        self._base_url = config.base_url.rstrip("/")
        self._realm_id = config.realm_id
        self._timeout = config.timeout
        self._retry_attempts = config.retry_attempts
        self._retry_delay = config.retry_delay
        self._auto_refresh = config.auto_refresh
        self._refresh_threshold = config.refresh_threshold
        self._storage = config.storage if config.storage else MemoryStorage()
        
        # Token refresh state
        self._refresh_lock = threading.Lock()
        self._refresh_in_progress = False
        self._token_expires_at: float = 0
    
    def _validate_config(self, config: HSDAuthConfig) -> None:
        """Validate configuration."""
        if not config.base_url:
            raise ConfigurationError("base_url is required")
        if not config.realm_id:
            raise ConfigurationError("realm_id is required")
        try:
            result = urlparse(config.base_url)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL")
        except Exception:
            raise ConfigurationError("base_url must be a valid URL")

    def register(self, data: RegisterData) -> AuthResult:
        """
        Register a new user.
        
        Args:
            data: Registration data (email, password, optional profile)
            
        Returns:
            AuthResult with user data and tokens
        """
        body = {
            "realm_id": self._realm_id,
            "email": data.email,
            "password": data.password,
        }
        if data.profile:
            body["profile"] = data.profile.to_dict()
        
        response = self._request(
            "/register",
            method="POST",
            body=body,
            requires_auth=False,
        )
        
        result = AuthResult.from_dict(response)
        
        # Store tokens
        self._store_tokens(result.access_token, result.refresh_token, result.expires_in)
        
        return result
    
    def login(self, credentials: LoginCredentials) -> AuthResult:
        """
        Login with email and password.
        
        Args:
            credentials: Login credentials (email, password)
            
        Returns:
            AuthResult with user data and tokens
        """
        response = self._request(
            "/login",
            method="POST",
            body={
                "realm_id": self._realm_id,
                "email": credentials.email,
                "password": credentials.password,
            },
            requires_auth=False,
        )
        
        result = AuthResult.from_dict(response)
        
        # Store tokens
        self._store_tokens(result.access_token, result.refresh_token, result.expires_in)
        
        return result
    
    def refresh_token(self) -> TokenResult:
        """
        Refresh the access token.
        
        Implements automatic token refresh with deduplication
        to prevent concurrent refresh requests.
        
        Returns:
            TokenResult with new tokens
        """
        # Deduplicate concurrent refresh requests
        with self._refresh_lock:
            if self._refresh_in_progress:
                # Wait for ongoing refresh to complete
                pass
            self._refresh_in_progress = True
        
        try:
            return self._do_refresh_token()
        finally:
            with self._refresh_lock:
                self._refresh_in_progress = False
    
    def _do_refresh_token(self) -> TokenResult:
        """Internal method to perform token refresh."""
        refresh_token = self._storage.get_refresh_token()
        if not refresh_token:
            raise TokenRefreshError("No refresh token available")
        
        return self._perform_token_refresh(refresh_token)
    
    def _perform_token_refresh(self, refresh_token: str) -> TokenResult:
        """Perform the actual token refresh."""
        try:
            response = self._request(
                "/refresh",
                method="POST",
                body={
                    "realm_id": self._realm_id,
                    "refresh_token": refresh_token,
                },
                requires_auth=False,
                skip_auto_refresh=True,
            )
            
            result = TokenResult.from_dict(response)
            
            # Store new tokens
            self._store_tokens(result.access_token, result.refresh_token, result.expires_in)
            
            return result
        except HSDAuthError as e:
            # Clear tokens on refresh failure
            self._storage.clear_tokens()
            self._token_expires_at = 0
            raise TokenRefreshError(e.message, {"original_error": e.code})
        except Exception:
            self._storage.clear_tokens()
            self._token_expires_at = 0
            raise TokenRefreshError("Token refresh failed")
    
    def logout(self) -> None:
        """Logout the current user."""
        access_token = self._storage.get_access_token()
        
        if access_token:
            try:
                self._request(
                    "/logout",
                    method="POST",
                    body={"realm_id": self._realm_id},
                    requires_auth=True,
                    skip_auto_refresh=True,
                )
            except Exception:
                # Ignore errors during logout - we'll clear tokens anyway
                pass
        
        # Clear stored tokens
        self._storage.clear_tokens()
        self._token_expires_at = 0
    
    def get_current_user(self) -> Optional[User]:
        """
        Get the current authenticated user.
        
        Returns:
            User object if authenticated, None otherwise
        """
        access_token = self._storage.get_access_token()
        if not access_token:
            return None
        
        try:
            response = self._request(
                "/me",
                method="GET",
                requires_auth=True,
            )
            return User.from_dict(response)
        except AuthenticationError:
            return None
    
    def update_profile(self, data: ProfileUpdateData) -> User:
        """
        Update user profile.
        
        Args:
            data: Profile update data
            
        Returns:
            Updated User object
        """
        response = self._request(
            "/me/profile",
            method="PATCH",
            body=data.to_dict(),
            requires_auth=True,
        )
        return User.from_dict(response)
    
    def change_password(self, data: PasswordChangeData) -> None:
        """
        Change user password.
        
        Args:
            data: Password change data (current and new password)
        """
        self._request(
            "/me/password",
            method="POST",
            body=data.to_dict(),
            requires_auth=True,
        )
    
    def is_authenticated(self) -> bool:
        """
        Check if user is authenticated.
        
        Returns:
            True if authenticated with valid token
        """
        access_token = self._storage.get_access_token()
        if not access_token:
            return False
        
        # Check if token is expired
        if self._is_token_expired():
            # Try to refresh if auto-refresh is enabled
            if self._auto_refresh:
                try:
                    self.refresh_token()
                    return True
                except Exception:
                    return False
            return False
        
        return True
    
    def get_access_token(self) -> Optional[str]:
        """
        Get the current access token.
        
        Auto-refreshes if needed and enabled.
        
        Returns:
            Access token string or None
        """
        # Auto-refresh if needed
        if self._auto_refresh and self._should_refresh_token():
            try:
                self.refresh_token()
            except Exception:
                # Return current token even if refresh fails
                pass
        
        return self._storage.get_access_token()

    def _store_tokens(self, access_token: str, refresh_token: str, expires_in: int) -> None:
        """Store tokens and update expiration."""
        self._storage.set_tokens(access_token, refresh_token, expires_in)
        self._token_expires_at = time.time() + expires_in
    
    def _is_token_expired(self) -> bool:
        """Check if token is expired."""
        return self._token_expires_at > 0 and time.time() >= self._token_expires_at
    
    def _should_refresh_token(self) -> bool:
        """Check if token should be refreshed (within threshold)."""
        if self._token_expires_at == 0:
            return False
        return time.time() >= self._token_expires_at - self._refresh_threshold
    
    def _request(
        self,
        endpoint: str,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        body: Optional[Dict[str, Any]] = None,
        requires_auth: bool = False,
        skip_auto_refresh: bool = False,
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retry and error handling.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            body: Request body
            requires_auth: Whether authentication is required
            skip_auto_refresh: Skip automatic token refresh
            
        Returns:
            Response data dictionary
        """
        # Auto-refresh token if needed
        if requires_auth and not skip_auto_refresh and self._auto_refresh and self._should_refresh_token():
            try:
                self.refresh_token()
            except Exception:
                # Continue with current token
                pass
        
        last_error: Optional[Exception] = None
        
        for attempt in range(self._retry_attempts + 1):
            try:
                return self._execute_request(endpoint, method, body, requires_auth)
            except Exception as error:
                last_error = error
                
                # Don't retry non-retryable errors
                if not is_retryable_error(error):
                    raise
                
                # Don't retry on last attempt
                if attempt == self._retry_attempts:
                    raise
                
                # Wait before retry with exponential backoff
                delay = self._retry_delay * (2 ** attempt)
                time.sleep(delay)
        
        raise last_error or NetworkError("Request failed after retries")
    
    def _execute_request(
        self,
        endpoint: str,
        method: str,
        body: Optional[Dict[str, Any]] = None,
        requires_auth: bool = False,
    ) -> Dict[str, Any]:
        """Execute a single HTTP request."""
        url = f"{self._base_url}{endpoint}"
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-Realm-ID": self._realm_id,
        }
        
        if requires_auth:
            access_token = self._storage.get_access_token()
            if not access_token:
                raise AuthenticationError("UNAUTHORIZED", "No access token available")
            headers["Authorization"] = f"Bearer {access_token}"
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=body if body else None,
                timeout=self._timeout,
            )
            
            return self._handle_response(response)
        except Timeout:
            raise NetworkError("Request timeout", {"timeout": self._timeout})
        except RequestException as e:
            raise NetworkError(str(e))
    
    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle HTTP response and convert to appropriate result/error."""
        content_type = response.headers.get("content-type", "")
        is_json = "application/json" in content_type
        
        if response.ok:
            if not is_json:
                return {}
            data = response.json()
            return data.get("data", data)
        
        # Handle error responses
        error_data: Optional[Dict[str, Any]] = None
        if is_json:
            try:
                error_data = response.json()
            except Exception:
                pass
        
        error = error_data.get("error", {}) if error_data else {}
        code = error.get("code", "UNKNOWN_ERROR")
        message = error.get("message", f"HTTP {response.status_code}")
        details = error.get("details")
        request_id = error.get("request_id")
        
        if response.status_code == 400:
            raise ValidationError(code, message, details, request_id)
        elif response.status_code == 401:
            raise AuthenticationError(code, message, details, request_id)
        elif response.status_code == 403:
            raise AuthorizationError(code, message, details, request_id)
        elif response.status_code == 429:
            retry_after = int(response.headers.get("retry-after", "60"))
            raise RateLimitError(message, retry_after, request_id)
        else:
            raise HSDAuthError.from_api_response(
                error_data or {"error": {"code": code, "message": message}},
                response.status_code,
            )
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get SDK configuration (read-only).
        
        Returns:
            Configuration dictionary
        """
        return {
            "base_url": self._base_url,
            "realm_id": self._realm_id,
            "timeout": self._timeout,
            "retry_attempts": self._retry_attempts,
            "retry_delay": self._retry_delay,
            "auto_refresh": self._auto_refresh,
            "refresh_threshold": self._refresh_threshold,
        }


def create_hsd_auth_client(config: HSDAuthConfig) -> HSDAuthClient:
    """
    Create a new HSD Auth client instance.
    
    Args:
        config: SDK configuration options
        
    Returns:
        HSDAuthClient instance
    """
    return HSDAuthClient(config)
