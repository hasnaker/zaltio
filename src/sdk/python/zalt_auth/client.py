"""
Zalt Auth SDK Client

Main client classes for Zalt.io Authentication Platform.
Provides both synchronous and asynchronous clients with automatic
token refresh and retry mechanisms.

API is consistent with TypeScript SDK for cross-SDK consistency.
"""

import asyncio
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Literal, Optional, TypeVar, Union
from urllib.parse import urljoin

import httpx

from .types import (
    ZaltConfig,
    User,
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
    is_valid_publishable_key,
    is_test_key,
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
    is_retryable_error,
)
from .storage import MemoryStorage


logger = logging.getLogger("zalt_auth")

T = TypeVar("T")

# Retry delays for exponential backoff
RETRY_DELAYS = [1.0, 2.0, 4.0]


class MFANamespace:
    """MFA operations namespace for sync client."""
    
    def __init__(self, client: "ZaltClient") -> None:
        self._client = client
    
    def setup(self, method: str = "totp") -> MFASetupResult:
        """Setup MFA with specified method (totp, webauthn)."""
        response = self._client._request(
            "/v1/auth/mfa/setup",
            method="POST",
            body={"method": method},
            requires_auth=True,
        )
        return MFASetupResult.from_dict(response)
    
    def verify(self, code: str, session_id: Optional[str] = None) -> MFAVerifyResult:
        """Verify MFA code. Use session_id for login MFA verification."""
        endpoint = "/v1/auth/mfa/login/verify" if session_id else "/v1/auth/mfa/verify"
        body: Dict[str, Any] = {"code": code}
        if session_id:
            body["mfa_session_id"] = session_id
        
        response = self._client._request(
            endpoint,
            method="POST",
            body=body,
            requires_auth=not session_id,
        )
        result = MFAVerifyResult.from_dict(response)
        
        # Store tokens if returned
        if result.tokens:
            self._client._store_tokens(result.tokens)
            if result.user:
                self._client._current_user = result.user
        
        return result
    
    def disable(self, code: str) -> None:
        """Disable MFA with verification code."""
        self._client._request(
            "/v1/auth/mfa/disable",
            method="POST",
            body={"code": code},
            requires_auth=True,
        )
    
    def get_status(self) -> MFAStatus:
        """Get current MFA status."""
        response = self._client._request(
            "/v1/auth/mfa/status",
            method="GET",
            requires_auth=True,
        )
        return MFAStatus.from_dict(response)


class SMSNamespace:
    """SMS MFA operations namespace (with security warning)."""
    
    def __init__(self, client: "ZaltClient") -> None:
        self._client = client
    
    def setup(self, phone_number: str, accept_risk: bool = False) -> Dict[str, Any]:
        """
        Setup SMS MFA.
        
        WARNING: SMS MFA is vulnerable to SS7 attacks and SIM swapping.
        Use TOTP or WebAuthn for better security.
        
        Args:
            phone_number: Phone number for SMS verification
            accept_risk: Must be True to acknowledge security risks
        """
        if not accept_risk:
            raise ValidationError(
                "SMS MFA requires explicit risk acceptance. "
                "Set accept_risk=True to acknowledge SS7 vulnerabilities."
            )
        
        response = self._client._request(
            "/v1/auth/mfa/sms/setup",
            method="POST",
            body={"phone_number": phone_number},
            requires_auth=True,
        )
        return response
    
    def verify(self, code: str, session_id: Optional[str] = None) -> MFAVerifyResult:
        """Verify SMS code."""
        endpoint = "/v1/auth/mfa/sms/login/verify" if session_id else "/v1/auth/mfa/sms/verify"
        body: Dict[str, Any] = {"code": code}
        if session_id:
            body["mfa_session_id"] = session_id
        
        response = self._client._request(
            endpoint,
            method="POST",
            body=body,
            requires_auth=not session_id,
        )
        return MFAVerifyResult.from_dict(response)
    
    def disable(self, code: str) -> None:
        """Disable SMS MFA."""
        self._client._request(
            "/v1/auth/mfa/sms/disable",
            method="POST",
            body={"code": code},
            requires_auth=True,
        )


class ZaltClient:
    """
    Zalt Auth Client - Synchronous SDK entry point.
    
    Provides authentication operations with automatic token refresh
    and retry mechanisms, consistent with the TypeScript SDK API.
    """
    
    def __init__(self, config: ZaltConfig) -> None:
        """Initialize the Zalt Auth client."""
        self._validate_config(config)
        
        self._publishable_key = config.publishable_key
        self._realm_id = config.realm_id
        self._base_url = config.base_url.rstrip("/")
        self._timeout = config.timeout
        self._retry_attempts = config.retry_attempts
        self._retry_delay = config.retry_delay
        self._auto_refresh = config.auto_refresh
        self._refresh_threshold = config.refresh_threshold
        self._storage = config.storage if config.storage else MemoryStorage()
        self._debug = config.debug
        self._custom_headers = config.headers or {}
        self._is_test_mode = is_test_key(config.publishable_key)
        
        # State
        self._current_user: Optional[User] = None
        self._token_expires_at: float = 0
        self._refresh_lock = threading.Lock()
        self._refresh_in_progress = False
        
        # HTTP client
        self._http_client = httpx.Client(timeout=self._timeout)
        
        # Namespaces
        self.mfa = MFANamespace(self)
        self.sms = SMSNamespace(self)
        
        self._log(f"ZaltClient initialized (test_mode={self._is_test_mode})")
    
    def _validate_config(self, config: ZaltConfig) -> None:
        """Validate configuration."""
        if not config.publishable_key:
            raise ConfigurationError("publishable_key is required")
        if not is_valid_publishable_key(config.publishable_key):
            raise ConfigurationError(
                "Invalid publishable_key format. Expected pk_live_xxx or pk_test_xxx"
            )
    
    def _log(self, message: str, *args: Any) -> None:
        """Log debug message."""
        if self._debug:
            logger.debug(f"[Zalt] {message}", *args)
    
    # =========================================================================
    # Authentication Methods
    # =========================================================================
    
    def login(self, credentials: LoginCredentials) -> AuthResult:
        """
        Login with email and password.
        
        Args:
            credentials: Login credentials (email, password)
            
        Returns:
            AuthResult with user data and tokens
            
        Raises:
            MFARequiredError: If MFA verification is required
        """
        self._log(f"Login attempt for: {credentials.email}")
        
        response = self._request(
            "/login",
            method="POST",
            body=credentials.to_dict(),
            requires_auth=False,
        )
        
        result = AuthResult.from_dict(response)
        
        # Check if MFA is required
        if result.mfa_required and result.mfa_session_id:
            raise MFARequiredError(result.mfa_session_id, result.mfa_methods)
        
        # Store tokens and user
        self._store_tokens(result.tokens)
        self._current_user = result.user
        
        self._log("Login successful")
        return result
    
    def register(self, data: RegisterData) -> AuthResult:
        """
        Register a new user.
        
        Args:
            data: Registration data (email, password, optional profile)
            
        Returns:
            AuthResult with user data and tokens
        """
        self._log(f"Register attempt for: {data.email}")
        
        response = self._request(
            "/register",
            method="POST",
            body=data.to_dict(),
            requires_auth=False,
        )
        
        result = AuthResult.from_dict(response)
        
        # Store tokens and user
        self._store_tokens(result.tokens)
        self._current_user = result.user
        
        self._log("Registration successful")
        return result
    
    def logout(self) -> None:
        """Logout the current user."""
        self._log("Logout")
        
        access_token = self._storage.get_access_token()
        if access_token:
            try:
                self._request(
                    "/logout",
                    method="POST",
                    requires_auth=True,
                    skip_auto_refresh=True,
                )
            except Exception:
                pass  # Ignore errors during logout
        
        self._clear_session()
    
    def refresh_token(self) -> TokenResult:
        """
        Refresh the access token.
        
        Returns:
            TokenResult with new tokens
        """
        with self._refresh_lock:
            if self._refresh_in_progress:
                # Wait for ongoing refresh
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
        
        try:
            response = self._request(
                "/refresh",
                method="POST",
                body={"refresh_token": refresh_token},
                requires_auth=False,
                skip_auto_refresh=True,
            )
            
            result = TokenResult.from_dict(response)
            self._store_tokens(result)
            
            return result
        except ZaltError as e:
            self._clear_session()
            raise TokenRefreshError(e.message, {"original_error": e.code})
    
    # =========================================================================
    # User Methods
    # =========================================================================
    
    def get_user(self) -> Optional[User]:
        """Get the current cached user."""
        return self._current_user
    
    def fetch_user(self) -> User:
        """Fetch current user from API."""
        response = self._request(
            "/me",
            method="GET",
            requires_auth=True,
        )
        
        user = User.from_dict(response.get("user", response))
        self._current_user = user
        return user
    
    def update_profile(self, data: ProfileUpdateData) -> User:
        """Update user profile."""
        response = self._request(
            "/me/profile",
            method="PATCH",
            body=data.to_dict(),
            requires_auth=True,
        )
        
        user = User.from_dict(response.get("user", response))
        self._current_user = user
        return user
    
    def change_password(self, data: PasswordChangeData) -> None:
        """Change user password."""
        self._request(
            "/me/password",
            method="POST",
            body=data.to_dict(),
            requires_auth=True,
        )
    
    def request_password_reset(self, email: str) -> None:
        """Request password reset email."""
        self._request(
            "/password/reset",
            method="POST",
            body={"email": email},
            requires_auth=False,
        )
    
    def confirm_password_reset(self, token: str, new_password: str) -> None:
        """Confirm password reset with token."""
        self._request(
            "/password/reset/confirm",
            method="POST",
            body={"token": token, "new_password": new_password},
            requires_auth=False,
        )
    
    # =========================================================================
    # State Methods
    # =========================================================================
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        access_token = self._storage.get_access_token()
        if not access_token:
            return False
        
        if self._is_token_expired():
            if self._auto_refresh:
                try:
                    self.refresh_token()
                    return True
                except Exception:
                    return False
            return False
        
        return True
    
    def get_access_token(self) -> Optional[str]:
        """Get the current access token (auto-refreshes if needed)."""
        if self._auto_refresh and self._should_refresh_token():
            try:
                self.refresh_token()
            except Exception:
                pass
        
        return self._storage.get_access_token()
    
    def is_test_mode(self) -> bool:
        """Check if client is in test mode."""
        return self._is_test_mode
    
    # =========================================================================
    # Internal Methods
    # =========================================================================
    
    def _store_tokens(self, tokens: TokenResult) -> None:
        """Store tokens and update expiration."""
        self._storage.set_tokens(
            tokens.access_token,
            tokens.refresh_token,
            tokens.expires_in,
        )
        self._token_expires_at = time.time() + tokens.expires_in
    
    def _clear_session(self) -> None:
        """Clear session data."""
        self._storage.clear_tokens()
        self._current_user = None
        self._token_expires_at = 0
    
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
        """Make HTTP request with retry and error handling."""
        # Auto-refresh token if needed
        if requires_auth and not skip_auto_refresh and self._auto_refresh:
            if self._should_refresh_token():
                try:
                    self.refresh_token()
                except Exception:
                    pass
        
        last_error: Optional[Exception] = None
        
        for attempt in range(self._retry_attempts + 1):
            try:
                return self._execute_request(endpoint, method, body, requires_auth)
            except Exception as error:
                last_error = error
                
                if not is_retryable_error(error):
                    raise
                
                if attempt == self._retry_attempts:
                    raise
                
                delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
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
            "X-API-Key": self._publishable_key,
            **self._custom_headers,
        }
        
        if self._realm_id:
            headers["X-Realm-ID"] = self._realm_id
        
        if requires_auth:
            access_token = self._storage.get_access_token()
            if not access_token:
                raise AuthenticationError("No access token available", "SESSION_EXPIRED")
            headers["Authorization"] = f"Bearer {access_token}"
        
        try:
            response = self._http_client.request(
                method=method,
                url=url,
                headers=headers,
                json=body if body else None,
            )
            
            return self._handle_response(response)
        except httpx.TimeoutException:
            raise NetworkError("Request timeout", {"timeout": self._timeout})
        except httpx.RequestError as e:
            raise NetworkError(str(e))
    
    def _handle_response(self, response: httpx.Response) -> Dict[str, Any]:
        """Handle HTTP response and convert to appropriate result/error."""
        content_type = response.headers.get("content-type", "")
        is_json = "application/json" in content_type
        
        if response.is_success:
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
            raise ValidationError(message, code, details, request_id)
        elif response.status_code == 401:
            raise AuthenticationError(message, code, details, request_id)
        elif response.status_code == 403:
            raise AuthorizationError(message, code, details, request_id)
        elif response.status_code == 429:
            retry_after = int(response.headers.get("retry-after", "60"))
            raise RateLimitError(message, retry_after, request_id)
        else:
            raise ZaltError.from_api_response(
                error_data or {"error": {"code": code, "message": message}},
                response.status_code,
            )
    
    def close(self) -> None:
        """Close the HTTP client."""
        self._http_client.close()
    
    def __enter__(self) -> "ZaltClient":
        return self
    
    def __exit__(self, *args: Any) -> None:
        self.close()



# =============================================================================
# Async Client
# =============================================================================

class AsyncMFANamespace:
    """MFA operations namespace for async client."""
    
    def __init__(self, client: "ZaltAsyncClient") -> None:
        self._client = client
    
    async def setup(self, method: str = "totp") -> MFASetupResult:
        """Setup MFA with specified method (totp, webauthn)."""
        response = await self._client._request(
            "/v1/auth/mfa/setup",
            method="POST",
            body={"method": method},
            requires_auth=True,
        )
        return MFASetupResult.from_dict(response)
    
    async def verify(self, code: str, session_id: Optional[str] = None) -> MFAVerifyResult:
        """Verify MFA code. Use session_id for login MFA verification."""
        endpoint = "/v1/auth/mfa/login/verify" if session_id else "/v1/auth/mfa/verify"
        body: Dict[str, Any] = {"code": code}
        if session_id:
            body["mfa_session_id"] = session_id
        
        response = await self._client._request(
            endpoint,
            method="POST",
            body=body,
            requires_auth=not session_id,
        )
        result = MFAVerifyResult.from_dict(response)
        
        if result.tokens:
            await self._client._store_tokens(result.tokens)
            if result.user:
                self._client._current_user = result.user
        
        return result
    
    async def disable(self, code: str) -> None:
        """Disable MFA with verification code."""
        await self._client._request(
            "/v1/auth/mfa/disable",
            method="POST",
            body={"code": code},
            requires_auth=True,
        )
    
    async def get_status(self) -> MFAStatus:
        """Get current MFA status."""
        response = await self._client._request(
            "/v1/auth/mfa/status",
            method="GET",
            requires_auth=True,
        )
        return MFAStatus.from_dict(response)


class AsyncSMSNamespace:
    """SMS MFA operations namespace for async client."""
    
    def __init__(self, client: "ZaltAsyncClient") -> None:
        self._client = client
    
    async def setup(self, phone_number: str, accept_risk: bool = False) -> Dict[str, Any]:
        """Setup SMS MFA (requires explicit risk acceptance)."""
        if not accept_risk:
            raise ValidationError(
                "SMS MFA requires explicit risk acceptance. "
                "Set accept_risk=True to acknowledge SS7 vulnerabilities."
            )
        
        response = await self._client._request(
            "/v1/auth/mfa/sms/setup",
            method="POST",
            body={"phone_number": phone_number},
            requires_auth=True,
        )
        return response
    
    async def verify(self, code: str, session_id: Optional[str] = None) -> MFAVerifyResult:
        """Verify SMS code."""
        endpoint = "/v1/auth/mfa/sms/login/verify" if session_id else "/v1/auth/mfa/sms/verify"
        body: Dict[str, Any] = {"code": code}
        if session_id:
            body["mfa_session_id"] = session_id
        
        response = await self._client._request(
            endpoint,
            method="POST",
            body=body,
            requires_auth=not session_id,
        )
        return MFAVerifyResult.from_dict(response)
    
    async def disable(self, code: str) -> None:
        """Disable SMS MFA."""
        await self._client._request(
            "/v1/auth/mfa/sms/disable",
            method="POST",
            body={"code": code},
            requires_auth=True,
        )


class ZaltAsyncClient:
    """
    Zalt Auth Async Client - Asynchronous SDK entry point.
    
    Provides async authentication operations with automatic token refresh
    and retry mechanisms, consistent with the TypeScript SDK API.
    
    Ideal for FastAPI, aiohttp, and other async frameworks.
    """
    
    def __init__(self, config: ZaltConfig) -> None:
        """Initialize the async Zalt Auth client."""
        self._validate_config(config)
        
        self._publishable_key = config.publishable_key
        self._realm_id = config.realm_id
        self._base_url = config.base_url.rstrip("/")
        self._timeout = config.timeout
        self._retry_attempts = config.retry_attempts
        self._retry_delay = config.retry_delay
        self._auto_refresh = config.auto_refresh
        self._refresh_threshold = config.refresh_threshold
        self._storage = config.storage if config.storage else MemoryStorage()
        self._debug = config.debug
        self._custom_headers = config.headers or {}
        self._is_test_mode = is_test_key(config.publishable_key)
        
        # State
        self._current_user: Optional[User] = None
        self._token_expires_at: float = 0
        self._refresh_lock = asyncio.Lock()
        self._refresh_in_progress = False
        
        # HTTP client (created lazily)
        self._http_client: Optional[httpx.AsyncClient] = None
        
        # Namespaces
        self.mfa = AsyncMFANamespace(self)
        self.sms = AsyncSMSNamespace(self)
        
        self._log(f"ZaltAsyncClient initialized (test_mode={self._is_test_mode})")
    
    def _validate_config(self, config: ZaltConfig) -> None:
        """Validate configuration."""
        if not config.publishable_key:
            raise ConfigurationError("publishable_key is required")
        if not is_valid_publishable_key(config.publishable_key):
            raise ConfigurationError(
                "Invalid publishable_key format. Expected pk_live_xxx or pk_test_xxx"
            )
    
    def _log(self, message: str, *args: Any) -> None:
        """Log debug message."""
        if self._debug:
            logger.debug(f"[Zalt] {message}", *args)
    
    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=self._timeout)
        return self._http_client
    
    # =========================================================================
    # Authentication Methods
    # =========================================================================
    
    async def login(self, credentials: LoginCredentials) -> AuthResult:
        """Login with email and password."""
        self._log(f"Login attempt for: {credentials.email}")
        
        response = await self._request(
            "/login",
            method="POST",
            body=credentials.to_dict(),
            requires_auth=False,
        )
        
        result = AuthResult.from_dict(response)
        
        if result.mfa_required and result.mfa_session_id:
            raise MFARequiredError(result.mfa_session_id, result.mfa_methods)
        
        await self._store_tokens(result.tokens)
        self._current_user = result.user
        
        self._log("Login successful")
        return result
    
    async def register(self, data: RegisterData) -> AuthResult:
        """Register a new user."""
        self._log(f"Register attempt for: {data.email}")
        
        response = await self._request(
            "/register",
            method="POST",
            body=data.to_dict(),
            requires_auth=False,
        )
        
        result = AuthResult.from_dict(response)
        
        await self._store_tokens(result.tokens)
        self._current_user = result.user
        
        self._log("Registration successful")
        return result
    
    async def logout(self) -> None:
        """Logout the current user."""
        self._log("Logout")
        
        access_token = self._storage.get_access_token()
        if access_token:
            try:
                await self._request(
                    "/logout",
                    method="POST",
                    requires_auth=True,
                    skip_auto_refresh=True,
                )
            except Exception:
                pass
        
        await self._clear_session()
    
    async def refresh_token(self) -> TokenResult:
        """Refresh the access token."""
        async with self._refresh_lock:
            if self._refresh_in_progress:
                pass
            self._refresh_in_progress = True
        
        try:
            return await self._do_refresh_token()
        finally:
            async with self._refresh_lock:
                self._refresh_in_progress = False
    
    async def _do_refresh_token(self) -> TokenResult:
        """Internal method to perform token refresh."""
        refresh_token = self._storage.get_refresh_token()
        if not refresh_token:
            raise TokenRefreshError("No refresh token available")
        
        try:
            response = await self._request(
                "/refresh",
                method="POST",
                body={"refresh_token": refresh_token},
                requires_auth=False,
                skip_auto_refresh=True,
            )
            
            result = TokenResult.from_dict(response)
            await self._store_tokens(result)
            
            return result
        except ZaltError as e:
            await self._clear_session()
            raise TokenRefreshError(e.message, {"original_error": e.code})
    
    # =========================================================================
    # User Methods
    # =========================================================================
    
    def get_user(self) -> Optional[User]:
        """Get the current cached user."""
        return self._current_user
    
    async def fetch_user(self) -> User:
        """Fetch current user from API."""
        response = await self._request(
            "/me",
            method="GET",
            requires_auth=True,
        )
        
        user = User.from_dict(response.get("user", response))
        self._current_user = user
        return user
    
    async def update_profile(self, data: ProfileUpdateData) -> User:
        """Update user profile."""
        response = await self._request(
            "/me/profile",
            method="PATCH",
            body=data.to_dict(),
            requires_auth=True,
        )
        
        user = User.from_dict(response.get("user", response))
        self._current_user = user
        return user
    
    async def change_password(self, data: PasswordChangeData) -> None:
        """Change user password."""
        await self._request(
            "/me/password",
            method="POST",
            body=data.to_dict(),
            requires_auth=True,
        )
    
    async def request_password_reset(self, email: str) -> None:
        """Request password reset email."""
        await self._request(
            "/password/reset",
            method="POST",
            body={"email": email},
            requires_auth=False,
        )
    
    async def confirm_password_reset(self, token: str, new_password: str) -> None:
        """Confirm password reset with token."""
        await self._request(
            "/password/reset/confirm",
            method="POST",
            body={"token": token, "new_password": new_password},
            requires_auth=False,
        )
    
    # =========================================================================
    # State Methods
    # =========================================================================
    
    async def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        access_token = self._storage.get_access_token()
        if not access_token:
            return False
        
        if self._is_token_expired():
            if self._auto_refresh:
                try:
                    await self.refresh_token()
                    return True
                except Exception:
                    return False
            return False
        
        return True
    
    async def get_access_token(self) -> Optional[str]:
        """Get the current access token (auto-refreshes if needed)."""
        if self._auto_refresh and self._should_refresh_token():
            try:
                await self.refresh_token()
            except Exception:
                pass
        
        return self._storage.get_access_token()
    
    def is_test_mode(self) -> bool:
        """Check if client is in test mode."""
        return self._is_test_mode
    
    # =========================================================================
    # Internal Methods
    # =========================================================================
    
    async def _store_tokens(self, tokens: TokenResult) -> None:
        """Store tokens and update expiration."""
        self._storage.set_tokens(
            tokens.access_token,
            tokens.refresh_token,
            tokens.expires_in,
        )
        self._token_expires_at = time.time() + tokens.expires_in
    
    async def _clear_session(self) -> None:
        """Clear session data."""
        self._storage.clear_tokens()
        self._current_user = None
        self._token_expires_at = 0
    
    def _is_token_expired(self) -> bool:
        """Check if token is expired."""
        return self._token_expires_at > 0 and time.time() >= self._token_expires_at
    
    def _should_refresh_token(self) -> bool:
        """Check if token should be refreshed."""
        if self._token_expires_at == 0:
            return False
        return time.time() >= self._token_expires_at - self._refresh_threshold
    
    async def _request(
        self,
        endpoint: str,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        body: Optional[Dict[str, Any]] = None,
        requires_auth: bool = False,
        skip_auto_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Make HTTP request with retry and error handling."""
        if requires_auth and not skip_auto_refresh and self._auto_refresh:
            if self._should_refresh_token():
                try:
                    await self.refresh_token()
                except Exception:
                    pass
        
        last_error: Optional[Exception] = None
        
        for attempt in range(self._retry_attempts + 1):
            try:
                return await self._execute_request(endpoint, method, body, requires_auth)
            except Exception as error:
                last_error = error
                
                if not is_retryable_error(error):
                    raise
                
                if attempt == self._retry_attempts:
                    raise
                
                delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
                await asyncio.sleep(delay)
        
        raise last_error or NetworkError("Request failed after retries")
    
    async def _execute_request(
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
            "X-API-Key": self._publishable_key,
            **self._custom_headers,
        }
        
        if self._realm_id:
            headers["X-Realm-ID"] = self._realm_id
        
        if requires_auth:
            access_token = self._storage.get_access_token()
            if not access_token:
                raise AuthenticationError("No access token available", "SESSION_EXPIRED")
            headers["Authorization"] = f"Bearer {access_token}"
        
        try:
            client = self._get_client()
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                json=body if body else None,
            )
            
            return self._handle_response(response)
        except httpx.TimeoutException:
            raise NetworkError("Request timeout", {"timeout": self._timeout})
        except httpx.RequestError as e:
            raise NetworkError(str(e))
    
    def _handle_response(self, response: httpx.Response) -> Dict[str, Any]:
        """Handle HTTP response."""
        content_type = response.headers.get("content-type", "")
        is_json = "application/json" in content_type
        
        if response.is_success:
            if not is_json:
                return {}
            data = response.json()
            return data.get("data", data)
        
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
            raise ValidationError(message, code, details, request_id)
        elif response.status_code == 401:
            raise AuthenticationError(message, code, details, request_id)
        elif response.status_code == 403:
            raise AuthorizationError(message, code, details, request_id)
        elif response.status_code == 429:
            retry_after = int(response.headers.get("retry-after", "60"))
            raise RateLimitError(message, retry_after, request_id)
        else:
            raise ZaltError.from_api_response(
                error_data or {"error": {"code": code, "message": message}},
                response.status_code,
            )
    
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
    
    async def __aenter__(self) -> "ZaltAsyncClient":
        return self
    
    async def __aexit__(self, *args: Any) -> None:
        await self.close()


# =============================================================================
# Factory Functions
# =============================================================================

def create_zalt_client(config: ZaltConfig) -> ZaltClient:
    """Create a new synchronous Zalt client."""
    return ZaltClient(config)


def create_async_zalt_client(config: ZaltConfig) -> ZaltAsyncClient:
    """Create a new asynchronous Zalt client."""
    return ZaltAsyncClient(config)


# Legacy aliases for backward compatibility
HSDAuthClient = ZaltClient
create_hsd_auth_client = create_zalt_client
