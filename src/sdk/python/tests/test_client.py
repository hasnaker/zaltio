"""
Tests for Zalt Auth Python SDK Client

Tests both sync and async clients with mocked HTTP responses.
"""

import asyncio
import json
import pytest
import time
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import httpx
import respx

from zalt_auth import (
    ZaltClient,
    ZaltAsyncClient,
    ZaltConfig,
    LoginCredentials,
    RegisterData,
    ProfileUpdateData,
    PasswordChangeData,
    User,
    AuthResult,
    TokenResult,
    MFASetupResult,
    MFAStatus,
)
from zalt_auth.errors import (
    ZaltError,
    AuthenticationError,
    ValidationError,
    RateLimitError,
    ConfigurationError,
    MFARequiredError,
    TokenRefreshError,
)
from zalt_auth.storage import MemoryStorage, FileStorage


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def valid_config() -> ZaltConfig:
    """Valid configuration for testing."""
    return ZaltConfig(
        publishable_key="pk_test_12345678901234567890123456789012",
        realm_id="test-realm",
        base_url="https://api.zalt.io",
        timeout=10.0,
        debug=True,
    )


@pytest.fixture
def mock_user_response() -> Dict[str, Any]:
    """Mock user response from API."""
    return {
        "user": {
            "id": "user_123",
            "realm_id": "test-realm",
            "email": "test@example.com",
            "email_verified": True,
            "profile": {
                "first_name": "Test",
                "last_name": "User",
            },
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "last_login": "2026-01-01T00:00:00Z",
            "status": "active",
            "mfa_enabled": False,
            "tenants": [],
        },
        "tokens": {
            "access_token": "access_token_123",
            "refresh_token": "refresh_token_123",
            "expires_in": 900,
            "token_type": "Bearer",
        },
    }


@pytest.fixture
def sync_client(valid_config: ZaltConfig) -> ZaltClient:
    """Create sync client for testing."""
    return ZaltClient(valid_config)


@pytest.fixture
def async_client(valid_config: ZaltConfig) -> ZaltAsyncClient:
    """Create async client for testing."""
    return ZaltAsyncClient(valid_config)


# =============================================================================
# Configuration Tests
# =============================================================================

class TestConfiguration:
    """Tests for SDK configuration."""
    
    def test_valid_live_key(self):
        """Test valid live publishable key."""
        config = ZaltConfig(publishable_key="pk_live_12345678901234567890123456789012")
        client = ZaltClient(config)
        assert not client.is_test_mode()
    
    def test_valid_test_key(self):
        """Test valid test publishable key."""
        config = ZaltConfig(publishable_key="pk_test_12345678901234567890123456789012")
        client = ZaltClient(config)
        assert client.is_test_mode()
    
    def test_missing_publishable_key(self):
        """Test missing publishable key raises error."""
        with pytest.raises(ConfigurationError) as exc_info:
            ZaltConfig(publishable_key="")
            ZaltClient(ZaltConfig(publishable_key=""))
        assert "publishable_key is required" in str(exc_info.value)
    
    def test_invalid_publishable_key_format(self):
        """Test invalid publishable key format raises error."""
        with pytest.raises(ConfigurationError) as exc_info:
            ZaltClient(ZaltConfig(publishable_key="invalid_key"))
        assert "Invalid publishable_key format" in str(exc_info.value)
    
    def test_short_publishable_key(self):
        """Test short publishable key raises error."""
        with pytest.raises(ConfigurationError):
            ZaltClient(ZaltConfig(publishable_key="pk_live_short"))
    
    def test_default_base_url(self):
        """Test default base URL."""
        config = ZaltConfig(publishable_key="pk_test_12345678901234567890123456789012")
        assert config.base_url == "https://api.zalt.io"
    
    def test_custom_base_url(self):
        """Test custom base URL."""
        config = ZaltConfig(
            publishable_key="pk_test_12345678901234567890123456789012",
            base_url="https://custom.api.com",
        )
        assert config.base_url == "https://custom.api.com"


# =============================================================================
# Sync Client Tests
# =============================================================================

class TestSyncClient:
    """Tests for synchronous client."""
    
    @respx.mock
    def test_login_success(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test successful login."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        result = sync_client.login(LoginCredentials(
            email="test@example.com",
            password="password123",
        ))
        
        assert result.user.email == "test@example.com"
        assert result.tokens.access_token == "access_token_123"
        assert sync_client.get_user() is not None
    
    @respx.mock
    def test_login_mfa_required(self, sync_client: ZaltClient):
        """Test login with MFA required."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json={
                "mfa_required": True,
                "mfa_session_id": "mfa_session_123",
                "mfa_methods": ["totp", "webauthn"],
            })
        )
        
        with pytest.raises(MFARequiredError) as exc_info:
            sync_client.login(LoginCredentials(
                email="test@example.com",
                password="password123",
            ))
        
        assert exc_info.value.mfa_session_id == "mfa_session_123"
        assert "totp" in exc_info.value.mfa_methods
    
    @respx.mock
    def test_login_invalid_credentials(self, sync_client: ZaltClient):
        """Test login with invalid credentials."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(401, json={
                "error": {
                    "code": "INVALID_CREDENTIALS",
                    "message": "Invalid email or password",
                }
            })
        )
        
        with pytest.raises(AuthenticationError) as exc_info:
            sync_client.login(LoginCredentials(
                email="test@example.com",
                password="wrong_password",
            ))
        
        assert exc_info.value.code == "INVALID_CREDENTIALS"
    
    @respx.mock
    def test_register_success(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test successful registration."""
        respx.post("https://api.zalt.io/register").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        result = sync_client.register(RegisterData(
            email="new@example.com",
            password="SecurePass123!",
        ))
        
        assert result.user.email == "test@example.com"
        assert result.tokens.access_token is not None
    
    @respx.mock
    def test_register_validation_error(self, sync_client: ZaltClient):
        """Test registration with validation error."""
        respx.post("https://api.zalt.io/register").mock(
            return_value=httpx.Response(400, json={
                "error": {
                    "code": "WEAK_PASSWORD",
                    "message": "Password does not meet requirements",
                }
            })
        )
        
        with pytest.raises(ValidationError) as exc_info:
            sync_client.register(RegisterData(
                email="new@example.com",
                password="weak",
            ))
        
        assert exc_info.value.code == "WEAK_PASSWORD"
    
    @respx.mock
    def test_logout(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test logout."""
        # First login
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        respx.post("https://api.zalt.io/logout").mock(
            return_value=httpx.Response(200, json={"success": True})
        )
        
        sync_client.login(LoginCredentials(
            email="test@example.com",
            password="password123",
        ))
        
        assert sync_client.get_user() is not None
        
        sync_client.logout()
        
        assert sync_client.get_user() is None
    
    @respx.mock
    def test_fetch_user(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test fetching current user."""
        # Login first
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        respx.get("https://api.zalt.io/me").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        sync_client.login(LoginCredentials(
            email="test@example.com",
            password="password123",
        ))
        
        user = sync_client.fetch_user()
        
        assert user.email == "test@example.com"
        assert user.profile.first_name == "Test"
    
    @respx.mock
    def test_refresh_token(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test token refresh."""
        # Login first
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        respx.post("https://api.zalt.io/refresh").mock(
            return_value=httpx.Response(200, json={
                "access_token": "new_access_token",
                "refresh_token": "new_refresh_token",
                "expires_in": 900,
            })
        )
        
        sync_client.login(LoginCredentials(
            email="test@example.com",
            password="password123",
        ))
        
        result = sync_client.refresh_token()
        
        assert result.access_token == "new_access_token"
        assert result.refresh_token == "new_refresh_token"
    
    @respx.mock
    def test_rate_limit_error(self, sync_client: ZaltClient):
        """Test rate limit handling."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(
                429,
                json={"error": {"code": "RATE_LIMITED", "message": "Too many requests"}},
                headers={"retry-after": "60"},
            )
        )
        
        with pytest.raises(RateLimitError) as exc_info:
            sync_client.login(LoginCredentials(
                email="test@example.com",
                password="password123",
            ))
        
        assert exc_info.value.retry_after == 60


# =============================================================================
# Async Client Tests
# =============================================================================

class TestAsyncClient:
    """Tests for asynchronous client."""
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_login_success(self, async_client: ZaltAsyncClient, mock_user_response: Dict):
        """Test successful async login."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        result = await async_client.login(LoginCredentials(
            email="test@example.com",
            password="password123",
        ))
        
        assert result.user.email == "test@example.com"
        assert async_client.get_user() is not None
        
        await async_client.close()
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_login_mfa_required(self, async_client: ZaltAsyncClient):
        """Test async login with MFA required."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json={
                "mfa_required": True,
                "mfa_session_id": "mfa_session_123",
                "mfa_methods": ["totp"],
            })
        )
        
        with pytest.raises(MFARequiredError) as exc_info:
            await async_client.login(LoginCredentials(
                email="test@example.com",
                password="password123",
            ))
        
        assert exc_info.value.mfa_session_id == "mfa_session_123"
        
        await async_client.close()
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_register_success(self, async_client: ZaltAsyncClient, mock_user_response: Dict):
        """Test successful async registration."""
        respx.post("https://api.zalt.io/register").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        result = await async_client.register(RegisterData(
            email="new@example.com",
            password="SecurePass123!",
        ))
        
        assert result.user is not None
        assert result.tokens.access_token is not None
        
        await async_client.close()
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_context_manager(self, valid_config: ZaltConfig, mock_user_response: Dict):
        """Test async context manager."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        async with ZaltAsyncClient(valid_config) as client:
            result = await client.login(LoginCredentials(
                email="test@example.com",
                password="password123",
            ))
            assert result.user is not None


# =============================================================================
# MFA Tests
# =============================================================================

class TestMFA:
    """Tests for MFA operations."""
    
    @respx.mock
    def test_mfa_setup(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test MFA setup."""
        # Login first
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        respx.post("https://api.zalt.io/v1/auth/mfa/setup").mock(
            return_value=httpx.Response(200, json={
                "secret": "JBSWY3DPEHPK3PXP",
                "qr_code": "data:image/png;base64,xxx",
                "backup_codes": ["12345678", "87654321"],
                "recovery_key": "recovery_key_123",
            })
        )
        
        sync_client.login(LoginCredentials(
            email="test@example.com",
            password="password123",
        ))
        
        result = sync_client.mfa.setup(method="totp")
        
        assert result.secret == "JBSWY3DPEHPK3PXP"
        assert len(result.backup_codes) == 2
    
    @respx.mock
    def test_mfa_verify(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test MFA verification."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        respx.post("https://api.zalt.io/v1/auth/mfa/verify").mock(
            return_value=httpx.Response(200, json={
                "success": True,
            })
        )
        
        sync_client.login(LoginCredentials(
            email="test@example.com",
            password="password123",
        ))
        
        result = sync_client.mfa.verify(code="123456")
        
        assert result.success is True
    
    @respx.mock
    def test_mfa_login_verify(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test MFA verification during login."""
        respx.post("https://api.zalt.io/v1/auth/mfa/login/verify").mock(
            return_value=httpx.Response(200, json={
                "success": True,
                "user": mock_user_response["user"],
                "tokens": mock_user_response["tokens"],
            })
        )
        
        result = sync_client.mfa.verify(code="123456", session_id="mfa_session_123")
        
        assert result.success is True
        assert result.user is not None
        assert sync_client.get_user() is not None
    
    @respx.mock
    def test_mfa_status(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test getting MFA status."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        respx.get("https://api.zalt.io/v1/auth/mfa/status").mock(
            return_value=httpx.Response(200, json={
                "enabled": True,
                "methods": ["totp"],
                "backup_codes_remaining": 8,
            })
        )
        
        sync_client.login(LoginCredentials(
            email="test@example.com",
            password="password123",
        ))
        
        status = sync_client.mfa.get_status()
        
        assert status.enabled is True
        assert "totp" in status.methods
        assert status.backup_codes_remaining == 8


# =============================================================================
# SMS MFA Tests
# =============================================================================

class TestSMSMFA:
    """Tests for SMS MFA operations."""
    
    def test_sms_setup_requires_risk_acceptance(self, sync_client: ZaltClient):
        """Test SMS setup requires explicit risk acceptance."""
        with pytest.raises(ValidationError) as exc_info:
            sync_client.sms.setup(phone_number="+1234567890")
        
        assert "risk acceptance" in str(exc_info.value.message).lower()
    
    @respx.mock
    def test_sms_setup_with_risk_acceptance(self, sync_client: ZaltClient, mock_user_response: Dict):
        """Test SMS setup with risk acceptance."""
        respx.post("https://api.zalt.io/login").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        respx.post("https://api.zalt.io/v1/auth/mfa/sms/setup").mock(
            return_value=httpx.Response(200, json={
                "phone_number": "+1234567890",
                "verification_required": True,
            })
        )
        
        sync_client.login(LoginCredentials(
            email="test@example.com",
            password="password123",
        ))
        
        result = sync_client.sms.setup(
            phone_number="+1234567890",
            accept_risk=True,
        )
        
        assert result["phone_number"] == "+1234567890"


# =============================================================================
# Storage Tests
# =============================================================================

class TestStorage:
    """Tests for token storage implementations."""
    
    def test_memory_storage(self):
        """Test memory storage."""
        storage = MemoryStorage()
        
        assert storage.get_access_token() is None
        assert storage.get_refresh_token() is None
        
        storage.set_tokens("access", "refresh", 900)
        
        assert storage.get_access_token() == "access"
        assert storage.get_refresh_token() == "refresh"
        
        storage.clear_tokens()
        
        assert storage.get_access_token() is None
        assert storage.get_refresh_token() is None
    
    def test_memory_storage_expiration(self):
        """Test memory storage token expiration."""
        storage = MemoryStorage()
        
        # Set tokens with 1 second expiry
        storage.set_tokens("access", "refresh", 1)
        
        assert storage.get_access_token() == "access"
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Access token should be None (expired)
        assert storage.get_access_token() is None
        # Refresh token should still be available
        assert storage.get_refresh_token() == "refresh"
    
    def test_file_storage(self, tmp_path):
        """Test file storage."""
        file_path = tmp_path / "tokens.json"
        storage = FileStorage(str(file_path))
        
        assert storage.get_access_token() is None
        
        storage.set_tokens("access", "refresh", 900)
        
        assert storage.get_access_token() == "access"
        assert storage.get_refresh_token() == "refresh"
        
        # Verify file was created
        assert file_path.exists()
        
        storage.clear_tokens()
        
        assert storage.get_access_token() is None
        assert not file_path.exists()


# =============================================================================
# Error Tests
# =============================================================================

class TestErrors:
    """Tests for error handling."""
    
    def test_zalt_error_to_dict(self):
        """Test error serialization."""
        error = ZaltError(
            code="TEST_ERROR",
            message="Test error message",
            status_code=400,
            details={"field": "email"},
            request_id="req_123",
        )
        
        error_dict = error.to_dict()
        
        assert error_dict["code"] == "TEST_ERROR"
        assert error_dict["message"] == "Test error message"
        assert error_dict["status_code"] == 400
        assert error_dict["details"]["field"] == "email"
        assert error_dict["request_id"] == "req_123"
    
    def test_mfa_required_error(self):
        """Test MFA required error."""
        error = MFARequiredError(
            mfa_session_id="session_123",
            mfa_methods=["totp", "webauthn"],
        )
        
        assert error.mfa_session_id == "session_123"
        assert error.mfa_methods == ["totp", "webauthn"]
        assert error.code == "MFA_REQUIRED"
    
    def test_rate_limit_error(self):
        """Test rate limit error."""
        error = RateLimitError(
            message="Too many requests",
            retry_after=60,
        )
        
        assert error.retry_after == 60
        assert error.code == "RATE_LIMITED"
        assert error.status_code == 429
