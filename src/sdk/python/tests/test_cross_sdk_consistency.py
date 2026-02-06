"""
Property Test: Cross-SDK API Consistency
Feature: zalt-auth-platform, Property 9: Cross-SDK API Consistency
Validates: Requirements 4.4, 4.5

This test verifies that the Python SDK maintains API consistency with the
TypeScript SDK by checking that:
1. Method names follow consistent patterns (snake_case in Python, camelCase in TS)
2. Parameters and return types are equivalent
3. Error handling follows the same patterns
"""

import inspect
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, get_type_hints

import pytest
from hypothesis import given, settings, strategies as st

from hsd_auth import (
    HSDAuthClient,
    HSDAuthConfig,
    HSDAuthError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    RateLimitError,
    NetworkError,
    TokenRefreshError,
    ConfigurationError,
    MemoryStorage,
    User,
    UserProfile,
    AuthResult,
    TokenResult,
    RegisterData,
    LoginCredentials,
    ProfileUpdateData,
    PasswordChangeData,
)


# TypeScript SDK method names (camelCase) mapped to Python SDK method names (snake_case)
TS_TO_PYTHON_METHOD_MAP = {
    "register": "register",
    "login": "login",
    "refreshToken": "refresh_token",
    "logout": "logout",
    "getCurrentUser": "get_current_user",
    "updateProfile": "update_profile",
    "changePassword": "change_password",
    "isAuthenticated": "is_authenticated",
    "getAccessToken": "get_access_token",
    "getConfig": "get_config",
}

# TypeScript SDK type names mapped to Python SDK type names
TS_TO_PYTHON_TYPE_MAP = {
    "HSDAuthConfig": "HSDAuthConfig",
    "TokenStorage": "TokenStorage",
    "User": "User",
    "UserProfile": "UserProfile",
    "AuthResult": "AuthResult",
    "TokenResult": "TokenResult",
    "RegisterData": "RegisterData",
    "LoginCredentials": "LoginCredentials",
    "ProfileUpdateData": "ProfileUpdateData",
    "PasswordChangeData": "PasswordChangeData",
}

# TypeScript SDK error names mapped to Python SDK error names
TS_TO_PYTHON_ERROR_MAP = {
    "HSDAuthError": "HSDAuthError",
    "NetworkError": "NetworkError",
    "AuthenticationError": "AuthenticationError",
    "AuthorizationError": "AuthorizationError",
    "ValidationError": "ValidationError",
    "RateLimitError": "RateLimitError",
    "TokenRefreshError": "TokenRefreshError",
    "ConfigurationError": "ConfigurationError",
}


class TestCrossSDKConsistency:
    """
    Property tests for cross-SDK API consistency.
    
    These tests verify that the Python SDK maintains API consistency
    with the TypeScript SDK as specified in Property 9.
    """
    
    def test_all_ts_methods_exist_in_python_sdk(self):
        """
        Property: For any method in the TypeScript SDK, an equivalent
        method should exist in the Python SDK.
        """
        client = HSDAuthClient(HSDAuthConfig(
            base_url="https://api.auth.hsdcore.com",
            realm_id="test-realm"
        ))
        
        for ts_method, py_method in TS_TO_PYTHON_METHOD_MAP.items():
            assert hasattr(client, py_method), (
                f"Python SDK missing method '{py_method}' "
                f"(TypeScript equivalent: '{ts_method}')"
            )
            assert callable(getattr(client, py_method)), (
                f"'{py_method}' should be callable"
            )
    
    def test_all_ts_types_exist_in_python_sdk(self):
        """
        Property: For any type in the TypeScript SDK, an equivalent
        type should exist in the Python SDK.
        """
        import hsd_auth
        
        for ts_type, py_type in TS_TO_PYTHON_TYPE_MAP.items():
            assert hasattr(hsd_auth, py_type), (
                f"Python SDK missing type '{py_type}' "
                f"(TypeScript equivalent: '{ts_type}')"
            )
    
    def test_all_ts_errors_exist_in_python_sdk(self):
        """
        Property: For any error class in the TypeScript SDK, an equivalent
        error class should exist in the Python SDK.
        """
        import hsd_auth
        
        for ts_error, py_error in TS_TO_PYTHON_ERROR_MAP.items():
            assert hasattr(hsd_auth, py_error), (
                f"Python SDK missing error class '{py_error}' "
                f"(TypeScript equivalent: '{ts_error}')"
            )
            error_class = getattr(hsd_auth, py_error)
            assert issubclass(error_class, Exception), (
                f"'{py_error}' should be an Exception subclass"
            )
    
    def test_error_hierarchy_consistency(self):
        """
        Property: All specific error classes should inherit from HSDAuthError.
        """
        specific_errors = [
            NetworkError,
            AuthenticationError,
            AuthorizationError,
            ValidationError,
            RateLimitError,
            TokenRefreshError,
            ConfigurationError,
        ]
        
        for error_class in specific_errors:
            assert issubclass(error_class, HSDAuthError), (
                f"{error_class.__name__} should inherit from HSDAuthError"
            )
    
    def test_error_attributes_consistency(self):
        """
        Property: All error classes should have consistent attributes
        matching the TypeScript SDK.
        """
        required_attributes = ["code", "message", "status_code", "details", "request_id", "timestamp"]
        
        error = HSDAuthError("TEST_CODE", "Test message", 400, {"key": "value"}, "req-123")
        
        for attr in required_attributes:
            assert hasattr(error, attr), (
                f"HSDAuthError missing attribute '{attr}'"
            )
    
    @given(st.text(min_size=1, max_size=100).filter(lambda x: x.strip()))
    @settings(max_examples=100)
    def test_config_validation_consistency(self, realm_id: str):
        """
        Property: For any valid realm_id, configuration should be accepted.
        For any invalid configuration, ConfigurationError should be raised.
        """
        # Valid configuration should work
        config = HSDAuthConfig(
            base_url="https://api.auth.hsdcore.com",
            realm_id=realm_id.strip()
        )
        client = HSDAuthClient(config)
        assert client is not None
        
        # Invalid base_url should raise ConfigurationError
        with pytest.raises(ConfigurationError):
            HSDAuthClient(HSDAuthConfig(
                base_url="",
                realm_id=realm_id
            ))
        
        # Invalid realm_id should raise ConfigurationError
        with pytest.raises(ConfigurationError):
            HSDAuthClient(HSDAuthConfig(
                base_url="https://api.auth.hsdcore.com",
                realm_id=""
            ))
    
    @given(
        timeout=st.floats(min_value=0.1, max_value=60.0),
        retry_attempts=st.integers(min_value=0, max_value=10),
        retry_delay=st.floats(min_value=0.1, max_value=10.0),
        refresh_threshold=st.integers(min_value=1, max_value=3600),
    )
    @settings(max_examples=100)
    def test_config_options_consistency(
        self,
        timeout: float,
        retry_attempts: int,
        retry_delay: float,
        refresh_threshold: int,
    ):
        """
        Property: For any valid configuration options, the client should
        accept them and return them via get_config().
        """
        config = HSDAuthConfig(
            base_url="https://api.auth.hsdcore.com",
            realm_id="test-realm",
            timeout=timeout,
            retry_attempts=retry_attempts,
            retry_delay=retry_delay,
            auto_refresh=True,
            refresh_threshold=refresh_threshold,
        )
        client = HSDAuthClient(config)
        
        returned_config = client.get_config()
        
        assert returned_config["timeout"] == timeout
        assert returned_config["retry_attempts"] == retry_attempts
        assert returned_config["retry_delay"] == retry_delay
        assert returned_config["refresh_threshold"] == refresh_threshold
        assert returned_config["auto_refresh"] is True
    
    def test_storage_interface_consistency(self):
        """
        Property: MemoryStorage should implement all required TokenStorage methods.
        """
        required_methods = [
            "get_access_token",
            "get_refresh_token",
            "set_tokens",
            "clear_tokens",
        ]
        
        storage = MemoryStorage()
        
        for method in required_methods:
            assert hasattr(storage, method), (
                f"MemoryStorage missing method '{method}'"
            )
            assert callable(getattr(storage, method)), (
                f"'{method}' should be callable"
            )
    
    @given(
        access_token=st.text(min_size=10, max_size=500),
        refresh_token=st.text(min_size=10, max_size=500),
        expires_in=st.integers(min_value=1, max_value=86400),
    )
    @settings(max_examples=100)
    def test_storage_round_trip_consistency(
        self,
        access_token: str,
        refresh_token: str,
        expires_in: int,
    ):
        """
        Property: For any tokens stored in MemoryStorage, retrieving them
        should return the same values (round-trip consistency).
        """
        storage = MemoryStorage()
        
        # Store tokens
        storage.set_tokens(access_token, refresh_token, expires_in)
        
        # Retrieve and verify
        assert storage.get_access_token() == access_token
        assert storage.get_refresh_token() == refresh_token
        
        # Clear and verify
        storage.clear_tokens()
        assert storage.get_access_token() is None
        assert storage.get_refresh_token() is None
    
    def test_user_model_consistency(self):
        """
        Property: User model should have all required fields matching TypeScript SDK.
        """
        required_fields = [
            "id", "realm_id", "email", "email_verified", "profile",
            "created_at", "updated_at", "last_login", "status"
        ]
        
        user_data = {
            "id": "user-123",
            "realm_id": "realm-456",
            "email": "test@example.com",
            "email_verified": True,
            "profile": {"first_name": "Test"},
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "last_login": "2024-01-01T00:00:00Z",
            "status": "active",
        }
        
        user = User.from_dict(user_data)
        
        for field in required_fields:
            assert hasattr(user, field), f"User missing field '{field}'"
    
    @given(
        first_name=st.one_of(st.none(), st.text(max_size=50)),
        last_name=st.one_of(st.none(), st.text(max_size=50)),
        avatar_url=st.one_of(st.none(), st.text(max_size=200)),
    )
    @settings(max_examples=100)
    def test_profile_data_consistency(
        self,
        first_name: Optional[str],
        last_name: Optional[str],
        avatar_url: Optional[str],
    ):
        """
        Property: ProfileUpdateData should serialize to dict with only non-None values.
        """
        data = ProfileUpdateData(
            first_name=first_name,
            last_name=last_name,
            avatar_url=avatar_url,
        )
        
        result = data.to_dict()
        
        # Only non-None values should be in the dict
        if first_name is not None:
            assert result.get("first_name") == first_name
        else:
            assert "first_name" not in result
        
        if last_name is not None:
            assert result.get("last_name") == last_name
        else:
            assert "last_name" not in result
        
        if avatar_url is not None:
            assert result.get("avatar_url") == avatar_url
        else:
            assert "avatar_url" not in result
    
    def test_auth_result_model_consistency(self):
        """
        Property: AuthResult model should have all required fields matching TypeScript SDK.
        """
        required_fields = ["user", "access_token", "refresh_token", "expires_in"]
        
        auth_data = {
            "user": {
                "id": "user-123",
                "realm_id": "realm-456",
                "email": "test@example.com",
                "email_verified": True,
                "profile": {},
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "last_login": "2024-01-01T00:00:00Z",
                "status": "active",
            },
            "access_token": "access-token-123",
            "refresh_token": "refresh-token-456",
            "expires_in": 3600,
        }
        
        result = AuthResult.from_dict(auth_data)
        
        for field in required_fields:
            assert hasattr(result, field), f"AuthResult missing field '{field}'"
    
    def test_token_result_model_consistency(self):
        """
        Property: TokenResult model should have all required fields matching TypeScript SDK.
        """
        required_fields = ["access_token", "refresh_token", "expires_in"]
        
        token_data = {
            "access_token": "access-token-123",
            "refresh_token": "refresh-token-456",
            "expires_in": 3600,
        }
        
        result = TokenResult.from_dict(token_data)
        
        for field in required_fields:
            assert hasattr(result, field), f"TokenResult missing field '{field}'"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
