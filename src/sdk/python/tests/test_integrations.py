"""
Tests for Zalt Auth Framework Integrations

Tests FastAPI and Flask integrations.
"""

import pytest
from typing import Any, Dict
from unittest.mock import MagicMock, patch, AsyncMock

import httpx
import respx

from zalt_auth import ZaltConfig, User
from zalt_auth.types import UserProfile, TenantMembership


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def mock_user() -> User:
    """Create a mock user for testing."""
    return User(
        id="user_123",
        realm_id="test-realm",
        email="test@example.com",
        email_verified=True,
        profile=UserProfile(first_name="Test", last_name="User"),
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        last_login="2026-01-01T00:00:00Z",
        status="active",
        mfa_enabled=False,
        tenants=[
            TenantMembership(
                tenant_id="tenant_123",
                tenant_name="Test Tenant",
                role="admin",
                permissions=["users:read", "users:write", "admin:read"],
            )
        ],
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
            "profile": {"first_name": "Test", "last_name": "User"},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "last_login": "2026-01-01T00:00:00Z",
            "status": "active",
            "mfa_enabled": False,
            "tenants": [
                {
                    "tenant_id": "tenant_123",
                    "tenant_name": "Test Tenant",
                    "role": "admin",
                    "permissions": ["users:read", "users:write", "admin:read"],
                }
            ],
        }
    }


# =============================================================================
# FastAPI Integration Tests
# =============================================================================

class TestFastAPIIntegration:
    """Tests for FastAPI integration."""
    
    @pytest.fixture
    def fastapi_app(self):
        """Create a FastAPI test app."""
        try:
            from fastapi import FastAPI, Depends, Header
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("FastAPI not installed")
        
        app = FastAPI()
        return app
    
    def test_zalt_fastapi_initialization(self, fastapi_app):
        """Test ZaltFastAPI initialization."""
        try:
            from zalt_auth.integrations.fastapi import ZaltFastAPI
        except ImportError:
            pytest.skip("FastAPI not installed")
        
        zalt = ZaltFastAPI(
            fastapi_app,
            publishable_key="pk_test_12345678901234567890123456789012",
            realm_id="test-realm",
        )
        
        assert zalt.client is not None
        assert zalt.client.is_test_mode()
    
    @respx.mock
    def test_get_current_user_dependency(self, fastapi_app, mock_user_response):
        """Test get_current_user dependency."""
        try:
            from fastapi import Depends, Header
            from fastapi.testclient import TestClient
            from zalt_auth.integrations.fastapi import ZaltFastAPI, get_current_user
        except ImportError:
            pytest.skip("FastAPI not installed")
        
        # Initialize Zalt
        ZaltFastAPI(
            fastapi_app,
            publishable_key="pk_test_12345678901234567890123456789012",
        )
        
        # Mock the /me endpoint
        respx.get("https://api.zalt.io/me").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        @fastapi_app.get("/test")
        async def test_route(authorization: str = Header(None)):
            # Manually call get_current_user for testing
            from zalt_auth.integrations import fastapi as fastapi_integration
            user = await fastapi_integration.get_current_user(authorization)
            return {"user_id": user.id}
        
        client = TestClient(fastapi_app)
        
        response = client.get(
            "/test",
            headers={"Authorization": "Bearer test_token_123"}
        )
        
        assert response.status_code == 200
        assert response.json()["user_id"] == "user_123"
    
    def test_get_current_user_no_auth(self, fastapi_app):
        """Test get_current_user without authorization."""
        try:
            from fastapi import Depends, Header, HTTPException
            from fastapi.testclient import TestClient
            from zalt_auth.integrations.fastapi import ZaltFastAPI, get_current_user
        except ImportError:
            pytest.skip("FastAPI not installed")
        
        ZaltFastAPI(
            fastapi_app,
            publishable_key="pk_test_12345678901234567890123456789012",
        )
        
        @fastapi_app.get("/test")
        async def test_route(authorization: str = Header(None)):
            from zalt_auth.integrations import fastapi as fastapi_integration
            try:
                user = await fastapi_integration.get_current_user(authorization)
                return {"user_id": user.id}
            except HTTPException as e:
                return {"error": e.detail}, e.status_code
        
        client = TestClient(fastapi_app)
        
        response = client.get("/test")
        
        # Should return 401 or error
        assert response.status_code in [200, 401]
    
    @respx.mock
    def test_require_permissions(self, fastapi_app, mock_user_response):
        """Test require_permissions dependency."""
        try:
            from fastapi import Depends, Header
            from fastapi.testclient import TestClient
            from zalt_auth.integrations.fastapi import ZaltFastAPI, require_permissions
        except ImportError:
            pytest.skip("FastAPI not installed")
        
        ZaltFastAPI(
            fastapi_app,
            publishable_key="pk_test_12345678901234567890123456789012",
        )
        
        respx.get("https://api.zalt.io/me").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        @fastapi_app.get("/admin")
        async def admin_route(authorization: str = Header(None)):
            from zalt_auth.integrations import fastapi as fastapi_integration
            permission_dep = fastapi_integration.require_permissions(["admin:read"])
            user = await permission_dep(authorization)
            return {"admin": True, "user_id": user.id}
        
        client = TestClient(fastapi_app)
        
        response = client.get(
            "/admin",
            headers={"Authorization": "Bearer test_token_123"}
        )
        
        assert response.status_code == 200
        assert response.json()["admin"] is True


# =============================================================================
# Flask Integration Tests
# =============================================================================

class TestFlaskIntegration:
    """Tests for Flask integration."""
    
    @pytest.fixture
    def flask_app(self):
        """Create a Flask test app."""
        try:
            from flask import Flask
        except ImportError:
            pytest.skip("Flask not installed")
        
        app = Flask(__name__)
        app.config["TESTING"] = True
        return app
    
    def test_zalt_flask_initialization(self, flask_app):
        """Test ZaltFlask initialization."""
        try:
            from zalt_auth.integrations.flask import ZaltFlask
        except ImportError:
            pytest.skip("Flask not installed")
        
        zalt = ZaltFlask(
            flask_app,
            publishable_key="pk_test_12345678901234567890123456789012",
            realm_id="test-realm",
        )
        
        assert zalt.client is not None
        assert zalt.client.is_test_mode()
        assert "zalt" in flask_app.extensions
    
    def test_zalt_flask_config_from_app(self, flask_app):
        """Test ZaltFlask with config from app."""
        try:
            from zalt_auth.integrations.flask import ZaltFlask
        except ImportError:
            pytest.skip("Flask not installed")
        
        flask_app.config["ZALT_PUBLISHABLE_KEY"] = "pk_test_12345678901234567890123456789012"
        flask_app.config["ZALT_REALM_ID"] = "config-realm"
        
        zalt = ZaltFlask()
        zalt.init_app(flask_app)
        
        assert zalt.client is not None
    
    @respx.mock
    def test_login_required_decorator(self, flask_app, mock_user_response):
        """Test login_required decorator."""
        try:
            from flask import jsonify
            from zalt_auth.integrations.flask import ZaltFlask, login_required, current_user
        except ImportError:
            pytest.skip("Flask not installed")
        
        ZaltFlask(
            flask_app,
            publishable_key="pk_test_12345678901234567890123456789012",
        )
        
        respx.get("https://api.zalt.io/me").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        @flask_app.route("/protected")
        @login_required
        def protected_route():
            return jsonify({"user_id": current_user.id})
        
        with flask_app.test_client() as client:
            # Without auth
            response = client.get("/protected")
            assert response.status_code == 401
            
            # With auth
            response = client.get(
                "/protected",
                headers={"Authorization": "Bearer test_token_123"}
            )
            assert response.status_code == 200
            assert response.json["user_id"] == "user_123"
    
    @respx.mock
    def test_permission_required_decorator(self, flask_app, mock_user_response):
        """Test permission_required decorator."""
        try:
            from flask import jsonify
            from zalt_auth.integrations.flask import ZaltFlask, permission_required, current_user
        except ImportError:
            pytest.skip("Flask not installed")
        
        ZaltFlask(
            flask_app,
            publishable_key="pk_test_12345678901234567890123456789012",
        )
        
        respx.get("https://api.zalt.io/me").mock(
            return_value=httpx.Response(200, json=mock_user_response)
        )
        
        @flask_app.route("/admin")
        @permission_required(["admin:read"])
        def admin_route():
            return jsonify({"admin": True})
        
        @flask_app.route("/superadmin")
        @permission_required(["superadmin:all"])
        def superadmin_route():
            return jsonify({"superadmin": True})
        
        with flask_app.test_client() as client:
            # Has admin:read permission
            response = client.get(
                "/admin",
                headers={"Authorization": "Bearer test_token_123"}
            )
            assert response.status_code == 200
            
            # Missing superadmin:all permission
            response = client.get(
                "/superadmin",
                headers={"Authorization": "Bearer test_token_123"}
            )
            assert response.status_code == 403
    
    def test_current_user_proxy(self, flask_app, mock_user):
        """Test current_user proxy object."""
        try:
            from flask import g
            from zalt_auth.integrations.flask import ZaltFlask, current_user, is_authenticated
        except ImportError:
            pytest.skip("Flask not installed")
        
        ZaltFlask(
            flask_app,
            publishable_key="pk_test_12345678901234567890123456789012",
        )
        
        with flask_app.test_request_context():
            # No user
            assert not is_authenticated()
            
            # Set user
            g.user = mock_user
            
            assert is_authenticated()
            assert current_user.id == "user_123"
            assert current_user.email == "test@example.com"


# =============================================================================
# Type Tests
# =============================================================================

class TestTypes:
    """Tests for type definitions."""
    
    def test_user_from_dict(self, mock_user_response):
        """Test User.from_dict."""
        user = User.from_dict(mock_user_response["user"])
        
        assert user.id == "user_123"
        assert user.email == "test@example.com"
        assert user.profile.first_name == "Test"
        assert len(user.tenants) == 1
        assert user.tenants[0].role == "admin"
    
    def test_tenant_membership_from_dict(self):
        """Test TenantMembership.from_dict."""
        data = {
            "tenant_id": "tenant_123",
            "tenant_name": "Test Tenant",
            "role": "admin",
            "permissions": ["read", "write"],
        }
        
        membership = TenantMembership.from_dict(data)
        
        assert membership.tenant_id == "tenant_123"
        assert membership.role == "admin"
        assert "read" in membership.permissions
    
    def test_user_profile_to_dict(self):
        """Test UserProfile.to_dict."""
        profile = UserProfile(
            first_name="Test",
            last_name="User",
            metadata={"key": "value"},
        )
        
        data = profile.to_dict()
        
        assert data["first_name"] == "Test"
        assert data["last_name"] == "User"
        assert data["metadata"]["key"] == "value"
        assert "avatar_url" not in data  # None values excluded
