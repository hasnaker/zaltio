"""
Zalt Auth Flask Integration

Provides extension, decorators, and utilities for Flask applications.

Usage:
    from flask import Flask, g
    from zalt_auth.integrations.flask import ZaltFlask, login_required, current_user
    
    app = Flask(__name__)
    zalt = ZaltFlask(app, publishable_key="pk_live_xxx")
    
    @app.route("/protected")
    @login_required
    def protected_route():
        return {"user_id": current_user.id}
    
    @app.route("/admin")
    @permission_required(["admin:read"])
    def admin_route():
        return {"admin": True}
"""

import logging
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, TypeVar

from ..client import ZaltClient
from ..types import ZaltConfig, User
from ..errors import AuthenticationError, AuthorizationError, ZaltError

logger = logging.getLogger("zalt_auth.flask")

# Global client instance
_zalt_client: Optional[ZaltClient] = None
_config: Optional[ZaltConfig] = None


def _get_client() -> ZaltClient:
    """Get the global Zalt client."""
    if _zalt_client is None:
        raise RuntimeError(
            "ZaltFlask not initialized. Call ZaltFlask(app, publishable_key=...) first."
        )
    return _zalt_client


class ZaltFlask:
    """
    Flask extension for Zalt Auth.
    
    Initializes the Zalt client and provides utilities for authentication.
    
    Args:
        app: Flask application instance (optional, can use init_app later)
        publishable_key: Zalt publishable API key
        realm_id: Optional realm ID for multi-tenant apps
        base_url: Optional custom API URL
        debug: Enable debug logging
    """
    
    def __init__(
        self,
        app: Optional[Any] = None,  # Flask
        publishable_key: Optional[str] = None,
        realm_id: Optional[str] = None,
        base_url: str = "https://api.zalt.io",
        debug: bool = False,
    ) -> None:
        self.publishable_key = publishable_key
        self.realm_id = realm_id
        self.base_url = base_url
        self.debug = debug
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Any) -> None:
        """Initialize the extension with a Flask app."""
        global _zalt_client, _config
        
        # Get config from app config or constructor
        publishable_key = self.publishable_key or app.config.get("ZALT_PUBLISHABLE_KEY")
        realm_id = self.realm_id or app.config.get("ZALT_REALM_ID")
        base_url = self.base_url or app.config.get("ZALT_BASE_URL", "https://api.zalt.io")
        debug = self.debug or app.config.get("ZALT_DEBUG", False)
        
        if not publishable_key:
            raise ValueError(
                "publishable_key is required. Set ZALT_PUBLISHABLE_KEY in app config "
                "or pass to ZaltFlask constructor."
            )
        
        _config = ZaltConfig(
            publishable_key=publishable_key,
            realm_id=realm_id,
            base_url=base_url,
            debug=debug,
        )
        _zalt_client = ZaltClient(_config)
        
        # Store extension on app
        if not hasattr(app, "extensions"):
            app.extensions = {}
        app.extensions["zalt"] = self
        
        # Register teardown
        app.teardown_appcontext(self._teardown)
        
        # Register before_request to load user
        app.before_request(self._load_user)
        
        logger.info(f"ZaltFlask initialized (test_mode={_zalt_client.is_test_mode()})")
    
    def _teardown(self, exception: Optional[Exception]) -> None:
        """Cleanup on request teardown."""
        pass  # Sync client doesn't need async cleanup
    
    def _load_user(self) -> None:
        """Load user from token before each request."""
        try:
            from flask import request, g
        except ImportError:
            raise ImportError("Flask is required. Install with: pip install flask")
        
        g.user = None
        
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return
        
        token = auth_header[7:]
        
        try:
            client = _get_client()
            client._storage.set_tokens(token, "", 900)
            user = client.fetch_user()
            g.user = user
        except Exception as e:
            logger.debug(f"Failed to load user: {e}")
    
    @property
    def client(self) -> ZaltClient:
        """Get the Zalt client instance."""
        return _get_client()


class _CurrentUserProxy:
    """Proxy object for accessing current user in request context."""
    
    def __getattr__(self, name: str) -> Any:
        try:
            from flask import g
        except ImportError:
            raise ImportError("Flask is required")
        
        user = getattr(g, "user", None)
        if user is None:
            raise AuthenticationError("No authenticated user", "NOT_AUTHENTICATED")
        return getattr(user, name)
    
    def __bool__(self) -> bool:
        try:
            from flask import g
        except ImportError:
            return False
        return getattr(g, "user", None) is not None
    
    def _get_current_user(self) -> Optional[User]:
        """Get the actual user object."""
        try:
            from flask import g
        except ImportError:
            return None
        return getattr(g, "user", None)


# Global proxy for current user
current_user = _CurrentUserProxy()


def login_required(f: Callable) -> Callable:
    """
    Decorator to require authentication for a route.
    
    Usage:
        @app.route("/protected")
        @login_required
        def protected_route():
            return {"user_id": current_user.id}
    """
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        try:
            from flask import g, jsonify
        except ImportError:
            raise ImportError("Flask is required")
        
        if not getattr(g, "user", None):
            return jsonify({"error": "Authentication required"}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


def permission_required(permissions: List[str]) -> Callable:
    """
    Decorator factory to require specific permissions.
    
    Usage:
        @app.route("/admin")
        @permission_required(["admin:read", "admin:write"])
        def admin_route():
            return {"admin": True}
    
    Args:
        permissions: List of required permissions
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            try:
                from flask import g, jsonify
            except ImportError:
                raise ImportError("Flask is required")
            
            user = getattr(g, "user", None)
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            
            # Collect user permissions from all tenants
            user_permissions: Set[str] = set()
            for tenant in user.tenants:
                user_permissions.update(tenant.permissions)
            
            # Check required permissions
            missing = set(permissions) - user_permissions
            if missing:
                return jsonify({
                    "error": "Insufficient permissions",
                    "missing": list(missing)
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator


def get_current_user() -> Optional[User]:
    """
    Get the current authenticated user.
    
    Returns:
        User object if authenticated, None otherwise
    """
    return current_user._get_current_user()


def is_authenticated() -> bool:
    """Check if current request is authenticated."""
    return bool(current_user)
