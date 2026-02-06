"""
Zalt Auth FastAPI Integration

Provides middleware, dependencies, and utilities for FastAPI applications.

Usage:
    from fastapi import FastAPI, Depends
    from zalt_auth.integrations.fastapi import ZaltFastAPI, get_current_user, require_permissions
    
    app = FastAPI()
    zalt = ZaltFastAPI(app, publishable_key="pk_live_xxx")
    
    @app.get("/protected")
    async def protected_route(user = Depends(get_current_user)):
        return {"user_id": user.id}
    
    @app.get("/admin")
    async def admin_route(user = Depends(require_permissions(["admin:read"]))):
        return {"admin": True}
"""

import logging
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, TypeVar, Union

from ..client import ZaltAsyncClient
from ..types import ZaltConfig, User
from ..errors import AuthenticationError, AuthorizationError, ZaltError

logger = logging.getLogger("zalt_auth.fastapi")

# Global client instance (set by ZaltFastAPI)
_zalt_client: Optional[ZaltAsyncClient] = None
_config: Optional[ZaltConfig] = None


def _get_client() -> ZaltAsyncClient:
    """Get the global Zalt client."""
    if _zalt_client is None:
        raise RuntimeError(
            "ZaltFastAPI not initialized. Call ZaltFastAPI(app, publishable_key=...) first."
        )
    return _zalt_client


class ZaltFastAPI:
    """
    FastAPI integration for Zalt Auth.
    
    Initializes the Zalt client and provides middleware for authentication.
    
    Args:
        app: FastAPI application instance
        publishable_key: Zalt publishable API key (pk_live_xxx or pk_test_xxx)
        realm_id: Optional realm ID for multi-tenant apps
        base_url: Optional custom API URL
        public_paths: Set of paths that don't require authentication
        debug: Enable debug logging
    """
    
    def __init__(
        self,
        app: Any,  # FastAPI
        publishable_key: str,
        realm_id: Optional[str] = None,
        base_url: str = "https://api.zalt.io",
        public_paths: Optional[Set[str]] = None,
        debug: bool = False,
    ) -> None:
        global _zalt_client, _config
        
        _config = ZaltConfig(
            publishable_key=publishable_key,
            realm_id=realm_id,
            base_url=base_url,
            debug=debug,
        )
        _zalt_client = ZaltAsyncClient(_config)
        
        self.app = app
        self.public_paths = public_paths or {"/", "/health", "/docs", "/openapi.json", "/redoc"}
        self.debug = debug
        
        # Add startup/shutdown handlers
        app.add_event_handler("shutdown", self._shutdown)
        
        logger.info(f"ZaltFastAPI initialized (test_mode={_zalt_client.is_test_mode()})")
    
    async def _shutdown(self) -> None:
        """Cleanup on app shutdown."""
        global _zalt_client
        if _zalt_client:
            await _zalt_client.close()
            _zalt_client = None
    
    @property
    def client(self) -> ZaltAsyncClient:
        """Get the Zalt client instance."""
        return _get_client()


async def _verify_token(token: str) -> User:
    """Verify JWT token and return user."""
    client = _get_client()
    
    # Store token temporarily for the request
    client._storage.set_tokens(token, "", 900)
    
    try:
        user = await client.fetch_user()
        return user
    except ZaltError as e:
        raise AuthenticationError(f"Invalid token: {e.message}", e.code)


async def get_current_user(
    authorization: Optional[str] = None,
) -> User:
    """
    FastAPI dependency to get the current authenticated user.
    
    Usage:
        @app.get("/me")
        async def get_me(user: User = Depends(get_current_user)):
            return {"id": user.id, "email": user.email}
    
    Raises:
        HTTPException: 401 if not authenticated
    """
    # Import here to avoid circular imports
    try:
        from fastapi import Header, HTTPException
    except ImportError:
        raise ImportError("FastAPI is required. Install with: pip install fastapi")
    
    # Get authorization header
    if authorization is None:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    
    token = authorization[7:]  # Remove "Bearer " prefix
    
    try:
        user = await _verify_token(token)
        return user
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e.message))
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")


async def get_optional_user(
    authorization: Optional[str] = None,
) -> Optional[User]:
    """
    FastAPI dependency to get the current user if authenticated, None otherwise.
    
    Usage:
        @app.get("/public")
        async def public_route(user: Optional[User] = Depends(get_optional_user)):
            if user:
                return {"message": f"Hello, {user.email}"}
            return {"message": "Hello, guest"}
    """
    if authorization is None:
        return None
    
    if not authorization.startswith("Bearer "):
        return None
    
    token = authorization[7:]
    
    try:
        return await _verify_token(token)
    except Exception:
        return None


def require_auth(func: Callable) -> Callable:
    """
    Decorator to require authentication for a route.
    
    Usage:
        @app.get("/protected")
        @require_auth
        async def protected_route(request: Request):
            user = request.state.user
            return {"user_id": user.id}
    """
    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            from fastapi import Request, HTTPException
        except ImportError:
            raise ImportError("FastAPI is required")
        
        # Find request in args or kwargs
        request = None
        for arg in args:
            if isinstance(arg, Request):
                request = arg
                break
        if request is None:
            request = kwargs.get("request")
        
        if request is None:
            raise HTTPException(status_code=500, detail="Request not found")
        
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization required")
        
        token = authorization[7:]
        
        try:
            user = await _verify_token(token)
            request.state.user = user
        except AuthenticationError as e:
            raise HTTPException(status_code=401, detail=str(e.message))
        
        return await func(*args, **kwargs)
    
    return wrapper


def require_permissions(permissions: List[str]) -> Callable:
    """
    FastAPI dependency factory to require specific permissions.
    
    Usage:
        @app.get("/admin")
        async def admin_route(user = Depends(require_permissions(["admin:read", "admin:write"]))):
            return {"admin": True}
    
    Args:
        permissions: List of required permissions (e.g., ["users:read", "users:write"])
    """
    async def dependency(
        authorization: Optional[str] = None,
    ) -> User:
        try:
            from fastapi import Header, HTTPException
        except ImportError:
            raise ImportError("FastAPI is required")
        
        if authorization is None:
            raise HTTPException(status_code=401, detail="Authorization required")
        
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid authorization format")
        
        token = authorization[7:]
        
        try:
            user = await _verify_token(token)
        except AuthenticationError as e:
            raise HTTPException(status_code=401, detail=str(e.message))
        
        # Check permissions from user's tenants
        user_permissions: Set[str] = set()
        for tenant in user.tenants:
            user_permissions.update(tenant.permissions)
        
        # Check if user has all required permissions
        missing = set(permissions) - user_permissions
        if missing:
            raise HTTPException(
                status_code=403,
                detail=f"Missing permissions: {', '.join(missing)}"
            )
        
        return user
    
    return dependency


class ZaltAuthMiddleware:
    """
    ASGI middleware for Zalt authentication.
    
    Automatically validates tokens and adds user to request state.
    
    Usage:
        from fastapi import FastAPI
        from zalt_auth.integrations.fastapi import ZaltAuthMiddleware
        
        app = FastAPI()
        app.add_middleware(ZaltAuthMiddleware, public_paths={"/", "/health"})
    """
    
    def __init__(
        self,
        app: Any,
        public_paths: Optional[Set[str]] = None,
    ) -> None:
        self.app = app
        self.public_paths = public_paths or {"/", "/health", "/docs", "/openapi.json"}
    
    async def __call__(self, scope: Dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        path = scope.get("path", "/")
        
        # Skip auth for public paths
        if path in self.public_paths:
            await self.app(scope, receive, send)
            return
        
        # Get authorization header
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()
        
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                user = await _verify_token(token)
                scope["state"] = scope.get("state", {})
                scope["state"]["user"] = user
            except Exception as e:
                logger.debug(f"Auth failed: {e}")
        
        await self.app(scope, receive, send)
