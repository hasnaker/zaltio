# FastAPI Integration Guide

Complete guide for integrating Zalt.io with FastAPI applications.

## Installation

```bash
pip install zalt-auth httpx python-jose
```

Or with the Zalt Python SDK:

```bash
pip install zalt-auth[fastapi]
```

## Quick Setup

### 1. Configuration

```python
# config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    zalt_realm_id: str
    zalt_api_url: str = "https://api.zalt.io"
    zalt_public_key: str  # RS256 public key for JWT verification
    
    class Config:
        env_file = ".env"

settings = Settings()
```

### 2. JWT Verification

```python
# auth/jwt.py
from datetime import datetime
from typing import Optional
from jose import jwt, JWTError
from pydantic import BaseModel
from fastapi import HTTPException, status
import httpx

from config import settings

class TokenPayload(BaseModel):
    sub: str  # user_id
    email: str
    realm_id: str
    roles: list[str] = []
    exp: datetime
    iat: datetime

# Cache for JWKS
_jwks_cache: dict = {}
_jwks_cache_time: Optional[datetime] = None
JWKS_CACHE_TTL = 3600  # 1 hour

async def get_jwks() -> dict:
    """Fetch JWKS from Zalt.io with caching."""
    global _jwks_cache, _jwks_cache_time
    
    now = datetime.utcnow()
    if _jwks_cache and _jwks_cache_time:
        if (now - _jwks_cache_time).seconds < JWKS_CACHE_TTL:
            return _jwks_cache
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{settings.zalt_api_url}/.well-known/jwks.json"
        )
        response.raise_for_status()
        _jwks_cache = response.json()
        _jwks_cache_time = now
        return _jwks_cache

def get_public_key(token: str, jwks: dict) -> str:
    """Get the public key for the token's kid."""
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token header"
        )
    
    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing kid header"
        )
    
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Public key not found"
    )

async def verify_token(token: str) -> TokenPayload:
    """Verify JWT token and return payload."""
    try:
        jwks = await get_jwks()
        public_key = get_public_key(token, jwks)
        
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience="zalt.io",
            issuer="zalt.io"
        )
        
        return TokenPayload(**payload)
        
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {str(e)}"
        )
```

### 3. Dependencies

```python
# auth/dependencies.py
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from auth.jwt import verify_token, TokenPayload

security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> TokenPayload:
    """Get current authenticated user from JWT token."""
    token = credentials.credentials
    return await verify_token(token)

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    )
) -> Optional[TokenPayload]:
    """Get current user if authenticated, None otherwise."""
    if not credentials:
        return None
    try:
        return await verify_token(credentials.credentials)
    except HTTPException:
        return None

def require_roles(*required_roles: str):
    """Dependency factory for role-based access control."""
    async def check_roles(
        user: TokenPayload = Depends(get_current_user)
    ) -> TokenPayload:
        if not any(role in user.roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return user
    return check_roles

def require_realm(realm_id: str):
    """Dependency factory for realm validation."""
    async def check_realm(
        user: TokenPayload = Depends(get_current_user)
    ) -> TokenPayload:
        if user.realm_id != realm_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied for this realm"
            )
        return user
    return check_realm
```

### 4. Main Application

```python
# main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from auth.dependencies import get_current_user, get_optional_user, require_roles
from auth.jwt import TokenPayload
from config import settings

app = FastAPI(title="My API with Zalt Auth")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://myapp.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Public endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok"}

# Protected endpoint
@app.get("/api/profile")
async def get_profile(user: TokenPayload = Depends(get_current_user)):
    return {
        "user_id": user.sub,
        "email": user.email,
        "realm_id": user.realm_id,
        "roles": user.roles
    }

# Optional auth endpoint
@app.get("/api/content")
async def get_content(user: TokenPayload | None = Depends(get_optional_user)):
    if user:
        return {"message": f"Hello, {user.email}!", "premium": True}
    return {"message": "Hello, guest!", "premium": False}

# Role-protected endpoint
@app.get("/api/admin/users")
async def list_users(user: TokenPayload = Depends(require_roles("admin", "owner"))):
    # Only admins and owners can access
    return {"users": []}

# Realm-specific endpoint
@app.get("/api/tenant/{tenant_id}/data")
async def get_tenant_data(
    tenant_id: str,
    user: TokenPayload = Depends(get_current_user)
):
    if user.realm_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return {"tenant_id": tenant_id, "data": {}}
```

## Using the Zalt Python SDK

If you installed `zalt-auth[fastapi]`, you can use the built-in integration:

```python
# main.py
from fastapi import FastAPI, Depends
from zalt_auth.integrations.fastapi import (
    ZaltFastAPI,
    get_current_user,
    get_optional_user,
    require_permissions
)
from zalt_auth import User

app = FastAPI()

# Initialize Zalt integration
zalt = ZaltFastAPI(
    app,
    realm_id="your-realm-id",
    api_url="https://api.zalt.io"
)

@app.get("/api/profile")
async def get_profile(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "profile": user.profile
    }

@app.get("/api/admin/settings")
async def admin_settings(
    user: User = Depends(require_permissions("settings:read"))
):
    return {"settings": {}}
```

## Authentication Proxy Routes

Create proxy routes for frontend authentication:

```python
# routes/auth.py
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, EmailStr
import httpx

from config import settings

router = APIRouter(prefix="/auth", tags=["auth"])

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str | None = None
    last_name: str | None = None

class MFAVerifyRequest(BaseModel):
    mfa_session_id: str
    code: str

@router.post("/login")
async def login(request: LoginRequest, response: Response):
    async with httpx.AsyncClient() as client:
        zalt_response = await client.post(
            f"{settings.zalt_api_url}/login",
            json={
                "realm_id": settings.zalt_realm_id,
                "email": request.email,
                "password": request.password
            }
        )
    
    data = zalt_response.json()
    
    if zalt_response.status_code != 200:
        raise HTTPException(
            status_code=zalt_response.status_code,
            detail=data.get("error", {}).get("message", "Login failed")
        )
    
    # MFA required
    if data.get("mfa_required"):
        return {
            "mfa_required": True,
            "mfa_session_id": data["mfa_session_id"]
        }
    
    # Set httpOnly cookies
    response.set_cookie(
        key="access_token",
        value=data["tokens"]["access_token"],
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=data["tokens"]["expires_in"]
    )
    response.set_cookie(
        key="refresh_token",
        value=data["tokens"]["refresh_token"],
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60  # 7 days
    )
    
    return {"user": data["user"]}

@router.post("/register")
async def register(request: RegisterRequest):
    async with httpx.AsyncClient() as client:
        zalt_response = await client.post(
            f"{settings.zalt_api_url}/register",
            json={
                "realm_id": settings.zalt_realm_id,
                "email": request.email,
                "password": request.password,
                "profile": {
                    "first_name": request.first_name,
                    "last_name": request.last_name
                }
            }
        )
    
    data = zalt_response.json()
    
    if zalt_response.status_code != 201:
        raise HTTPException(
            status_code=zalt_response.status_code,
            detail=data.get("error", {}).get("message", "Registration failed")
        )
    
    return {"message": "Registration successful. Please check your email."}

@router.post("/mfa/verify")
async def verify_mfa(request: MFAVerifyRequest, response: Response):
    async with httpx.AsyncClient() as client:
        zalt_response = await client.post(
            f"{settings.zalt_api_url}/mfa/verify",
            json={
                "mfa_session_id": request.mfa_session_id,
                "code": request.code
            }
        )
    
    data = zalt_response.json()
    
    if zalt_response.status_code != 200:
        raise HTTPException(
            status_code=zalt_response.status_code,
            detail=data.get("error", {}).get("message", "MFA verification failed")
        )
    
    # Set cookies
    response.set_cookie(
        key="access_token",
        value=data["tokens"]["access_token"],
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=data["tokens"]["expires_in"]
    )
    response.set_cookie(
        key="refresh_token",
        value=data["tokens"]["refresh_token"],
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60
    )
    
    return {"user": data["user"]}

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"message": "Logged out"}

@router.post("/refresh")
async def refresh_token(response: Response, request: Request):
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")
    
    async with httpx.AsyncClient() as client:
        zalt_response = await client.post(
            f"{settings.zalt_api_url}/refresh",
            json={"refresh_token": refresh_token}
        )
    
    if zalt_response.status_code != 200:
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        raise HTTPException(status_code=401, detail="Token refresh failed")
    
    data = zalt_response.json()
    
    response.set_cookie(
        key="access_token",
        value=data["tokens"]["access_token"],
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=data["tokens"]["expires_in"]
    )
    response.set_cookie(
        key="refresh_token",
        value=data["tokens"]["refresh_token"],
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60
    )
    
    return {"message": "Token refreshed"}
```

## Middleware for Cookie-Based Auth

```python
# middleware/auth.py
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from auth.jwt import verify_token

class AuthMiddleware(BaseHTTPMiddleware):
    """Extract token from cookie and add to Authorization header."""
    
    async def dispatch(self, request: Request, call_next):
        # Skip for public paths
        public_paths = ["/health", "/auth/login", "/auth/register", "/docs", "/openapi.json"]
        if any(request.url.path.startswith(p) for p in public_paths):
            return await call_next(request)
        
        # Check for token in cookie
        access_token = request.cookies.get("access_token")
        
        if access_token and "authorization" not in request.headers:
            # Add to headers for downstream processing
            request.state.user_token = access_token
        
        return await call_next(request)

# Add to app
app.add_middleware(AuthMiddleware)
```

## Rate Limiting

```python
# middleware/ratelimit.py
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict
from datetime import datetime, timedelta
import asyncio

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 100):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests: dict[str, list[datetime]] = defaultdict(list)
        self.lock = asyncio.Lock()
    
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=1)
        
        async with self.lock:
            # Clean old requests
            self.requests[client_ip] = [
                t for t in self.requests[client_ip] if t > window_start
            ]
            
            if len(self.requests[client_ip]) >= self.requests_per_minute:
                raise HTTPException(
                    status_code=429,
                    detail="Too many requests",
                    headers={"Retry-After": "60"}
                )
            
            self.requests[client_ip].append(now)
        
        return await call_next(request)

# Add to app
app.add_middleware(RateLimitMiddleware, requests_per_minute=100)
```

## Audit Logging

```python
# middleware/audit.py
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import json

logger = logging.getLogger("audit")

class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Get user from state if available
        user_id = getattr(request.state, "user_id", None)
        
        # Log the request
        logger.info(json.dumps({
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "user_id": user_id,
            "ip": request.client.host,
            "user_agent": request.headers.get("user-agent")
        }))
        
        return response

app.add_middleware(AuditMiddleware)
```

## Testing

```python
# tests/test_auth.py
import pytest
from fastapi.testclient import TestClient
from jose import jwt
from datetime import datetime, timedelta

from main import app

client = TestClient(app)

# Test keys (use real keys in production)
TEST_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----"""

def create_test_token(
    user_id: str = "test-user",
    email: str = "test@example.com",
    roles: list[str] = None,
    expired: bool = False
) -> str:
    exp = datetime.utcnow() + timedelta(hours=-1 if expired else 1)
    payload = {
        "sub": user_id,
        "email": email,
        "realm_id": "test-realm",
        "roles": roles or [],
        "exp": exp,
        "iat": datetime.utcnow(),
        "aud": "zalt.io",
        "iss": "zalt.io"
    }
    return jwt.encode(payload, TEST_PRIVATE_KEY, algorithm="RS256")

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200

def test_protected_route_without_token():
    response = client.get("/api/profile")
    assert response.status_code == 403  # No credentials

def test_protected_route_with_valid_token():
    token = create_test_token()
    response = client.get(
        "/api/profile",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == "test@example.com"

def test_protected_route_with_expired_token():
    token = create_test_token(expired=True)
    response = client.get(
        "/api/profile",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401

def test_admin_route_without_role():
    token = create_test_token(roles=["user"])
    response = client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403

def test_admin_route_with_role():
    token = create_test_token(roles=["admin"])
    response = client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
```

## Environment Variables

```env
# .env
ZALT_REALM_ID=your-realm-id
ZALT_API_URL=https://api.zalt.io
ZALT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"
```

## Security Best Practices

1. **Always use HTTPS** in production
2. **Store tokens in httpOnly cookies** - not accessible to JavaScript
3. **Validate tokens server-side** - never trust client-side validation
4. **Use rate limiting** - prevent brute force attacks
5. **Audit log all requests** - for compliance and debugging
6. **Validate realm** - ensure users can only access their tenant's data
7. **Use RS256** - asymmetric signing for better security
