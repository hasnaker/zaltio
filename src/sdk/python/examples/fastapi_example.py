"""
Zalt Auth Python SDK - FastAPI Integration Example

This example demonstrates how to integrate Zalt Auth with FastAPI.

Run with: uvicorn fastapi_example:app --reload
"""

from typing import Optional

# Note: Requires fastapi to be installed
# pip install zalt-auth[fastapi]

try:
    from fastapi import FastAPI, Depends, Header, HTTPException
    from zalt_auth import User
    from zalt_auth.integrations.fastapi import (
        ZaltFastAPI,
        get_current_user,
        get_optional_user,
        require_permissions,
    )
    
    app = FastAPI(
        title="Zalt Auth FastAPI Example",
        description="Example FastAPI app with Zalt authentication",
    )
    
    # Initialize Zalt
    zalt = ZaltFastAPI(
        app,
        publishable_key="pk_test_12345678901234567890123456789012",
        realm_id="example-realm",
        public_paths={"/", "/health", "/docs", "/openapi.json"},
        debug=True,
    )
    
    
    @app.get("/")
    async def root():
        """Public endpoint."""
        return {"message": "Welcome to Zalt Auth FastAPI Example"}
    
    
    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy"}
    
    
    @app.get("/me")
    async def get_me(authorization: str = Header(None)):
        """
        Get current user profile.
        
        Requires: Bearer token in Authorization header
        """
        user = await get_current_user(authorization)
        return {
            "id": user.id,
            "email": user.email,
            "profile": {
                "first_name": user.profile.first_name,
                "last_name": user.profile.last_name,
            },
            "mfa_enabled": user.mfa_enabled,
        }
    
    
    @app.get("/profile")
    async def get_profile(authorization: str = Header(None)):
        """
        Get user profile (optional auth).
        
        Returns user info if authenticated, guest message otherwise.
        """
        user = await get_optional_user(authorization)
        if user:
            return {
                "authenticated": True,
                "message": f"Hello, {user.email}!",
            }
        return {
            "authenticated": False,
            "message": "Hello, guest!",
        }
    
    
    @app.get("/admin")
    async def admin_only(authorization: str = Header(None)):
        """
        Admin-only endpoint.
        
        Requires: admin:read permission
        """
        permission_dep = require_permissions(["admin:read"])
        user = await permission_dep(authorization)
        return {
            "admin": True,
            "user_id": user.id,
            "message": "Welcome, admin!",
        }
    
    
    @app.get("/users")
    async def list_users(authorization: str = Header(None)):
        """
        List users endpoint.
        
        Requires: users:read permission
        """
        permission_dep = require_permissions(["users:read"])
        user = await permission_dep(authorization)
        return {
            "users": [],  # Would fetch from database
            "requested_by": user.id,
        }
    
    
    if __name__ == "__main__":
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)

except ImportError as e:
    print(f"FastAPI not installed. Install with: pip install zalt-auth[fastapi]")
    print(f"Error: {e}")
