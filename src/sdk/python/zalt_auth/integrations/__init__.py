"""
Zalt Auth Framework Integrations

Provides middleware and utilities for popular Python web frameworks.
"""

from .fastapi import (
    ZaltFastAPI,
    get_current_user,
    get_optional_user,
    require_auth,
    require_permissions,
)
from .flask import (
    ZaltFlask,
    login_required,
    permission_required,
    current_user,
)

__all__ = [
    # FastAPI
    "ZaltFastAPI",
    "get_current_user",
    "get_optional_user",
    "require_auth",
    "require_permissions",
    # Flask
    "ZaltFlask",
    "login_required",
    "permission_required",
    "current_user",
]
