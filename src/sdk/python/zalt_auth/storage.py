"""
Zalt Auth SDK Token Storage Implementations

Provides various storage backends for token persistence.
"""

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional


class MemoryStorage:
    """In-memory token storage (default, non-persistent)."""
    
    def __init__(self) -> None:
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._expires_at: float = 0
        self._lock = threading.Lock()
    
    def get_access_token(self) -> Optional[str]:
        """Get the stored access token."""
        with self._lock:
            if self._expires_at > 0 and time.time() >= self._expires_at:
                return None
            return self._access_token
    
    def get_refresh_token(self) -> Optional[str]:
        """Get the stored refresh token."""
        with self._lock:
            return self._refresh_token
    
    def set_tokens(self, access_token: str, refresh_token: str, expires_in: int) -> None:
        """Store tokens with expiration."""
        with self._lock:
            self._access_token = access_token
            self._refresh_token = refresh_token
            self._expires_at = time.time() + expires_in
    
    def clear_tokens(self) -> None:
        """Clear all stored tokens."""
        with self._lock:
            self._access_token = None
            self._refresh_token = None
            self._expires_at = 0
    
    def get_expires_at(self) -> float:
        """Get token expiration timestamp."""
        with self._lock:
            return self._expires_at


class FileStorage:
    """File-based token storage (persistent across restarts)."""
    
    def __init__(self, file_path: Optional[str] = None) -> None:
        """
        Initialize file storage.
        
        Args:
            file_path: Path to token file. Defaults to ~/.zalt/tokens.json
        """
        if file_path:
            self._file_path = Path(file_path)
        else:
            self._file_path = Path.home() / ".zalt" / "tokens.json"
        
        self._lock = threading.Lock()
        self._ensure_directory()
    
    def _ensure_directory(self) -> None:
        """Ensure the storage directory exists."""
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _read_data(self) -> Dict[str, Any]:
        """Read token data from file."""
        try:
            if self._file_path.exists():
                with open(self._file_path, "r") as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
        return {}
    
    def _write_data(self, data: Dict[str, Any]) -> None:
        """Write token data to file."""
        try:
            with open(self._file_path, "w") as f:
                json.dump(data, f)
            # Set restrictive permissions (owner read/write only)
            os.chmod(self._file_path, 0o600)
        except IOError:
            pass
    
    def get_access_token(self) -> Optional[str]:
        """Get the stored access token."""
        with self._lock:
            data = self._read_data()
            expires_at = data.get("expires_at", 0)
            if expires_at > 0 and time.time() >= expires_at:
                return None
            return data.get("access_token")
    
    def get_refresh_token(self) -> Optional[str]:
        """Get the stored refresh token."""
        with self._lock:
            data = self._read_data()
            return data.get("refresh_token")
    
    def set_tokens(self, access_token: str, refresh_token: str, expires_in: int) -> None:
        """Store tokens with expiration."""
        with self._lock:
            data = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": time.time() + expires_in,
            }
            self._write_data(data)
    
    def clear_tokens(self) -> None:
        """Clear all stored tokens."""
        with self._lock:
            try:
                if self._file_path.exists():
                    self._file_path.unlink()
            except IOError:
                pass
    
    def get_expires_at(self) -> float:
        """Get token expiration timestamp."""
        with self._lock:
            data = self._read_data()
            return data.get("expires_at", 0)


class EnvironmentStorage:
    """Environment variable based storage (for serverless/containers)."""
    
    def __init__(
        self,
        access_token_var: str = "ZALT_ACCESS_TOKEN",
        refresh_token_var: str = "ZALT_REFRESH_TOKEN",
    ) -> None:
        self._access_token_var = access_token_var
        self._refresh_token_var = refresh_token_var
        self._expires_at: float = 0
        self._lock = threading.Lock()
    
    def get_access_token(self) -> Optional[str]:
        """Get the stored access token from environment."""
        return os.environ.get(self._access_token_var)
    
    def get_refresh_token(self) -> Optional[str]:
        """Get the stored refresh token from environment."""
        return os.environ.get(self._refresh_token_var)
    
    def set_tokens(self, access_token: str, refresh_token: str, expires_in: int) -> None:
        """Store tokens in environment variables."""
        with self._lock:
            os.environ[self._access_token_var] = access_token
            os.environ[self._refresh_token_var] = refresh_token
            self._expires_at = time.time() + expires_in
    
    def clear_tokens(self) -> None:
        """Clear tokens from environment."""
        with self._lock:
            os.environ.pop(self._access_token_var, None)
            os.environ.pop(self._refresh_token_var, None)
            self._expires_at = 0
    
    def get_expires_at(self) -> float:
        """Get token expiration timestamp."""
        with self._lock:
            return self._expires_at
