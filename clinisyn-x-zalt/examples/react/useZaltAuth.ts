/**
 * Clinisyn x Zalt.io - React Hook for Authentication
 * 
 * Kullanım:
 * const { user, login, logout, isLoading, error } = useZaltAuth();
 */

import { useState, useEffect, useCallback } from 'react';

// Configuration
const ZALT_CONFIG = {
  apiUrl: process.env.REACT_APP_ZALT_API_URL || 'https://api.zalt.io',
  realmId: 'clinisyn',
  accessTokenKey: 'zalt_access_token',
  refreshTokenKey: 'zalt_refresh_token',
};

// Types
interface User {
  id: string;
  email: string;
  realmId: string;
}

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
}

interface MfaChallenge {
  sessionId: string;
  methods: string[];
}

interface UseZaltAuthReturn extends AuthState {
  login: (email: string, password: string) => Promise<MfaChallenge | null>;
  logout: () => Promise<void>;
  verifyMfa: (sessionId: string, code: string, method?: string) => Promise<void>;
  refreshSession: () => Promise<boolean>;
  clearError: () => void;
}

// Token utilities
function getStoredTokens() {
  return {
    accessToken: localStorage.getItem(ZALT_CONFIG.accessTokenKey),
    refreshToken: localStorage.getItem(ZALT_CONFIG.refreshTokenKey),
  };
}

function setStoredTokens(accessToken: string, refreshToken: string) {
  localStorage.setItem(ZALT_CONFIG.accessTokenKey, accessToken);
  localStorage.setItem(ZALT_CONFIG.refreshTokenKey, refreshToken);
}

function clearStoredTokens() {
  localStorage.removeItem(ZALT_CONFIG.accessTokenKey);
  localStorage.removeItem(ZALT_CONFIG.refreshTokenKey);
}

function parseToken(token: string): User | null {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return {
      id: payload.sub,
      email: payload.email,
      realmId: payload.realm_id,
    };
  } catch {
    return null;
  }
}

function isTokenExpired(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return Date.now() >= payload.exp * 1000;
  } catch {
    return true;
  }
}

// Hook
export function useZaltAuth(): UseZaltAuthReturn {
  const [state, setState] = useState<AuthState>({
    user: null,
    isLoading: true,
    isAuthenticated: false,
    error: null,
  });

  // Initialize auth state from stored tokens
  useEffect(() => {
    const initAuth = async () => {
      const { accessToken, refreshToken } = getStoredTokens();

      if (!accessToken) {
        setState(prev => ({ ...prev, isLoading: false }));
        return;
      }

      if (isTokenExpired(accessToken)) {
        if (refreshToken) {
          const refreshed = await refreshSession();
          if (!refreshed) {
            clearStoredTokens();
            setState(prev => ({ ...prev, isLoading: false }));
          }
        } else {
          clearStoredTokens();
          setState(prev => ({ ...prev, isLoading: false }));
        }
        return;
      }

      const user = parseToken(accessToken);
      setState({
        user,
        isLoading: false,
        isAuthenticated: !!user,
        error: null,
      });
    };

    initAuth();
  }, []);

  // Login
  const login = useCallback(async (email: string, password: string): Promise<MfaChallenge | null> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await fetch(`${ZALT_CONFIG.apiUrl}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          realm_id: ZALT_CONFIG.realmId,
          email,
          password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMessage = getErrorMessage(data.error?.code);
        setState(prev => ({ ...prev, isLoading: false, error: errorMessage }));
        return null;
      }

      // MFA required
      if (data.mfa_required) {
        setState(prev => ({ ...prev, isLoading: false }));
        return {
          sessionId: data.mfa_session_id,
          methods: data.available_methods,
        };
      }

      // Success
      setStoredTokens(data.tokens.access_token, data.tokens.refresh_token);
      const user = parseToken(data.tokens.access_token);
      
      setState({
        user,
        isLoading: false,
        isAuthenticated: true,
        error: null,
      });

      return null;
    } catch {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: 'Bağlantı hatası. Lütfen tekrar deneyin.',
      }));
      return null;
    }
  }, []);

  // Verify MFA
  const verifyMfa = useCallback(async (sessionId: string, code: string, method = 'totp') => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await fetch(`${ZALT_CONFIG.apiUrl}/v1/auth/mfa/login/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfa_session_id: sessionId,
          code,
          method,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMessage = getErrorMessage(data.error?.code);
        setState(prev => ({ ...prev, isLoading: false, error: errorMessage }));
        return;
      }

      setStoredTokens(data.tokens.access_token, data.tokens.refresh_token);
      const user = parseToken(data.tokens.access_token);

      setState({
        user,
        isLoading: false,
        isAuthenticated: true,
        error: null,
      });
    } catch {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: 'Doğrulama başarısız. Lütfen tekrar deneyin.',
      }));
    }
  }, []);

  // Logout
  const logout = useCallback(async () => {
    const { accessToken } = getStoredTokens();

    if (accessToken) {
      try {
        await fetch(`${ZALT_CONFIG.apiUrl}/logout`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${accessToken}` },
        });
      } catch {
        // Ignore errors
      }
    }

    clearStoredTokens();
    setState({
      user: null,
      isLoading: false,
      isAuthenticated: false,
      error: null,
    });
  }, []);

  // Refresh session
  const refreshSession = useCallback(async (): Promise<boolean> => {
    const { refreshToken } = getStoredTokens();

    if (!refreshToken) {
      return false;
    }

    try {
      const response = await fetch(`${ZALT_CONFIG.apiUrl}/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (!response.ok) {
        clearStoredTokens();
        setState(prev => ({
          ...prev,
          user: null,
          isAuthenticated: false,
        }));
        return false;
      }

      const data = await response.json();
      setStoredTokens(data.tokens.access_token, data.tokens.refresh_token);
      
      const user = parseToken(data.tokens.access_token);
      setState(prev => ({
        ...prev,
        user,
        isAuthenticated: true,
      }));

      return true;
    } catch {
      return false;
    }
  }, []);

  // Clear error
  const clearError = useCallback(() => {
    setState(prev => ({ ...prev, error: null }));
  }, []);

  return {
    ...state,
    login,
    logout,
    verifyMfa,
    refreshSession,
    clearError,
  };
}

// Error message helper
function getErrorMessage(code?: string): string {
  switch (code) {
    case 'INVALID_CREDENTIALS':
      return 'Email veya şifre hatalı.';
    case 'RATE_LIMITED':
      return 'Çok fazla deneme. Lütfen bekleyin.';
    case 'ACCOUNT_LOCKED':
      return 'Hesabınız kilitlendi.';
    case 'INVALID_TOKEN':
      return 'Geçersiz kod.';
    default:
      return 'Bir hata oluştu. Lütfen tekrar deneyin.';
  }
}

export default useZaltAuth;
