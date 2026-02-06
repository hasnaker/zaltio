/**
 * Clinisyn x Zalt.io - Next.js Authentication Client
 * 
 * Kullanım:
 * import { zaltAuth } from './auth-client';
 * 
 * // Login
 * const result = await zaltAuth.login(email, password);
 * 
 * // Logout
 * await zaltAuth.logout();
 */

import { ZALT_CONFIG, ZALT_ENDPOINTS, ZALT_ERROR_CODES, ZaltErrorCode } from './auth-config';

// Types
interface LoginResponse {
  message: string;
  user: {
    id: string;
    email: string;
    email_verified: boolean;
    profile: Record<string, unknown>;
    status: string;
  };
  tokens: {
    access_token: string;
    refresh_token: string;
    expires_in: number;
  };
}

interface MfaRequiredResponse {
  mfa_required: true;
  mfa_session_id: string;
  available_methods: string[];
}

interface ErrorResponse {
  error: {
    code: ZaltErrorCode;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id: string;
  };
}

type LoginResult = LoginResponse | MfaRequiredResponse | ErrorResponse;

// Token storage
const tokenStorage = {
  getAccessToken: (): string | null => {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(ZALT_CONFIG.tokens.accessTokenKey);
  },
  
  getRefreshToken: (): string | null => {
    if (typeof window === 'undefined') return null;
    return localStorage.getItem(ZALT_CONFIG.tokens.refreshTokenKey);
  },
  
  setTokens: (accessToken: string, refreshToken: string): void => {
    if (typeof window === 'undefined') return;
    localStorage.setItem(ZALT_CONFIG.tokens.accessTokenKey, accessToken);
    localStorage.setItem(ZALT_CONFIG.tokens.refreshTokenKey, refreshToken);
  },
  
  clearTokens: (): void => {
    if (typeof window === 'undefined') return;
    localStorage.removeItem(ZALT_CONFIG.tokens.accessTokenKey);
    localStorage.removeItem(ZALT_CONFIG.tokens.refreshTokenKey);
  },
};

// Token utilities
function isTokenExpired(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return Date.now() >= payload.exp * 1000;
  } catch {
    return true;
  }
}

function shouldRefreshToken(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const expiresAt = payload.exp * 1000;
    return expiresAt - Date.now() < ZALT_CONFIG.tokens.refreshThreshold;
  } catch {
    return true;
  }
}

// API client
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${ZALT_CONFIG.apiUrl}${endpoint}`;
  
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    throw data;
  }
  
  return data;
}

async function authenticatedRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  let accessToken = tokenStorage.getAccessToken();
  
  // Token yoksa veya expired ise refresh dene
  if (!accessToken || isTokenExpired(accessToken)) {
    const refreshed = await zaltAuth.refreshTokens();
    if (!refreshed) {
      throw { error: { code: ZALT_ERROR_CODES.INVALID_TOKEN, message: 'Session expired' } };
    }
    accessToken = tokenStorage.getAccessToken();
  }
  // Token yakında expire olacaksa background'da refresh
  else if (shouldRefreshToken(accessToken)) {
    zaltAuth.refreshTokens().catch(console.error);
  }
  
  return apiRequest<T>(endpoint, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`,
    },
  });
}

// Auth client
export const zaltAuth = {
  /**
   * Login with email and password
   */
  async login(email: string, password: string): Promise<LoginResult> {
    const result = await apiRequest<LoginResult>(ZALT_ENDPOINTS.login, {
      method: 'POST',
      body: JSON.stringify({
        realm_id: ZALT_CONFIG.realmId,
        email,
        password,
      }),
    });
    
    // MFA required
    if ('mfa_required' in result && result.mfa_required) {
      return result;
    }
    
    // Success
    if ('tokens' in result) {
      tokenStorage.setTokens(result.tokens.access_token, result.tokens.refresh_token);
    }
    
    return result;
  },
  
  /**
   * Logout current session
   */
  async logout(): Promise<void> {
    const accessToken = tokenStorage.getAccessToken();
    
    if (accessToken) {
      try {
        await apiRequest(ZALT_ENDPOINTS.logout, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${accessToken}` },
        });
      } catch {
        // Ignore errors, clear tokens anyway
      }
    }
    
    tokenStorage.clearTokens();
  },
  
  /**
   * Refresh tokens
   */
  async refreshTokens(): Promise<boolean> {
    const refreshToken = tokenStorage.getRefreshToken();
    
    if (!refreshToken) {
      return false;
    }
    
    try {
      const result = await apiRequest<{ tokens: LoginResponse['tokens'] }>(
        ZALT_ENDPOINTS.refresh,
        {
          method: 'POST',
          body: JSON.stringify({ refresh_token: refreshToken }),
        }
      );
      
      tokenStorage.setTokens(result.tokens.access_token, result.tokens.refresh_token);
      return true;
    } catch {
      tokenStorage.clearTokens();
      return false;
    }
  },
  
  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    const accessToken = tokenStorage.getAccessToken();
    return !!accessToken && !isTokenExpired(accessToken);
  },
  
  /**
   * Get current user from token
   */
  getCurrentUser(): { id: string; email: string; realmId: string } | null {
    const accessToken = tokenStorage.getAccessToken();
    if (!accessToken) return null;
    
    try {
      const payload = JSON.parse(atob(accessToken.split('.')[1]));
      return {
        id: payload.sub,
        email: payload.email,
        realmId: payload.realm_id,
      };
    } catch {
      return null;
    }
  },
  
  // MFA Methods
  mfa: {
    /**
     * Setup TOTP MFA
     */
    async setupTOTP(): Promise<{ secret: string; qr_code?: string }> {
      return authenticatedRequest(ZALT_ENDPOINTS.mfaSetup, {
        method: 'POST',
        body: JSON.stringify({ method: 'totp' }),
      });
    },
    
    /**
     * Verify TOTP code during setup
     */
    async verifyTOTP(code: string): Promise<{ message: string; backup_codes: string[] }> {
      return authenticatedRequest(ZALT_ENDPOINTS.mfaVerify, {
        method: 'POST',
        body: JSON.stringify({ code }),
      });
    },
    
    /**
     * Complete MFA login
     */
    async loginVerify(sessionId: string, code: string, method: string = 'totp'): Promise<LoginResponse> {
      const result = await apiRequest<LoginResponse>(ZALT_ENDPOINTS.mfaLoginVerify, {
        method: 'POST',
        body: JSON.stringify({
          mfa_session_id: sessionId,
          code,
          method,
        }),
      });
      
      tokenStorage.setTokens(result.tokens.access_token, result.tokens.refresh_token);
      return result;
    },
  },
  
  // WebAuthn Methods
  webauthn: {
    /**
     * Check if WebAuthn is supported
     */
    isSupported(): boolean {
      return typeof window !== 'undefined' && !!window.PublicKeyCredential;
    },
    
    /**
     * Get registration options
     */
    async getRegisterOptions(): Promise<PublicKeyCredentialCreationOptions> {
      const response = await authenticatedRequest<{ options: PublicKeyCredentialCreationOptions }>(
        ZALT_ENDPOINTS.webauthnRegisterOptions,
        { method: 'POST' }
      );
      return response.options;
    },
    
    /**
     * List registered credentials
     */
    async listCredentials(): Promise<Array<{ id: string; name: string; created_at: string }>> {
      const response = await authenticatedRequest<{ credentials: Array<{ id: string; name: string; created_at: string }> }>(
        ZALT_ENDPOINTS.webauthnCredentials
      );
      return response.credentials;
    },
  },
  
  // Password Reset
  password: {
    /**
     * Request password reset email
     */
    async requestReset(email: string): Promise<{ message: string }> {
      return apiRequest(ZALT_ENDPOINTS.passwordResetRequest, {
        method: 'POST',
        body: JSON.stringify({
          realm_id: ZALT_CONFIG.realmId,
          email,
        }),
      });
    },
    
    /**
     * Confirm password reset with token
     */
    async confirmReset(token: string, newPassword: string): Promise<{ message: string }> {
      return apiRequest(ZALT_ENDPOINTS.passwordResetConfirm, {
        method: 'POST',
        body: JSON.stringify({
          token,
          new_password: newPassword,
        }),
      });
    },
  },
};

export default zaltAuth;
