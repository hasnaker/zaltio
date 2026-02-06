/**
 * Zalt.io Auth SDK Client
 * @zalt/auth-sdk - Official TypeScript SDK for Zalt.io Authentication Platform
 * 
 * Main client class for Zalt.io authentication operations
 * with automatic token refresh and retry mechanisms
 * 
 * Validates: Requirements 4.1, 4.3, 4.5
 */

import {
  ZaltAuthConfig,
  TokenStorage,
  User,
  AuthResult,
  TokenResult,
  RegisterData,
  LoginCredentials,
  ProfileUpdateData,
  PasswordChangeData,
  EmailVerificationData,
  PasswordResetRequestData,
  PasswordResetConfirmData,
  APISuccessResponse,
  APIErrorResponse,
  MFASetupResult,
  MFAVerifyResult,
  MFAStatus,
  BackupCodesResult,
  WebAuthnRegistrationOptions,
  WebAuthnAuthenticationOptions,
  WebAuthnCredential,
  WebAuthnRegisterResult,
  WebAuthnAuthResult,
  Device,
  DeviceListResult,
  SocialAuthUrlResult,
  SocialCallbackResult
} from './types';
import {
  ZaltAuthError,
  NetworkError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  RateLimitError,
  TokenRefreshError,
  ConfigurationError,
  MFARequiredError,
  AccountLockedError,
  isRetryableError
} from './errors';
import { MemoryStorage } from './storage';

/**
 * Default configuration values
 */
const DEFAULT_CONFIG = {
  timeout: 10000,
  retryAttempts: 3,
  retryDelay: 1000,
  autoRefresh: true,
  refreshThreshold: 300 // 5 minutes before expiry
};

/**
 * Zalt.io Auth Client - Main SDK entry point
 * 
 * @example
 * ```typescript
 * const auth = createZaltClient({
 *   baseUrl: 'https://api.zalt.io/v1',
 *   realmId: 'clinisyn-psychologists'
 * });
 * 
 * // Register a new user
 * await auth.register({
 *   email: 'dr.ayse@clinisyn.com',
 *   password: 'SecurePassword123!'
 * });
 * 
 * // Login
 * const result = await auth.login({
 *   email: 'dr.ayse@clinisyn.com',
 *   password: 'SecurePassword123!'
 * });
 * 
 * // Get current user
 * const user = await auth.getCurrentUser();
 * ```
 */
export class ZaltAuthClient {
  private readonly config: Required<Omit<ZaltAuthConfig, 'storage'>> & { storage: TokenStorage };
  private refreshPromise: Promise<TokenResult> | null = null;
  private tokenExpiresAt: number = 0;

  constructor(config: ZaltAuthConfig) {
    this.validateConfig(config);
    
    this.config = {
      baseUrl: config.baseUrl.replace(/\/$/, ''), // Remove trailing slash
      realmId: config.realmId,
      timeout: config.timeout ?? DEFAULT_CONFIG.timeout,
      retryAttempts: config.retryAttempts ?? DEFAULT_CONFIG.retryAttempts,
      retryDelay: config.retryDelay ?? DEFAULT_CONFIG.retryDelay,
      autoRefresh: config.autoRefresh ?? DEFAULT_CONFIG.autoRefresh,
      refreshThreshold: config.refreshThreshold ?? DEFAULT_CONFIG.refreshThreshold,
      storage: config.storage ?? new MemoryStorage()
    };
  }

  /**
   * Validate configuration
   */
  private validateConfig(config: ZaltAuthConfig): void {
    if (!config.baseUrl) {
      throw new ConfigurationError('baseUrl is required');
    }
    if (!config.realmId) {
      throw new ConfigurationError('realmId is required');
    }
    try {
      new URL(config.baseUrl);
    } catch {
      throw new ConfigurationError('baseUrl must be a valid URL');
    }
  }

  /**
   * Register a new user
   * 
   * @param data - Registration data including email, password, and optional profile
   * @returns Authentication result with tokens and user data
   * @throws ValidationError if email/password is invalid
   * @throws RateLimitError if rate limit exceeded (3/hour/IP)
   */
  async register(data: RegisterData): Promise<AuthResult> {
    const response = await this.request<AuthResult>('/register', {
      method: 'POST',
      body: {
        realm_id: this.config.realmId,
        email: data.email,
        password: data.password,
        profile: data.profile
      },
      requiresAuth: false
    });

    // Store tokens if returned (some flows may require email verification first)
    if (response.access_token && response.refresh_token) {
      await this.storeTokens(response.access_token, response.refresh_token, response.expires_in);
    }

    return response;
  }

  /**
   * Login with email and password
   * 
   * @param credentials - Login credentials
   * @returns Authentication result with tokens and user data
   * @throws AuthenticationError if credentials are invalid
   * @throws MFARequiredError if MFA verification is required
   * @throws AccountLockedError if account is locked
   * @throws RateLimitError if rate limit exceeded (5/15min/IP)
   */
  async login(credentials: LoginCredentials): Promise<AuthResult> {
    const response = await this.request<AuthResult>('/login', {
      method: 'POST',
      body: {
        realm_id: this.config.realmId,
        email: credentials.email,
        password: credentials.password,
        device_fingerprint: credentials.device_fingerprint
      },
      requiresAuth: false
    });

    // Check if MFA is required
    if (response.mfa_required && response.mfa_session_id) {
      throw new MFARequiredError(
        'MFA verification required',
        response.mfa_session_id,
        ['totp', 'webauthn', 'backup_code']
      );
    }

    // Store tokens
    if (response.access_token && response.refresh_token) {
      await this.storeTokens(response.access_token, response.refresh_token, response.expires_in);
    }

    return response;
  }

  /**
   * Refresh the access token
   * Implements automatic token refresh with deduplication
   * 
   * @returns New token result
   * @throws TokenRefreshError if refresh fails
   */
  async refreshToken(): Promise<TokenResult> {
    // Deduplicate concurrent refresh requests
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    // Create the promise immediately to prevent race conditions
    this.refreshPromise = this.doRefreshToken();

    try {
      const result = await this.refreshPromise;
      return result;
    } finally {
      this.refreshPromise = null;
    }
  }

  /**
   * Internal method to perform token refresh
   */
  private async doRefreshToken(): Promise<TokenResult> {
    const refreshToken = await this.config.storage.getRefreshToken();
    if (!refreshToken) {
      throw new TokenRefreshError('No refresh token available');
    }

    return this.performTokenRefresh(refreshToken);
  }

  /**
   * Perform the actual token refresh
   */
  private async performTokenRefresh(refreshToken: string): Promise<TokenResult> {
    try {
      const response = await this.request<TokenResult>('/refresh', {
        method: 'POST',
        body: {
          realm_id: this.config.realmId,
          refresh_token: refreshToken
        },
        requiresAuth: false,
        skipAutoRefresh: true
      });

      // Store new tokens
      await this.storeTokens(response.access_token, response.refresh_token, response.expires_in);

      return response;
    } catch (error) {
      // Clear tokens on refresh failure
      await this.config.storage.clearTokens();
      this.tokenExpiresAt = 0;
      
      if (error instanceof ZaltAuthError) {
        throw new TokenRefreshError(error.message, { originalError: error.code });
      }
      throw new TokenRefreshError('Token refresh failed');
    }
  }

  /**
   * Logout the current user
   * 
   * @param allDevices - If true, logout from all devices
   */
  async logout(allDevices: boolean = false): Promise<void> {
    const accessToken = await this.config.storage.getAccessToken();
    
    if (accessToken) {
      try {
        await this.request<void>('/logout', {
          method: 'POST',
          body: { 
            realm_id: this.config.realmId,
            all_devices: allDevices
          },
          requiresAuth: true,
          skipAutoRefresh: true
        });
      } catch {
        // Ignore errors during logout - we'll clear tokens anyway
      }
    }

    // Clear stored tokens
    await this.config.storage.clearTokens();
    this.tokenExpiresAt = 0;
  }

  /**
   * Get the current authenticated user
   * 
   * @returns User data or null if not authenticated
   */
  async getCurrentUser(): Promise<User | null> {
    const accessToken = await this.config.storage.getAccessToken();
    if (!accessToken) {
      return null;
    }

    try {
      return await this.request<User>('/auth/me', {
        method: 'GET',
        requiresAuth: true
      });
    } catch (error) {
      if (error instanceof AuthenticationError) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Update user profile
   * 
   * @param data - Profile data to update
   * @returns Updated user data
   */
  async updateProfile(data: ProfileUpdateData): Promise<User> {
    return this.request<User>('/auth/me/profile', {
      method: 'PATCH',
      body: data as unknown as Record<string, unknown>,
      requiresAuth: true
    });
  }

  /**
   * Change user password
   * 
   * @param data - Current and new password
   * @throws ValidationError if new password doesn't meet requirements
   * @throws AuthenticationError if current password is wrong
   */
  async changePassword(data: PasswordChangeData): Promise<void> {
    await this.request<void>('/auth/me/password', {
      method: 'POST',
      body: data as unknown as Record<string, unknown>,
      requiresAuth: true
    });
  }

  /**
   * Send email verification code
   */
  async sendVerificationEmail(): Promise<void> {
    await this.request<void>('/v1/auth/verify-email/send', {
      method: 'POST',
      body: { realm_id: this.config.realmId },
      requiresAuth: true
    });
  }

  /**
   * Verify email with code
   * 
   * @param data - Verification code
   */
  async verifyEmail(data: EmailVerificationData): Promise<void> {
    await this.request<void>('/v1/auth/verify-email/confirm', {
      method: 'POST',
      body: { 
        realm_id: this.config.realmId,
        code: data.code 
      },
      requiresAuth: true
    });
  }

  /**
   * Request password reset email
   * 
   * @param data - Email address
   */
  async requestPasswordReset(data: PasswordResetRequestData): Promise<void> {
    await this.request<void>('/v1/auth/password-reset/request', {
      method: 'POST',
      body: {
        realm_id: this.config.realmId,
        email: data.email
      },
      requiresAuth: false
    });
  }

  /**
   * Confirm password reset with token
   * 
   * @param data - Reset token and new password
   */
  async confirmPasswordReset(data: PasswordResetConfirmData): Promise<void> {
    await this.request<void>('/v1/auth/password-reset/confirm', {
      method: 'POST',
      body: {
        realm_id: this.config.realmId,
        token: data.token,
        new_password: data.new_password
      },
      requiresAuth: false
    });
  }

  /**
   * Check if user is authenticated
   * 
   * @returns true if user has valid tokens
   */
  async isAuthenticated(): Promise<boolean> {
    const accessToken = await this.config.storage.getAccessToken();
    if (!accessToken) {
      return false;
    }

    // Check if token is expired
    if (this.isTokenExpired()) {
      // Try to refresh if auto-refresh is enabled
      if (this.config.autoRefresh) {
        try {
          await this.refreshToken();
          return true;
        } catch {
          return false;
        }
      }
      return false;
    }

    return true;
  }

  /**
   * Get the current access token
   * Will auto-refresh if needed and enabled
   * 
   * @returns Access token or null
   */
  async getAccessToken(): Promise<string | null> {
    // Auto-refresh if needed
    if (this.config.autoRefresh && this.shouldRefreshToken()) {
      try {
        await this.refreshToken();
      } catch {
        // Return current token even if refresh fails
      }
    }

    return this.config.storage.getAccessToken();
  }

  /**
   * Store tokens and update expiration
   */
  private async storeTokens(accessToken: string, refreshToken: string, expiresIn: number): Promise<void> {
    await this.config.storage.setTokens(accessToken, refreshToken, expiresIn);
    this.tokenExpiresAt = Date.now() + expiresIn * 1000;
  }

  /**
   * Check if token is expired
   */
  private isTokenExpired(): boolean {
    return this.tokenExpiresAt > 0 && Date.now() >= this.tokenExpiresAt;
  }

  /**
   * Check if token should be refreshed (within threshold)
   */
  private shouldRefreshToken(): boolean {
    if (this.tokenExpiresAt === 0) {
      return false;
    }
    const thresholdMs = this.config.refreshThreshold * 1000;
    return Date.now() >= this.tokenExpiresAt - thresholdMs;
  }

  /**
   * Make HTTP request with retry and error handling
   */
  private async request<T>(
    endpoint: string,
    options: {
      method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
      body?: Record<string, unknown>;
      requiresAuth?: boolean;
      skipAutoRefresh?: boolean;
    }
  ): Promise<T> {
    const { method, body, requiresAuth = false, skipAutoRefresh = false } = options;

    // Auto-refresh token if needed
    if (requiresAuth && !skipAutoRefresh && this.config.autoRefresh && this.shouldRefreshToken()) {
      try {
        await this.refreshToken();
      } catch {
        // Continue with current token
      }
    }

    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt <= this.config.retryAttempts; attempt++) {
      try {
        return await this.executeRequest<T>(endpoint, method, body, requiresAuth);
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry non-retryable errors
        if (!isRetryableError(error)) {
          throw error;
        }

        // Don't retry on last attempt
        if (attempt === this.config.retryAttempts) {
          throw error;
        }

        // Wait before retry with exponential backoff
        const delay = this.config.retryDelay * Math.pow(2, attempt);
        await this.sleep(delay);
      }
    }

    throw lastError || new NetworkError('Request failed after retries');
  }

  /**
   * Execute a single HTTP request
   */
  private async executeRequest<T>(
    endpoint: string,
    method: string,
    body?: Record<string, unknown>,
    requiresAuth?: boolean
  ): Promise<T> {
    const url = `${this.config.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Realm-ID': this.config.realmId
    };

    if (requiresAuth) {
      const accessToken = await this.config.storage.getAccessToken();
      if (!accessToken) {
        throw new AuthenticationError('UNAUTHORIZED', 'No access token available');
      }
      headers['Authorization'] = `Bearer ${accessToken}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      return await this.handleResponse<T>(response);
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof ZaltAuthError) {
        throw error;
      }

      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new NetworkError('Request timeout', { timeout: this.config.timeout });
        }
        throw new NetworkError(error.message);
      }

      throw new NetworkError('Unknown network error');
    }
  }

  /**
   * Handle HTTP response and convert to appropriate result/error
   */
  private async handleResponse<T>(response: Response): Promise<T> {
    const contentType = response.headers.get('content-type');
    const isJson = contentType?.includes('application/json');

    if (response.ok) {
      if (!isJson) {
        return undefined as T;
      }
      const data = await response.json() as APISuccessResponse<T>;
      return data.data as T;
    }

    // Handle error responses
    let errorData: APIErrorResponse | null = null;
    if (isJson) {
      try {
        errorData = await response.json() as APIErrorResponse;
      } catch {
        // Ignore JSON parse errors
      }
    }

    const code = errorData?.error?.code || 'UNKNOWN_ERROR';
    const message = errorData?.error?.message || `HTTP ${response.status}`;
    const details = errorData?.error?.details;
    const requestId = errorData?.error?.request_id;

    switch (response.status) {
      case 400:
        throw new ValidationError(code, message, details, requestId);
      case 401:
        throw new AuthenticationError(code, message, details, requestId);
      case 403:
        // Check for specific error types
        if (code === 'MFA_REQUIRED' && details?.mfa_session_id) {
          throw new MFARequiredError(
            message,
            details.mfa_session_id as string,
            (details.mfa_methods as string[]) || ['totp'],
            requestId
          );
        }
        if (code === 'ACCOUNT_LOCKED') {
          throw new AccountLockedError(message, details?.locked_until as string, requestId);
        }
        throw new AuthorizationError(code, message, details, requestId);
      case 429:
        const retryAfter = parseInt(response.headers.get('retry-after') || '60', 10);
        throw new RateLimitError(message, retryAfter, requestId);
      default:
        throw ZaltAuthError.fromAPIResponse(
          errorData || { error: { code, message, timestamp: new Date().toISOString() } },
          response.status
        );
    }
  }

  /**
   * Sleep utility for retry delays
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get SDK configuration (read-only)
   */
  getConfig(): Readonly<Omit<ZaltAuthConfig, 'storage'>> {
    return {
      baseUrl: this.config.baseUrl,
      realmId: this.config.realmId,
      timeout: this.config.timeout,
      retryAttempts: this.config.retryAttempts,
      retryDelay: this.config.retryDelay,
      autoRefresh: this.config.autoRefresh,
      refreshThreshold: this.config.refreshThreshold
    };
  }

  // ============================================
  // MFA Methods
  // ============================================

  /**
   * MFA namespace for MFA-related operations
   */
  public readonly mfa = {
    /**
     * Setup TOTP MFA - returns QR code and backup codes
     * 
     * @returns MFA setup result with secret, QR code URL, and backup codes
     */
    setup: async (): Promise<MFASetupResult> => {
      return this.request<MFASetupResult>('/v1/auth/mfa/setup', {
        method: 'POST',
        body: { realm_id: this.config.realmId },
        requiresAuth: true
      });
    },

    /**
     * Verify TOTP code to enable MFA
     * 
     * @param code - 6-digit TOTP code from authenticator app
     */
    verify: async (code: string): Promise<void> => {
      await this.request<void>('/v1/auth/mfa/verify', {
        method: 'POST',
        body: { 
          realm_id: this.config.realmId,
          code 
        },
        requiresAuth: true
      });
    },

    /**
     * Disable TOTP MFA (requires password confirmation)
     * 
     * @param password - Current password for confirmation
     */
    disable: async (password: string): Promise<void> => {
      await this.request<void>('/v1/auth/mfa/disable', {
        method: 'DELETE',
        body: { 
          realm_id: this.config.realmId,
          password 
        },
        requiresAuth: true
      });
    },

    /**
     * Verify MFA code during login flow
     * 
     * @param mfaSessionId - MFA session ID from login response
     * @param code - TOTP code or backup code
     * @returns Authentication result with tokens
     */
    verifyLogin: async (mfaSessionId: string, code: string): Promise<MFAVerifyResult> => {
      const response = await this.request<MFAVerifyResult>('/v1/auth/mfa/login/verify', {
        method: 'POST',
        body: {
          realm_id: this.config.realmId,
          mfa_session_id: mfaSessionId,
          code
        },
        requiresAuth: false
      });

      // Store tokens after successful MFA verification
      if (response.access_token && response.refresh_token) {
        await this.storeTokens(response.access_token, response.refresh_token, response.expires_in);
      }

      return response;
    },

    /**
     * Get MFA status for current user
     * 
     * @returns MFA status including enabled methods and backup codes remaining
     */
    getStatus: async (): Promise<MFAStatus> => {
      return this.request<MFAStatus>('/v1/auth/mfa/status', {
        method: 'GET',
        requiresAuth: true
      });
    },

    /**
     * Regenerate backup codes (invalidates old codes)
     * 
     * @param password - Current password for confirmation
     * @returns New backup codes
     */
    regenerateBackupCodes: async (password: string): Promise<BackupCodesResult> => {
      return this.request<BackupCodesResult>('/v1/auth/mfa/backup-codes/regenerate', {
        method: 'POST',
        body: { 
          realm_id: this.config.realmId,
          password 
        },
        requiresAuth: true
      });
    }
  };

  // ============================================
  // WebAuthn Methods (Passkey - Phishing-proof!)
  // ============================================

  /**
   * WebAuthn namespace for passkey operations
   * Required for healthcare realms (Evilginx2 protection)
   */
  public readonly webauthn = {
    /**
     * Get registration options for creating a new passkey
     * 
     * @returns WebAuthn registration options for browser API
     */
    registerOptions: async (): Promise<WebAuthnRegistrationOptions> => {
      return this.request<WebAuthnRegistrationOptions>('/v1/auth/webauthn/register/options', {
        method: 'POST',
        body: { realm_id: this.config.realmId },
        requiresAuth: true
      });
    },

    /**
     * Verify and save the created passkey credential
     * 
     * @param credential - Credential from browser WebAuthn API
     * @param name - Optional friendly name for the credential
     * @returns Registration result
     */
    registerVerify: async (credential: unknown, name?: string): Promise<WebAuthnRegisterResult> => {
      return this.request<WebAuthnRegisterResult>('/v1/auth/webauthn/register/verify', {
        method: 'POST',
        body: {
          realm_id: this.config.realmId,
          credential,
          name
        },
        requiresAuth: true
      });
    },

    /**
     * Get authentication options for passkey login
     * 
     * @param email - Optional email to get user-specific credentials
     * @returns WebAuthn authentication options for browser API
     */
    authenticateOptions: async (email?: string): Promise<WebAuthnAuthenticationOptions> => {
      return this.request<WebAuthnAuthenticationOptions>('/v1/auth/webauthn/authenticate/options', {
        method: 'POST',
        body: { 
          realm_id: this.config.realmId,
          email 
        },
        requiresAuth: false
      });
    },

    /**
     * Verify passkey authentication and get tokens
     * 
     * @param credential - Credential from browser WebAuthn API
     * @returns Authentication result with tokens
     */
    authenticateVerify: async (credential: unknown): Promise<WebAuthnAuthResult> => {
      const response = await this.request<WebAuthnAuthResult>('/v1/auth/webauthn/authenticate/verify', {
        method: 'POST',
        body: {
          realm_id: this.config.realmId,
          credential
        },
        requiresAuth: false
      });

      // Store tokens after successful WebAuthn authentication
      if (response.access_token && response.refresh_token) {
        await this.storeTokens(response.access_token, response.refresh_token, response.expires_in);
      }

      return response;
    },

    /**
     * List all registered passkeys for current user
     * 
     * @returns List of WebAuthn credentials
     */
    listCredentials: async (): Promise<WebAuthnCredential[]> => {
      return this.request<WebAuthnCredential[]>('/v1/auth/webauthn/credentials', {
        method: 'GET',
        requiresAuth: true
      });
    },

    /**
     * Delete a passkey credential
     * 
     * @param credentialId - ID of the credential to delete
     * @param password - Password for confirmation
     */
    deleteCredential: async (credentialId: string, password: string): Promise<void> => {
      await this.request<void>(`/v1/auth/webauthn/credentials/${credentialId}`, {
        method: 'DELETE',
        body: { password },
        requiresAuth: true
      });
    }
  };

  // ============================================
  // Device Management Methods
  // ============================================

  /**
   * Device namespace for device management operations
   */
  public readonly devices = {
    /**
     * List all devices for current user
     * 
     * @returns List of devices with trust status
     */
    list: async (): Promise<Device[]> => {
      const result = await this.request<DeviceListResult>('/auth/devices', {
        method: 'GET',
        requiresAuth: true
      });
      return result.devices;
    },

    /**
     * Revoke/remove a device
     * 
     * @param deviceId - ID of the device to revoke
     */
    revoke: async (deviceId: string): Promise<void> => {
      await this.request<void>(`/auth/devices/${deviceId}`, {
        method: 'DELETE',
        requiresAuth: true
      });
    },

    /**
     * Trust the current device (skip MFA for 30 days)
     */
    trustCurrent: async (): Promise<void> => {
      await this.request<void>('/auth/devices/trust', {
        method: 'POST',
        body: { realm_id: this.config.realmId },
        requiresAuth: true
      });
    }
  };

  // ============================================
  // Social Login Methods
  // ============================================

  /**
   * Social namespace for OAuth social login operations
   * OAuth credentials belong to customer (shows "Clinisyn" not "Zalt.io")
   */
  public readonly social = {
    /**
     * Get OAuth authorization URL for social login
     * 
     * @param provider - OAuth provider ('google' | 'apple')
     * @param redirectUri - Optional custom redirect URI
     * @returns Authorization URL and state
     */
    getAuthUrl: async (provider: 'google' | 'apple', redirectUri?: string): Promise<SocialAuthUrlResult> => {
      return this.request<SocialAuthUrlResult>(`/auth/social/${provider}/authorize`, {
        method: 'GET',
        body: redirectUri ? { redirect_uri: redirectUri } : undefined,
        requiresAuth: false
      });
    },

    /**
     * Handle OAuth callback and exchange code for tokens
     * 
     * @param provider - OAuth provider ('google' | 'apple')
     * @param code - Authorization code from OAuth callback
     * @param state - State parameter from OAuth callback
     * @returns Authentication result with tokens
     */
    handleCallback: async (provider: 'google' | 'apple', code: string, state: string): Promise<SocialCallbackResult> => {
      const response = await this.request<SocialCallbackResult>(`/auth/social/${provider}/callback`, {
        method: 'POST',
        body: {
          realm_id: this.config.realmId,
          code,
          state
        },
        requiresAuth: false
      });

      // Store tokens after successful social login
      if (response.access_token && response.refresh_token) {
        await this.storeTokens(response.access_token, response.refresh_token, response.expires_in);
      }

      return response;
    }
  };
}

/**
 * Create a new Zalt.io Auth client instance
 * 
 * @param config - Client configuration
 * @returns ZaltAuthClient instance
 * 
 * @example
 * ```typescript
 * const auth = createZaltClient({
 *   baseUrl: 'https://api.zalt.io/v1',
 *   realmId: 'clinisyn-psychologists'
 * });
 * ```
 */
export function createZaltClient(config: ZaltAuthConfig): ZaltAuthClient {
  return new ZaltAuthClient(config);
}

// Legacy aliases for backward compatibility
/** @deprecated Use ZaltAuthClient instead */
export const HSDAuthClient = ZaltAuthClient;
/** @deprecated Use createZaltClient instead */
export const createHSDAuthClient = createZaltClient;
