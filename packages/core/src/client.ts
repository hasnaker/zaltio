/**
 * Zalt Client
 * @zalt/core
 * 
 * Main client for interacting with Zalt API
 */

import type {
  ZaltConfig,
  User,
  AuthResult,
  TokenResult,
  LoginCredentials,
  RegisterData,
  ProfileUpdateData,
  PasswordChangeData,
  PasswordResetRequestData,
  PasswordResetConfirmData,
  AuthState,
  AuthStateChangeCallback,
  AuthStateChangeEvent,
} from './types';
import {
  ZaltError,
  AuthenticationError,
  NetworkError,
  RateLimitError,
  MFARequiredError,
  ConfigurationError,
  createErrorFromResponse,
} from './errors';
import { TokenManager } from './token-manager';
import { createAutoStorage, STORAGE_KEYS } from './storage';

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_BASE_URL = 'https://api.zalt.io';
const DEFAULT_TIMEOUT = 30000;
const MAX_RETRIES = 3;
const RETRY_DELAYS = [1000, 2000, 4000]; // Exponential backoff

// API Key format validation
const PUBLISHABLE_KEY_REGEX = /^pk_(live|test)_[A-Za-z0-9]{32}$/;

/**
 * Validate publishable key format
 */
function isValidPublishableKey(key: string): boolean {
  return PUBLISHABLE_KEY_REGEX.test(key);
}

/**
 * Check if key is for test environment
 */
function isTestKey(key: string): boolean {
  return key.startsWith('pk_test_');
}

// ============================================================================
// ZaltClient
// ============================================================================

/**
 * Main Zalt authentication client
 */
export class ZaltClient {
  private config: {
    publishableKey: string;
    realmId?: string;
    baseUrl: string;
    storage: ReturnType<typeof createAutoStorage>;
    autoRefresh: boolean;
    debug: boolean;
    timeout: number;
    headers?: Record<string, string>;
    isTestMode: boolean;
  };
  private tokenManager: TokenManager;
  private listeners: Set<AuthStateChangeCallback> = new Set();
  private currentUser: User | null = null;
  private isInitialized = false;

  constructor(config: ZaltConfig) {
    if (!config.publishableKey) {
      throw new ConfigurationError('publishableKey is required');
    }

    if (!isValidPublishableKey(config.publishableKey)) {
      throw new ConfigurationError(
        'Invalid publishableKey format. Expected pk_live_xxx or pk_test_xxx with 32 character suffix.'
      );
    }

    this.config = {
      publishableKey: config.publishableKey,
      realmId: config.realmId,
      baseUrl: config.baseUrl || DEFAULT_BASE_URL,
      storage: config.storage || createAutoStorage(),
      autoRefresh: config.autoRefresh ?? true,
      debug: config.debug ?? false,
      timeout: config.timeout ?? DEFAULT_TIMEOUT,
      headers: config.headers,
      isTestMode: isTestKey(config.publishableKey),
    };

    this.tokenManager = new TokenManager({
      storage: this.config.storage,
      onRefresh: () => this.refreshTokenInternal(),
      debug: this.config.debug,
    });

    this.log('ZaltClient initialized with publishableKey:', this.config.publishableKey.substring(0, 12) + '...');
    if (this.config.isTestMode) {
      this.log('⚠️ Running in TEST mode');
    }
  }

  /**
   * Check if client is in test mode
   */
  isTestMode(): boolean {
    return this.config.isTestMode;
  }

  /**
   * Get the publishable key (masked)
   */
  getPublishableKey(): string {
    return this.config.publishableKey.substring(0, 12) + '...';
  }

  // ============================================================================
  // Authentication Methods
  // ============================================================================

  /**
   * Login with email and password
   */
  async login(credentials: LoginCredentials): Promise<AuthResult> {
    this.log('Login attempt for:', credentials.email);

    const response = await this.request<AuthResult>('/login', {
      method: 'POST',
      body: {
        email: credentials.email,
        password: credentials.password,
        device_fingerprint: credentials.deviceFingerprint,
      },
    });

    // Check if MFA is required
    if (response.mfaRequired && response.mfaSessionId) {
      throw new MFARequiredError(response.mfaSessionId, response.mfaMethods);
    }

    // Store tokens and user
    await this.tokenManager.storeTokens(response.tokens);
    await this.storeUser(response.user);
    this.currentUser = response.user;

    this.emit({ type: 'SIGNED_IN', user: response.user });
    this.log('Login successful');

    return response;
  }

  /**
   * Register a new user
   */
  async register(data: RegisterData): Promise<AuthResult> {
    this.log('Register attempt for:', data.email);

    const response = await this.request<AuthResult>('/register', {
      method: 'POST',
      body: {
        email: data.email,
        password: data.password,
        profile: data.profile,
        device_fingerprint: data.deviceFingerprint,
      },
    });

    // Store tokens and user
    await this.tokenManager.storeTokens(response.tokens);
    await this.storeUser(response.user);
    this.currentUser = response.user;

    this.emit({ type: 'SIGNED_IN', user: response.user });
    this.log('Registration successful');

    return response;
  }

  /**
   * Logout current user
   */
  async logout(): Promise<void> {
    this.log('Logout');

    try {
      const token = await this.tokenManager.getAccessToken();
      if (token) {
        // Call logout endpoint to invalidate session
        await this.request('/logout', {
          method: 'POST',
          requireAuth: true,
        }).catch(() => {
          // Ignore errors - we're logging out anyway
        });
      }
    } finally {
      await this.clearSession();
      this.emit({ type: 'SIGNED_OUT' });
    }
  }

  /**
   * Refresh tokens
   */
  async refreshToken(): Promise<TokenResult> {
    return this.tokenManager.refresh();
  }

  /**
   * Get current user
   */
  getUser(): User | null {
    return this.currentUser;
  }

  /**
   * Initialize client and restore session
   */
  async initialize(): Promise<User | null> {
    if (this.isInitialized) {
      return this.currentUser;
    }

    this.log('Initializing client');

    try {
      // Try to restore user from storage
      const storedUser = await this.config.storage.get(STORAGE_KEYS.USER);
      if (storedUser) {
        this.currentUser = JSON.parse(storedUser);
      }

      // Check if we have valid tokens
      const hasTokens = await this.tokenManager.hasTokens();
      if (!hasTokens) {
        this.currentUser = null;
        this.isInitialized = true;
        return null;
      }

      // Verify tokens are still valid by fetching user
      if (this.config.autoRefresh) {
        try {
          const user = await this.fetchCurrentUser();
          this.currentUser = user;
          await this.storeUser(user);
        } catch {
          // Token invalid, clear session
          await this.clearSession();
        }
      }

      this.isInitialized = true;
      return this.currentUser;
    } catch (error) {
      this.log('Initialization error:', error);
      this.isInitialized = true;
      return null;
    }
  }

  // ============================================================================
  // User Methods
  // ============================================================================

  /**
   * Fetch current user from API
   */
  async fetchCurrentUser(): Promise<User> {
    const response = await this.request<{ user: User }>('/me', {
      method: 'GET',
      requireAuth: true,
    });

    this.currentUser = response.user;
    await this.storeUser(response.user);

    return response.user;
  }

  /**
   * Update user profile
   */
  async updateProfile(data: ProfileUpdateData): Promise<User> {
    const response = await this.request<{ user: User }>('/me/profile', {
      method: 'PATCH',
      body: data as unknown as Record<string, unknown>,
      requireAuth: true,
    });

    this.currentUser = response.user;
    await this.storeUser(response.user);
    this.emit({ type: 'USER_UPDATED', user: response.user });

    return response.user;
  }

  /**
   * Change password
   */
  async changePassword(data: PasswordChangeData): Promise<void> {
    await this.request('/me/password', {
      method: 'POST',
      body: data as unknown as Record<string, unknown>,
      requireAuth: true,
    });
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(data: PasswordResetRequestData): Promise<void> {
    await this.request('/password/reset', {
      method: 'POST',
      body: {
        email: data.email,
      },
    });
  }

  /**
   * Confirm password reset
   */
  async confirmPasswordReset(data: PasswordResetConfirmData): Promise<void> {
    await this.request('/password/reset/confirm', {
      method: 'POST',
      body: {
        token: data.token,
        new_password: data.newPassword,
      },
    });
  }

  // ============================================================================
  // Event Handling
  // ============================================================================

  /**
   * Subscribe to auth state changes
   */
  onAuthStateChange(callback: AuthStateChangeCallback): () => void {
    this.listeners.add(callback);
    return () => {
      this.listeners.delete(callback);
    };
  }

  /**
   * Get current auth state
   */
  getAuthState(): AuthState {
    return {
      user: this.currentUser,
      isLoading: false,
      isAuthenticated: this.currentUser !== null,
      error: null,
    };
  }

  // ============================================================================
  // MFA Namespace
  // ============================================================================

  mfa = {
    /**
     * Setup TOTP MFA
     */
    setup: async (method: 'totp' = 'totp') => {
      return this.request<{
        secret: string;
        qrCode: string;
        backupCodes: string[];
        recoveryKey: string;
      }>('/v1/auth/mfa/setup', {
        method: 'POST',
        body: { method },
        requireAuth: true,
      });
    },

    /**
     * Verify MFA code
     */
    verify: async (code: string, sessionId?: string) => {
      return this.request<{ success: boolean; user: User; tokens: TokenResult }>(
        sessionId ? '/v1/auth/mfa/login/verify' : '/v1/auth/mfa/verify',
        {
          method: 'POST',
          body: sessionId ? { mfa_session_id: sessionId, code } : { code },
          requireAuth: !sessionId,
        }
      );
    },

    /**
     * Disable MFA
     */
    disable: async (code: string) => {
      return this.request('/v1/auth/mfa/disable', {
        method: 'POST',
        body: { code },
        requireAuth: true,
      });
    },

    /**
     * Get MFA status
     */
    getStatus: async () => {
      return this.request<{
        enabled: boolean;
        methods: string[];
        backupCodesRemaining: number;
      }>('/v1/auth/mfa/status', {
        method: 'GET',
        requireAuth: true,
      });
    },
  };

  // ============================================================================
  // WebAuthn Namespace
  // ============================================================================

  webauthn = {
    /**
     * Get registration options
     */
    getRegistrationOptions: async () => {
      return this.request<{
        challenge: string;
        rp: { name: string; id: string };
        user: { id: string; name: string; displayName: string };
        pubKeyCredParams: PublicKeyCredentialParameters[];
      }>('/v1/auth/webauthn/register/options', {
        method: 'POST',
        requireAuth: true,
      });
    },

    /**
     * Complete registration
     */
    register: async (credential: PublicKeyCredential, name?: string) => {
      return this.request<{ credential: { id: string; name: string } }>(
        '/v1/auth/webauthn/register/complete',
        {
          method: 'POST',
          body: {
            credential: this.serializeCredential(credential),
            name,
          },
          requireAuth: true,
        }
      );
    },

    /**
     * Get authentication options
     */
    getAuthenticationOptions: async (email?: string) => {
      return this.request<{
        challenge: string;
        rpId: string;
        allowCredentials: PublicKeyCredentialDescriptor[];
      }>('/v1/auth/webauthn/authenticate/options', {
        method: 'POST',
        body: email ? { email } : undefined,
      });
    },

    /**
     * Complete authentication
     */
    authenticate: async (credential: PublicKeyCredential) => {
      const response = await this.request<AuthResult>(
        '/v1/auth/webauthn/authenticate/complete',
        {
          method: 'POST',
          body: {
            credential: this.serializeCredential(credential),
          },
        }
      );

      await this.tokenManager.storeTokens(response.tokens);
      await this.storeUser(response.user);
      this.currentUser = response.user;
      this.emit({ type: 'SIGNED_IN', user: response.user });

      return response;
    },

    /**
     * List registered credentials
     */
    listCredentials: async () => {
      return this.request<{ credentials: Array<{ id: string; name: string; createdAt: string }> }>(
        '/v1/auth/webauthn/credentials',
        {
          method: 'GET',
          requireAuth: true,
        }
      );
    },

    /**
     * Remove credential
     */
    removeCredential: async (credentialId: string) => {
      return this.request(`/v1/auth/webauthn/credentials/${credentialId}`, {
        method: 'DELETE',
        requireAuth: true,
      });
    },
  };

  // ============================================================================
  // SMS MFA Namespace (Optional - with risk acceptance)
  // ============================================================================

  sms = {
    /**
     * Setup SMS MFA
     * Note: SMS MFA is available but less secure than TOTP/WebAuthn due to SS7 vulnerabilities
     */
    setup: async (phoneNumber: string) => {
      return this.request<{
        phoneNumber: string;
        verificationRequired: boolean;
      }>('/v1/auth/mfa/sms/setup', {
        method: 'POST',
        body: { phone_number: phoneNumber },
        requireAuth: true,
      });
    },

    /**
     * Verify SMS code
     */
    verify: async (code: string, sessionId?: string) => {
      return this.request<{ success: boolean; user: User; tokens: TokenResult }>(
        sessionId ? '/v1/auth/mfa/sms/login/verify' : '/v1/auth/mfa/sms/verify',
        {
          method: 'POST',
          body: sessionId ? { mfa_session_id: sessionId, code } : { code },
          requireAuth: !sessionId,
        }
      );
    },

    /**
     * Disable SMS MFA
     */
    disable: async (code: string) => {
      return this.request('/v1/auth/mfa/sms/disable', {
        method: 'POST',
        body: { code },
        requireAuth: true,
      });
    },
  };

  // ============================================================================
  // Private Methods
  // ============================================================================

  private async request<T>(
    path: string,
    options: {
      method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
      body?: Record<string, unknown>;
      requireAuth?: boolean;
      retry?: number;
    }
  ): Promise<T> {
    const { method, body, requireAuth = false, retry = 0 } = options;
    const url = `${this.config.baseUrl}${path}`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-API-Key': this.config.publishableKey,
      ...this.config.headers,
    };

    if (requireAuth) {
      const token = await this.tokenManager.getAccessToken();
      if (!token) {
        throw new AuthenticationError('No access token available', 'SESSION_EXPIRED');
      }
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

      this.log(`${method} ${path}`, body ? JSON.stringify(body).substring(0, 100) : '');

      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        const error = createErrorFromResponse(response.status, errorBody);

        // Handle specific errors
        if (error instanceof RateLimitError && retry < MAX_RETRIES) {
          await this.delay(RETRY_DELAYS[retry] || 4000);
          return this.request(path, { ...options, retry: retry + 1 });
        }

        throw error;
      }

      return response.json();
    } catch (error) {
      if (error instanceof ZaltError) {
        throw error;
      }

      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new NetworkError('Request timeout', true);
        }
        
        // Network error - retry
        if (retry < MAX_RETRIES) {
          await this.delay(RETRY_DELAYS[retry] || 4000);
          return this.request(path, { ...options, retry: retry + 1 });
        }

        throw new NetworkError(error.message, false);
      }

      throw new NetworkError('Unknown error', false);
    }
  }

  private async refreshTokenInternal(): Promise<TokenResult> {
    const refreshToken = await this.tokenManager.getRefreshToken();
    if (!refreshToken) {
      throw new AuthenticationError('No refresh token available', 'SESSION_EXPIRED');
    }

    const response = await this.request<{ tokens: TokenResult }>('/refresh', {
      method: 'POST',
      body: { refresh_token: refreshToken },
    });

    this.emit({ type: 'TOKEN_REFRESHED' });
    return response.tokens;
  }

  private async storeUser(user: User): Promise<void> {
    await this.config.storage.set(STORAGE_KEYS.USER, JSON.stringify(user));
  }

  private async clearSession(): Promise<void> {
    await this.tokenManager.clearTokens();
    await this.config.storage.remove(STORAGE_KEYS.USER);
    this.currentUser = null;
  }

  private emit(event: AuthStateChangeEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch (error) {
        this.log('Event listener error:', error);
      }
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private serializeCredential(credential: PublicKeyCredential): Record<string, unknown> {
    const response = credential.response as AuthenticatorAttestationResponse | AuthenticatorAssertionResponse;
    
    return {
      id: credential.id,
      rawId: this.arrayBufferToBase64(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: this.arrayBufferToBase64(response.clientDataJSON),
        ...('attestationObject' in response && {
          attestationObject: this.arrayBufferToBase64(response.attestationObject),
        }),
        ...('authenticatorData' in response && {
          authenticatorData: this.arrayBufferToBase64(response.authenticatorData),
          signature: this.arrayBufferToBase64((response as AuthenticatorAssertionResponse).signature),
          userHandle: (response as AuthenticatorAssertionResponse).userHandle
            ? this.arrayBufferToBase64((response as AuthenticatorAssertionResponse).userHandle!)
            : null,
        }),
      },
    };
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private log(...args: unknown[]): void {
    if (this.config.debug) {
      console.log('[Zalt]', ...args);
    }
  }
}

// ============================================================================
// Factory Function
// ============================================================================

/**
 * Create a new Zalt client
 */
export function createZaltClient(config: ZaltConfig): ZaltClient {
  return new ZaltClient(config);
}

// Legacy alias
export { ZaltClient as HSDAuthClient };
export const createHSDAuthClient = createZaltClient;
