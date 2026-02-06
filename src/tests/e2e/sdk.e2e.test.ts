/**
 * Zalt.io Auth SDK E2E Tests
 * @zalt/auth-sdk - Official TypeScript SDK for Zalt.io Authentication Platform
 * 
 * End-to-end tests for SDK core functionality
 * Tests the SDK against mock API responses simulating real scenarios
 */

import { 
  ZaltAuthClient, 
  createZaltClient,
  MemoryStorage,
  BrowserStorage,
  SessionStorage,
  CustomStorage,
  ZaltAuthError,
  NetworkError,
  AuthenticationError,
  ValidationError,
  RateLimitError,
  TokenRefreshError,
  ConfigurationError,
  MFARequiredError,
  AccountLockedError,
  isZaltAuthError,
  isRetryableError
} from '../../sdk';

/**
 * Mock fetch helper - uses any to avoid TypeScript Response type issues in tests
 */
const createMockFetch = (handler: (url: string, options?: RequestInit) => Promise<unknown>) => {
  return jest.fn().mockImplementation(handler);
};

/**
 * Create standard API response
 */
const createApiResponse = (status: number, data: unknown, headers?: Record<string, string>): unknown => ({
  ok: status >= 200 && status < 300,
  status,
  headers: new Map([
    ['content-type', 'application/json'],
    ...Object.entries(headers || {})
  ]),
  json: () => Promise.resolve(data)
});

/**
 * Create mock user
 */
const createMockUser = (overrides: Partial<{
  id: string;
  realm_id: string;
  email: string;
  email_verified: boolean;
  mfa_enabled: boolean;
}> = {}) => ({
  id: overrides.id || 'user-123',
  realm_id: overrides.realm_id || 'clinisyn-psychologists',
  email: overrides.email || 'dr.ayse@clinisyn.com',
  email_verified: overrides.email_verified ?? true,
  profile: { first_name: 'Ayşe', last_name: 'Yılmaz', metadata: {} },
  created_at: '2026-01-15T10:00:00Z',
  updated_at: '2026-01-15T10:00:00Z',
  last_login: '2026-01-15T10:00:00Z',
  status: 'active' as const,
  mfa_enabled: overrides.mfa_enabled ?? false,
  webauthn_enabled: false
});

describe('Zalt.io SDK E2E Tests', () => {
  let originalFetch: typeof global.fetch;

  beforeAll(() => {
    originalFetch = global.fetch;
  });

  afterAll(() => {
    global.fetch = originalFetch;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('SDK Initialization', () => {
    it('should create client with minimal config', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });
      
      expect(client).toBeInstanceOf(ZaltAuthClient);
      expect(client.getConfig().baseUrl).toBe('https://api.zalt.io/v1');
      expect(client.getConfig().realmId).toBe('clinisyn-psychologists');
    });

    it('should create client with custom storage', () => {
      const storage = new MemoryStorage();
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });
      
      expect(client).toBeInstanceOf(ZaltAuthClient);
    });

    it('should throw ConfigurationError for invalid baseUrl', () => {
      expect(() => createZaltClient({
        baseUrl: 'not-a-valid-url',
        realmId: 'test'
      })).toThrow(ConfigurationError);
    });

    it('should throw ConfigurationError for missing realmId', () => {
      expect(() => createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: ''
      })).toThrow(ConfigurationError);
    });

    it('should normalize baseUrl by removing trailing slash', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1/',
        realmId: 'test'
      });
      
      expect(client.getConfig().baseUrl).toBe('https://api.zalt.io/v1');
    });
  });

  describe('User Registration Flow', () => {
    it('should register new user successfully', async () => {
      const mockUser = createMockUser();
      
      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/register')) {
          return createApiResponse(200, {
            data: {
              user: mockUser,
              access_token: 'access-token-123',
              refresh_token: 'refresh-token-123',
              expires_in: 900
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const storage = new MemoryStorage();
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const result = await client.register({
        email: 'dr.ayse@clinisyn.com',
        password: 'SecurePassword123!',
        profile: { first_name: 'Ayşe', last_name: 'Yılmaz' }
      });

      expect(result.user.email).toBe('dr.ayse@clinisyn.com');
      expect(result.access_token).toBe('access-token-123');
      expect(await storage.getAccessToken()).toBe('access-token-123');
      expect(await storage.getRefreshToken()).toBe('refresh-token-123');
    });

    it('should handle registration with weak password', async () => {
      global.fetch = createMockFetch(async () => {
        return createApiResponse(400, {
          error: {
            code: 'WEAK_PASSWORD',
            message: 'Password does not meet security requirements',
            details: { requirements: ['min 12 characters', 'uppercase', 'lowercase', 'number'] },
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      await expect(client.register({
        email: 'test@example.com',
        password: 'weak'
      })).rejects.toThrow(ValidationError);
    });

    it('should handle registration with existing email', async () => {
      global.fetch = createMockFetch(async () => {
        return createApiResponse(400, {
          error: {
            code: 'EMAIL_EXISTS',
            message: 'Email already registered',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      await expect(client.register({
        email: 'existing@example.com',
        password: 'SecurePassword123!'
      })).rejects.toThrow(ValidationError);
    });

    it('should handle rate limiting on registration', async () => {
      global.fetch = createMockFetch(async () => {
        return createApiResponse(429, {
          error: {
            code: 'RATE_LIMITED',
            message: 'Too many registration attempts',
            timestamp: new Date().toISOString()
          }
        }, { 'retry-after': '3600' });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        retryAttempts: 0
      });

      try {
        await client.register({
          email: 'test@example.com',
          password: 'SecurePassword123!'
        });
        fail('Should have thrown RateLimitError');
      } catch (error) {
        expect(error).toBeInstanceOf(RateLimitError);
        expect((error as RateLimitError).retryAfter).toBe(3600);
      }
    });
  });

  describe('User Login Flow', () => {
    it('should login successfully without MFA', async () => {
      const mockUser = createMockUser();
      
      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/login')) {
          return createApiResponse(200, {
            data: {
              user: mockUser,
              access_token: 'access-token-456',
              refresh_token: 'refresh-token-456',
              expires_in: 900
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const storage = new MemoryStorage();
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const result = await client.login({
        email: 'dr.ayse@clinisyn.com',
        password: 'SecurePassword123!'
      });

      expect(result.user.email).toBe('dr.ayse@clinisyn.com');
      expect(result.access_token).toBe('access-token-456');
      expect(await client.isAuthenticated()).toBe(true);
    });

    it('should handle MFA required response', async () => {
      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/login')) {
          return createApiResponse(200, {
            data: {
              mfa_required: true,
              mfa_session_id: 'mfa-session-789'
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      try {
        await client.login({
          email: 'dr.ayse@clinisyn.com',
          password: 'SecurePassword123!'
        });
        fail('Should have thrown MFARequiredError');
      } catch (error) {
        expect(error).toBeInstanceOf(MFARequiredError);
        expect((error as MFARequiredError).mfaSessionId).toBe('mfa-session-789');
        expect((error as MFARequiredError).mfaMethods).toContain('totp');
      }
    });

    it('should handle invalid credentials', async () => {
      global.fetch = createMockFetch(async () => {
        return createApiResponse(401, {
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Invalid email or password',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      await expect(client.login({
        email: 'wrong@example.com',
        password: 'WrongPassword'
      })).rejects.toThrow(AuthenticationError);
    });

    it('should handle account lockout', async () => {
      global.fetch = createMockFetch(async () => {
        return createApiResponse(403, {
          error: {
            code: 'ACCOUNT_LOCKED',
            message: 'Account is locked due to too many failed attempts',
            details: { locked_until: '2026-01-15T11:00:00Z' },
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      try {
        await client.login({
          email: 'locked@example.com',
          password: 'Password123!'
        });
        fail('Should have thrown AccountLockedError');
      } catch (error) {
        expect(error).toBeInstanceOf(AccountLockedError);
        expect((error as AccountLockedError).lockedUntil).toBe('2026-01-15T11:00:00Z');
      }
    });

    it('should handle login rate limiting', async () => {
      global.fetch = createMockFetch(async () => {
        return createApiResponse(429, {
          error: {
            code: 'RATE_LIMITED',
            message: 'Too many login attempts',
            timestamp: new Date().toISOString()
          }
        }, { 'retry-after': '900' });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        retryAttempts: 0
      });

      try {
        await client.login({
          email: 'test@example.com',
          password: 'Password123!'
        });
        fail('Should have thrown RateLimitError');
      } catch (error) {
        expect(error).toBeInstanceOf(RateLimitError);
        expect((error as RateLimitError).retryAfter).toBe(900);
      }
    });

    it('should include device fingerprint in login request', async () => {
      let capturedBody: Record<string, unknown> = {};
      
      global.fetch = createMockFetch(async (url, options) => {
        if (url.includes('/auth/login') && options?.body) {
          capturedBody = JSON.parse(options.body as string) as Record<string, unknown>;
          return createApiResponse(200, {
            data: {
              user: createMockUser(),
              access_token: 'token',
              refresh_token: 'refresh',
              expires_in: 900
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      await client.login({
        email: 'test@example.com',
        password: 'Password123!',
        device_fingerprint: {
          userAgent: 'Mozilla/5.0',
          screen: '1920x1080',
          timezone: 'Europe/Istanbul',
          language: 'tr-TR',
          platform: 'MacIntel'
        }
      });

      expect(capturedBody.device_fingerprint).toEqual({
        userAgent: 'Mozilla/5.0',
        screen: '1920x1080',
        timezone: 'Europe/Istanbul',
        language: 'tr-TR',
        platform: 'MacIntel'
      });
    });
  });

  describe('Token Refresh Flow', () => {
    it('should refresh tokens successfully', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('old-access', 'old-refresh', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/refresh')) {
          return createApiResponse(200, {
            data: {
              access_token: 'new-access-token',
              refresh_token: 'new-refresh-token',
              expires_in: 900
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const result = await client.refreshToken();

      expect(result.access_token).toBe('new-access-token');
      expect(result.refresh_token).toBe('new-refresh-token');
      expect(await storage.getAccessToken()).toBe('new-access-token');
      expect(await storage.getRefreshToken()).toBe('new-refresh-token');
    });

    it('should handle expired refresh token', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('old-access', 'expired-refresh', 3600);

      global.fetch = createMockFetch(async () => {
        return createApiResponse(401, {
          error: {
            code: 'TOKEN_EXPIRED',
            message: 'Refresh token has expired',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await expect(client.refreshToken()).rejects.toThrow(TokenRefreshError);
      
      // Tokens should be cleared
      expect(await storage.getAccessToken()).toBeNull();
      expect(await storage.getRefreshToken()).toBeNull();
    });

    it('should throw error when no refresh token available', async () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      await expect(client.refreshToken()).rejects.toThrow(TokenRefreshError);
      await expect(client.refreshToken()).rejects.toThrow('No refresh token available');
    });

    it('should deduplicate concurrent refresh requests', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('old-access', 'old-refresh', 3600);

      let refreshCallCount = 0;
      
      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/refresh')) {
          refreshCallCount++;
          // Simulate network delay
          await new Promise(resolve => setTimeout(resolve, 50));
          return createApiResponse(200, {
            data: {
              access_token: 'new-access',
              refresh_token: 'new-refresh',
              expires_in: 900
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      // Fire multiple concurrent refresh requests
      const results = await Promise.all([
        client.refreshToken(),
        client.refreshToken(),
        client.refreshToken()
      ]);

      // All should return same result
      results.forEach(result => {
        expect(result.access_token).toBe('new-access');
      });

      // Only one actual API call should be made
      expect(refreshCallCount).toBe(1);
    });

    it('should auto-refresh token before expiry', async () => {
      const storage = new MemoryStorage();
      let refreshCalled = false;

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/login')) {
          return createApiResponse(200, {
            data: {
              user: createMockUser(),
              access_token: 'short-lived-token',
              refresh_token: 'refresh-token',
              expires_in: 1 // 1 second expiry
            }
          });
        }
        if (url.includes('/auth/refresh')) {
          refreshCalled = true;
          return createApiResponse(200, {
            data: {
              access_token: 'new-token',
              refresh_token: 'new-refresh',
              expires_in: 900
            }
          });
        }
        if (url.includes('/auth/me')) {
          return createApiResponse(200, { data: createMockUser() });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage,
        autoRefresh: true,
        refreshThreshold: 300 // 5 minutes threshold
      });

      // Login with short-lived token
      await client.login({ email: 'test@example.com', password: 'password' });

      // Wait a bit for token to be "expiring soon"
      await new Promise(resolve => setTimeout(resolve, 10));

      // Make authenticated request - should trigger auto-refresh
      await client.getCurrentUser();

      expect(refreshCalled).toBe(true);
      expect(await storage.getAccessToken()).toBe('new-token');
    });
  });

  describe('Logout Flow', () => {
    it('should logout and clear tokens', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/logout')) {
          return createApiResponse(200, { data: { success: true } });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await client.logout();

      expect(await storage.getAccessToken()).toBeNull();
      expect(await storage.getRefreshToken()).toBeNull();
      expect(await client.isAuthenticated()).toBe(false);
    });

    it('should logout from all devices', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);
      let capturedBody: Record<string, unknown> = {};

      global.fetch = createMockFetch(async (url, options) => {
        if (url.includes('/auth/logout') && options?.body) {
          capturedBody = JSON.parse(options.body as string) as Record<string, unknown>;
          return createApiResponse(200, { data: { success: true } });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await client.logout(true);

      expect(capturedBody.all_devices).toBe(true);
      expect(await storage.getAccessToken()).toBeNull();
    });

    it('should clear tokens even if logout API fails', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async () => {
        return createApiResponse(500, {
          error: {
            code: 'SERVER_ERROR',
            message: 'Internal server error',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage,
        retryAttempts: 0
      });

      // Should not throw
      await client.logout();

      // Tokens should still be cleared
      expect(await storage.getAccessToken()).toBeNull();
      expect(await storage.getRefreshToken()).toBeNull();
    });

    it('should not make API call if no access token', async () => {
      let apiCalled = false;

      global.fetch = createMockFetch(async () => {
        apiCalled = true;
        return createApiResponse(200, { data: {} });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      await client.logout();

      expect(apiCalled).toBe(false);
    });
  });

  describe('Get Current User', () => {
    it('should return user when authenticated', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('valid-token', 'refresh-token', 3600);
      const mockUser = createMockUser();

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/me')) {
          return createApiResponse(200, { data: mockUser });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const user = await client.getCurrentUser();

      expect(user).not.toBeNull();
      expect(user?.email).toBe('dr.ayse@clinisyn.com');
      expect(user?.profile.first_name).toBe('Ayşe');
    });

    it('should return null when not authenticated', async () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      const user = await client.getCurrentUser();

      expect(user).toBeNull();
    });

    it('should return null on authentication error', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('invalid-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async () => {
        return createApiResponse(401, {
          error: {
            code: 'INVALID_TOKEN',
            message: 'Token is invalid or expired',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const user = await client.getCurrentUser();

      expect(user).toBeNull();
    });
  });

  describe('Email Verification', () => {
    it('should send verification email', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/verify-email/send')) {
          return createApiResponse(200, { data: { message: 'Verification email sent' } });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await expect(client.sendVerificationEmail()).resolves.toBeUndefined();
    });

    it('should verify email with code', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/verify-email/confirm')) {
          return createApiResponse(200, { data: { email_verified: true } });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await expect(client.verifyEmail({ code: '123456' })).resolves.toBeUndefined();
    });

    it('should handle invalid verification code', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async () => {
        return createApiResponse(400, {
          error: {
            code: 'INVALID_CODE',
            message: 'Verification code is invalid or expired',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await expect(client.verifyEmail({ code: 'wrong' })).rejects.toThrow(ValidationError);
    });
  });

  describe('Password Reset', () => {
    it('should request password reset', async () => {
      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/password-reset/request')) {
          return createApiResponse(200, { data: { message: 'Reset email sent' } });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      await expect(client.requestPasswordReset({ email: 'test@example.com' })).resolves.toBeUndefined();
    });

    it('should confirm password reset', async () => {
      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/password-reset/confirm')) {
          return createApiResponse(200, { data: { success: true } });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      await expect(client.confirmPasswordReset({
        token: 'reset-token-123',
        new_password: 'NewSecurePassword123!'
      })).resolves.toBeUndefined();
    });

    it('should handle invalid reset token', async () => {
      global.fetch = createMockFetch(async () => {
        return createApiResponse(400, {
          error: {
            code: 'INVALID_TOKEN',
            message: 'Reset token is invalid or expired',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      await expect(client.confirmPasswordReset({
        token: 'invalid-token',
        new_password: 'NewPassword123!'
      })).rejects.toThrow(ValidationError);
    });

    it('should handle rate limiting on password reset', async () => {
      global.fetch = createMockFetch(async () => {
        return createApiResponse(429, {
          error: {
            code: 'RATE_LIMITED',
            message: 'Too many password reset attempts',
            timestamp: new Date().toISOString()
          }
        }, { 'retry-after': '3600' });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        retryAttempts: 0
      });

      await expect(client.requestPasswordReset({ email: 'test@example.com' })).rejects.toThrow(RateLimitError);
    });
  });

  describe('Profile Management', () => {
    it('should update user profile', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);
      const updatedUser = createMockUser();
      updatedUser.profile.first_name = 'Updated';
      updatedUser.profile.last_name = 'Name';

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/me/profile')) {
          return createApiResponse(200, { data: updatedUser });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const result = await client.updateProfile({
        first_name: 'Updated',
        last_name: 'Name'
      });

      expect(result.profile.first_name).toBe('Updated');
      expect(result.profile.last_name).toBe('Name');
    });

    it('should change password', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/me/password')) {
          return createApiResponse(200, { data: { success: true } });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await expect(client.changePassword({
        current_password: 'OldPassword123!',
        new_password: 'NewSecurePassword123!'
      })).resolves.toBeUndefined();
    });

    it('should handle wrong current password', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async () => {
        return createApiResponse(401, {
          error: {
            code: 'INVALID_PASSWORD',
            message: 'Current password is incorrect',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await expect(client.changePassword({
        current_password: 'WrongPassword',
        new_password: 'NewPassword123!'
      })).rejects.toThrow(AuthenticationError);
    });
  });

  describe('Storage Implementations', () => {
    it('should work with MemoryStorage', async () => {
      const storage = new MemoryStorage();
      
      expect(storage.getAccessToken()).toBeNull();
      expect(storage.getRefreshToken()).toBeNull();

      storage.setTokens('access', 'refresh', 3600);
      
      expect(storage.getAccessToken()).toBe('access');
      expect(storage.getRefreshToken()).toBe('refresh');

      storage.clearTokens();
      
      expect(storage.getAccessToken()).toBeNull();
      expect(storage.getRefreshToken()).toBeNull();
    });

    it('should work with CustomStorage', async () => {
      const store: Record<string, string> = {};
      const customStorage = new CustomStorage({
        get: (key) => store[key] || null,
        set: (key, value) => { store[key] = value; },
        remove: (key) => { delete store[key]; }
      });

      expect(await customStorage.getAccessToken()).toBeNull();

      await customStorage.setTokens('custom-access', 'custom-refresh', 3600);
      
      expect(await customStorage.getAccessToken()).toBe('custom-access');
      expect(await customStorage.getRefreshToken()).toBe('custom-refresh');

      await customStorage.clearTokens();
      
      expect(await customStorage.getAccessToken()).toBeNull();
    });
  });

  describe('Error Handling', () => {
    it('should identify ZaltAuthError correctly', () => {
      const error = new ZaltAuthError('TEST', 'Test error', 400);
      expect(isZaltAuthError(error)).toBe(true);
      expect(isZaltAuthError(new Error('regular error'))).toBe(false);
    });

    it('should identify retryable errors', () => {
      expect(isRetryableError(new NetworkError('timeout'))).toBe(true);
      expect(isRetryableError(new ZaltAuthError('SERVER_ERROR', 'error', 500))).toBe(true);
      expect(isRetryableError(new ValidationError('INVALID', 'error'))).toBe(false);
      expect(isRetryableError(new AuthenticationError('UNAUTHORIZED', 'error'))).toBe(false);
    });

    it('should serialize error to JSON', () => {
      const error = new ZaltAuthError('TEST_CODE', 'Test message', 400, { detail: 'value' }, 'req-123');
      const json = error.toJSON();

      expect(json.code).toBe('TEST_CODE');
      expect(json.message).toBe('Test message');
      expect(json.statusCode).toBe(400);
      expect(json.details).toEqual({ detail: 'value' });
      expect(json.requestId).toBe('req-123');
    });

    it('should handle network timeout', async () => {
      global.fetch = createMockFetch(async () => {
        const error = new Error('Aborted');
        error.name = 'AbortError';
        throw error;
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        timeout: 100,
        retryAttempts: 0
      });

      await expect(client.login({
        email: 'test@example.com',
        password: 'password'
      })).rejects.toThrow(NetworkError);
    });

    it('should retry on server errors', async () => {
      let callCount = 0;

      global.fetch = createMockFetch(async () => {
        callCount++;
        if (callCount < 3) {
          return createApiResponse(500, {
            error: {
              code: 'SERVER_ERROR',
              message: 'Internal server error',
              timestamp: new Date().toISOString()
            }
          });
        }
        return createApiResponse(200, {
          data: {
            user: createMockUser(),
            access_token: 'token',
            refresh_token: 'refresh',
            expires_in: 900
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        retryAttempts: 3,
        retryDelay: 10
      });

      const result = await client.login({
        email: 'test@example.com',
        password: 'password'
      });

      expect(result.access_token).toBe('token');
      expect(callCount).toBe(3);
    });

    it('should not retry on client errors', async () => {
      let callCount = 0;

      global.fetch = createMockFetch(async () => {
        callCount++;
        return createApiResponse(400, {
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid input',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        retryAttempts: 3
      });

      await expect(client.login({
        email: 'test@example.com',
        password: 'password'
      })).rejects.toThrow(ValidationError);

      expect(callCount).toBe(1);
    });
  });

  describe('Clinisyn Integration Scenario', () => {
    it('should complete full psychologist registration flow', async () => {
      const storage = new MemoryStorage();
      const mockUser = createMockUser({
        email: 'dr.mehmet@clinisyn.com',
        realm_id: 'clinisyn-psychologists'
      });

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/register')) {
          return createApiResponse(200, {
            data: {
              user: { ...mockUser, email_verified: false },
              access_token: 'initial-token',
              refresh_token: 'initial-refresh',
              expires_in: 900
            }
          });
        }
        if (url.includes('/auth/verify-email/send')) {
          return createApiResponse(200, { data: {} });
        }
        if (url.includes('/auth/verify-email/confirm')) {
          return createApiResponse(200, { data: { email_verified: true } });
        }
        if (url.includes('/auth/me')) {
          return createApiResponse(200, { data: mockUser });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      // Step 1: Register
      const registerResult = await client.register({
        email: 'dr.mehmet@clinisyn.com',
        password: 'SecurePassword123!',
        profile: {
          first_name: 'Mehmet',
          last_name: 'Öz',
          metadata: { license_number: 'PSK-54321', role: 'psychologist' }
        }
      });

      expect(registerResult.user.email).toBe('dr.mehmet@clinisyn.com');
      expect(await storage.getAccessToken()).toBe('initial-token');

      // Step 2: Send verification email
      await client.sendVerificationEmail();

      // Step 3: Verify email
      await client.verifyEmail({ code: '123456' });

      // Step 4: Get current user
      const user = await client.getCurrentUser();
      expect(user?.email).toBe('dr.mehmet@clinisyn.com');
    });

    it('should handle MFA flow for healthcare realm', async () => {
      const storage = new MemoryStorage();
      const mockUser = createMockUser({ mfa_enabled: true });

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/login')) {
          return createApiResponse(200, {
            data: {
              mfa_required: true,
              mfa_session_id: 'mfa-session-healthcare'
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      // Login should trigger MFA
      try {
        await client.login({
          email: 'dr.ayse@clinisyn.com',
          password: 'SecurePassword123!'
        });
        fail('Should have thrown MFARequiredError');
      } catch (error) {
        expect(error).toBeInstanceOf(MFARequiredError);
        const mfaError = error as MFARequiredError;
        expect(mfaError.mfaSessionId).toBe('mfa-session-healthcare');
        // SDK should provide MFA methods for healthcare (TOTP + WebAuthn, NO SMS)
        expect(mfaError.mfaMethods).toContain('totp');
        expect(mfaError.mfaMethods).toContain('webauthn');
      }
    });
  });
});


  describe('MFA SDK Methods', () => {
    it('should setup TOTP MFA', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/mfa/totp/setup')) {
          return createApiResponse(200, {
            data: {
              secret: 'JBSWY3DPEHPK3PXP',
              qr_code_url: 'otpauth://totp/Zalt.io:dr.ayse@clinisyn.com?secret=JBSWY3DPEHPK3PXP&issuer=Zalt.io',
              backup_codes: ['ABC12345', 'DEF67890', 'GHI11111', 'JKL22222', 'MNO33333', 'PQR44444', 'STU55555', 'VWX66666']
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const result = await client.mfa.setup();

      expect(result.secret).toBe('JBSWY3DPEHPK3PXP');
      expect(result.qr_code_url).toContain('otpauth://totp/');
      expect(result.backup_codes).toHaveLength(8);
    });

    it('should verify TOTP code to enable MFA', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/mfa/totp/verify')) {
          return createApiResponse(200, { data: { success: true } });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await expect(client.mfa.verify('123456')).resolves.toBeUndefined();
    });

    it('should handle invalid TOTP code', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async () => {
        return createApiResponse(400, {
          error: {
            code: 'INVALID_CODE',
            message: 'Invalid TOTP code',
            timestamp: new Date().toISOString()
          }
        });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await expect(client.mfa.verify('000000')).rejects.toThrow(ValidationError);
    });

    it('should disable MFA with password', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/mfa/totp')) {
          return createApiResponse(200, { data: { success: true } });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      await expect(client.mfa.disable('SecurePassword123!')).resolves.toBeUndefined();
    });

    it('should verify MFA during login flow', async () => {
      const storage = new MemoryStorage();
      const mockUser = createMockUser({ mfa_enabled: true });

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/mfa/verify')) {
          return createApiResponse(200, {
            data: {
              user: mockUser,
              access_token: 'mfa-verified-token',
              refresh_token: 'mfa-verified-refresh',
              expires_in: 900
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const result = await client.mfa.verifyLogin('mfa-session-123', '123456');

      expect(result.access_token).toBe('mfa-verified-token');
      expect(result.user.email).toBe('dr.ayse@clinisyn.com');
      expect(await storage.getAccessToken()).toBe('mfa-verified-token');
    });

    it('should verify MFA with backup code', async () => {
      const storage = new MemoryStorage();

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/mfa/verify')) {
          return createApiResponse(200, {
            data: {
              user: createMockUser(),
              access_token: 'backup-code-token',
              refresh_token: 'backup-code-refresh',
              expires_in: 900
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const result = await client.mfa.verifyLogin('mfa-session-123', 'ABC12345');

      expect(result.access_token).toBe('backup-code-token');
    });

    it('should get MFA status', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/mfa/status')) {
          return createApiResponse(200, {
            data: {
              totp_enabled: true,
              webauthn_enabled: false,
              backup_codes_remaining: 6
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const status = await client.mfa.getStatus();

      expect(status.totp_enabled).toBe(true);
      expect(status.webauthn_enabled).toBe(false);
      expect(status.backup_codes_remaining).toBe(6);
    });

    it('should regenerate backup codes', async () => {
      const storage = new MemoryStorage();
      await storage.setTokens('access-token', 'refresh-token', 3600);

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/mfa/backup-codes/regenerate')) {
          return createApiResponse(200, {
            data: {
              backup_codes: ['NEW11111', 'NEW22222', 'NEW33333', 'NEW44444', 'NEW55555', 'NEW66666', 'NEW77777', 'NEW88888']
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      const result = await client.mfa.regenerateBackupCodes('SecurePassword123!');

      expect(result.backup_codes).toHaveLength(8);
      expect(result.backup_codes[0]).toBe('NEW11111');
    });

    it('should handle complete MFA login flow', async () => {
      const storage = new MemoryStorage();
      const mockUser = createMockUser({ mfa_enabled: true });

      global.fetch = createMockFetch(async (url) => {
        if (url.includes('/auth/login')) {
          return createApiResponse(200, {
            data: {
              mfa_required: true,
              mfa_session_id: 'mfa-session-healthcare'
            }
          });
        }
        if (url.includes('/auth/mfa/verify')) {
          return createApiResponse(200, {
            data: {
              user: mockUser,
              access_token: 'final-access-token',
              refresh_token: 'final-refresh-token',
              expires_in: 900
            }
          });
        }
        return createApiResponse(404, { error: { code: 'NOT_FOUND', message: 'Not found', timestamp: new Date().toISOString() } });
      });

      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        storage
      });

      // Step 1: Login triggers MFA
      let mfaSessionId: string | undefined;
      try {
        await client.login({
          email: 'dr.ayse@clinisyn.com',
          password: 'SecurePassword123!'
        });
      } catch (error) {
        if (error instanceof MFARequiredError) {
          mfaSessionId = error.mfaSessionId;
        }
      }

      expect(mfaSessionId).toBe('mfa-session-healthcare');

      // Step 2: Verify MFA
      const result = await client.mfa.verifyLogin(mfaSessionId!, '123456');

      expect(result.access_token).toBe('final-access-token');
      expect(await storage.getAccessToken()).toBe('final-access-token');
      expect(await client.isAuthenticated()).toBe(true);
    });
  });
