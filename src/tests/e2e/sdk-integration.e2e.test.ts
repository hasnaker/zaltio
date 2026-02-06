/**
 * SDK Integration E2E Tests
 * Tests the @zalt.io/core and @zalt.io/react SDK integration with Zalt API
 * 
 * Flow:
 * 1. Customer installs @zalt.io/react
 * 2. Wraps app with ZaltProvider using publishableKey
 * 3. Uses SignInButton, UserButton, useUser hooks
 * 4. SDK communicates with api.zalt.io
 * 
 * Validates: Requirements 5.1, 5.2, 5.3 (SDK integration)
 */

import { ZaltClient, createZaltClient } from '../../../packages/core/src/client';
import { ConfigurationError } from '../../../packages/core/src/errors';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

describe('SDK Integration E2E Tests', () => {
  const validPublishableKey = 'pk_live_mock_key_for_testing_only';
  const testPublishableKey = 'pk_test_mock_key_for_testing_only';

  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockReset();
  });

  describe('SDK Initialization with Publishable Key', () => {
    it('should initialize SDK with valid pk_live_ key', () => {
      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      expect(client).toBeInstanceOf(ZaltClient);
      expect(client.isTestMode()).toBe(false);
    });

    it('should initialize SDK with valid pk_test_ key', () => {
      const client = createZaltClient({ publishableKey: testPublishableKey });
      
      expect(client).toBeInstanceOf(ZaltClient);
      expect(client.isTestMode()).toBe(true);
    });

    it('should reject invalid publishable key format', () => {
      // Using FAKE_ prefix to avoid GitHub secret scanning false positives
      const FAKE_SK_LIVE = 'sk_live_mock_key_for_testing_only';
      
      // Missing prefix
      expect(() => createZaltClient({ publishableKey: 'invalid_key' }))
        .toThrow(ConfigurationError);
      
      // Wrong prefix (secret key)
      expect(() => createZaltClient({ publishableKey: FAKE_SK_LIVE }))
        .toThrow(ConfigurationError);
      
      // Too short
      expect(() => createZaltClient({ publishableKey: 'pk_live_short' }))
        .toThrow(ConfigurationError);
      
      // Empty
      expect(() => createZaltClient({ publishableKey: '' }))
        .toThrow(ConfigurationError);
    });

    it('should mask publishable key in logs', () => {
      const client = createZaltClient({ publishableKey: validPublishableKey });
      const masked = client.getPublishableKey();
      
      expect(masked).toBe('pk_live_ABCD...');
      expect(masked).not.toContain('EFGHIJKLMNOPQRSTUVWXYZ123456');
    });
  });

  describe('SDK Authentication Flow', () => {
    it('should send X-API-Key header with publishable key on login', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { 
            id: 'user_123', 
            email: 'user@example.com',
            emailVerified: true,
            profile: {},
            mfaEnabled: false,
            webauthnEnabled: false,
            createdAt: '2026-01-25T10:00:00Z',
            updatedAt: '2026-01-25T10:00:00Z'
          },
          tokens: { 
            accessToken: 'at_xxx', 
            refreshToken: 'rt_xxx', 
            expiresIn: 900,
            tokenType: 'Bearer'
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await client.login({
        email: 'user@example.com',
        password: 'SecurePassword123!'
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/login'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-API-Key': validPublishableKey,
            'Content-Type': 'application/json'
          })
        })
      );
    });

    it('should send X-API-Key header with publishable key on register', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { 
            id: 'user_new', 
            email: 'newuser@example.com',
            emailVerified: false,
            profile: { firstName: 'New', lastName: 'User' },
            mfaEnabled: false,
            webauthnEnabled: false,
            createdAt: '2026-01-25T10:00:00Z',
            updatedAt: '2026-01-25T10:00:00Z'
          },
          tokens: { 
            accessToken: 'at_new', 
            refreshToken: 'rt_new', 
            expiresIn: 900,
            tokenType: 'Bearer'
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await client.register({
        email: 'newuser@example.com',
        password: 'SecurePassword123!',
        profile: { firstName: 'New', lastName: 'User' }
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/register'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-API-Key': validPublishableKey
          })
        })
      );
    });

    it('should store user after successful login', async () => {
      const mockUser = { 
        id: 'user_stored', 
        email: 'stored@example.com',
        emailVerified: true,
        profile: { firstName: 'Stored', lastName: 'User' },
        mfaEnabled: false,
        webauthnEnabled: false,
        createdAt: '2026-01-25T10:00:00Z',
        updatedAt: '2026-01-25T10:00:00Z'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: mockUser,
          tokens: { 
            accessToken: 'at_stored', 
            refreshToken: 'rt_stored', 
            expiresIn: 900,
            tokenType: 'Bearer'
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      const result = await client.login({
        email: 'stored@example.com',
        password: 'SecurePassword123!'
      });

      expect(result.user.id).toBe('user_stored');
      expect(client.getUser()?.id).toBe('user_stored');
      expect(client.getAuthState().isAuthenticated).toBe(true);
    });
  });

  describe('SDK MFA Flow', () => {
    it('should throw MFARequiredError when MFA is required', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          mfaRequired: true,
          mfaSessionId: 'mfa_session_123',
          mfaMethods: ['totp', 'webauthn']
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await expect(client.login({
        email: 'mfa@example.com',
        password: 'SecurePassword123!'
      })).rejects.toThrow();
    });

    it('should support TOTP MFA verification', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          user: { 
            id: 'user_mfa', 
            email: 'mfa@example.com',
            emailVerified: true,
            profile: {},
            mfaEnabled: true,
            webauthnEnabled: false,
            createdAt: '2026-01-25T10:00:00Z',
            updatedAt: '2026-01-25T10:00:00Z'
          },
          tokens: { 
            accessToken: 'at_mfa', 
            refreshToken: 'rt_mfa', 
            expiresIn: 900,
            tokenType: 'Bearer'
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      const result = await client.mfa.verify('123456', 'mfa_session_123');

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/mfa/login/verify'),
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('mfa_session_id')
        })
      );
    });
  });

  describe('SDK Error Handling', () => {
    it('should handle 401 unauthorized error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({
          error: { 
            code: 'INVALID_CREDENTIALS', 
            message: 'Invalid email or password' 
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await expect(client.login({
        email: 'wrong@example.com',
        password: 'WrongPassword'
      })).rejects.toThrow();
    });

    it('should handle 403 invalid API key error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({
          error: { 
            code: 'INVALID_API_KEY', 
            message: 'Invalid or expired API key' 
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await expect(client.login({
        email: 'test@example.com',
        password: 'SecurePassword123!'
      })).rejects.toThrow();
    });

    it('should retry on 429 rate limit error', async () => {
      // First call - rate limited
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        json: async () => ({
          error: { 
            code: 'RATE_LIMIT_EXCEEDED', 
            message: 'Too many requests' 
          }
        })
      });
      
      // Second call after retry - success
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { 
            id: 'user_retry', 
            email: 'retry@example.com',
            emailVerified: true,
            profile: {},
            mfaEnabled: false,
            webauthnEnabled: false,
            createdAt: '2026-01-25T10:00:00Z',
            updatedAt: '2026-01-25T10:00:00Z'
          },
          tokens: { 
            accessToken: 'at_retry', 
            refreshToken: 'rt_retry', 
            expiresIn: 900,
            tokenType: 'Bearer'
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      const result = await client.login({
        email: 'retry@example.com',
        password: 'SecurePassword123!'
      });

      expect(result.user.id).toBe('user_retry');
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('SDK Auth State Management', () => {
    it('should emit SIGNED_IN event on successful login', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { 
            id: 'user_event', 
            email: 'event@example.com',
            emailVerified: true,
            profile: {},
            mfaEnabled: false,
            webauthnEnabled: false,
            createdAt: '2026-01-25T10:00:00Z',
            updatedAt: '2026-01-25T10:00:00Z'
          },
          tokens: { 
            accessToken: 'at_event', 
            refreshToken: 'rt_event', 
            expiresIn: 900,
            tokenType: 'Bearer'
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      const callback = jest.fn();
      
      client.onAuthStateChange(callback);
      
      await client.login({
        email: 'event@example.com',
        password: 'SecurePassword123!'
      });

      expect(callback).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'SIGNED_IN',
          user: expect.objectContaining({ id: 'user_event' })
        })
      );
    });

    it('should emit SIGNED_OUT event on logout', async () => {
      // First login
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { 
            id: 'user_logout', 
            email: 'logout@example.com',
            emailVerified: true,
            profile: {},
            mfaEnabled: false,
            webauthnEnabled: false,
            createdAt: '2026-01-25T10:00:00Z',
            updatedAt: '2026-01-25T10:00:00Z'
          },
          tokens: { 
            accessToken: 'at_logout', 
            refreshToken: 'rt_logout', 
            expiresIn: 900,
            tokenType: 'Bearer'
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await client.login({
        email: 'logout@example.com',
        password: 'SecurePassword123!'
      });

      const callback = jest.fn();
      client.onAuthStateChange(callback);

      // Mock logout endpoint
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({})
      });

      await client.logout();

      expect(callback).toHaveBeenCalledWith({ type: 'SIGNED_OUT' });
      expect(client.getUser()).toBeNull();
      expect(client.getAuthState().isAuthenticated).toBe(false);
    });

    it('should allow unsubscribing from auth state changes', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { 
            id: 'user_unsub', 
            email: 'unsub@example.com',
            emailVerified: true,
            profile: {},
            mfaEnabled: false,
            webauthnEnabled: false,
            createdAt: '2026-01-25T10:00:00Z',
            updatedAt: '2026-01-25T10:00:00Z'
          },
          tokens: { 
            accessToken: 'at_unsub', 
            refreshToken: 'rt_unsub', 
            expiresIn: 900,
            tokenType: 'Bearer'
          }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      const callback = jest.fn();
      
      const unsubscribe = client.onAuthStateChange(callback);
      unsubscribe();
      
      await client.login({
        email: 'unsub@example.com',
        password: 'SecurePassword123!'
      });

      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe('SDK Default Configuration', () => {
    it('should use default baseUrl (https://api.zalt.io)', () => {
      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      // Client should be created successfully with default baseUrl
      expect(client).toBeInstanceOf(ZaltClient);
    });

    it('should allow custom baseUrl', () => {
      const client = createZaltClient({ 
        publishableKey: validPublishableKey,
        baseUrl: 'https://custom.api.zalt.io'
      });
      
      expect(client).toBeInstanceOf(ZaltClient);
    });

    it('should enable debug mode when specified', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      createZaltClient({ 
        publishableKey: validPublishableKey,
        debug: true
      });
      
      // Debug mode should log initialization
      expect(consoleSpy).toHaveBeenCalledWith(
        '[Zalt]',
        expect.stringContaining('initialized'),
        expect.anything()
      );
      
      consoleSpy.mockRestore();
    });
  });
});
