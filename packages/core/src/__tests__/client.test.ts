/**
 * ZaltClient Tests
 * 
 * Validates: Requirements 5.1, 5.2 (SDK initialization with publishableKey)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ZaltClient, createZaltClient } from '../client';
import { ConfigurationError } from '../errors';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('ZaltClient', () => {
  const validPublishableKey = 'pk_live_mock_key_for_testing_only';
  const testPublishableKey = 'pk_test_FAKE000000000000000000000000000';

  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Initialization', () => {
    it('should create client with valid publishableKey', () => {
      const client = createZaltClient({ publishableKey: validPublishableKey });
      expect(client).toBeInstanceOf(ZaltClient);
    });

    it('should throw ConfigurationError when publishableKey is missing', () => {
      expect(() => {
        // @ts-expect-error Testing missing required field
        createZaltClient({});
      }).toThrow(ConfigurationError);
    });

    it('should throw ConfigurationError for invalid publishableKey format', () => {
      expect(() => {
        createZaltClient({ publishableKey: 'invalid_key' });
      }).toThrow(ConfigurationError);
      
      expect(() => {
        createZaltClient({ publishableKey: 'pk_live_short' });
      }).toThrow(ConfigurationError);
      
      expect(() => {
        createZaltClient({ publishableKey: 'sk_live_mock_key_for_testing_only' });
      }).toThrow(ConfigurationError);
    });

    it('should accept pk_live_ prefix', () => {
      const client = createZaltClient({ publishableKey: validPublishableKey });
      expect(client.isTestMode()).toBe(false);
    });

    it('should accept pk_test_ prefix and set test mode', () => {
      const client = createZaltClient({ publishableKey: testPublishableKey });
      expect(client.isTestMode()).toBe(true);
    });

    it('should use default baseUrl when not provided', () => {
      const client = createZaltClient({ publishableKey: validPublishableKey });
      expect(client).toBeDefined();
    });

    it('should use custom baseUrl when provided', () => {
      const client = createZaltClient({ 
        publishableKey: validPublishableKey,
        baseUrl: 'https://custom.api.zalt.io'
      });
      expect(client).toBeDefined();
    });

    it('should return masked publishableKey', () => {
      const client = createZaltClient({ publishableKey: validPublishableKey });
      const masked = client.getPublishableKey();
      expect(masked).toBe('pk_live_ABCD...');
      expect(masked).not.toContain('EFGHIJKLMNOPQRSTUVWXYZ123456');
    });
  });

  describe('Login', () => {
    it('should send X-API-Key header with publishableKey', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { id: 'user_123', email: 'test@example.com' },
          tokens: { accessToken: 'at_xxx', refreshToken: 'rt_xxx', expiresIn: 900 }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await client.login({
        email: 'test@example.com',
        password: 'SecurePass123!'
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

    it('should not include realm_id in request body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { id: 'user_123', email: 'test@example.com' },
          tokens: { accessToken: 'at_xxx', refreshToken: 'rt_xxx', expiresIn: 900 }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await client.login({
        email: 'test@example.com',
        password: 'SecurePass123!'
      });

      const callArgs = mockFetch.mock.calls[0];
      const body = JSON.parse(callArgs[1].body);
      
      expect(body).not.toHaveProperty('realm_id');
      expect(body.email).toBe('test@example.com');
      expect(body.password).toBe('SecurePass123!');
    });

    it('should store user and tokens on successful login', async () => {
      const mockUser = { 
        id: 'user_123', 
        email: 'test@example.com',
        emailVerified: true,
        profile: {},
        mfaEnabled: false,
        webauthnEnabled: false,
        createdAt: '2026-01-25T10:00:00Z',
        updatedAt: '2026-01-25T10:00:00Z'
      };
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: mockUser,
          tokens: { accessToken: 'at_xxx', refreshToken: 'rt_xxx', expiresIn: 900, tokenType: 'Bearer' }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      const result = await client.login({
        email: 'test@example.com',
        password: 'SecurePass123!'
      });

      expect(result.user.id).toBe('user_123');
      expect(client.getUser()?.id).toBe('user_123');
    });
  });

  describe('Register', () => {
    it('should send X-API-Key header with publishableKey', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { id: 'user_123', email: 'new@example.com' },
          tokens: { accessToken: 'at_xxx', refreshToken: 'rt_xxx', expiresIn: 900 }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await client.register({
        email: 'new@example.com',
        password: 'SecurePass123!'
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

    it('should not include realm_id in request body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { id: 'user_123', email: 'new@example.com' },
          tokens: { accessToken: 'at_xxx', refreshToken: 'rt_xxx', expiresIn: 900 }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await client.register({
        email: 'new@example.com',
        password: 'SecurePass123!',
        profile: { firstName: 'Test' }
      });

      const callArgs = mockFetch.mock.calls[0];
      const body = JSON.parse(callArgs[1].body);
      
      expect(body).not.toHaveProperty('realm_id');
      expect(body.email).toBe('new@example.com');
      expect(body.profile.firstName).toBe('Test');
    });
  });

  describe('Auth State', () => {
    it('should return null user when not authenticated', () => {
      const client = createZaltClient({ publishableKey: validPublishableKey });
      expect(client.getUser()).toBeNull();
    });

    it('should return correct auth state when not authenticated', () => {
      const client = createZaltClient({ publishableKey: validPublishableKey });
      const state = client.getAuthState();
      
      expect(state.user).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(state.isLoading).toBe(false);
    });

    it('should emit SIGNED_IN event on successful login', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { id: 'user_123', email: 'test@example.com' },
          tokens: { accessToken: 'at_xxx', refreshToken: 'rt_xxx', expiresIn: 900 }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      const callback = vi.fn();
      
      client.onAuthStateChange(callback);
      
      await client.login({
        email: 'test@example.com',
        password: 'SecurePass123!'
      });

      expect(callback).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'SIGNED_IN',
          user: expect.objectContaining({ id: 'user_123' })
        })
      );
    });

    it('should emit SIGNED_OUT event on logout', async () => {
      // First login
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { id: 'user_123', email: 'test@example.com' },
          tokens: { accessToken: 'at_xxx', refreshToken: 'rt_xxx', expiresIn: 900 }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await client.login({
        email: 'test@example.com',
        password: 'SecurePass123!'
      });

      const callback = vi.fn();
      client.onAuthStateChange(callback);

      // Mock logout endpoint
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({})
      });

      await client.logout();

      expect(callback).toHaveBeenCalledWith({ type: 'SIGNED_OUT' });
      expect(client.getUser()).toBeNull();
    });
  });

  describe('Error Handling', () => {
    it('should handle 401 unauthorized error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({
          error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await expect(client.login({
        email: 'test@example.com',
        password: 'wrong'
      })).rejects.toThrow();
    });

    it('should handle 403 invalid API key error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        json: async () => ({
          error: { code: 'INVALID_API_KEY', message: 'Invalid or expired API key' }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      await expect(client.login({
        email: 'test@example.com',
        password: 'SecurePass123!'
      })).rejects.toThrow();
    });

    it('should handle 429 rate limit error', async () => {
      // First call - rate limited
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        json: async () => ({
          error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' }
        })
      });
      
      // Second call after retry - success
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { id: 'user_123', email: 'test@example.com' },
          tokens: { accessToken: 'at_xxx', refreshToken: 'rt_xxx', expiresIn: 900 }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      
      // Should retry and eventually succeed
      const result = await client.login({
        email: 'test@example.com',
        password: 'SecurePass123!'
      });

      expect(result.user.id).toBe('user_123');
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Unsubscribe', () => {
    it('should allow unsubscribing from auth state changes', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          user: { id: 'user_123', email: 'test@example.com' },
          tokens: { accessToken: 'at_xxx', refreshToken: 'rt_xxx', expiresIn: 900 }
        })
      });

      const client = createZaltClient({ publishableKey: validPublishableKey });
      const callback = vi.fn();
      
      const unsubscribe = client.onAuthStateChange(callback);
      unsubscribe();
      
      await client.login({
        email: 'test@example.com',
        password: 'SecurePass123!'
      });

      expect(callback).not.toHaveBeenCalled();
    });
  });
});
