/**
 * Token Manager Property Tests
 * @zalt/core
 * 
 * Property 4: Auto-Refresh Idempotence
 * For any expired access token, calling multiple API methods concurrently
 * SHALL result in exactly one refresh request (not multiple).
 * 
 * Validates: Requirements 1.8, 6.1
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fc from 'fast-check';
import { TokenManager, createTokenManager } from '../token-manager';
import { MemoryStorage } from '../storage';
import type { TokenResult } from '../types';

// ============================================================================
// Property Test: Auto-Refresh Idempotence
// ============================================================================

describe('Property 4: Auto-Refresh Idempotence', () => {
  /**
   * Feature: zalt-sdk-packages, Property 4: Auto-Refresh Idempotence
   * Multiple concurrent refresh calls SHALL result in exactly one refresh request
   */

  it('should deduplicate concurrent refresh calls', async () => {
    let refreshCallCount = 0;
    
    const mockRefresh = vi.fn(async (): Promise<TokenResult> => {
      refreshCallCount++;
      // Simulate network delay
      await new Promise(resolve => setTimeout(resolve, 50));
      return {
        accessToken: `new_token_${refreshCallCount}`,
        refreshToken: 'new_refresh_token',
        expiresIn: 900,
        tokenType: 'Bearer',
      };
    });

    const storage = new MemoryStorage();
    const tokenManager = new TokenManager({
      storage,
      onRefresh: mockRefresh,
      refreshBuffer: 60000,
    });

    // Store initial tokens that are about to expire
    await tokenManager.storeTokens({
      accessToken: 'old_token',
      refreshToken: 'old_refresh',
      expiresIn: 30, // 30 seconds - within refresh buffer
      tokenType: 'Bearer',
    });

    // Make multiple concurrent refresh calls
    const concurrentCalls = 10;
    const promises = Array(concurrentCalls)
      .fill(null)
      .map(() => tokenManager.refresh());

    // All should resolve to the same result
    const results = await Promise.all(promises);

    // Should only have called refresh once
    expect(mockRefresh).toHaveBeenCalledTimes(1);
    
    // All results should be the same token
    const firstToken = results[0].accessToken;
    expect(results.every(r => r.accessToken === firstToken)).toBe(true);
  });

  it('should allow sequential refresh calls after completion', async () => {
    let refreshCallCount = 0;
    
    const mockRefresh = vi.fn(async (): Promise<TokenResult> => {
      refreshCallCount++;
      return {
        accessToken: `token_${refreshCallCount}`,
        refreshToken: 'refresh_token',
        expiresIn: 900,
        tokenType: 'Bearer',
      };
    });

    const storage = new MemoryStorage();
    const tokenManager = new TokenManager({
      storage,
      onRefresh: mockRefresh,
    });

    // First refresh
    const result1 = await tokenManager.refresh();
    expect(result1.accessToken).toBe('token_1');

    // Second refresh (sequential, not concurrent)
    const result2 = await tokenManager.refresh();
    expect(result2.accessToken).toBe('token_2');

    // Should have called refresh twice
    expect(mockRefresh).toHaveBeenCalledTimes(2);
  });

  it('should handle refresh errors without blocking future refreshes', async () => {
    let callCount = 0;
    
    const mockRefresh = vi.fn(async (): Promise<TokenResult> => {
      callCount++;
      if (callCount === 1) {
        throw new Error('Network error');
      }
      return {
        accessToken: 'success_token',
        refreshToken: 'refresh_token',
        expiresIn: 900,
        tokenType: 'Bearer',
      };
    });

    const storage = new MemoryStorage();
    const tokenManager = new TokenManager({
      storage,
      onRefresh: mockRefresh,
    });

    // First refresh should fail
    await expect(tokenManager.refresh()).rejects.toThrow('Network error');

    // Second refresh should succeed
    const result = await tokenManager.refresh();
    expect(result.accessToken).toBe('success_token');
  });
});

// ============================================================================
// Unit Tests for TokenManager
// ============================================================================

describe('TokenManager', () => {
  let storage: MemoryStorage;
  let tokenManager: TokenManager;

  beforeEach(() => {
    storage = new MemoryStorage();
    tokenManager = new TokenManager({ storage });
  });

  describe('storeTokens', () => {
    it('should store all token components', async () => {
      const tokens: TokenResult = {
        accessToken: 'access_123',
        refreshToken: 'refresh_456',
        expiresIn: 900,
        tokenType: 'Bearer',
      };

      await tokenManager.storeTokens(tokens);

      expect(await storage.get('access_token')).toBe('access_123');
      expect(await storage.get('refresh_token')).toBe('refresh_456');
      expect(await storage.get('expires_at')).toBeDefined();
    });
  });

  describe('getAccessToken', () => {
    it('should return null when no token stored', async () => {
      const token = await tokenManager.getAccessToken();
      expect(token).toBeNull();
    });

    it('should return token when valid', async () => {
      await tokenManager.storeTokens({
        accessToken: 'valid_token',
        refreshToken: 'refresh',
        expiresIn: 900,
        tokenType: 'Bearer',
      });

      const token = await tokenManager.getAccessToken();
      expect(token).toBe('valid_token');
    });
  });

  describe('isExpired', () => {
    it('should return true when no expiry stored', async () => {
      expect(await tokenManager.isExpired()).toBe(true);
    });

    it('should return false for valid token', async () => {
      await tokenManager.storeTokens({
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresIn: 900,
        tokenType: 'Bearer',
      });

      expect(await tokenManager.isExpired()).toBe(false);
    });

    it('should return true for expired token', async () => {
      await tokenManager.storeTokens({
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresIn: -1, // Already expired
        tokenType: 'Bearer',
      });

      expect(await tokenManager.isExpired()).toBe(true);
    });
  });

  describe('clearTokens', () => {
    it('should remove all tokens', async () => {
      await tokenManager.storeTokens({
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresIn: 900,
        tokenType: 'Bearer',
      });

      await tokenManager.clearTokens();

      expect(await storage.get('access_token')).toBeNull();
      expect(await storage.get('refresh_token')).toBeNull();
      expect(await storage.get('expires_at')).toBeNull();
    });
  });

  describe('decodeToken', () => {
    it('should decode valid JWT payload', () => {
      // Create a mock JWT (header.payload.signature)
      const payload = {
        sub: 'user_123',
        email: 'test@example.com',
        realm_id: 'test-realm',
        iat: 1234567890,
        exp: 1234568790,
        iss: 'https://api.zalt.io',
        aud: 'zalt-client',
      };
      
      const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const mockJwt = `eyJhbGciOiJSUzI1NiJ9.${encodedPayload}.signature`;

      const decoded = tokenManager.decodeToken(mockJwt);
      
      expect(decoded).toEqual(payload);
    });

    it('should return null for invalid JWT', () => {
      expect(tokenManager.decodeToken('invalid')).toBeNull();
      expect(tokenManager.decodeToken('a.b')).toBeNull();
      expect(tokenManager.decodeToken('')).toBeNull();
    });
  });

  describe('hasTokens', () => {
    it('should return false when no tokens', async () => {
      expect(await tokenManager.hasTokens()).toBe(false);
    });

    it('should return true when tokens exist', async () => {
      await tokenManager.storeTokens({
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresIn: 900,
        tokenType: 'Bearer',
      });

      expect(await tokenManager.hasTokens()).toBe(true);
    });
  });
});

// ============================================================================
// Property Tests for Token Operations
// ============================================================================

describe('Token Operations Properties', () => {
  it('should maintain token integrity through store/retrieve cycle', () => {
    fc.assert(
      fc.asyncProperty(
        fc.record({
          accessToken: fc.string({ minLength: 10, maxLength: 500 }),
          refreshToken: fc.string({ minLength: 10, maxLength: 500 }),
          expiresIn: fc.integer({ min: 60, max: 86400 }),
        }),
        async (tokenData) => {
          const storage = new MemoryStorage();
          const manager = new TokenManager({ storage });

          const tokens: TokenResult = {
            ...tokenData,
            tokenType: 'Bearer',
          };

          await manager.storeTokens(tokens);
          
          const retrievedAccess = await manager.getAccessToken();
          const retrievedRefresh = await manager.getRefreshToken();

          return (
            retrievedAccess === tokens.accessToken &&
            retrievedRefresh === tokens.refreshToken
          );
        }
      ),
      { numRuns: 100 }
    );
  });

  it('should correctly calculate expiry status', () => {
    fc.assert(
      fc.asyncProperty(
        fc.integer({ min: -3600, max: 3600 }), // -1 hour to +1 hour
        async (expiresIn) => {
          const storage = new MemoryStorage();
          const manager = new TokenManager({ storage, refreshBuffer: 0 });

          await manager.storeTokens({
            accessToken: 'token',
            refreshToken: 'refresh',
            expiresIn,
            tokenType: 'Bearer',
          });

          const isExpired = await manager.isExpired();
          
          // If expiresIn <= 0, should be expired
          // If expiresIn > 0, should not be expired
          return isExpired === (expiresIn <= 0);
        }
      ),
      { numRuns: 100 }
    );
  });
});
