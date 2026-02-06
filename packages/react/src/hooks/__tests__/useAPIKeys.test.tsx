/**
 * useAPIKeys Hook Tests
 * @zalt/react
 * 
 * Tests for the useAPIKeys hook - API key management functionality.
 * 
 * Validates: Requirements 2.9, 2.10
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { useAPIKeys, type APIKey } from '../useAPIKeys';

// ============================================================================
// Mock Data
// ============================================================================

const mockAPIKeys: APIKey[] = [
  {
    id: 'key_1',
    user_id: 'user_123',
    realm_id: 'realm_456',
    name: 'Production API Key',
    description: 'Used for production environment',
    key_prefix: 'zalt_key_abc123',
    scopes: ['read:users', 'write:users'],
    status: 'active',
    created_at: '2026-01-25T10:00:00Z',
    last_used_at: '2026-01-25T12:00:00Z',
  },
  {
    id: 'key_2',
    user_id: 'user_123',
    realm_id: 'realm_456',
    name: 'Development API Key',
    key_prefix: 'zalt_key_def456',
    scopes: ['read:users'],
    status: 'active',
    expires_at: '2026-06-25T10:00:00Z',
    created_at: '2026-01-20T08:00:00Z',
  },
  {
    id: 'key_3',
    user_id: 'user_123',
    realm_id: 'realm_456',
    name: 'Old API Key',
    key_prefix: 'zalt_key_ghi789',
    scopes: [],
    status: 'revoked',
    created_at: '2026-01-15T14:00:00Z',
    revoked_at: '2026-01-24T16:00:00Z',
  },
];

// ============================================================================
// Mock Setup
// ============================================================================

const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock clipboard API
const mockClipboard = {
  writeText: vi.fn().mockResolvedValue(undefined),
};
Object.assign(navigator, { clipboard: mockClipboard });

// ============================================================================
// Tests
// ============================================================================

describe('useAPIKeys Hook', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
    mockClipboard.writeText.mockReset();
  });

  afterEach(() => {
    vi.clearAllTimers();
  });

  describe('Initial State', () => {
    it('should have correct initial state', () => {
      const { result } = renderHook(() => useAPIKeys({ autoFetch: false }));

      expect(result.current.keys).toEqual([]);
      expect(result.current.activeKeys).toEqual([]);
      expect(result.current.totalKeys).toBe(0);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should have all required methods', () => {
      const { result } = renderHook(() => useAPIKeys({ autoFetch: false }));

      expect(typeof result.current.fetchKeys).toBe('function');
      expect(typeof result.current.createKey).toBe('function');
      expect(typeof result.current.revokeKey).toBe('function');
      expect(typeof result.current.clearError).toBe('function');
      expect(typeof result.current.copyToClipboard).toBe('function');
    });
  });

  describe('Fetching API Keys', () => {
    it('should fetch API keys successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ keys: mockAPIKeys }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(result.current.keys).toHaveLength(3);
      expect(result.current.totalKeys).toBe(3);
    });

    it('should filter active keys correctly', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ keys: mockAPIKeys }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(result.current.activeKeys).toHaveLength(2);
      expect(result.current.activeKeys.every(k => k.status === 'active')).toBe(true);
    });

    it('should handle fetch error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: { message: 'Unauthorized' } }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(result.current.keys).toHaveLength(0);
      expect(result.current.error).toBe('Unauthorized');
    });

    it('should require access token', async () => {
      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(result.current.error).toBe('Access token is required');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should auto-fetch on mount when autoFetch is true', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ keys: mockAPIKeys }),
      });

      renderHook(() => 
        useAPIKeys({ autoFetch: true, accessToken: 'test_token' })
      );

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });
    });

    it('should not auto-fetch without access token', async () => {
      renderHook(() => 
        useAPIKeys({ autoFetch: true })
      );

      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('Creating API Keys', () => {
    it('should create an API key successfully', async () => {
      const newKey: APIKey = {
        id: 'key_new',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'New API Key',
        key_prefix: 'zalt_key_new123',
        scopes: [],
        status: 'active',
        created_at: new Date().toISOString(),
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ key: newKey, full_key: 'zalt_key_new123_full_secret_key' }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      let createResult: { key: APIKey; full_key: string } | undefined;
      await act(async () => {
        createResult = await result.current.createKey({ name: 'New API Key' });
      });

      expect(createResult).toBeDefined();
      expect(createResult!.key.name).toBe('New API Key');
      expect(createResult!.full_key).toBe('zalt_key_new123_full_secret_key');
      expect(result.current.keys).toHaveLength(1);
    });

    it('should add new key to the beginning of the list', async () => {
      const existingKeys = mockAPIKeys.filter(k => k.status === 'active');
      const newKey: APIKey = {
        id: 'key_new',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'New API Key',
        key_prefix: 'zalt_key_new123',
        scopes: [],
        status: 'active',
        created_at: new Date().toISOString(),
      };

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ keys: existingKeys }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ key: newKey, full_key: 'zalt_key_new123_full' }),
        });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(result.current.keys).toHaveLength(2);

      await act(async () => {
        await result.current.createKey({ name: 'New API Key' });
      });

      expect(result.current.keys).toHaveLength(3);
      expect(result.current.keys[0].id).toBe('key_new');
    });

    it('should handle create error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: { message: 'Invalid name' } }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      let thrownError: Error | null = null;
      await act(async () => {
        try {
          await result.current.createKey({ name: 'Test' });
        } catch (err) {
          thrownError = err as Error;
        }
      });

      expect(thrownError).not.toBeNull();
      expect(thrownError!.message).toBe('Invalid name');
      expect(result.current.error).toBe('Invalid name');
    });

    it('should validate name is required', async () => {
      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      await expect(
        act(async () => {
          await result.current.createKey({ name: '' });
        })
      ).rejects.toThrow('API key name is required');
    });

    it('should call onKeyCreated callback', async () => {
      const onKeyCreated = vi.fn();
      const newKey: APIKey = {
        id: 'key_new',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'New API Key',
        key_prefix: 'zalt_key_new123',
        scopes: [],
        status: 'active',
        created_at: new Date().toISOString(),
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ key: newKey, full_key: 'zalt_key_new123_full' }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ 
          autoFetch: false, 
          accessToken: 'test_token',
          onKeyCreated 
        })
      );

      await act(async () => {
        await result.current.createKey({ name: 'New API Key' });
      });

      expect(onKeyCreated).toHaveBeenCalledWith(newKey, 'zalt_key_new123_full');
    });

    it('should include expiry date when provided', async () => {
      const newKey: APIKey = {
        id: 'key_new',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Expiring Key',
        key_prefix: 'zalt_key_exp',
        scopes: [],
        status: 'active',
        expires_at: '2026-06-25T10:00:00Z',
        created_at: new Date().toISOString(),
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ key: newKey, full_key: 'zalt_key_exp_full' }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.createKey({ 
          name: 'Expiring Key',
          expires_at: '2026-06-25T10:00:00Z'
        });
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('expires_at'),
        })
      );
    });
  });

  describe('Revoking API Keys', () => {
    it('should revoke an API key successfully', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ keys: mockAPIKeys }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(result.current.activeKeys).toHaveLength(2);

      let success: boolean = false;
      await act(async () => {
        success = await result.current.revokeKey('key_1');
      });

      expect(success).toBe(true);
      expect(result.current.keys.find(k => k.id === 'key_1')?.status).toBe('revoked');
      expect(result.current.activeKeys).toHaveLength(1);
    });

    it('should handle revoke error', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ keys: mockAPIKeys }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 404,
          json: async () => ({ error: { message: 'Key not found' } }),
        });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      let success: boolean = true;
      await act(async () => {
        success = await result.current.revokeKey('invalid_key');
      });

      expect(success).toBe(false);
      expect(result.current.error).toBe('Key not found');
    });

    it('should call onKeyRevoked callback', async () => {
      const onKeyRevoked = vi.fn();

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ keys: mockAPIKeys }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        });

      const { result } = renderHook(() => 
        useAPIKeys({ 
          autoFetch: false, 
          accessToken: 'test_token',
          onKeyRevoked 
        })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      await act(async () => {
        await result.current.revokeKey('key_1');
      });

      expect(onKeyRevoked).toHaveBeenCalledWith('key_1');
    });
  });

  describe('Clear Error', () => {
    it('should clear error state', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({ error: { message: 'Some error' } }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(result.current.error).toBe('Some error');

      act(() => {
        result.current.clearError();
      });

      expect(result.current.error).toBeNull();
    });
  });

  describe('Copy to Clipboard', () => {
    it('should copy text to clipboard successfully', async () => {
      mockClipboard.writeText.mockResolvedValueOnce(undefined);

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false })
      );

      let success: boolean = false;
      await act(async () => {
        success = await result.current.copyToClipboard('test_key_value');
      });

      expect(success).toBe(true);
      expect(mockClipboard.writeText).toHaveBeenCalledWith('test_key_value');
    });

    it('should handle clipboard error gracefully', async () => {
      mockClipboard.writeText.mockRejectedValueOnce(new Error('Clipboard error'));

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false })
      );

      let success: boolean = true;
      await act(async () => {
        success = await result.current.copyToClipboard('test_key_value');
      });

      expect(success).toBe(false);
    });
  });

  describe('API URL', () => {
    it('should use custom API URL when provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ keys: mockAPIKeys }),
      });

      const { result } = renderHook(() =>
        useAPIKeys({ 
          autoFetch: false, 
          accessToken: 'test_token',
          apiUrl: 'https://custom.api.com' 
        })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://custom.api.com/api-keys',
        expect.any(Object)
      );
    });
  });

  describe('Authorization', () => {
    it('should include authorization header in requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ keys: mockAPIKeys }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ autoFetch: false, accessToken: 'my_token' })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer my_token',
          }),
        })
      );
    });
  });

  describe('Error Callback', () => {
    it('should call onError callback on fetch error', async () => {
      const onError = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({ error: { message: 'Server error' } }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ 
          autoFetch: false, 
          accessToken: 'test_token',
          onError 
        })
      );

      await act(async () => {
        await result.current.fetchKeys();
      });

      expect(onError).toHaveBeenCalledWith(expect.any(Error));
    });

    it('should call onError callback on create error', async () => {
      const onError = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ error: { message: 'Bad request' } }),
      });

      const { result } = renderHook(() => 
        useAPIKeys({ 
          autoFetch: false, 
          accessToken: 'test_token',
          onError 
        })
      );

      try {
        await act(async () => {
          await result.current.createKey({ name: 'Test' });
        });
      } catch {
        // Expected to throw
      }

      expect(onError).toHaveBeenCalledWith(expect.any(Error));
    });
  });
});
