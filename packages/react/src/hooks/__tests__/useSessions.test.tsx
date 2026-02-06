/**
 * useSessions Hook Tests
 * @zalt/react
 * 
 * Tests for the useSessions hook - session management functionality.
 * 
 * Validates: Requirement 13.7
 */

import React from 'react';
import { renderHook, act, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { useSessions, type Session } from '../useSessions';

// ============================================================================
// Mock Data
// ============================================================================

const mockSessions: Session[] = [
  {
    id: 'session_1',
    device: 'MacBook Pro',
    browser: 'Chrome 120',
    ip_address: '192.168.1.1',
    location: {
      city: 'San Francisco',
      country: 'United States',
      country_code: 'US',
    },
    last_activity: '2026-01-25T12:00:00Z',
    created_at: '2026-01-25T10:00:00Z',
    is_current: true,
    user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
  },
  {
    id: 'session_2',
    device: 'iPhone 15',
    browser: 'Safari 17',
    ip_address: '10.0.0.1',
    location: {
      city: 'New York',
      country: 'United States',
      country_code: 'US',
    },
    last_activity: '2026-01-25T09:00:00Z',
    created_at: '2026-01-24T08:00:00Z',
    is_current: false,
    user_agent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)',
  },
  {
    id: 'session_3',
    device: 'Pixel 8',
    browser: 'Chrome 120',
    ip_address: '172.16.0.1',
    location: {
      city: 'London',
      country: 'United Kingdom',
      country_code: 'GB',
    },
    last_activity: '2026-01-24T16:00:00Z',
    created_at: '2026-01-23T14:00:00Z',
    is_current: false,
    user_agent: 'Mozilla/5.0 (Linux; Android 14)',
  },
];

// ============================================================================
// Mock Setup
// ============================================================================

const mockFetch = vi.fn();
global.fetch = mockFetch;

// ============================================================================
// Tests
// ============================================================================

describe('useSessions Hook', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.clearAllTimers();
  });

  describe('Initial State', () => {
    it('should have correct initial state', () => {
      const { result } = renderHook(() => useSessions({ autoFetch: false }));

      expect(result.current.sessions).toEqual([]);
      expect(result.current.currentSession).toBeNull();
      expect(result.current.otherSessions).toEqual([]);
      expect(result.current.totalSessions).toBe(0);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should have all required methods', () => {
      const { result } = renderHook(() => useSessions({ autoFetch: false }));

      expect(typeof result.current.fetchSessions).toBe('function');
      expect(typeof result.current.revokeSession).toBe('function');
      expect(typeof result.current.revokeAllSessions).toBe('function');
      expect(typeof result.current.clearError).toBe('function');
    });
  });

  describe('Fetching Sessions', () => {
    it('should fetch sessions successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessions: mockSessions }),
      });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.sessions).toHaveLength(3);
      expect(result.current.totalSessions).toBe(3);
    });

    it('should set current session correctly', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessions: mockSessions }),
      });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.currentSession).not.toBeNull();
      expect(result.current.currentSession?.id).toBe('session_1');
      expect(result.current.currentSession?.is_current).toBe(true);
    });

    it('should set other sessions correctly', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessions: mockSessions }),
      });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.otherSessions).toHaveLength(2);
      expect(result.current.otherSessions.every(s => !s.is_current)).toBe(true);
    });

    it('should handle fetch error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: { message: 'Unauthorized' } }),
      });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.sessions).toHaveLength(0);
      expect(result.current.error).toBe('Unauthorized');
    });

    it('should require access token', async () => {
      const { result } = renderHook(() => 
        useSessions({ autoFetch: false })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.error).toBe('Access token is required');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should auto-fetch on mount when autoFetch is true', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessions: mockSessions }),
      });

      renderHook(() => 
        useSessions({ autoFetch: true, accessToken: 'test_token' })
      );

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });
    });

    it('should not auto-fetch without access token', async () => {
      renderHook(() => 
        useSessions({ autoFetch: true })
      );

      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('Revoking Sessions', () => {
    it('should revoke a session successfully', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ sessions: mockSessions }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.sessions).toHaveLength(3);

      let success: boolean = false;
      await act(async () => {
        success = await result.current.revokeSession('session_2');
      });

      expect(success).toBe(true);
      expect(result.current.sessions).toHaveLength(2);
      expect(result.current.sessions.find(s => s.id === 'session_2')).toBeUndefined();
    });

    it('should handle revoke error', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ sessions: mockSessions }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 404,
          json: async () => ({ error: { message: 'Session not found' } }),
        });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      let success: boolean = true;
      await act(async () => {
        success = await result.current.revokeSession('invalid_session');
      });

      expect(success).toBe(false);
      expect(result.current.error).toBe('Session not found');
    });

    it('should call onSessionRevoked callback', async () => {
      const onSessionRevoked = vi.fn();

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ sessions: mockSessions }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        });

      const { result } = renderHook(() => 
        useSessions({ 
          autoFetch: false, 
          accessToken: 'test_token',
          onSessionRevoked 
        })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      await act(async () => {
        await result.current.revokeSession('session_2');
      });

      expect(onSessionRevoked).toHaveBeenCalledWith('session_2');
    });
  });

  describe('Revoking All Sessions', () => {
    it('should revoke all sessions except current', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ sessions: mockSessions }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ revoked_count: 2 }),
        });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.sessions).toHaveLength(3);

      let revokedCount: number = 0;
      await act(async () => {
        revokedCount = await result.current.revokeAllSessions();
      });

      expect(revokedCount).toBe(2);
      expect(result.current.sessions).toHaveLength(1);
      expect(result.current.sessions[0].is_current).toBe(true);
    });

    it('should handle revoke all error', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ sessions: mockSessions }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          json: async () => ({ error: { message: 'Server error' } }),
        });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      let revokedCount: number = -1;
      await act(async () => {
        revokedCount = await result.current.revokeAllSessions();
      });

      expect(revokedCount).toBe(0);
      expect(result.current.error).toBe('Server error');
    });

    it('should call onAllSessionsRevoked callback', async () => {
      const onAllSessionsRevoked = vi.fn();

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ sessions: mockSessions }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ revoked_count: 2 }),
        });

      const { result } = renderHook(() => 
        useSessions({ 
          autoFetch: false, 
          accessToken: 'test_token',
          onAllSessionsRevoked 
        })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      await act(async () => {
        await result.current.revokeAllSessions();
      });

      expect(onAllSessionsRevoked).toHaveBeenCalledWith(2);
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
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.error).toBe('Some error');

      act(() => {
        result.current.clearError();
      });

      expect(result.current.error).toBeNull();
    });
  });

  describe('Impossible Travel Detection', () => {
    it('should detect impossible travel', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ 
          sessions: mockSessions,
          impossible_travel_detected: true 
        }),
      });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.impossibleTravelDetected).toBe(true);
    });

    it('should not detect impossible travel when not present', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessions: mockSessions }),
      });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'test_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(result.current.impossibleTravelDetected).toBe(false);
    });
  });

  describe('API URL', () => {
    it('should use custom API URL when provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessions: mockSessions }),
      });

      const { result } = renderHook(() =>
        useSessions({ 
          autoFetch: false, 
          accessToken: 'test_token',
          apiUrl: 'https://custom.api.com' 
        })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://custom.api.com/sessions',
        expect.any(Object)
      );
    });
  });

  describe('Authorization', () => {
    it('should include authorization header in requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessions: mockSessions }),
      });

      const { result } = renderHook(() => 
        useSessions({ autoFetch: false, accessToken: 'my_token' })
      );

      await act(async () => {
        await result.current.fetchSessions();
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
        useSessions({ 
          autoFetch: false, 
          accessToken: 'test_token',
          onError 
        })
      );

      await act(async () => {
        await result.current.fetchSessions();
      });

      expect(onError).toHaveBeenCalledWith(expect.any(Error));
    });
  });
});
