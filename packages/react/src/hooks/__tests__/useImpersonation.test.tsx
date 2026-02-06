/**
 * useImpersonation Hook Tests
 * Task 11.5: SDK useImpersonation() hook
 * 
 * Validates: Requirements 6.4, 6.10 (User Impersonation)
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { useImpersonation, RestrictedAction } from '../useImpersonation';

// Mock fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Configure fake timers to work with waitFor
vi.setConfig({ testTimeout: 10000 });

describe('useImpersonation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const defaultOptions = {
    apiUrl: '/api',
    accessToken: 'test-token'
  };

  const mockImpersonationSession = {
    id: 'imp_test123',
    admin_id: 'admin-001',
    admin_email: 'admin@example.com',
    target_user_id: 'user-123',
    target_user_email: 'user@example.com',
    status: 'active' as const,
    restricted_actions: [
      'change_password',
      'delete_account',
      'change_email'
    ] as RestrictedAction[],
    started_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    reason: 'Debugging user issue'
  };

  describe('initial state', () => {
    it('should start with loading state', () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: { is_impersonating: false }
        })
      });

      const { result } = renderHook(() => useImpersonation(defaultOptions));

      expect(result.current.isLoading).toBe(true);
    });

    it('should fetch status on mount', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: { is_impersonating: false }
        })
      });

      renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          '/api/impersonation/status',
          expect.objectContaining({
            method: 'GET',
            headers: expect.objectContaining({
              'Authorization': 'Bearer test-token'
            })
          })
        );
      });
    });

    it('should not fetch without access token', async () => {
      const { result } = renderHook(() => useImpersonation({ apiUrl: '/api' }));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('when not impersonating', () => {
    beforeEach(() => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: { is_impersonating: false }
        })
      });
    });

    it('should return isImpersonating as false', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isImpersonating).toBe(false);
      expect(result.current.session).toBeNull();
    });

    it('should return empty restricted actions', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.restrictedActions).toEqual([]);
    });

    it('should return false for isActionRestricted', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isActionRestricted('change_password')).toBe(false);
    });
  });

  describe('when impersonating', () => {
    beforeEach(() => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: {
            is_impersonating: true,
            session: mockImpersonationSession,
            remaining_seconds: 3500
          }
        })
      });
    });

    it('should return isImpersonating as true', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isImpersonating).toBe(true);
    });

    it('should return session data', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.session).toBeTruthy();
      expect(result.current.session?.id).toBe('imp_test123');
      expect(result.current.session?.admin_id).toBe('admin-001');
      expect(result.current.session?.target_user_id).toBe('user-123');
    });

    it('should return remaining seconds', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.remainingSeconds).toBe(3500);
    });

    it('should format remaining time', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.remainingTimeFormatted).toBe('58:20');
    });

    it('should return restricted actions', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.restrictedActions).toContain('change_password');
      expect(result.current.restrictedActions).toContain('delete_account');
      expect(result.current.restrictedActions).toContain('change_email');
    });

    it('should check if action is restricted', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isActionRestricted('change_password')).toBe(true);
      expect(result.current.isActionRestricted('delete_account')).toBe(true);
      expect(result.current.isActionRestricted('billing_changes')).toBe(false);
    });
  });

  describe('endImpersonation', () => {
    beforeEach(() => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            data: {
              is_impersonating: true,
              session: mockImpersonationSession,
              remaining_seconds: 3500
            }
          })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            data: { message: 'Impersonation ended' }
          })
        });
    });

    it('should call end impersonation API', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      await act(async () => {
        await result.current.endImpersonation();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/impersonation/end',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      );
    });

    it('should update state after ending', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isImpersonating).toBe(true);
      });

      await act(async () => {
        await result.current.endImpersonation();
      });

      expect(result.current.isImpersonating).toBe(false);
      expect(result.current.session).toBeNull();
    });

    it('should call onImpersonationEnd callback', async () => {
      const onEnd = vi.fn();
      const { result } = renderHook(() => 
        useImpersonation({ ...defaultOptions, onImpersonationEnd: onEnd })
      );

      await waitFor(() => {
        expect(result.current.isImpersonating).toBe(true);
      });

      await act(async () => {
        await result.current.endImpersonation();
      });

      expect(onEnd).toHaveBeenCalled();
    });

    it('should handle end impersonation error', async () => {
      mockFetch
        .mockReset()
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            data: {
              is_impersonating: true,
              session: mockImpersonationSession,
              remaining_seconds: 3500
            }
          })
        })
        .mockResolvedValueOnce({
          ok: false,
          json: () => Promise.resolve({
            error: { message: 'Session not found' }
          })
        });

      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isImpersonating).toBe(true);
      });

      await act(async () => {
        try {
          await result.current.endImpersonation();
        } catch {
          // Expected error
        }
      });

      expect(result.current.error).toBe('Session not found');
    });
  });

  describe('countdown timer', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: {
            is_impersonating: true,
            session: mockImpersonationSession,
            remaining_seconds: 10
          }
        })
      });
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should countdown remaining seconds', async () => {
      const { result } = renderHook(() => useImpersonation(defaultOptions));

      // Wait for initial fetch to complete
      await act(async () => {
        await vi.runAllTimersAsync();
      });

      expect(result.current.remainingSeconds).toBe(10);

      await act(async () => {
        vi.advanceTimersByTime(1000);
      });

      expect(result.current.remainingSeconds).toBe(9);

      await act(async () => {
        vi.advanceTimersByTime(5000);
      });

      expect(result.current.remainingSeconds).toBe(4);
    });

    it('should call onImpersonationExpire when timer reaches zero', async () => {
      const onExpire = vi.fn();
      const { result } = renderHook(() => 
        useImpersonation({ ...defaultOptions, onImpersonationExpire: onExpire })
      );

      // Wait for initial fetch to complete
      await act(async () => {
        await vi.runAllTimersAsync();
      });

      expect(result.current.remainingSeconds).toBe(10);

      await act(async () => {
        vi.advanceTimersByTime(11000);
      });

      expect(onExpire).toHaveBeenCalled();
      expect(result.current.remainingSeconds).toBe(0);
    });
  });

  describe('polling', () => {
    it('should poll when enabled', async () => {
      let fetchCount = 0;
      mockFetch.mockImplementation(() => {
        fetchCount++;
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            data: {
              is_impersonating: true,
              session: mockImpersonationSession,
              remaining_seconds: 3500
            }
          })
        });
      });

      const { result } = renderHook(() => 
        useImpersonation({ 
          ...defaultOptions, 
          enablePolling: true,
          pollingInterval: 100 // Short interval for testing
        })
      );

      // Wait for initial fetch
      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      const initialCount = fetchCount;

      // Wait for polling to trigger
      await waitFor(() => {
        expect(fetchCount).toBeGreaterThan(initialCount);
      }, { timeout: 500 });
    });

    it('should not poll when disabled', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: {
            is_impersonating: true,
            session: mockImpersonationSession,
            remaining_seconds: 3500
          }
        })
      });

      const { result } = renderHook(() => 
        useImpersonation({ 
          ...defaultOptions, 
          enablePolling: false
        })
      );

      // Wait for initial fetch
      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Wait a bit and verify no additional calls
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('refresh', () => {
    it('should refresh status on demand', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: { is_impersonating: false }
        })
      });

      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);

      await act(async () => {
        await result.current.refresh();
      });

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('error handling', () => {
    it('should handle fetch error', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.error).toBe('Network error');
      expect(result.current.isImpersonating).toBe(false);
    });

    it('should handle non-ok response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        json: () => Promise.resolve({
          error: { message: 'Unauthorized' }
        })
      });

      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.isImpersonating).toBe(false);
      expect(result.current.error).toBeNull();
    });
  });

  describe('time formatting', () => {
    it('should format time correctly', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: {
            is_impersonating: true,
            session: mockImpersonationSession,
            remaining_seconds: 125 // 2:05
          }
        })
      });

      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.remainingTimeFormatted).toBe('02:05');
    });

    it('should format zero time', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: {
            is_impersonating: true,
            session: mockImpersonationSession,
            remaining_seconds: 0
          }
        })
      });

      const { result } = renderHook(() => useImpersonation(defaultOptions));

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });

      expect(result.current.remainingTimeFormatted).toBe('00:00');
    });
  });
});
