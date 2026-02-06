/**
 * useReverification Hook Tests
 * 
 * Validates: Requirements 3.6, 3.7 (SDK Reverification)
 * 
 * Tests:
 * - Detect 403 REVERIFICATION_REQUIRED response
 * - Show reverification modal
 * - Retry original request after success
 * - Password, MFA, and WebAuthn verification flows
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import React, { ReactNode } from 'react';
import { useReverification } from '../useReverification';
import { ZaltContext, ZaltContextValue } from '../../context';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Create mock client
const createMockClient = () => ({
  getAuthState: vi.fn().mockReturnValue({
    user: { id: 'user_123', email: 'test@example.com' },
    isAuthenticated: true,
    isLoading: false,
    error: null,
  }),
  login: vi.fn(),
  logout: vi.fn(),
  register: vi.fn(),
  onAuthStateChange: vi.fn().mockReturnValue(() => {}),
  mfa: {
    setup: vi.fn(),
    verify: vi.fn(),
    disable: vi.fn(),
    getStatus: vi.fn(),
  },
  webauthn: {
    getRegistrationOptions: vi.fn(),
    register: vi.fn(),
    getAuthenticationOptions: vi.fn(),
    authenticate: vi.fn(),
    listCredentials: vi.fn(),
    removeCredential: vi.fn(),
  },
});

// Create wrapper with mock context
const createWrapper = (mockClient: ReturnType<typeof createMockClient>) => {
  const contextValue: ZaltContextValue = {
    client: mockClient as any,
    state: {
      user: { id: 'user_123', email: 'test@example.com' } as any,
      isAuthenticated: true,
      isLoading: false,
      error: null,
    },
    signIn: vi.fn(),
    signUp: vi.fn(),
    signOut: vi.fn(),
  };

  return ({ children }: { children: ReactNode }) => (
    <ZaltContext.Provider value={contextValue}>
      {children}
    </ZaltContext.Provider>
  );
};

describe('useReverification', () => {
  let mockClient: ReturnType<typeof createMockClient>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
    mockClient = createMockClient();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Initial State', () => {
    it('should initialize with modal closed', () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      expect(result.current.isModalOpen).toBe(false);
      expect(result.current.requiredLevel).toBeNull();
      expect(result.current.pendingRequest).toBeNull();
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should have all required methods', () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      expect(typeof result.current.verifyWithPassword).toBe('function');
      expect(typeof result.current.verifyWithMFA).toBe('function');
      expect(typeof result.current.verifyWithWebAuthn).toBe('function');
      expect(typeof result.current.getWebAuthnChallenge).toBe('function');
      expect(typeof result.current.checkStatus).toBe('function');
      expect(typeof result.current.closeModal).toBe('function');
      expect(typeof result.current.clearPendingRequest).toBe('function');
      expect(typeof result.current.withReverification).toBe('function');
      expect(typeof result.current.interceptResponse).toBe('function');
    });
  });

  describe('Password Verification', () => {
    it('should verify with password successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          message: 'Reverification successful',
          reverification: {
            level: 'password',
            verified_at: '2026-01-25T10:00:00Z',
            expires_at: '2026-01-25T10:10:00Z',
          },
        }),
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      await act(async () => {
        await result.current.verifyWithPassword('SecurePass123!');
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/reverify/password'),
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ password: 'SecurePass123!' }),
        })
      );

      expect(result.current.lastReverification).toEqual({
        level: 'password',
        verifiedAt: '2026-01-25T10:00:00Z',
        expiresAt: '2026-01-25T10:10:00Z',
      });
      expect(result.current.isModalOpen).toBe(false);
    });

    it('should handle password verification failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => ({
          error: {
            code: 'INVALID_CREDENTIALS',
            message: 'Invalid credentials',
          },
        }),
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      await act(async () => {
        try {
          await result.current.verifyWithPassword('wrong_password');
        } catch {
          // Expected to throw
        }
      });

      expect(result.current.error).toBe('Invalid credentials');
      expect(result.current.lastReverification).toBeNull();
    });

    it('should set error when password is empty', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      await act(async () => {
        await result.current.verifyWithPassword('');
      });

      expect(result.current.error).toBe('Password is required');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should set loading state during verification', async () => {
      let resolvePromise: (value: unknown) => void;
      const promise = new Promise((resolve) => {
        resolvePromise = resolve;
      });

      mockFetch.mockReturnValueOnce(promise);

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      act(() => {
        result.current.verifyWithPassword('SecurePass123!');
      });

      // Should be loading
      expect(result.current.isLoading).toBe(true);

      // Resolve the promise
      await act(async () => {
        resolvePromise!({
          ok: true,
          json: async () => ({
            reverification: {
              level: 'password',
              verified_at: '2026-01-25T10:00:00Z',
              expires_at: '2026-01-25T10:10:00Z',
            },
          }),
        });
      });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });
    });
  });

  describe('MFA Verification', () => {
    it('should verify with MFA code successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          message: 'Reverification successful',
          reverification: {
            level: 'mfa',
            verified_at: '2026-01-25T10:00:00Z',
            expires_at: '2026-01-25T10:10:00Z',
          },
          used_backup_code: false,
        }),
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      await act(async () => {
        await result.current.verifyWithMFA('123456');
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/reverify/mfa'),
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ code: '123456' }),
        })
      );

      expect(result.current.lastReverification?.level).toBe('mfa');
    });

    it('should handle MFA verification failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => ({
          error: {
            code: 'INVALID_MFA_CODE',
            message: 'Invalid MFA code',
          },
        }),
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      await act(async () => {
        try {
          await result.current.verifyWithMFA('000000');
        } catch {
          // Expected to throw
        }
      });

      expect(result.current.error).toBe('Invalid MFA code');
    });

    it('should set error when MFA code is empty', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      await act(async () => {
        await result.current.verifyWithMFA('');
      });

      expect(result.current.error).toBe('MFA code is required');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('WebAuthn Verification', () => {
    it('should get WebAuthn challenge', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          challenge: 'test_challenge_base64',
          rpId: 'zalt.io',
        }),
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      let challenge: { challenge: string; rpId: string };
      await act(async () => {
        challenge = await result.current.getWebAuthnChallenge();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/reverify/webauthn/challenge'),
        expect.objectContaining({
          method: 'POST',
        })
      );

      expect(challenge!.challenge).toBe('test_challenge_base64');
      expect(challenge!.rpId).toBe('zalt.io');
    });

    it('should verify with WebAuthn credential', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          message: 'Reverification successful',
          reverification: {
            level: 'webauthn',
            verified_at: '2026-01-25T10:00:00Z',
            expires_at: '2026-01-25T10:10:00Z',
          },
        }),
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      // Create mock credential
      const mockCredential = {
        id: 'credential_id',
        rawId: new ArrayBuffer(32),
        type: 'public-key',
        response: {
          clientDataJSON: new ArrayBuffer(100),
          authenticatorData: new ArrayBuffer(37),
          signature: new ArrayBuffer(64),
          userHandle: new ArrayBuffer(16),
        },
      } as unknown as PublicKeyCredential;

      await act(async () => {
        await result.current.verifyWithWebAuthn(mockCredential, 'test_challenge');
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/reverify/webauthn'),
        expect.objectContaining({
          method: 'POST',
        })
      );

      expect(result.current.lastReverification?.level).toBe('webauthn');
    });
  });

  describe('Check Status', () => {
    it('should check reverification status', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          has_reverification: true,
          is_valid: true,
          reverification: {
            level: 'password',
            verified_at: '2026-01-25T10:00:00Z',
            expires_at: '2026-01-25T10:10:00Z',
            method: 'password',
          },
          required_level: null,
          satisfies_required: null,
        }),
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      let status: any;
      await act(async () => {
        status = await result.current.checkStatus();
      });

      expect(status.hasReverification).toBe(true);
      expect(status.isValid).toBe(true);
      expect(status.level).toBe('password');
    });

    it('should check status with required level', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          has_reverification: true,
          is_valid: true,
          reverification: {
            level: 'mfa',
            verified_at: '2026-01-25T10:00:00Z',
            expires_at: '2026-01-25T10:10:00Z',
            method: 'totp',
          },
          required_level: 'password',
          satisfies_required: true,
        }),
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      let status: any;
      await act(async () => {
        status = await result.current.checkStatus('password');
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('level=password'),
        expect.any(Object)
      );
    });
  });

  describe('Modal Control', () => {
    it('should close modal', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      // Manually set modal open state by triggering a reverification requirement
      // This is done through withReverification

      act(() => {
        result.current.closeModal();
      });

      expect(result.current.isModalOpen).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should clear pending request', () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      act(() => {
        result.current.clearPendingRequest();
      });

      expect(result.current.pendingRequest).toBeNull();
    });
  });

  describe('withReverification Wrapper', () => {
    it('should execute function normally when no reverification required', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      const mockFn = vi.fn().mockResolvedValue({ success: true });

      let response: any;
      await act(async () => {
        response = await result.current.withReverification(mockFn);
      });

      expect(mockFn).toHaveBeenCalled();
      expect(response).toEqual({ success: true });
      expect(result.current.isModalOpen).toBe(false);
    });

    it('should show modal when reverification required error is thrown', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      const reverificationError = {
        code: 'REVERIFICATION_REQUIRED',
        message: 'This operation requires password reverification',
        requiredLevel: 'password',
        validityMinutes: 10,
      };

      const mockFn = vi.fn().mockRejectedValue(reverificationError);

      // Start the wrapped function (it will wait for reverification)
      act(() => {
        result.current.withReverification(mockFn);
      });

      // Wait for state to update
      await waitFor(() => {
        expect(result.current.isModalOpen).toBe(true);
      });

      expect(result.current.requiredLevel).toBe('password');
      expect(result.current.validityMinutes).toBe(10);
    });

    it('should retry original request after successful reverification', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      let callCount = 0;
      const mockFn = vi.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.reject({
            code: 'REVERIFICATION_REQUIRED',
            message: 'Reverification required',
            requiredLevel: 'password',
          });
        }
        return Promise.resolve({ success: true, data: 'sensitive_data' });
      });

      // Start the wrapped function
      let resultPromise: Promise<any>;
      act(() => {
        resultPromise = result.current.withReverification(mockFn);
      });

      // Wait for modal to open
      await waitFor(() => {
        expect(result.current.isModalOpen).toBe(true);
      });

      // Mock successful password verification
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          reverification: {
            level: 'password',
            verified_at: '2026-01-25T10:00:00Z',
            expires_at: '2026-01-25T10:10:00Z',
          },
        }),
      });

      // Complete reverification
      await act(async () => {
        await result.current.verifyWithPassword('SecurePass123!');
      });

      // Wait for retry to complete
      const finalResult = await resultPromise!;

      expect(mockFn).toHaveBeenCalledTimes(2);
      expect(finalResult).toEqual({ success: true, data: 'sensitive_data' });
      expect(result.current.isModalOpen).toBe(false);
    });

    it('should reject when modal is closed without completing reverification', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      const reverificationError = {
        code: 'REVERIFICATION_REQUIRED',
        message: 'Reverification required',
        requiredLevel: 'mfa',
      };

      const mockFn = vi.fn().mockRejectedValue(reverificationError);

      let resultPromise: Promise<any>;
      act(() => {
        resultPromise = result.current.withReverification(mockFn);
      });

      // Wait for modal to open
      await waitFor(() => {
        expect(result.current.isModalOpen).toBe(true);
      });

      // Close modal without completing
      act(() => {
        result.current.closeModal();
      });

      // Should reject with cancellation error
      await expect(resultPromise!).rejects.toThrow('Reverification cancelled');
    });
  });

  describe('interceptResponse', () => {
    it('should return false for non-reverification responses', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      const mockResponse = new Response(JSON.stringify({ data: 'test' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

      let intercepted: boolean;
      await act(async () => {
        intercepted = await result.current.interceptResponse(mockResponse, vi.fn());
      });

      expect(intercepted!).toBe(false);
      expect(result.current.isModalOpen).toBe(false);
    });

    it('should return true and show modal for reverification required response', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      const mockResponse = new Response(
        JSON.stringify({
          error: { code: 'REVERIFICATION_REQUIRED', message: 'Reverification required' },
          reverification: { level: 'password', validityMinutes: 10 },
        }),
        {
          status: 403,
          headers: {
            'Content-Type': 'application/json',
            'X-Reverification-Required': 'true',
            'X-Reverification-Level': 'password',
          },
        }
      );

      const retryFn = vi.fn();

      let intercepted: boolean;
      await act(async () => {
        intercepted = await result.current.interceptResponse(mockResponse, retryFn);
      });

      expect(intercepted!).toBe(true);
      expect(result.current.isModalOpen).toBe(true);
      expect(result.current.requiredLevel).toBe('password');
    });

    it('should extract level from X-Reverification-Level header', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      const mockResponse = new Response('{}', {
        status: 403,
        headers: {
          'X-Reverification-Required': 'true',
          'X-Reverification-Level': 'mfa',
        },
      });

      await act(async () => {
        await result.current.interceptResponse(mockResponse, vi.fn());
      });

      expect(result.current.requiredLevel).toBe('mfa');
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      await act(async () => {
        try {
          await result.current.verifyWithPassword('SecurePass123!');
        } catch {
          // Expected to throw
        }
      });

      expect(result.current.error).toBe('Network error');
      expect(result.current.isLoading).toBe(false);
    });

    it('should clear error on new verification attempt', async () => {
      // First call fails
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => ({
          error: { message: 'First error' },
        }),
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      await act(async () => {
        try {
          await result.current.verifyWithPassword('wrong');
        } catch {
          // Expected
        }
      });

      expect(result.current.error).toBe('First error');

      // Second call succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          reverification: {
            level: 'password',
            verified_at: '2026-01-25T10:00:00Z',
            expires_at: '2026-01-25T10:10:00Z',
          },
        }),
      });

      await act(async () => {
        await result.current.verifyWithPassword('correct');
      });

      expect(result.current.error).toBeNull();
    });
  });

  describe('Level Hierarchy', () => {
    it('should handle password level requirement', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      const mockFn = vi.fn().mockRejectedValue({
        code: 'REVERIFICATION_REQUIRED',
        requiredLevel: 'password',
      });

      act(() => {
        result.current.withReverification(mockFn);
      });

      await waitFor(() => {
        expect(result.current.requiredLevel).toBe('password');
      });
    });

    it('should handle mfa level requirement', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      const mockFn = vi.fn().mockRejectedValue({
        code: 'REVERIFICATION_REQUIRED',
        requiredLevel: 'mfa',
      });

      act(() => {
        result.current.withReverification(mockFn);
      });

      await waitFor(() => {
        expect(result.current.requiredLevel).toBe('mfa');
      });
    });

    it('should handle webauthn level requirement', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useReverification(), { wrapper });

      const mockFn = vi.fn().mockRejectedValue({
        code: 'REVERIFICATION_REQUIRED',
        requiredLevel: 'webauthn',
      });

      act(() => {
        result.current.withReverification(mockFn);
      });

      await waitFor(() => {
        expect(result.current.requiredLevel).toBe('webauthn');
      });
    });
  });
});
