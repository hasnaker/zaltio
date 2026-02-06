/**
 * useInvitations Hook Tests
 * 
 * Validates: Requirement 11.10 (SDK InvitationList)
 * 
 * Tests:
 * - Fetch invitations for a tenant
 * - Create new invitations
 * - Resend pending invitations
 * - Revoke pending invitations
 * - Pagination support
 * - Error handling
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import React, { ReactNode } from 'react';
import { useInvitations, Invitation } from '../useInvitations';
import { ZaltContext, ZaltContextValue } from '../../context';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Sample invitation data
const mockInvitations: Invitation[] = [
  {
    id: 'inv_001',
    tenant_id: 'tenant_123',
    email: 'alice@example.com',
    role: 'admin',
    invited_by: 'user_001',
    status: 'pending',
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date().toISOString(),
    metadata: {
      tenant_name: 'Acme Corp',
      inviter_name: 'John Doe',
    },
  },
  {
    id: 'inv_002',
    tenant_id: 'tenant_123',
    email: 'bob@example.com',
    role: 'member',
    invited_by: 'user_001',
    status: 'accepted',
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    accepted_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: 'inv_003',
    tenant_id: 'tenant_123',
    email: 'charlie@example.com',
    role: 'viewer',
    invited_by: 'user_001',
    status: 'expired',
    expires_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
  },
];

// Create mock client with request method
const createMockClient = () => {
  const requestMock = vi.fn();
  
  return {
    request: requestMock,
    getAuthState: vi.fn().mockReturnValue({
      user: { id: 'user_001', email: 'admin@example.com' },
      isAuthenticated: true,
      isLoading: false,
      error: null,
    }),
    login: vi.fn(),
    logout: vi.fn(),
    register: vi.fn(),
    onAuthStateChange: vi.fn().mockReturnValue(() => {}),
  };
};

// Create wrapper with mock context
const createWrapper = (mockClient: ReturnType<typeof createMockClient>) => {
  const contextValue: ZaltContextValue = {
    client: mockClient as any,
    state: {
      user: { id: 'user_001', email: 'admin@example.com' } as any,
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

describe('useInvitations', () => {
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
    it('should initialize with empty invitations', () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      expect(result.current.invitations).toEqual([]);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBeNull();
      expect(result.current.hasMore).toBe(false);
    });

    it('should have all required methods', () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      expect(typeof result.current.fetchInvitations).toBe('function');
      expect(typeof result.current.loadMore).toBe('function');
      expect(typeof result.current.createInvitation).toBe('function');
      expect(typeof result.current.resendInvitation).toBe('function');
      expect(typeof result.current.revokeInvitation).toBe('function');
      expect(typeof result.current.clearError).toBe('function');
      expect(typeof result.current.refresh).toBe('function');
    });
  });

  describe('Fetch Invitations', () => {
    it('should fetch invitations for a tenant', async () => {
      mockClient.request.mockResolvedValueOnce({
        invitations: mockInvitations,
        next_cursor: undefined,
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123');
      });

      expect(mockClient.request).toHaveBeenCalledWith(
        '/tenants/tenant_123/invitations',
        expect.objectContaining({
          method: 'GET',
          requireAuth: true,
        })
      );

      expect(result.current.invitations).toHaveLength(3);
      expect(result.current.invitations[0].email).toBe('alice@example.com');
      expect(result.current.isLoading).toBe(false);
      expect(result.current.hasMore).toBe(false);
    });

    it('should fetch invitations with status filter', async () => {
      mockClient.request.mockResolvedValueOnce({
        invitations: [mockInvitations[0]],
        next_cursor: undefined,
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123', 'pending');
      });

      expect(mockClient.request).toHaveBeenCalledWith(
        '/tenants/tenant_123/invitations?status=pending',
        expect.any(Object)
      );

      expect(result.current.invitations).toHaveLength(1);
      expect(result.current.invitations[0].status).toBe('pending');
    });

    it('should handle pagination with next_cursor', async () => {
      mockClient.request.mockResolvedValueOnce({
        invitations: mockInvitations.slice(0, 2),
        next_cursor: 'cursor_abc123',
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123');
      });

      expect(result.current.invitations).toHaveLength(2);
      expect(result.current.hasMore).toBe(true);
    });

    it('should handle fetch error', async () => {
      mockClient.request.mockRejectedValueOnce(new Error('Network error'));

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123');
      });

      expect(result.current.invitations).toEqual([]);
      expect(result.current.error).toBe('Network error');
      expect(result.current.isLoading).toBe(false);
    });

    it('should set loading state during fetch', async () => {
      let resolvePromise: (value: unknown) => void;
      const promise = new Promise((resolve) => {
        resolvePromise = resolve;
      });

      mockClient.request.mockReturnValueOnce(promise);

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      act(() => {
        result.current.fetchInvitations('tenant_123');
      });

      expect(result.current.isLoading).toBe(true);

      await act(async () => {
        resolvePromise!({ invitations: [], next_cursor: undefined });
      });

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });
    });
  });

  describe('Load More (Pagination)', () => {
    it('should load more invitations', async () => {
      // First fetch
      mockClient.request.mockResolvedValueOnce({
        invitations: mockInvitations.slice(0, 2),
        next_cursor: 'cursor_abc123',
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123');
      });

      expect(result.current.invitations).toHaveLength(2);
      expect(result.current.hasMore).toBe(true);

      // Load more
      mockClient.request.mockResolvedValueOnce({
        invitations: [mockInvitations[2]],
        next_cursor: undefined,
      });

      await act(async () => {
        await result.current.loadMore();
      });

      expect(result.current.invitations).toHaveLength(3);
      expect(result.current.hasMore).toBe(false);
    });

    it('should not load more when no cursor', async () => {
      mockClient.request.mockResolvedValueOnce({
        invitations: mockInvitations,
        next_cursor: undefined,
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123');
      });

      await act(async () => {
        await result.current.loadMore();
      });

      // Should only have been called once (initial fetch)
      expect(mockClient.request).toHaveBeenCalledTimes(1);
    });
  });

  describe('Create Invitation', () => {
    it('should create a new invitation', async () => {
      const newInvitation: Invitation = {
        id: 'inv_004',
        tenant_id: 'tenant_123',
        email: 'dave@example.com',
        role: 'member',
        invited_by: 'user_001',
        status: 'pending',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: new Date().toISOString(),
      };

      mockClient.request.mockResolvedValueOnce({
        invitation: newInvitation,
        token: 'secret_token_xyz',
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      let createdInvitation: Invitation;
      await act(async () => {
        createdInvitation = await result.current.createInvitation('tenant_123', {
          email: 'dave@example.com',
          role: 'member',
        });
      });

      expect(mockClient.request).toHaveBeenCalledWith(
        '/tenants/tenant_123/invitations',
        expect.objectContaining({
          method: 'POST',
          body: {
            email: 'dave@example.com',
            role: 'member',
            permissions: undefined,
            custom_message: undefined,
          },
          requireAuth: true,
        })
      );

      expect(createdInvitation!.email).toBe('dave@example.com');
      expect(result.current.invitations).toContainEqual(newInvitation);
    });

    it('should create invitation with custom message', async () => {
      const newInvitation: Invitation = {
        id: 'inv_005',
        tenant_id: 'tenant_123',
        email: 'eve@example.com',
        role: 'admin',
        invited_by: 'user_001',
        status: 'pending',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: new Date().toISOString(),
        metadata: {
          custom_message: 'Welcome to the team!',
        },
      };

      mockClient.request.mockResolvedValueOnce({
        invitation: newInvitation,
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.createInvitation('tenant_123', {
          email: 'eve@example.com',
          role: 'admin',
          custom_message: 'Welcome to the team!',
        });
      });

      expect(mockClient.request).toHaveBeenCalledWith(
        '/tenants/tenant_123/invitations',
        expect.objectContaining({
          body: expect.objectContaining({
            custom_message: 'Welcome to the team!',
          }),
        })
      );
    });

    it('should handle create error', async () => {
      mockClient.request.mockRejectedValueOnce(new Error('Duplicate invitation'));

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        try {
          await result.current.createInvitation('tenant_123', {
            email: 'existing@example.com',
            role: 'member',
          });
        } catch {
          // Expected to throw
        }
      });

      expect(result.current.error).toBe('Duplicate invitation');
    });
  });

  describe('Resend Invitation', () => {
    it('should resend a pending invitation', async () => {
      // First fetch invitations
      mockClient.request.mockResolvedValueOnce({
        invitations: [mockInvitations[0]],
        next_cursor: undefined,
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123');
      });

      // Resend invitation
      const updatedInvitation = {
        ...mockInvitations[0],
        metadata: {
          ...mockInvitations[0].metadata,
          resend_count: 1,
        },
      };

      mockClient.request.mockResolvedValueOnce({
        invitation: updatedInvitation,
      });

      await act(async () => {
        await result.current.resendInvitation('tenant_123', 'inv_001');
      });

      expect(mockClient.request).toHaveBeenCalledWith(
        '/invitations/inv_001/resend',
        expect.objectContaining({
          method: 'POST',
          body: { tenant_id: 'tenant_123' },
          requireAuth: true,
        })
      );

      // Check that local state was updated
      expect(result.current.invitations[0].metadata?.resend_count).toBe(1);
    });

    it('should handle resend error', async () => {
      mockClient.request.mockRejectedValueOnce(new Error('Cannot resend expired invitation'));

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        try {
          await result.current.resendInvitation('tenant_123', 'inv_003');
        } catch {
          // Expected to throw
        }
      });

      expect(result.current.error).toBe('Cannot resend expired invitation');
    });
  });

  describe('Revoke Invitation', () => {
    it('should revoke a pending invitation', async () => {
      // First fetch invitations
      mockClient.request.mockResolvedValueOnce({
        invitations: [mockInvitations[0]],
        next_cursor: undefined,
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123');
      });

      expect(result.current.invitations[0].status).toBe('pending');

      // Revoke invitation
      mockClient.request.mockResolvedValueOnce({});

      await act(async () => {
        await result.current.revokeInvitation('tenant_123', 'inv_001');
      });

      expect(mockClient.request).toHaveBeenCalledWith(
        '/invitations/inv_001',
        expect.objectContaining({
          method: 'DELETE',
          body: { tenant_id: 'tenant_123' },
          requireAuth: true,
        })
      );

      // Check that local state was updated
      expect(result.current.invitations[0].status).toBe('revoked');
      expect(result.current.invitations[0].revoked_at).toBeDefined();
    });

    it('should handle revoke error', async () => {
      mockClient.request.mockRejectedValueOnce(new Error('Cannot revoke accepted invitation'));

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        try {
          await result.current.revokeInvitation('tenant_123', 'inv_002');
        } catch {
          // Expected to throw
        }
      });

      expect(result.current.error).toBe('Cannot revoke accepted invitation');
    });
  });

  describe('Clear Error', () => {
    it('should clear error state', async () => {
      mockClient.request.mockRejectedValueOnce(new Error('Some error'));

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123');
      });

      expect(result.current.error).toBe('Some error');

      act(() => {
        result.current.clearError();
      });

      expect(result.current.error).toBeNull();
    });
  });

  describe('Refresh', () => {
    it('should refresh invitations', async () => {
      mockClient.request.mockResolvedValueOnce({
        invitations: mockInvitations,
        next_cursor: undefined,
      });

      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.fetchInvitations('tenant_123');
      });

      expect(mockClient.request).toHaveBeenCalledTimes(1);

      // Refresh
      mockClient.request.mockResolvedValueOnce({
        invitations: mockInvitations,
        next_cursor: undefined,
      });

      await act(async () => {
        await result.current.refresh();
      });

      expect(mockClient.request).toHaveBeenCalledTimes(2);
    });

    it('should not refresh if no tenant set', async () => {
      const wrapper = createWrapper(mockClient);
      const { result } = renderHook(() => useInvitations(), { wrapper });

      await act(async () => {
        await result.current.refresh();
      });

      expect(mockClient.request).not.toHaveBeenCalled();
    });
  });
});
