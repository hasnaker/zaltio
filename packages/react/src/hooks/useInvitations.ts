/**
 * useInvitations Hook
 * @zalt/react
 * 
 * Hook for managing team invitations within a tenant.
 * Provides CRUD operations for invitations with loading and error states.
 * 
 * Validates: Requirement 11.10
 */

'use client';

import { useState, useCallback, useEffect } from 'react';
import { useZaltClient } from './useZaltClient';

// ============================================================================
// Types
// ============================================================================

/**
 * Invitation status
 */
export type InvitationStatus = 'pending' | 'accepted' | 'expired' | 'revoked';

/**
 * Invitation data returned from API
 */
export interface Invitation {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  permissions?: string[];
  invited_by: string;
  status: InvitationStatus;
  expires_at: string;
  created_at: string;
  accepted_at?: string;
  revoked_at?: string;
  metadata?: {
    tenant_name?: string;
    inviter_name?: string;
    inviter_email?: string;
    custom_message?: string;
    resend_count?: number;
  };
}

/**
 * Input for creating an invitation
 */
export interface CreateInvitationInput {
  email: string;
  role: string;
  permissions?: string[];
  custom_message?: string;
}

/**
 * Hook return type
 */
export interface UseInvitationsReturn {
  /** List of invitations */
  invitations: Invitation[];
  /** Loading state */
  isLoading: boolean;
  /** Error message */
  error: string | null;
  /** Whether there are more invitations to load */
  hasMore: boolean;
  /** Fetch invitations for a tenant */
  fetchInvitations: (tenantId: string, status?: InvitationStatus) => Promise<void>;
  /** Load more invitations (pagination) */
  loadMore: () => Promise<void>;
  /** Create a new invitation */
  createInvitation: (tenantId: string, input: CreateInvitationInput) => Promise<Invitation>;
  /** Resend an invitation */
  resendInvitation: (tenantId: string, invitationId: string) => Promise<void>;
  /** Revoke an invitation */
  revokeInvitation: (tenantId: string, invitationId: string) => Promise<void>;
  /** Clear error */
  clearError: () => void;
  /** Refresh invitations */
  refresh: () => Promise<void>;
}

// ============================================================================
// Hook Implementation
// ============================================================================

/**
 * Hook for managing team invitations
 * 
 * @example
 * ```tsx
 * import { useInvitations } from '@zalt/react';
 * 
 * function InvitationManager({ tenantId }) {
 *   const {
 *     invitations,
 *     isLoading,
 *     error,
 *     fetchInvitations,
 *     createInvitation,
 *     resendInvitation,
 *     revokeInvitation,
 *   } = useInvitations();
 * 
 *   useEffect(() => {
 *     fetchInvitations(tenantId);
 *   }, [tenantId]);
 * 
 *   const handleInvite = async (email: string, role: string) => {
 *     await createInvitation(tenantId, { email, role });
 *   };
 * 
 *   return (
 *     <div>
 *       {invitations.map(inv => (
 *         <div key={inv.id}>
 *           {inv.email} - {inv.status}
 *           {inv.status === 'pending' && (
 *             <>
 *               <button onClick={() => resendInvitation(tenantId, inv.id)}>Resend</button>
 *               <button onClick={() => revokeInvitation(tenantId, inv.id)}>Revoke</button>
 *             </>
 *           )}
 *         </div>
 *       ))}
 *     </div>
 *   );
 * }
 * ```
 */
export function useInvitations(): UseInvitationsReturn {
  const client = useZaltClient();
  
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [currentTenantId, setCurrentTenantId] = useState<string | null>(null);
  const [currentStatus, setCurrentStatus] = useState<InvitationStatus | undefined>(undefined);

  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  /**
   * Fetch invitations for a tenant
   */
  const fetchInvitations = useCallback(async (
    tenantId: string,
    status?: InvitationStatus
  ): Promise<void> => {
    setIsLoading(true);
    setError(null);
    setCurrentTenantId(tenantId);
    setCurrentStatus(status);
    setCursor(undefined);

    try {
      const response = await (client as any).request<{
        invitations: Invitation[];
        next_cursor?: string;
      }>(`/tenants/${tenantId}/invitations${status ? `?status=${status}` : ''}`, {
        method: 'GET',
        requireAuth: true,
      });

      setInvitations(response.invitations || []);
      setCursor(response.next_cursor);
      setHasMore(!!response.next_cursor);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to fetch invitations';
      setError(message);
      setInvitations([]);
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  /**
   * Load more invitations (pagination)
   */
  const loadMore = useCallback(async (): Promise<void> => {
    if (!currentTenantId || !cursor || isLoading) return;

    setIsLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams();
      if (currentStatus) params.set('status', currentStatus);
      params.set('cursor', cursor);

      const response = await (client as any).request<{
        invitations: Invitation[];
        next_cursor?: string;
      }>(`/tenants/${currentTenantId}/invitations?${params.toString()}`, {
        method: 'GET',
        requireAuth: true,
      });

      setInvitations(prev => [...prev, ...(response.invitations || [])]);
      setCursor(response.next_cursor);
      setHasMore(!!response.next_cursor);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load more invitations';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, [client, currentTenantId, currentStatus, cursor, isLoading]);

  /**
   * Create a new invitation
   */
  const createInvitation = useCallback(async (
    tenantId: string,
    input: CreateInvitationInput
  ): Promise<Invitation> => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await (client as any).request<{
        invitation: Invitation;
        token?: string; // Token is only returned once
      }>(`/tenants/${tenantId}/invitations`, {
        method: 'POST',
        body: {
          email: input.email,
          role: input.role,
          permissions: input.permissions,
          custom_message: input.custom_message,
        },
        requireAuth: true,
      });

      // Add to local state
      setInvitations(prev => [response.invitation, ...prev]);

      return response.invitation;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create invitation';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  /**
   * Resend an invitation
   */
  const resendInvitation = useCallback(async (
    tenantId: string,
    invitationId: string
  ): Promise<void> => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await (client as any).request<{
        invitation: Invitation;
      }>(`/invitations/${invitationId}/resend`, {
        method: 'POST',
        body: { tenant_id: tenantId },
        requireAuth: true,
      });

      // Update local state
      setInvitations(prev =>
        prev.map(inv =>
          inv.id === invitationId ? response.invitation : inv
        )
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to resend invitation';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  /**
   * Revoke an invitation
   */
  const revokeInvitation = useCallback(async (
    tenantId: string,
    invitationId: string
  ): Promise<void> => {
    setIsLoading(true);
    setError(null);

    try {
      await (client as any).request(`/invitations/${invitationId}`, {
        method: 'DELETE',
        body: { tenant_id: tenantId },
        requireAuth: true,
      });

      // Update local state - mark as revoked
      setInvitations(prev =>
        prev.map(inv =>
          inv.id === invitationId
            ? { ...inv, status: 'revoked' as InvitationStatus, revoked_at: new Date().toISOString() }
            : inv
        )
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to revoke invitation';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  /**
   * Refresh invitations
   */
  const refresh = useCallback(async (): Promise<void> => {
    if (currentTenantId) {
      await fetchInvitations(currentTenantId, currentStatus);
    }
  }, [currentTenantId, currentStatus, fetchInvitations]);

  return {
    invitations,
    isLoading,
    error,
    hasMore,
    fetchInvitations,
    loadMore,
    createInvitation,
    resendInvitation,
    revokeInvitation,
    clearError,
    refresh,
  };
}

export default useInvitations;
