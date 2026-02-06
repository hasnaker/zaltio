/**
 * InvitationList Component
 * @zalt/react
 * 
 * Component for managing team invitations within a tenant.
 * Displays pending invitations with resend/revoke actions and a create form.
 * 
 * Validates: Requirement 11.10
 */

'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { useInvitations, type Invitation, type InvitationStatus, type CreateInvitationInput } from '../hooks/useInvitations';

// ============================================================================
// Types
// ============================================================================

/**
 * Available roles for invitation
 */
export interface InvitationRole {
  id: string;
  name: string;
  description?: string;
}

/**
 * InvitationList props
 */
export interface InvitationListProps {
  /** Tenant ID to manage invitations for */
  tenantId: string;
  /** Available roles for invitation */
  roles?: InvitationRole[];
  /** Default role for new invitations */
  defaultRole?: string;
  /** Filter by status */
  statusFilter?: InvitationStatus | 'all';
  /** Show create invitation form */
  showCreateForm?: boolean;
  /** Custom class name */
  className?: string;
  /** Callback when invitation is created */
  onInvitationCreated?: (invitation: Invitation) => void;
  /** Callback when invitation is revoked */
  onInvitationRevoked?: (invitationId: string) => void;
  /** Callback when invitation is resent */
  onInvitationResent?: (invitationId: string) => void;
  /** Custom empty state message */
  emptyMessage?: string;
  /** Hide status badges */
  hideStatusBadges?: boolean;
  /** Compact mode */
  compact?: boolean;
}

// ============================================================================
// Styles
// ============================================================================

const styles = {
  container: {
    fontFamily: 'var(--zalt-font, system-ui, sans-serif)',
    color: 'var(--zalt-text, #fff)',
  } as React.CSSProperties,
  
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '16px',
  } as React.CSSProperties,
  
  title: {
    fontSize: '18px',
    fontWeight: 600,
    margin: 0,
  } as React.CSSProperties,
  
  form: {
    background: 'rgba(255,255,255,0.05)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    padding: '16px',
    marginBottom: '16px',
  } as React.CSSProperties,
  
  formRow: {
    display: 'flex',
    gap: '12px',
    marginBottom: '12px',
    flexWrap: 'wrap' as const,
  } as React.CSSProperties,
  
  input: {
    flex: 1,
    minWidth: '200px',
    padding: '10px 12px',
    background: 'rgba(255,255,255,0.1)',
    border: '1px solid rgba(255,255,255,0.2)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: 'var(--zalt-text, #fff)',
    fontSize: '14px',
    outline: 'none',
    transition: 'border-color 0.15s',
  } as React.CSSProperties,
  
  select: {
    minWidth: '150px',
    padding: '10px 12px',
    background: 'rgba(255,255,255,0.1)',
    border: '1px solid rgba(255,255,255,0.2)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: 'var(--zalt-text, #fff)',
    fontSize: '14px',
    outline: 'none',
    cursor: 'pointer',
  } as React.CSSProperties,
  
  textarea: {
    width: '100%',
    padding: '10px 12px',
    background: 'rgba(255,255,255,0.1)',
    border: '1px solid rgba(255,255,255,0.2)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: 'var(--zalt-text, #fff)',
    fontSize: '14px',
    outline: 'none',
    resize: 'vertical' as const,
    minHeight: '60px',
    fontFamily: 'inherit',
  } as React.CSSProperties,
  
  button: {
    padding: '10px 20px',
    background: 'var(--zalt-primary, #10b981)',
    color: '#000',
    border: 'none',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '14px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'opacity 0.15s',
  } as React.CSSProperties,
  
  buttonSecondary: {
    padding: '6px 12px',
    background: 'transparent',
    color: 'var(--zalt-primary, #10b981)',
    border: '1px solid var(--zalt-primary, #10b981)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '12px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.15s',
  } as React.CSSProperties,
  
  buttonDanger: {
    padding: '6px 12px',
    background: 'transparent',
    color: '#ef4444',
    border: '1px solid #ef4444',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '12px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.15s',
  } as React.CSSProperties,
  
  list: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '8px',
  } as React.CSSProperties,
  
  listItem: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '12px 16px',
    background: 'rgba(255,255,255,0.05)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    border: '1px solid rgba(255,255,255,0.1)',
  } as React.CSSProperties,
  
  listItemCompact: {
    padding: '8px 12px',
  } as React.CSSProperties,
  
  invitationInfo: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '4px',
    flex: 1,
  } as React.CSSProperties,
  
  email: {
    fontSize: '14px',
    fontWeight: 500,
  } as React.CSSProperties,
  
  meta: {
    display: 'flex',
    gap: '12px',
    fontSize: '12px',
    color: 'rgba(255,255,255,0.6)',
  } as React.CSSProperties,
  
  badge: {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '2px 8px',
    borderRadius: '9999px',
    fontSize: '11px',
    fontWeight: 500,
    textTransform: 'uppercase' as const,
  } as React.CSSProperties,
  
  actions: {
    display: 'flex',
    gap: '8px',
    marginLeft: '16px',
  } as React.CSSProperties,
  
  error: {
    padding: '12px 16px',
    background: 'rgba(239, 68, 68, 0.1)',
    border: '1px solid rgba(239, 68, 68, 0.3)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: '#ef4444',
    fontSize: '14px',
    marginBottom: '16px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  } as React.CSSProperties,
  
  empty: {
    textAlign: 'center' as const,
    padding: '32px',
    color: 'rgba(255,255,255,0.5)',
    fontSize: '14px',
  } as React.CSSProperties,
  
  loading: {
    display: 'flex',
    justifyContent: 'center',
    padding: '32px',
  } as React.CSSProperties,
  
  loadMore: {
    display: 'flex',
    justifyContent: 'center',
    marginTop: '16px',
  } as React.CSSProperties,
};

// ============================================================================
// Helper Components
// ============================================================================

/**
 * Status badge component
 */
function StatusBadge({ status }: { status: InvitationStatus }): JSX.Element {
  const colors: Record<InvitationStatus, { bg: string; text: string }> = {
    pending: { bg: 'rgba(234, 179, 8, 0.2)', text: '#eab308' },
    accepted: { bg: 'rgba(34, 197, 94, 0.2)', text: '#22c55e' },
    expired: { bg: 'rgba(156, 163, 175, 0.2)', text: '#9ca3af' },
    revoked: { bg: 'rgba(239, 68, 68, 0.2)', text: '#ef4444' },
  };

  const { bg, text } = colors[status] || colors.pending;

  return (
    <span style={{ ...styles.badge, background: bg, color: text }}>
      {status}
    </span>
  );
}

/**
 * Loading spinner component
 */
function LoadingSpinner(): JSX.Element {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      style={{ animation: 'zalt-spin 1s linear infinite' }}
    >
      <style>{`@keyframes zalt-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray="50"
        strokeDashoffset="15"
        opacity="0.3"
      />
    </svg>
  );
}

/**
 * Format relative time
 */
function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = date.getTime() - now.getTime();
  const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays < 0) {
    const absDays = Math.abs(diffDays);
    if (absDays === 0) return 'today';
    if (absDays === 1) return 'yesterday';
    if (absDays < 7) return `${absDays} days ago`;
    return date.toLocaleDateString();
  }

  if (diffDays === 0) return 'today';
  if (diffDays === 1) return 'tomorrow';
  if (diffDays < 7) return `in ${diffDays} days`;
  return date.toLocaleDateString();
}

// ============================================================================
// Main Component
// ============================================================================

/**
 * InvitationList component for managing team invitations
 * 
 * @example
 * ```tsx
 * import { InvitationList } from '@zalt/react';
 * 
 * function TeamSettings({ tenantId }) {
 *   return (
 *     <InvitationList
 *       tenantId={tenantId}
 *       roles={[
 *         { id: 'admin', name: 'Admin', description: 'Full access' },
 *         { id: 'member', name: 'Member', description: 'Standard access' },
 *         { id: 'viewer', name: 'Viewer', description: 'Read-only access' },
 *       ]}
 *       defaultRole="member"
 *       onInvitationCreated={(inv) => console.log('Invited:', inv.email)}
 *     />
 *   );
 * }
 * ```
 */
export function InvitationList({
  tenantId,
  roles = [
    { id: 'admin', name: 'Admin' },
    { id: 'member', name: 'Member' },
    { id: 'viewer', name: 'Viewer' },
  ],
  defaultRole = 'member',
  statusFilter = 'all',
  showCreateForm = true,
  className = '',
  onInvitationCreated,
  onInvitationRevoked,
  onInvitationResent,
  emptyMessage = 'No invitations yet. Invite team members to get started.',
  hideStatusBadges = false,
  compact = false,
}: InvitationListProps): JSX.Element {
  const {
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
  } = useInvitations();

  // Form state
  const [email, setEmail] = useState('');
  const [role, setRole] = useState(defaultRole);
  const [customMessage, setCustomMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [showMessageField, setShowMessageField] = useState(false);

  // Action loading states
  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});

  // Fetch invitations on mount and when tenantId changes
  useEffect(() => {
    if (tenantId) {
      const status = statusFilter === 'all' ? undefined : statusFilter;
      fetchInvitations(tenantId, status);
    }
  }, [tenantId, statusFilter, fetchInvitations]);

  /**
   * Handle form submission
   */
  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setFormError('Please enter a valid email address');
      return;
    }

    setIsSubmitting(true);

    try {
      const input: CreateInvitationInput = {
        email: email.trim().toLowerCase(),
        role,
        custom_message: customMessage.trim() || undefined,
      };

      const invitation = await createInvitation(tenantId, input);
      
      // Reset form
      setEmail('');
      setCustomMessage('');
      setShowMessageField(false);
      
      onInvitationCreated?.(invitation);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to send invitation';
      setFormError(message);
    } finally {
      setIsSubmitting(false);
    }
  }, [email, role, customMessage, tenantId, createInvitation, onInvitationCreated]);

  /**
   * Handle resend action
   */
  const handleResend = useCallback(async (invitationId: string) => {
    setActionLoading(prev => ({ ...prev, [invitationId]: true }));

    try {
      await resendInvitation(tenantId, invitationId);
      onInvitationResent?.(invitationId);
    } catch {
      // Error is handled by the hook
    } finally {
      setActionLoading(prev => ({ ...prev, [invitationId]: false }));
    }
  }, [tenantId, resendInvitation, onInvitationResent]);

  /**
   * Handle revoke action
   */
  const handleRevoke = useCallback(async (invitationId: string) => {
    if (!window.confirm('Are you sure you want to revoke this invitation?')) {
      return;
    }

    setActionLoading(prev => ({ ...prev, [invitationId]: true }));

    try {
      await revokeInvitation(tenantId, invitationId);
      onInvitationRevoked?.(invitationId);
    } catch {
      // Error is handled by the hook
    } finally {
      setActionLoading(prev => ({ ...prev, [invitationId]: false }));
    }
  }, [tenantId, revokeInvitation, onInvitationRevoked]);

  // Filter invitations based on status
  const filteredInvitations = statusFilter === 'all'
    ? invitations
    : invitations.filter(inv => inv.status === statusFilter);

  return (
    <div className={`zalt-invitation-list ${className}`} style={styles.container}>
      {/* Error display */}
      {(error || formError) && (
        <div style={styles.error}>
          <span>{error || formError}</span>
          <button
            onClick={() => {
              clearError();
              setFormError(null);
            }}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#ef4444',
              cursor: 'pointer',
              fontSize: '18px',
            }}
            aria-label="Dismiss error"
          >
            ×
          </button>
        </div>
      )}

      {/* Create invitation form */}
      {showCreateForm && (
        <form onSubmit={handleSubmit} style={styles.form}>
          <div style={styles.formRow}>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Email address"
              style={styles.input}
              disabled={isSubmitting}
              required
              aria-label="Email address"
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              style={styles.select}
              disabled={isSubmitting}
              aria-label="Role"
            >
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
            <button
              type="submit"
              style={{
                ...styles.button,
                opacity: isSubmitting ? 0.6 : 1,
                cursor: isSubmitting ? 'not-allowed' : 'pointer',
              }}
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Sending...' : 'Send Invite'}
            </button>
          </div>

          {/* Optional message field */}
          {showMessageField ? (
            <textarea
              value={customMessage}
              onChange={(e) => setCustomMessage(e.target.value)}
              placeholder="Add a personal message (optional)"
              style={styles.textarea}
              disabled={isSubmitting}
              aria-label="Custom message"
            />
          ) : (
            <button
              type="button"
              onClick={() => setShowMessageField(true)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'rgba(255,255,255,0.5)',
                fontSize: '12px',
                cursor: 'pointer',
                padding: 0,
              }}
            >
              + Add a personal message
            </button>
          )}
        </form>
      )}

      {/* Loading state */}
      {isLoading && invitations.length === 0 && (
        <div style={styles.loading}>
          <LoadingSpinner />
        </div>
      )}

      {/* Empty state */}
      {!isLoading && filteredInvitations.length === 0 && (
        <div style={styles.empty}>
          {emptyMessage}
        </div>
      )}

      {/* Invitation list */}
      {filteredInvitations.length > 0 && (
        <div style={styles.list}>
          {filteredInvitations.map((invitation) => (
            <div
              key={invitation.id}
              style={{
                ...styles.listItem,
                ...(compact ? styles.listItemCompact : {}),
              }}
            >
              <div style={styles.invitationInfo}>
                <div style={styles.email}>
                  {invitation.email}
                  {!hideStatusBadges && (
                    <span style={{ marginLeft: '8px' }}>
                      <StatusBadge status={invitation.status} />
                    </span>
                  )}
                </div>
                <div style={styles.meta}>
                  <span>Role: {invitation.role}</span>
                  {invitation.status === 'pending' && (
                    <span>Expires: {formatRelativeTime(invitation.expires_at)}</span>
                  )}
                  {invitation.status === 'accepted' && invitation.accepted_at && (
                    <span>Accepted: {formatRelativeTime(invitation.accepted_at)}</span>
                  )}
                  {invitation.metadata?.inviter_name && (
                    <span>Invited by: {invitation.metadata.inviter_name}</span>
                  )}
                </div>
              </div>

              {/* Actions for pending invitations */}
              {invitation.status === 'pending' && (
                <div style={styles.actions}>
                  <button
                    onClick={() => handleResend(invitation.id)}
                    disabled={actionLoading[invitation.id]}
                    style={{
                      ...styles.buttonSecondary,
                      opacity: actionLoading[invitation.id] ? 0.6 : 1,
                      cursor: actionLoading[invitation.id] ? 'not-allowed' : 'pointer',
                    }}
                    aria-label={`Resend invitation to ${invitation.email}`}
                  >
                    {actionLoading[invitation.id] ? '...' : 'Resend'}
                  </button>
                  <button
                    onClick={() => handleRevoke(invitation.id)}
                    disabled={actionLoading[invitation.id]}
                    style={{
                      ...styles.buttonDanger,
                      opacity: actionLoading[invitation.id] ? 0.6 : 1,
                      cursor: actionLoading[invitation.id] ? 'not-allowed' : 'pointer',
                    }}
                    aria-label={`Revoke invitation to ${invitation.email}`}
                  >
                    Revoke
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Load more button */}
      {hasMore && (
        <div style={styles.loadMore}>
          <button
            onClick={loadMore}
            disabled={isLoading}
            style={{
              ...styles.buttonSecondary,
              opacity: isLoading ? 0.6 : 1,
            }}
          >
            {isLoading ? 'Loading...' : 'Load More'}
          </button>
        </div>
      )}
    </div>
  );
}

export default InvitationList;
