/**
 * SessionList Component
 * @zalt/react
 * 
 * Component for displaying and managing user sessions.
 * Shows active sessions with device info, location, and revoke actions.
 * 
 * Validates: Requirement 13.7
 */

'use client';

import React, { useState, useCallback } from 'react';
import { useSessions, type Session } from '../hooks/useSessions';

// ============================================================================
// Types
// ============================================================================

/**
 * SessionList component props
 */
export interface SessionListProps {
  /** Access token for API calls */
  accessToken?: string;
  /** Custom class name */
  className?: string;
  /** API base URL override */
  apiUrl?: string;
  /** Show revoke all button */
  showRevokeAll?: boolean;
  /** Show current session indicator */
  showCurrentIndicator?: boolean;
  /** Show location info */
  showLocation?: boolean;
  /** Show last activity time */
  showLastActivity?: boolean;
  /** Compact mode */
  compact?: boolean;
  /** Polling interval in milliseconds (0 to disable) */
  pollingInterval?: number;
  /** Callback when session is revoked */
  onSessionRevoked?: (sessionId: string) => void;
  /** Callback when all sessions are revoked */
  onAllSessionsRevoked?: (count: number) => void;
  /** Callback on error */
  onError?: (error: Error) => void;
  /** Custom empty state message */
  emptyMessage?: string;
  /** Custom title */
  title?: string;
  /** Hide title */
  hideTitle?: boolean;
  /** Confirm before revoke */
  confirmRevoke?: boolean;
  /** Custom confirm message */
  confirmMessage?: string;
  /** Custom revoke all confirm message */
  confirmAllMessage?: string;
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

  list: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '8px',
  } as React.CSSProperties,

  sessionItem: {
    display: 'flex',
    alignItems: 'center',
    padding: '16px',
    background: 'rgba(255,255,255,0.05)',
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    border: '1px solid rgba(255,255,255,0.1)',
    transition: 'border-color 0.15s',
  } as React.CSSProperties,

  sessionItemCurrent: {
    borderColor: 'var(--zalt-primary, #10b981)',
    background: 'rgba(16, 185, 129, 0.05)',
  } as React.CSSProperties,

  sessionItemCompact: {
    padding: '12px',
  } as React.CSSProperties,

  sessionInfo: {
    flex: 1,
    minWidth: 0,
  } as React.CSSProperties,

  sessionMain: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '4px',
  } as React.CSSProperties,

  deviceName: {
    fontSize: '14px',
    fontWeight: 500,
    whiteSpace: 'nowrap' as const,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  } as React.CSSProperties,

  currentBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '2px 8px',
    background: 'rgba(16, 185, 129, 0.2)',
    color: '#10b981',
    borderRadius: '9999px',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
  } as React.CSSProperties,

  sessionMeta: {
    display: 'flex',
    flexWrap: 'wrap' as const,
    gap: '8px',
    fontSize: '12px',
    color: 'rgba(255,255,255,0.6)',
  } as React.CSSProperties,

  metaItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  } as React.CSSProperties,

  actions: {
    marginLeft: '16px',
    flexShrink: 0,
  } as React.CSSProperties,

  button: {
    padding: '8px 16px',
    background: 'transparent',
    color: '#ef4444',
    border: '1px solid #ef4444',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '13px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.15s',
  } as React.CSSProperties,

  buttonDisabled: {
    opacity: 0.5,
    cursor: 'not-allowed',
  } as React.CSSProperties,

  buttonDanger: {
    padding: '8px 16px',
    background: '#ef4444',
    color: '#fff',
    border: 'none',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '13px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.15s',
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

  footer: {
    marginTop: '16px',
    paddingTop: '16px',
    borderTop: '1px solid rgba(255,255,255,0.1)',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  } as React.CSSProperties,

  sessionCount: {
    fontSize: '13px',
    color: 'rgba(255,255,255,0.6)',
  } as React.CSSProperties,

  impossibleTravel: {
    padding: '12px 16px',
    background: 'rgba(234, 179, 8, 0.1)',
    border: '1px solid rgba(234, 179, 8, 0.3)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: '#eab308',
    fontSize: '14px',
    marginBottom: '16px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  } as React.CSSProperties,
};

// ============================================================================
// Helper Components
// ============================================================================

function LocationIcon(): JSX.Element {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" opacity="0.5">
      <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z" />
    </svg>
  );
}

function ClockIcon(): JSX.Element {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" opacity="0.5">
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z" />
    </svg>
  );
}

function WarningIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z" />
    </svg>
  );
}

function LoadingSpinner(): JSX.Element {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" style={{ animation: 'zalt-spin 1s linear infinite' }}>
      <style>{`@keyframes zalt-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeDasharray="50" strokeDashoffset="15" opacity="0.3" />
    </svg>
  );
}

function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

function formatLocation(session: Session): string {
  const parts: string[] = [];
  if (session.location?.city) parts.push(session.location.city);
  if (session.location?.country) parts.push(session.location.country);
  if (parts.length === 0 && session.ip_address) return session.ip_address;
  return parts.join(', ') || 'Unknown location';
}

// ============================================================================
// Main Component
// ============================================================================

export function SessionList({
  accessToken,
  className = '',
  apiUrl,
  showRevokeAll = true,
  showCurrentIndicator = true,
  showLocation = true,
  showLastActivity = true,
  compact = false,
  pollingInterval = 0,
  onSessionRevoked,
  onAllSessionsRevoked,
  onError,
  emptyMessage = 'No active sessions found.',
  title = 'Active Sessions',
  hideTitle = false,
  confirmRevoke = true,
  confirmMessage = 'Are you sure you want to sign out this device?',
  confirmAllMessage = 'Are you sure you want to sign out all other devices?',
}: SessionListProps): JSX.Element {
  const { sessions, otherSessions, totalSessions, impossibleTravelDetected, isLoading, error, revokeSession, revokeAllSessions, clearError } = useSessions({
    autoFetch: true, pollingInterval, apiUrl, accessToken, onSessionRevoked, onAllSessionsRevoked, onError,
  });

  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});
  const [revokeAllLoading, setRevokeAllLoading] = useState(false);

  const handleRevokeSession = useCallback(async (sessionId: string) => {
    if (confirmRevoke && !window.confirm(confirmMessage)) return;
    setActionLoading(prev => ({ ...prev, [sessionId]: true }));
    try { await revokeSession(sessionId); } finally { setActionLoading(prev => ({ ...prev, [sessionId]: false })); }
  }, [confirmRevoke, confirmMessage, revokeSession]);

  const handleRevokeAllSessions = useCallback(async () => {
    if (confirmRevoke && !window.confirm(confirmAllMessage)) return;
    setRevokeAllLoading(true);
    try { await revokeAllSessions(); } finally { setRevokeAllLoading(false); }
  }, [confirmRevoke, confirmAllMessage, revokeAllSessions]);

  return (
    <div className={`zalt-session-list ${className}`} style={styles.container}>
      {!hideTitle && (
        <div style={styles.header}>
          <h3 style={styles.title}>{title}</h3>
          {showRevokeAll && otherSessions.length > 0 && (
            <button onClick={handleRevokeAllSessions} disabled={revokeAllLoading} style={{ ...styles.buttonDanger, ...(revokeAllLoading ? styles.buttonDisabled : {}) }} aria-label="Sign out all other devices">
              {revokeAllLoading ? 'Signing out...' : 'Sign out all other devices'}
            </button>
          )}
        </div>
      )}
      {impossibleTravelDetected && (<div style={styles.impossibleTravel}><WarningIcon /><span>Suspicious activity detected: Impossible travel between sessions</span></div>)}
      {error && (<div style={styles.error}><span>{error}</span><button onClick={clearError} style={{ background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: '18px' }} aria-label="Dismiss error">×</button></div>)}
      {isLoading && sessions.length === 0 && (<div style={styles.loading}><LoadingSpinner /></div>)}
      {!isLoading && sessions.length === 0 && (<div style={styles.empty}>{emptyMessage}</div>)}
      {sessions.length > 0 && (
        <div style={styles.list}>
          {sessions.map((session) => (
            <div key={session.id} style={{ ...styles.sessionItem, ...(session.is_current ? styles.sessionItemCurrent : {}), ...(compact ? styles.sessionItemCompact : {}) }} data-testid={`session-${session.id}`}>
              <div style={styles.sessionInfo}>
                <div style={styles.sessionMain}>
                  <span style={styles.deviceName}>{session.device} - {session.browser}</span>
                  {showCurrentIndicator && session.is_current && (<span style={styles.currentBadge}>This device</span>)}
                </div>
                <div style={styles.sessionMeta}>
                  {showLocation && (<span style={styles.metaItem}><LocationIcon />{formatLocation(session)}</span>)}
                  {showLastActivity && (<span style={styles.metaItem}><ClockIcon />{formatRelativeTime(session.last_activity)}</span>)}
                </div>
              </div>
              {!session.is_current && (<div style={styles.actions}><button onClick={() => handleRevokeSession(session.id)} disabled={actionLoading[session.id]} style={{ ...styles.button, ...(actionLoading[session.id] ? styles.buttonDisabled : {}) }} aria-label={`Sign out ${session.device}`}>{actionLoading[session.id] ? 'Signing out...' : 'Sign out'}</button></div>)}
            </div>
          ))}
        </div>
      )}
      {sessions.length > 0 && (
        <div style={styles.footer}>
          <span style={styles.sessionCount}>{totalSessions} active session{totalSessions !== 1 ? 's' : ''}{otherSessions.length > 0 && ` (${otherSessions.length} other device${otherSessions.length !== 1 ? 's' : ''})`}</span>
          {hideTitle && showRevokeAll && otherSessions.length > 0 && (<button onClick={handleRevokeAllSessions} disabled={revokeAllLoading} style={{ ...styles.buttonDanger, ...(revokeAllLoading ? styles.buttonDisabled : {}) }} aria-label="Sign out all other devices">{revokeAllLoading ? 'Signing out...' : 'Sign out all other devices'}</button>)}
        </div>
      )}
    </div>
  );
}

export default SessionList;
