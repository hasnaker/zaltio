/**
 * APIKeyManager Component
 * @zalt/react
 * 
 * Component for managing user-generated API keys.
 * Provides create form, list view with masked keys, and revoke actions.
 * 
 * Validates: Requirements 2.9, 2.10 (API Key Management UI)
 */

'use client';

import React, { useState, useCallback } from 'react';
import { useAPIKeys, type APIKey, type CreateAPIKeyInput } from '../hooks/useAPIKeys';

// ============================================================================
// Types
// ============================================================================

/**
 * APIKeyManager component props
 */
export interface APIKeyManagerProps {
  /** Access token for API calls */
  accessToken?: string;
  /** Custom class name */
  className?: string;
  /** API base URL override */
  apiUrl?: string;
  /** Show create form */
  showCreateForm?: boolean;
  /** Show revoked keys */
  showRevokedKeys?: boolean;
  /** Show expiry date picker */
  showExpiryPicker?: boolean;
  /** Show description field */
  showDescriptionField?: boolean;
  /** Compact mode */
  compact?: boolean;
  /** Callback when key is created */
  onKeyCreated?: (key: APIKey, fullKey: string) => void;
  /** Callback when key is revoked */
  onKeyRevoked?: (keyId: string) => void;
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
  /** Available scopes for selection */
  availableScopes?: { id: string; name: string; description?: string }[];
  /** Default expiry options in days */
  expiryOptions?: { label: string; days: number | null }[];
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
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    padding: '16px',
    marginBottom: '16px',
    border: '1px solid rgba(255,255,255,0.1)',
  } as React.CSSProperties,

  formRow: {
    display: 'flex',
    gap: '12px',
    marginBottom: '12px',
    flexWrap: 'wrap' as const,
  } as React.CSSProperties,

  formGroup: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '4px',
    flex: 1,
    minWidth: '200px',
  } as React.CSSProperties,

  label: {
    fontSize: '12px',
    fontWeight: 500,
    color: 'rgba(255,255,255,0.7)',
  } as React.CSSProperties,

  input: {
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

  buttonDisabled: {
    opacity: 0.5,
    cursor: 'not-allowed',
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

  keyItem: {
    display: 'flex',
    alignItems: 'center',
    padding: '16px',
    background: 'rgba(255,255,255,0.05)',
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    border: '1px solid rgba(255,255,255,0.1)',
    transition: 'border-color 0.15s',
  } as React.CSSProperties,

  keyItemCompact: {
    padding: '12px',
  } as React.CSSProperties,

  keyItemRevoked: {
    opacity: 0.6,
  } as React.CSSProperties,

  keyInfo: {
    flex: 1,
    minWidth: 0,
  } as React.CSSProperties,

  keyMain: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '4px',
  } as React.CSSProperties,

  keyName: {
    fontSize: '14px',
    fontWeight: 500,
    whiteSpace: 'nowrap' as const,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  } as React.CSSProperties,

  keyPrefix: {
    fontFamily: 'monospace',
    fontSize: '12px',
    color: 'rgba(255,255,255,0.6)',
    background: 'rgba(255,255,255,0.1)',
    padding: '2px 6px',
    borderRadius: '4px',
  } as React.CSSProperties,

  statusBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '2px 8px',
    borderRadius: '9999px',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
  } as React.CSSProperties,

  keyMeta: {
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
    display: 'flex',
    gap: '8px',
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

  success: {
    padding: '12px 16px',
    background: 'rgba(16, 185, 129, 0.1)',
    border: '1px solid rgba(16, 185, 129, 0.3)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: '#10b981',
    fontSize: '14px',
    marginBottom: '16px',
  } as React.CSSProperties,

  newKeyDisplay: {
    padding: '16px',
    background: 'rgba(16, 185, 129, 0.1)',
    border: '1px solid rgba(16, 185, 129, 0.3)',
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    marginBottom: '16px',
  } as React.CSSProperties,

  newKeyHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '12px',
    color: '#10b981',
    fontWeight: 600,
    fontSize: '14px',
  } as React.CSSProperties,

  newKeyValue: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '12px',
    background: 'rgba(0,0,0,0.2)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontFamily: 'monospace',
    fontSize: '13px',
    wordBreak: 'break-all' as const,
  } as React.CSSProperties,

  newKeyWarning: {
    marginTop: '12px',
    fontSize: '12px',
    color: 'rgba(255,255,255,0.6)',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
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
    fontSize: '13px',
    color: 'rgba(255,255,255,0.6)',
  } as React.CSSProperties,
};

// ============================================================================
// Helper Components
// ============================================================================

function KeyIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z" />
    </svg>
  );
}

function CopyIcon(): JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z" />
    </svg>
  );
}

function CheckIcon(): JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
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
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
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

function StatusBadge({ status }: { status: string }): JSX.Element {
  const colors: Record<string, { bg: string; text: string }> = {
    active: { bg: 'rgba(16, 185, 129, 0.2)', text: '#10b981' },
    revoked: { bg: 'rgba(239, 68, 68, 0.2)', text: '#ef4444' },
    expired: { bg: 'rgba(156, 163, 175, 0.2)', text: '#9ca3af' },
  };

  const { bg, text } = colors[status] || colors.active;

  return (
    <span style={{ ...styles.statusBadge, background: bg, color: text }}>
      {status}
    </span>
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

function formatExpiryDate(dateString?: string): string {
  if (!dateString) return 'Never';
  const date = new Date(dateString);
  const now = new Date();
  if (date < now) return 'Expired';
  return date.toLocaleDateString();
}

// ============================================================================
// Default Options
// ============================================================================

const DEFAULT_EXPIRY_OPTIONS = [
  { label: 'Never', days: null },
  { label: '30 days', days: 30 },
  { label: '90 days', days: 90 },
  { label: '1 year', days: 365 },
];

// ============================================================================
// Main Component
// ============================================================================

export function APIKeyManager({
  accessToken,
  className = '',
  apiUrl,
  showCreateForm = true,
  showRevokedKeys = false,
  showExpiryPicker = true,
  showDescriptionField = false,
  compact = false,
  onKeyCreated,
  onKeyRevoked,
  onError,
  emptyMessage = 'No API keys yet. Create one to get started.',
  title = 'API Keys',
  hideTitle = false,
  confirmRevoke = true,
  confirmMessage = 'Are you sure you want to revoke this API key? This action cannot be undone.',
  expiryOptions = DEFAULT_EXPIRY_OPTIONS,
}: APIKeyManagerProps): JSX.Element {
  const { 
    keys, 
    activeKeys, 
    totalKeys, 
    isLoading, 
    error, 
    createKey, 
    revokeKey, 
    clearError, 
    copyToClipboard 
  } = useAPIKeys({
    autoFetch: true,
    apiUrl,
    accessToken,
    onKeyCreated,
    onKeyRevoked,
    onError,
  });

  // Form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [expiryDays, setExpiryDays] = useState<number | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // New key display state
  const [newKey, setNewKey] = useState<{ key: APIKey; fullKey: string } | null>(null);
  const [copied, setCopied] = useState(false);

  // Action loading states
  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});

  /**
   * Handle form submission
   */
  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!name.trim()) {
      setFormError('API key name is required');
      return;
    }

    setIsSubmitting(true);

    try {
      const input: CreateAPIKeyInput = {
        name: name.trim(),
        description: description.trim() || undefined,
      };

      if (expiryDays !== null) {
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + expiryDays);
        input.expires_at = expiryDate.toISOString();
      }

      const result = await createKey(input);
      
      // Show the new key
      setNewKey({ key: result.key, fullKey: result.full_key });
      setCopied(false);
      
      // Reset form
      setName('');
      setDescription('');
      setExpiryDays(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create API key';
      setFormError(message);
    } finally {
      setIsSubmitting(false);
    }
  }, [name, description, expiryDays, createKey]);

  /**
   * Handle copy key
   */
  const handleCopyKey = useCallback(async () => {
    if (!newKey) return;
    
    const success = await copyToClipboard(newKey.fullKey);
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [newKey, copyToClipboard]);

  /**
   * Handle dismiss new key
   */
  const handleDismissNewKey = useCallback(() => {
    setNewKey(null);
    setCopied(false);
  }, []);

  /**
   * Handle revoke key
   */
  const handleRevokeKey = useCallback(async (keyId: string) => {
    if (confirmRevoke && !window.confirm(confirmMessage)) {
      return;
    }

    setActionLoading(prev => ({ ...prev, [keyId]: true }));

    try {
      await revokeKey(keyId);
    } finally {
      setActionLoading(prev => ({ ...prev, [keyId]: false }));
    }
  }, [confirmRevoke, confirmMessage, revokeKey]);

  // Filter keys based on showRevokedKeys
  const displayKeys = showRevokedKeys ? keys : activeKeys;

  return (
    <div className={`zalt-api-key-manager ${className}`} style={styles.container}>
      {/* Header */}
      {!hideTitle && (
        <div style={styles.header}>
          <h3 style={styles.title}>{title}</h3>
        </div>
      )}

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

      {/* New key display */}
      {newKey && (
        <div style={styles.newKeyDisplay} data-testid="new-key-display">
          <div style={styles.newKeyHeader}>
            <KeyIcon />
            <span>API Key Created: {newKey.key.name}</span>
          </div>
          <div style={styles.newKeyValue}>
            <code style={{ flex: 1 }}>{newKey.fullKey}</code>
            <button
              onClick={handleCopyKey}
              style={{
                ...styles.buttonSecondary,
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
              }}
              aria-label="Copy API key"
            >
              {copied ? <CheckIcon /> : <CopyIcon />}
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div style={styles.newKeyWarning}>
            <WarningIcon />
            <span>Make sure to copy your API key now. You won't be able to see it again!</span>
          </div>
          <button
            onClick={handleDismissNewKey}
            style={{
              ...styles.buttonSecondary,
              marginTop: '12px',
            }}
          >
            I've saved my key
          </button>
        </div>
      )}

      {/* Create form */}
      {showCreateForm && !newKey && (
        <form onSubmit={handleSubmit} style={styles.form} data-testid="create-key-form">
          <div style={styles.formRow}>
            <div style={styles.formGroup}>
              <label style={styles.label} htmlFor="key-name">Name *</label>
              <input
                id="key-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., Production API Key"
                style={styles.input}
                disabled={isSubmitting}
                required
                aria-label="API key name"
              />
            </div>
            {showExpiryPicker && (
              <div style={{ ...styles.formGroup, minWidth: '150px', flex: 'none' }}>
                <label style={styles.label} htmlFor="key-expiry">Expiration</label>
                <select
                  id="key-expiry"
                  value={expiryDays === null ? '' : expiryDays}
                  onChange={(e) => setExpiryDays(e.target.value === '' ? null : Number(e.target.value))}
                  style={styles.select}
                  disabled={isSubmitting}
                  aria-label="API key expiration"
                >
                  {expiryOptions.map((option) => (
                    <option key={option.label} value={option.days === null ? '' : option.days}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>
          {showDescriptionField && (
            <div style={{ ...styles.formGroup, marginBottom: '12px' }}>
              <label style={styles.label} htmlFor="key-description">Description</label>
              <textarea
                id="key-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="What will this key be used for?"
                style={styles.textarea}
                disabled={isSubmitting}
                aria-label="API key description"
              />
            </div>
          )}
          <button
            type="submit"
            style={{
              ...styles.button,
              ...(isSubmitting ? styles.buttonDisabled : {}),
            }}
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Creating...' : 'Create API Key'}
          </button>
        </form>
      )}

      {/* Loading state */}
      {isLoading && keys.length === 0 && (
        <div style={styles.loading}>
          <LoadingSpinner />
        </div>
      )}

      {/* Empty state */}
      {!isLoading && displayKeys.length === 0 && !newKey && (
        <div style={styles.empty}>{emptyMessage}</div>
      )}

      {/* Key list */}
      {displayKeys.length > 0 && (
        <div style={styles.list}>
          {displayKeys.map((key) => (
            <div
              key={key.id}
              style={{
                ...styles.keyItem,
                ...(compact ? styles.keyItemCompact : {}),
                ...(key.status !== 'active' ? styles.keyItemRevoked : {}),
              }}
              data-testid={`api-key-${key.id}`}
            >
              <div style={styles.keyInfo}>
                <div style={styles.keyMain}>
                  <span style={styles.keyName}>{key.name}</span>
                  <span style={styles.keyPrefix}>{key.key_prefix}...</span>
                  <StatusBadge status={key.status} />
                </div>
                <div style={styles.keyMeta}>
                  <span style={styles.metaItem}>
                    <ClockIcon />
                    Created {formatRelativeTime(key.created_at)}
                  </span>
                  {key.expires_at && (
                    <span style={styles.metaItem}>
                      Expires: {formatExpiryDate(key.expires_at)}
                    </span>
                  )}
                  {key.last_used_at && (
                    <span style={styles.metaItem}>
                      Last used: {formatRelativeTime(key.last_used_at)}
                    </span>
                  )}
                </div>
              </div>
              {key.status === 'active' && (
                <div style={styles.actions}>
                  <button
                    onClick={() => handleRevokeKey(key.id)}
                    disabled={actionLoading[key.id]}
                    style={{
                      ...styles.buttonDanger,
                      ...(actionLoading[key.id] ? styles.buttonDisabled : {}),
                    }}
                    aria-label={`Revoke ${key.name}`}
                  >
                    {actionLoading[key.id] ? 'Revoking...' : 'Revoke'}
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Footer */}
      {displayKeys.length > 0 && (
        <div style={styles.footer}>
          {totalKeys} API key{totalKeys !== 1 ? 's' : ''} ({activeKeys.length} active)
        </div>
      )}
    </div>
  );
}

export default APIKeyManager;
