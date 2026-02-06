/**
 * ImpersonationBanner Component
 * @zalt/react
 * 
 * Fixed banner component that displays when an admin is impersonating a user.
 * Shows impersonation status, impersonated user info, countdown timer,
 * and provides an end impersonation button.
 * 
 * Validates: Requirement 6.4 (Impersonation visual indicator)
 */

'use client';

import React, { useState, useCallback, useEffect, useMemo } from 'react';
import {
  useImpersonation,
  type UseImpersonationOptions,
  type ImpersonationSession,
  type RestrictedAction,
} from '../hooks/useImpersonation';

// ============================================================================
// Types
// ============================================================================

/**
 * Banner position options
 */
export type BannerPosition = 'top' | 'bottom';

/**
 * Banner variant options
 */
export type BannerVariant = 'warning' | 'info' | 'danger';

/**
 * ImpersonationBanner component props
 */
export interface ImpersonationBannerProps {
  /** API base URL */
  apiUrl?: string;
  /** Access token for API calls */
  accessToken?: string;
  /** Banner position */
  position?: BannerPosition;
  /** Banner variant/color scheme */
  variant?: BannerVariant;
  /** Custom class name */
  className?: string;
  /** Show countdown timer */
  showTimer?: boolean;
  /** Show admin info */
  showAdminInfo?: boolean;
  /** Show reason for impersonation */
  showReason?: boolean;
  /** Show restricted actions warning */
  showRestrictions?: boolean;
  /** Enable polling for status updates */
  enablePolling?: boolean;
  /** Polling interval in milliseconds */
  pollingInterval?: number;
  /** Callback when impersonation ends */
  onImpersonationEnd?: () => void;
  /** Callback when impersonation expires */
  onImpersonationExpire?: () => void;
  /** Callback on error */
  onError?: (error: Error) => void;
  /** Custom labels */
  labels?: {
    title?: string;
    impersonating?: string;
    asAdmin?: string;
    reason?: string;
    timeRemaining?: string;
    endButton?: string;
    endingButton?: string;
    restrictedActions?: string;
    expired?: string;
  };
  /** Custom render for user info */
  renderUserInfo?: (session: ImpersonationSession) => React.ReactNode;
  /** Custom render for admin info */
  renderAdminInfo?: (session: ImpersonationSession) => React.ReactNode;
  /** Custom render for timer */
  renderTimer?: (remainingSeconds: number, formatted: string) => React.ReactNode;
  /** Z-index for the banner */
  zIndex?: number;
  /** Whether to render as fixed position */
  fixed?: boolean;
  /** Compact mode */
  compact?: boolean;
  /** Hide when not impersonating */
  hideWhenNotImpersonating?: boolean;
}

// ============================================================================
// Styles
// ============================================================================

const getVariantColors = (variant: BannerVariant) => {
  switch (variant) {
    case 'danger':
      return {
        background: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
        border: '#ef4444',
        text: '#fff',
        accent: '#fca5a5',
      };
    case 'info':
      return {
        background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
        border: '#3b82f6',
        text: '#fff',
        accent: '#93c5fd',
      };
    case 'warning':
    default:
      return {
        background: 'linear-gradient(135deg, #d97706 0%, #b45309 100%)',
        border: '#f59e0b',
        text: '#fff',
        accent: '#fcd34d',
      };
  }
};

const createStyles = (position: BannerPosition, variant: BannerVariant, zIndex: number, fixed: boolean, compact: boolean) => {
  const colors = getVariantColors(variant);
  
  return {
    banner: {
      position: fixed ? 'fixed' as const : 'relative' as const,
      [position]: 0,
      left: 0,
      right: 0,
      background: colors.background,
      borderBottom: position === 'top' ? `2px solid ${colors.border}` : 'none',
      borderTop: position === 'bottom' ? `2px solid ${colors.border}` : 'none',
      padding: compact ? '8px 16px' : '12px 24px',
      zIndex,
      fontFamily: 'var(--zalt-font, system-ui, sans-serif)',
      color: colors.text,
      boxShadow: position === 'top' 
        ? '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)'
        : '0 -4px 6px -1px rgba(0, 0, 0, 0.1), 0 -2px 4px -1px rgba(0, 0, 0, 0.06)',
    } as React.CSSProperties,

    container: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      maxWidth: '1400px',
      margin: '0 auto',
      gap: compact ? '12px' : '20px',
      flexWrap: 'wrap' as const,
    } as React.CSSProperties,

    leftSection: {
      display: 'flex',
      alignItems: 'center',
      gap: compact ? '8px' : '12px',
      flex: 1,
      minWidth: 0,
    } as React.CSSProperties,

    icon: {
      flexShrink: 0,
      width: compact ? '20px' : '24px',
      height: compact ? '20px' : '24px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
    } as React.CSSProperties,

    content: {
      display: 'flex',
      flexDirection: 'column' as const,
      gap: '2px',
      minWidth: 0,
    } as React.CSSProperties,

    title: {
      fontSize: compact ? '13px' : '14px',
      fontWeight: 600,
      display: 'flex',
      alignItems: 'center',
      gap: '8px',
      flexWrap: 'wrap' as const,
    } as React.CSSProperties,

    userInfo: {
      display: 'flex',
      alignItems: 'center',
      gap: '6px',
      fontSize: compact ? '12px' : '13px',
      opacity: 0.9,
    } as React.CSSProperties,

    adminInfo: {
      fontSize: compact ? '11px' : '12px',
      opacity: 0.75,
    } as React.CSSProperties,

    reason: {
      fontSize: compact ? '11px' : '12px',
      opacity: 0.75,
      fontStyle: 'italic' as const,
    } as React.CSSProperties,

    rightSection: {
      display: 'flex',
      alignItems: 'center',
      gap: compact ? '12px' : '16px',
      flexShrink: 0,
    } as React.CSSProperties,

    timer: {
      display: 'flex',
      alignItems: 'center',
      gap: '6px',
      padding: compact ? '4px 10px' : '6px 12px',
      background: 'rgba(0, 0, 0, 0.2)',
      borderRadius: 'var(--zalt-radius, 0.5rem)',
      fontSize: compact ? '12px' : '13px',
      fontWeight: 500,
      fontFamily: 'monospace',
    } as React.CSSProperties,

    timerWarning: {
      background: 'rgba(239, 68, 68, 0.3)',
      animation: 'zalt-pulse 1s ease-in-out infinite',
    } as React.CSSProperties,

    button: {
      padding: compact ? '6px 14px' : '8px 18px',
      background: 'rgba(255, 255, 255, 0.2)',
      color: colors.text,
      border: '1px solid rgba(255, 255, 255, 0.3)',
      borderRadius: 'var(--zalt-radius, 0.5rem)',
      fontSize: compact ? '12px' : '13px',
      fontWeight: 600,
      cursor: 'pointer',
      transition: 'all 0.15s',
      display: 'flex',
      alignItems: 'center',
      gap: '6px',
      whiteSpace: 'nowrap' as const,
    } as React.CSSProperties,

    buttonHover: {
      background: 'rgba(255, 255, 255, 0.3)',
    } as React.CSSProperties,

    buttonDisabled: {
      opacity: 0.5,
      cursor: 'not-allowed',
    } as React.CSSProperties,

    restrictions: {
      display: 'flex',
      alignItems: 'center',
      gap: '4px',
      fontSize: compact ? '10px' : '11px',
      opacity: 0.7,
      marginTop: '2px',
    } as React.CSSProperties,

    restrictionBadge: {
      padding: '1px 6px',
      background: 'rgba(0, 0, 0, 0.2)',
      borderRadius: '4px',
      fontSize: '10px',
    } as React.CSSProperties,

    error: {
      padding: '8px 12px',
      background: 'rgba(239, 68, 68, 0.2)',
      borderRadius: 'var(--zalt-radius, 0.5rem)',
      fontSize: '12px',
      display: 'flex',
      alignItems: 'center',
      gap: '6px',
    } as React.CSSProperties,

    spinner: {
      animation: 'zalt-spin 1s linear infinite',
    } as React.CSSProperties,
  };
};

// ============================================================================
// Helper Components
// ============================================================================

function ImpersonationIcon(): JSX.Element {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z" />
      <path d="M19 3v2h2v2h-2v2h-2V7h-2V5h2V3h2z" opacity="0.6" />
    </svg>
  );
}

function ClockIcon(): JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67V7z" />
    </svg>
  );
}

function ExitIcon(): JSX.Element {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z" />
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
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" style={{ animation: 'zalt-spin 1s linear infinite' }}>
      <style>{`@keyframes zalt-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeDasharray="50" strokeDashoffset="15" />
    </svg>
  );
}

function formatRestriction(action: RestrictedAction): string {
  const labels: Record<RestrictedAction, string> = {
    change_password: 'Password',
    delete_account: 'Delete',
    change_email: 'Email',
    disable_mfa: 'MFA',
    revoke_sessions: 'Sessions',
    manage_api_keys: 'API Keys',
    billing_changes: 'Billing',
  };
  return labels[action] || action;
}

// ============================================================================
// Main Component
// ============================================================================

/**
 * ImpersonationBanner - Visual indicator for admin impersonation sessions
 * 
 * @example
 * ```tsx
 * import { ImpersonationBanner } from '@zalt/react';
 * 
 * function App() {
 *   return (
 *     <>
 *       <ImpersonationBanner
 *         accessToken={accessToken}
 *         position="top"
 *         variant="warning"
 *         showTimer
 *         showAdminInfo
 *         onImpersonationEnd={() => {
 *           // Redirect back to admin dashboard
 *           window.location.href = '/admin/users';
 *         }}
 *       />
 *       <YourApp />
 *     </>
 *   );
 * }
 * ```
 */
export function ImpersonationBanner({
  apiUrl,
  accessToken,
  position = 'top',
  variant = 'warning',
  className = '',
  showTimer = true,
  showAdminInfo = true,
  showReason = false,
  showRestrictions = false,
  enablePolling = true,
  pollingInterval = 30000,
  onImpersonationEnd,
  onImpersonationExpire,
  onError,
  labels = {},
  renderUserInfo,
  renderAdminInfo,
  renderTimer,
  zIndex = 9999,
  fixed = true,
  compact = false,
  hideWhenNotImpersonating = true,
}: ImpersonationBannerProps): JSX.Element | null {
  // Use the impersonation hook
  const {
    isImpersonating,
    session,
    remainingSeconds,
    remainingTimeFormatted,
    restrictedActions,
    endImpersonation,
    isLoading,
    error,
  } = useImpersonation({
    apiUrl,
    accessToken,
    pollingInterval,
    enablePolling,
    onImpersonationEnd,
    onImpersonationExpire,
  });

  // Local state
  const [isHovered, setIsHovered] = useState(false);
  const [isEnding, setIsEnding] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  // Generate styles based on props
  const styles = useMemo(
    () => createStyles(position, variant, zIndex, fixed, compact),
    [position, variant, zIndex, fixed, compact]
  );

  // Check if timer is in warning state (less than 5 minutes)
  const isTimerWarning = remainingSeconds > 0 && remainingSeconds < 300;

  // Handle end impersonation
  const handleEndImpersonation = useCallback(async () => {
    if (isEnding || isLoading) return;
    
    setIsEnding(true);
    setLocalError(null);
    
    try {
      await endImpersonation();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to end impersonation';
      setLocalError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setIsEnding(false);
    }
  }, [isEnding, isLoading, endImpersonation, onError]);

  // Clear local error after 5 seconds
  useEffect(() => {
    if (localError) {
      const timer = setTimeout(() => setLocalError(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [localError]);

  // Don't render if not impersonating and hideWhenNotImpersonating is true
  if (!isImpersonating && hideWhenNotImpersonating) {
    return null;
  }

  // Don't render if no session data
  if (!session) {
    return null;
  }

  // Get labels with defaults
  const {
    title: titleLabel = 'Impersonation Mode',
    impersonating: impersonatingLabel = 'Viewing as',
    asAdmin: asAdminLabel = 'Admin',
    reason: reasonLabel = 'Reason',
    timeRemaining: timeRemainingLabel = 'Time remaining',
    endButton: endButtonLabel = 'End Session',
    endingButton: endingButtonLabel = 'Ending...',
    restrictedActions: restrictedActionsLabel = 'Restricted',
    expired: expiredLabel = 'Session Expired',
  } = labels;

  // Check if session is expired
  const isExpired = session.status === 'expired' || remainingSeconds <= 0;

  return (
    <div
      className={`zalt-impersonation-banner ${className}`}
      style={styles.banner}
      role="alert"
      aria-live="polite"
      data-testid="impersonation-banner"
    >
      {/* Keyframe animation for pulse */}
      <style>{`
        @keyframes zalt-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.7; }
        }
      `}</style>

      <div style={styles.container}>
        {/* Left Section - Icon and Info */}
        <div style={styles.leftSection}>
          <div style={styles.icon}>
            <ImpersonationIcon />
          </div>
          
          <div style={styles.content}>
            <div style={styles.title}>
              <span>{titleLabel}</span>
              {isExpired && (
                <span style={{ 
                  padding: '2px 8px', 
                  background: 'rgba(239, 68, 68, 0.3)', 
                  borderRadius: '4px',
                  fontSize: '11px',
                }}>
                  {expiredLabel}
                </span>
              )}
            </div>
            
            {/* User Info */}
            <div style={styles.userInfo}>
              {renderUserInfo ? (
                renderUserInfo(session)
              ) : (
                <>
                  <span>{impersonatingLabel}:</span>
                  <strong>{session.target_user_email || session.target_user_id}</strong>
                </>
              )}
            </div>

            {/* Admin Info */}
            {showAdminInfo && (
              <div style={styles.adminInfo}>
                {renderAdminInfo ? (
                  renderAdminInfo(session)
                ) : (
                  <>
                    {asAdminLabel}: {session.admin_email || session.admin_id}
                  </>
                )}
              </div>
            )}

            {/* Reason */}
            {showReason && session.reason && (
              <div style={styles.reason}>
                {reasonLabel}: {session.reason}
              </div>
            )}

            {/* Restricted Actions */}
            {showRestrictions && restrictedActions.length > 0 && (
              <div style={styles.restrictions}>
                <WarningIcon />
                <span>{restrictedActionsLabel}:</span>
                {restrictedActions.slice(0, 3).map((action) => (
                  <span key={action} style={styles.restrictionBadge}>
                    {formatRestriction(action)}
                  </span>
                ))}
                {restrictedActions.length > 3 && (
                  <span style={styles.restrictionBadge}>
                    +{restrictedActions.length - 3}
                  </span>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Section - Timer and Button */}
        <div style={styles.rightSection}>
          {/* Error Display */}
          {(localError || error) && (
            <div style={styles.error}>
              <WarningIcon />
              <span>{localError || error}</span>
            </div>
          )}

          {/* Timer */}
          {showTimer && !isExpired && (
            <div 
              style={{
                ...styles.timer,
                ...(isTimerWarning ? styles.timerWarning : {}),
              }}
              title={timeRemainingLabel}
              aria-label={`${timeRemainingLabel}: ${remainingTimeFormatted}`}
            >
              {renderTimer ? (
                renderTimer(remainingSeconds, remainingTimeFormatted)
              ) : (
                <>
                  <ClockIcon />
                  <span>{remainingTimeFormatted}</span>
                </>
              )}
            </div>
          )}

          {/* End Impersonation Button */}
          <button
            onClick={handleEndImpersonation}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            disabled={isEnding || isLoading}
            style={{
              ...styles.button,
              ...(isHovered && !isEnding && !isLoading ? styles.buttonHover : {}),
              ...(isEnding || isLoading ? styles.buttonDisabled : {}),
            }}
            aria-label={isEnding ? endingButtonLabel : endButtonLabel}
            data-testid="end-impersonation-button"
          >
            {isEnding ? <LoadingSpinner /> : <ExitIcon />}
            <span>{isEnding ? endingButtonLabel : endButtonLabel}</span>
          </button>
        </div>
      </div>
    </div>
  );
}

export default ImpersonationBanner;
