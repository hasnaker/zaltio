/**
 * useImpersonation Hook - Impersonation Status and Control
 * Task 11.5: SDK useImpersonation() hook
 * 
 * Provides:
 * - Detect impersonation status
 * - Show visual indicator
 * - End impersonation action
 * - Restricted actions awareness
 * 
 * Validates: Requirements 6.4, 6.10 (User Impersonation)
 */

import { useState, useEffect, useCallback, useMemo } from 'react';

/**
 * Restricted actions during impersonation
 */
export type RestrictedAction = 
  | 'change_password'
  | 'delete_account'
  | 'change_email'
  | 'disable_mfa'
  | 'revoke_sessions'
  | 'manage_api_keys'
  | 'billing_changes';

/**
 * Impersonation session data
 */
export interface ImpersonationSession {
  id: string;
  admin_id: string;
  admin_email?: string;
  target_user_id: string;
  target_user_email?: string;
  status: 'active' | 'ended' | 'expired';
  restricted_actions: RestrictedAction[];
  started_at: string;
  expires_at: string;
  reason?: string;
}

/**
 * Impersonation status response
 */
export interface ImpersonationStatus {
  is_impersonating: boolean;
  session?: ImpersonationSession;
  remaining_seconds?: number;
}

/**
 * Hook options
 */
export interface UseImpersonationOptions {
  /** API base URL */
  apiUrl?: string;
  /** Access token for API calls */
  accessToken?: string;
  /** Polling interval in milliseconds (default: 30000) */
  pollingInterval?: number;
  /** Enable polling for status updates */
  enablePolling?: boolean;
  /** Callback when impersonation ends */
  onImpersonationEnd?: () => void;
  /** Callback when impersonation expires */
  onImpersonationExpire?: () => void;
}

/**
 * Hook return type
 */
export interface UseImpersonationReturn {
  /** Whether currently in an impersonation session */
  isImpersonating: boolean;
  /** Current impersonation session data */
  session: ImpersonationSession | null;
  /** Remaining time in seconds */
  remainingSeconds: number;
  /** Formatted remaining time (e.g., "45:30") */
  remainingTimeFormatted: string;
  /** List of restricted actions */
  restrictedActions: RestrictedAction[];
  /** Check if a specific action is restricted */
  isActionRestricted: (action: RestrictedAction) => boolean;
  /** End the current impersonation session */
  endImpersonation: () => Promise<void>;
  /** Loading state */
  isLoading: boolean;
  /** Error state */
  error: string | null;
  /** Refresh impersonation status */
  refresh: () => Promise<void>;
}

/**
 * Default restricted actions
 */
const DEFAULT_RESTRICTED_ACTIONS: RestrictedAction[] = [
  'change_password',
  'delete_account',
  'change_email',
  'disable_mfa',
  'revoke_sessions',
  'manage_api_keys',
  'billing_changes'
];

/**
 * Format seconds to MM:SS
 */
function formatTime(seconds: number): string {
  if (seconds <= 0) return '00:00';
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

/**
 * useImpersonation Hook
 * 
 * Detects and manages impersonation sessions in the React SDK.
 * Shows visual indicators and provides controls for ending impersonation.
 */
export function useImpersonation(options: UseImpersonationOptions = {}): UseImpersonationReturn {
  const {
    apiUrl = '/api',
    accessToken,
    pollingInterval = 30000,
    enablePolling = false,
    onImpersonationEnd,
    onImpersonationExpire
  } = options;

  // State
  const [isImpersonating, setIsImpersonating] = useState(false);
  const [session, setSession] = useState<ImpersonationSession | null>(null);
  const [remainingSeconds, setRemainingSeconds] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  /**
   * Fetch impersonation status from API
   */
  const fetchStatus = useCallback(async () => {
    if (!accessToken) {
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch(`${apiUrl}/impersonation/status`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        // Not impersonating or error
        setIsImpersonating(false);
        setSession(null);
        setRemainingSeconds(0);
        setError(null);
        return;
      }

      const data = await response.json() as { data: ImpersonationStatus };
      const status = data.data;

      setIsImpersonating(status.is_impersonating);
      setSession(status.session || null);
      setRemainingSeconds(status.remaining_seconds || 0);
      setError(null);

      // Check if expired
      if (status.session?.status === 'expired') {
        onImpersonationExpire?.();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch impersonation status');
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, onImpersonationExpire]);

  /**
   * End impersonation session
   */
  const endImpersonation = useCallback(async () => {
    if (!accessToken || !isImpersonating) {
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/impersonation/end`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error?.message || 'Failed to end impersonation');
      }

      setIsImpersonating(false);
      setSession(null);
      setRemainingSeconds(0);
      onImpersonationEnd?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to end impersonation');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, isImpersonating, onImpersonationEnd]);

  /**
   * Check if action is restricted
   */
  const isActionRestricted = useCallback((action: RestrictedAction): boolean => {
    if (!isImpersonating || !session) {
      return false;
    }
    const restrictions = session.restricted_actions || DEFAULT_RESTRICTED_ACTIONS;
    return restrictions.includes(action);
  }, [isImpersonating, session]);

  /**
   * Get restricted actions list
   */
  const restrictedActions = useMemo((): RestrictedAction[] => {
    if (!isImpersonating || !session) {
      return [];
    }
    return session.restricted_actions || DEFAULT_RESTRICTED_ACTIONS;
  }, [isImpersonating, session]);

  /**
   * Format remaining time
   */
  const remainingTimeFormatted = useMemo(() => {
    return formatTime(remainingSeconds);
  }, [remainingSeconds]);

  /**
   * Initial fetch
   */
  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  /**
   * Polling for status updates
   */
  useEffect(() => {
    if (!enablePolling || !isImpersonating) {
      return;
    }

    const interval = setInterval(() => {
      fetchStatus();
    }, pollingInterval);

    return () => clearInterval(interval);
  }, [enablePolling, isImpersonating, pollingInterval, fetchStatus]);

  /**
   * Countdown timer for remaining time
   */
  useEffect(() => {
    if (!isImpersonating || remainingSeconds <= 0) {
      return;
    }

    const timer = setInterval(() => {
      setRemainingSeconds(prev => {
        const newValue = prev - 1;
        if (newValue <= 0) {
          onImpersonationExpire?.();
          return 0;
        }
        return newValue;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [isImpersonating, remainingSeconds, onImpersonationExpire]);

  return {
    isImpersonating,
    session,
    remainingSeconds,
    remainingTimeFormatted,
    restrictedActions,
    isActionRestricted,
    endImpersonation,
    isLoading,
    error,
    refresh: fetchStatus
  };
}

export default useImpersonation;
