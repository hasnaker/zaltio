/**
 * useSessions Hook - Session Management
 * Task 21.5: SDK <SessionList /> component support hook
 * 
 * Provides:
 * - List active sessions
 * - Current session indicator
 * - Revoke session action
 * - Revoke all sessions action
 * - Session location and last activity
 * 
 * Validates: Requirements 13.7 (Session Handler SDK)
 */

import { useState, useEffect, useCallback, useMemo } from 'react';

/**
 * Session location information
 */
export interface SessionLocation {
  city?: string;
  country?: string;
  country_code?: string;
}

/**
 * Impossible travel detection info
 */
export interface ImpossibleTravelInfo {
  detected: boolean;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  previous_location?: SessionLocation;
  current_location?: SessionLocation;
  distance_km?: number;
  time_elapsed_hours?: number;
  speed_kmh?: number;
  reason?: string;
}

/**
 * Session information returned from API
 */
export interface Session {
  id: string;
  device: string;
  browser: string;
  ip_address: string;
  location?: SessionLocation;
  last_activity: string;
  created_at: string;
  is_current: boolean;
  user_agent: string;
  impossible_travel?: ImpossibleTravelInfo;
}

/**
 * Hook options
 */
export interface UseSessionsOptions {
  /** API base URL */
  apiUrl?: string;
  /** Access token for API calls */
  accessToken?: string;
  /** Auto-fetch sessions on mount */
  autoFetch?: boolean;
  /** Polling interval in milliseconds (0 to disable) */
  pollingInterval?: number;
  /** Callback when session is revoked */
  onSessionRevoked?: (sessionId: string) => void;
  /** Callback when all sessions are revoked */
  onAllSessionsRevoked?: (count: number) => void;
  /** Callback on error */
  onError?: (error: Error) => void;
}

/**
 * Hook return type
 */
export interface UseSessionsReturn {
  /** List of active sessions */
  sessions: Session[];
  /** Current session (if found) */
  currentSession: Session | null;
  /** Other sessions (excluding current) */
  otherSessions: Session[];
  /** Total session count */
  totalSessions: number;
  /** Whether impossible travel was detected */
  impossibleTravelDetected: boolean;
  /** Loading state */
  isLoading: boolean;
  /** Error state */
  error: string | null;
  /** Fetch/refresh sessions */
  fetchSessions: () => Promise<void>;
  /** Revoke a specific session */
  revokeSession: (sessionId: string) => Promise<boolean>;
  /** Revoke all sessions except current */
  revokeAllSessions: () => Promise<number>;
  /** Clear error */
  clearError: () => void;
}

/**
 * useSessions Hook
 * 
 * Manages user sessions with support for listing, revoking, and monitoring.
 * Includes impossible travel detection awareness.
 * 
 * @example
 * ```tsx
 * import { useSessions } from '@zalt/react';
 * 
 * function SessionManager() {
 *   const { 
 *     sessions, 
 *     currentSession, 
 *     revokeSession, 
 *     revokeAllSessions 
 *   } = useSessions({ accessToken });
 * 
 *   return (
 *     <div>
 *       {sessions.map(session => (
 *         <div key={session.id}>
 *           {session.device} - {session.browser}
 *           {!session.is_current && (
 *             <button onClick={() => revokeSession(session.id)}>
 *               Revoke
 *             </button>
 *           )}
 *         </div>
 *       ))}
 *     </div>
 *   );
 * }
 * ```
 */
export function useSessions(options: UseSessionsOptions = {}): UseSessionsReturn {
  const {
    apiUrl = '/api',
    accessToken,
    autoFetch = true,
    pollingInterval = 0,
    onSessionRevoked,
    onAllSessionsRevoked,
    onError
  } = options;

  // State
  const [sessions, setSessions] = useState<Session[]>([]);
  const [impossibleTravelDetected, setImpossibleTravelDetected] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  /**
   * Fetch sessions from API
   */
  const fetchSessions = useCallback(async () => {
    if (!accessToken) {
      setError('Access token is required');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/sessions`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `Failed to fetch sessions (${response.status})`;
        throw new Error(errorMessage);
      }

      const data = await response.json();
      
      setSessions(data.sessions || []);
      setImpossibleTravelDetected(data.impossible_travel_detected || false);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch sessions';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, onError]);

  /**
   * Revoke a specific session
   */
  const revokeSession = useCallback(async (sessionId: string): Promise<boolean> => {
    if (!accessToken) {
      setError('Access token is required');
      return false;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/sessions/${sessionId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `Failed to revoke session (${response.status})`;
        throw new Error(errorMessage);
      }

      // Remove the session from local state
      setSessions(prev => prev.filter(s => s.id !== sessionId));
      
      onSessionRevoked?.(sessionId);
      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to revoke session';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
      return false;
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, onSessionRevoked, onError]);

  /**
   * Revoke all sessions except current
   */
  const revokeAllSessions = useCallback(async (): Promise<number> => {
    if (!accessToken) {
      setError('Access token is required');
      return 0;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/sessions`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `Failed to revoke sessions (${response.status})`;
        throw new Error(errorMessage);
      }

      const data = await response.json();
      const revokedCount = data.revoked_count || 0;

      // Keep only the current session in local state
      setSessions(prev => prev.filter(s => s.is_current));
      
      onAllSessionsRevoked?.(revokedCount);
      return revokedCount;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to revoke sessions';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
      return 0;
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, onAllSessionsRevoked, onError]);

  /**
   * Computed: Current session
   */
  const currentSession = useMemo(() => {
    return sessions.find(s => s.is_current) || null;
  }, [sessions]);

  /**
   * Computed: Other sessions (excluding current)
   */
  const otherSessions = useMemo(() => {
    return sessions.filter(s => !s.is_current);
  }, [sessions]);

  /**
   * Computed: Total session count
   */
  const totalSessions = useMemo(() => {
    return sessions.length;
  }, [sessions]);

  /**
   * Auto-fetch on mount
   */
  useEffect(() => {
    if (autoFetch && accessToken) {
      fetchSessions();
    }
  }, [autoFetch, accessToken, fetchSessions]);

  /**
   * Polling for session updates
   */
  useEffect(() => {
    if (pollingInterval <= 0 || !accessToken) {
      return;
    }

    const interval = setInterval(() => {
      fetchSessions();
    }, pollingInterval);

    return () => clearInterval(interval);
  }, [pollingInterval, accessToken, fetchSessions]);

  return {
    sessions,
    currentSession,
    otherSessions,
    totalSessions,
    impossibleTravelDetected,
    isLoading,
    error,
    fetchSessions,
    revokeSession,
    revokeAllSessions,
    clearError
  };
}

export default useSessions;
