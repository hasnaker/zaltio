/**
 * useMFA Hook
 * @zalt/react
 */

'use client';

import { useState, useCallback } from 'react';
import type { MFAMethod, MFASetupResult, MFAStatus } from '@zalt.io/core';
import { useZaltContext } from '../context';

/**
 * useMFA return type
 */
export interface UseMFAReturn {
  /** Whether MFA verification is required */
  isRequired: boolean;
  /** MFA session ID for verification */
  sessionId: string | null;
  /** Available MFA methods */
  methods: MFAMethod[];
  /** Verify MFA code */
  verify: (code: string) => Promise<void>;
  /** Setup MFA */
  setup: (method?: 'totp') => Promise<MFASetupResult>;
  /** Disable MFA */
  disable: (code: string) => Promise<void>;
  /** Get MFA status */
  getStatus: () => Promise<MFAStatus>;
  /** Loading state */
  isLoading: boolean;
  /** Error message */
  error: string | null;
}

/**
 * Hook to manage MFA (Multi-Factor Authentication)
 * 
 * @example
 * ```tsx
 * import { useMFA } from '@zalt/react';
 * 
 * function MFAVerification() {
 *   const { isRequired, verify, isLoading, error } = useMFA();
 *   const [code, setCode] = useState('');
 * 
 *   if (!isRequired) return null;
 * 
 *   return (
 *     <form onSubmit={(e) => { e.preventDefault(); verify(code); }}>
 *       <input value={code} onChange={(e) => setCode(e.target.value)} />
 *       <button disabled={isLoading}>Verify</button>
 *       {error && <p>{error}</p>}
 *     </form>
 *   );
 * }
 * ```
 */
export function useMFA(): UseMFAReturn {
  const { client, state } = useZaltContext();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mfaState, setMfaState] = useState({
    isRequired: false,
    sessionId: null as string | null,
    methods: [] as MFAMethod[],
  });

  const verify = useCallback(async (code: string) => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await client.mfa.verify(code, mfaState.sessionId || undefined);
      setMfaState({ isRequired: false, sessionId: null, methods: [] });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client, mfaState.sessionId]);

  const setup = useCallback(async (method: 'totp' = 'totp') => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await client.mfa.setup(method);
      return result;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  const disable = useCallback(async (code: string) => {
    setIsLoading(true);
    setError(null);

    try {
      await client.mfa.disable(code);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Disable failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  const getStatus = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const status = await client.mfa.getStatus();
      return status;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get status');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  return {
    isRequired: mfaState.isRequired,
    sessionId: mfaState.sessionId,
    methods: mfaState.methods,
    verify,
    setup,
    disable,
    getStatus,
    isLoading,
    error,
  };
}

export default useMFA;
