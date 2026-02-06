/**
 * useReverification Hook
 * @zalt/react
 * 
 * Hook for handling step-up authentication (reverification) flows.
 * Detects 403 REVERIFICATION_REQUIRED responses and provides state
 * for showing reverification modals and retrying original requests.
 * 
 * Validates: Requirements 3.6, 3.7 (SDK Reverification)
 */

'use client';

import { useState, useCallback, useRef, useMemo } from 'react';
import { useZaltContext } from '../context';

/**
 * Reverification levels supported by Zalt
 */
export type ReverificationLevel = 'password' | 'mfa' | 'webauthn';

/**
 * Reverification status from the API
 */
export interface ReverificationStatus {
  hasReverification: boolean;
  isValid: boolean;
  level: ReverificationLevel | null;
  verifiedAt: string | null;
  expiresAt: string | null;
  method: string | null;
}

/**
 * Pending request that requires reverification
 */
export interface PendingRequest<T = unknown> {
  /** Unique ID for this request */
  id: string;
  /** The function to retry after reverification */
  retryFn: () => Promise<T>;
  /** Required reverification level */
  requiredLevel: ReverificationLevel;
  /** Validity period in minutes */
  validityMinutes?: number;
  /** Timestamp when the request was intercepted */
  timestamp: number;
}

/**
 * Reverification result after successful verification
 */
export interface ReverificationResult {
  level: ReverificationLevel;
  verifiedAt: string;
  expiresAt: string;
}

/**
 * Error response from API indicating reverification is required
 */
export interface ReverificationRequiredError {
  code: 'REVERIFICATION_REQUIRED';
  message: string;
  requiredLevel: ReverificationLevel;
  validityMinutes?: number;
}

/**
 * useReverification return type
 */
export interface UseReverificationReturn {
  /** Whether reverification modal should be shown */
  isModalOpen: boolean;
  /** Required reverification level for current pending request */
  requiredLevel: ReverificationLevel | null;
  /** Validity period in minutes */
  validityMinutes: number | null;
  /** Current pending request awaiting reverification */
  pendingRequest: PendingRequest | null;
  /** Loading state during reverification */
  isLoading: boolean;
  /** Error message if reverification failed */
  error: string | null;
  /** Last successful reverification result */
  lastReverification: ReverificationResult | null;
  
  /**
   * Verify with password
   * @param password - User's password
   */
  verifyWithPassword: (password: string) => Promise<void>;
  
  /**
   * Verify with MFA code (TOTP or backup code)
   * @param code - 6-digit TOTP code or backup code
   */
  verifyWithMFA: (code: string) => Promise<void>;
  
  /**
   * Verify with WebAuthn credential
   * @param credential - WebAuthn credential from navigator.credentials.get()
   * @param challenge - Challenge from getWebAuthnChallenge()
   */
  verifyWithWebAuthn: (credential: PublicKeyCredential, challenge: string) => Promise<void>;
  
  /**
   * Get WebAuthn challenge for reverification
   */
  getWebAuthnChallenge: () => Promise<{ challenge: string; rpId: string }>;
  
  /**
   * Check current reverification status
   * @param requiredLevel - Optional level to check against
   */
  checkStatus: (requiredLevel?: ReverificationLevel) => Promise<ReverificationStatus>;
  
  /**
   * Close the reverification modal without completing
   */
  closeModal: () => void;
  
  /**
   * Clear any pending request
   */
  clearPendingRequest: () => void;
  
  /**
   * Wrap an async function to automatically handle reverification
   * When the wrapped function returns 403 REVERIFICATION_REQUIRED,
   * it will show the modal and retry after successful verification.
   * 
   * @param fn - Async function to wrap
   * @returns Wrapped function that handles reverification
   */
  withReverification: <T>(fn: () => Promise<T>) => Promise<T>;
  
  /**
   * Intercept a response and check if reverification is required
   * @param response - Fetch Response object
   * @param retryFn - Function to retry if reverification succeeds
   * @returns true if reverification is required, false otherwise
   */
  interceptResponse: <T>(response: Response, retryFn: () => Promise<T>) => Promise<boolean>;
}

/**
 * Check if an error indicates reverification is required
 */
function isReverificationRequiredError(error: unknown): error is ReverificationRequiredError {
  if (typeof error !== 'object' || error === null) return false;
  const err = error as Record<string, unknown>;
  return err.code === 'REVERIFICATION_REQUIRED' && typeof err.requiredLevel === 'string';
}

/**
 * Check if a response indicates reverification is required
 */
function isReverificationRequiredResponse(response: Response): boolean {
  return response.status === 403 && 
         response.headers.get('X-Reverification-Required') === 'true';
}

/**
 * Extract reverification details from response
 */
async function extractReverificationDetails(response: Response): Promise<{
  requiredLevel: ReverificationLevel;
  validityMinutes?: number;
} | null> {
  // Check header first
  const levelHeader = response.headers.get('X-Reverification-Level');
  if (levelHeader && ['password', 'mfa', 'webauthn'].includes(levelHeader)) {
    return {
      requiredLevel: levelHeader as ReverificationLevel,
    };
  }
  
  // Try to parse body
  try {
    const body = await response.clone().json();
    if (body.reverification) {
      return {
        requiredLevel: body.reverification.level,
        validityMinutes: body.reverification.validityMinutes,
      };
    }
    if (body.error?.requiredLevel) {
      return {
        requiredLevel: body.error.requiredLevel,
        validityMinutes: body.error.validityMinutes,
      };
    }
  } catch {
    // Ignore JSON parse errors
  }
  
  return null;
}

/**
 * Generate unique request ID
 */
function generateRequestId(): string {
  return `rev_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Serialize WebAuthn credential for API
 */
function serializeCredential(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAssertionResponse;
  
  const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  };
  
  return {
    id: credential.id,
    rawId: arrayBufferToBase64(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: arrayBufferToBase64(response.clientDataJSON),
      authenticatorData: arrayBufferToBase64(response.authenticatorData),
      signature: arrayBufferToBase64(response.signature),
      userHandle: response.userHandle ? arrayBufferToBase64(response.userHandle) : null,
    },
  };
}

/**
 * Hook to handle reverification (step-up authentication) flows
 * 
 * @example
 * ```tsx
 * import { useReverification } from '@zalt/react';
 * 
 * function SensitiveAction() {
 *   const {
 *     isModalOpen,
 *     requiredLevel,
 *     verifyWithPassword,
 *     verifyWithMFA,
 *     withReverification,
 *     closeModal,
 *     isLoading,
 *     error,
 *   } = useReverification();
 * 
 *   const handleDeleteAccount = async () => {
 *     await withReverification(async () => {
 *       // This will automatically show reverification modal if needed
 *       await api.deleteAccount();
 *     });
 *   };
 * 
 *   return (
 *     <>
 *       <button onClick={handleDeleteAccount}>Delete Account</button>
 *       
 *       {isModalOpen && (
 *         <ReverificationModal
 *           level={requiredLevel}
 *           onPasswordSubmit={verifyWithPassword}
 *           onMFASubmit={verifyWithMFA}
 *           onClose={closeModal}
 *           isLoading={isLoading}
 *           error={error}
 *         />
 *       )}
 *     </>
 *   );
 * }
 * ```
 */
export function useReverification(): UseReverificationReturn {
  const { client } = useZaltContext();
  
  // State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastReverification, setLastReverification] = useState<ReverificationResult | null>(null);
  const [pendingRequest, setPendingRequest] = useState<PendingRequest | null>(null);
  
  // Refs for pending request resolution
  const pendingResolveRef = useRef<((value: unknown) => void) | null>(null);
  const pendingRejectRef = useRef<((error: Error) => void) | null>(null);
  
  // Derived state
  const requiredLevel = pendingRequest?.requiredLevel ?? null;
  const validityMinutes = pendingRequest?.validityMinutes ?? null;
  
  /**
   * Get base URL from client config
   */
  const getBaseUrl = useCallback((): string => {
    // Access internal config - in production this would be exposed properly
    return 'https://api.zalt.io';
  }, []);
  
  /**
   * Get auth headers
   */
  const getAuthHeaders = useCallback(async (): Promise<Record<string, string>> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    // Get access token from client
    try {
      const state = client.getAuthState();
      if (state.isAuthenticated) {
        // The client handles token management internally
        // We need to make authenticated requests through the client
      }
    } catch {
      // Ignore errors
    }
    
    return headers;
  }, [client]);
  
  /**
   * Complete reverification and retry pending request
   */
  const completeReverification = useCallback(async (result: ReverificationResult) => {
    setLastReverification(result);
    setIsModalOpen(false);
    setError(null);
    
    // Retry pending request if exists
    if (pendingRequest && pendingResolveRef.current) {
      try {
        const retryResult = await pendingRequest.retryFn();
        pendingResolveRef.current(retryResult);
      } catch (retryError) {
        if (pendingRejectRef.current) {
          pendingRejectRef.current(retryError instanceof Error ? retryError : new Error(String(retryError)));
        }
      } finally {
        setPendingRequest(null);
        pendingResolveRef.current = null;
        pendingRejectRef.current = null;
      }
    }
  }, [pendingRequest]);
  
  /**
   * Verify with password
   */
  const verifyWithPassword = useCallback(async (password: string): Promise<void> => {
    if (!password) {
      setError('Password is required');
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${getBaseUrl()}/reverify/password`, {
        method: 'POST',
        headers: await getAuthHeaders(),
        credentials: 'include',
        body: JSON.stringify({ password }),
      });
      
      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(errorBody.error?.message || 'Password verification failed');
      }
      
      const data = await response.json();
      
      await completeReverification({
        level: data.reverification.level,
        verifiedAt: data.reverification.verified_at,
        expiresAt: data.reverification.expires_at,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Password verification failed';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [getBaseUrl, getAuthHeaders, completeReverification]);
  
  /**
   * Verify with MFA code
   */
  const verifyWithMFA = useCallback(async (code: string): Promise<void> => {
    if (!code) {
      setError('MFA code is required');
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${getBaseUrl()}/reverify/mfa`, {
        method: 'POST',
        headers: await getAuthHeaders(),
        credentials: 'include',
        body: JSON.stringify({ code }),
      });
      
      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(errorBody.error?.message || 'MFA verification failed');
      }
      
      const data = await response.json();
      
      await completeReverification({
        level: data.reverification.level,
        verifiedAt: data.reverification.verified_at,
        expiresAt: data.reverification.expires_at,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'MFA verification failed';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [getBaseUrl, getAuthHeaders, completeReverification]);
  
  /**
   * Get WebAuthn challenge for reverification
   */
  const getWebAuthnChallenge = useCallback(async (): Promise<{ challenge: string; rpId: string }> => {
    const response = await fetch(`${getBaseUrl()}/reverify/webauthn/challenge`, {
      method: 'POST',
      headers: await getAuthHeaders(),
      credentials: 'include',
    });
    
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(errorBody.error?.message || 'Failed to get WebAuthn challenge');
    }
    
    return response.json();
  }, [getBaseUrl, getAuthHeaders]);
  
  /**
   * Verify with WebAuthn credential
   */
  const verifyWithWebAuthn = useCallback(async (
    credential: PublicKeyCredential,
    challenge: string
  ): Promise<void> => {
    if (!credential) {
      setError('WebAuthn credential is required');
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${getBaseUrl()}/reverify/webauthn`, {
        method: 'POST',
        headers: await getAuthHeaders(),
        credentials: 'include',
        body: JSON.stringify({
          credential: serializeCredential(credential),
          challenge,
        }),
      });
      
      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        throw new Error(errorBody.error?.message || 'WebAuthn verification failed');
      }
      
      const data = await response.json();
      
      await completeReverification({
        level: data.reverification.level,
        verifiedAt: data.reverification.verified_at,
        expiresAt: data.reverification.expires_at,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'WebAuthn verification failed';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [getBaseUrl, getAuthHeaders, completeReverification]);
  
  /**
   * Check reverification status
   */
  const checkStatus = useCallback(async (
    requiredLevel?: ReverificationLevel
  ): Promise<ReverificationStatus> => {
    const url = new URL(`${getBaseUrl()}/reverify/status`);
    if (requiredLevel) {
      url.searchParams.set('level', requiredLevel);
    }
    
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: await getAuthHeaders(),
      credentials: 'include',
    });
    
    if (!response.ok) {
      throw new Error('Failed to check reverification status');
    }
    
    const data = await response.json();
    
    return {
      hasReverification: data.has_reverification,
      isValid: data.is_valid,
      level: data.reverification?.level ?? null,
      verifiedAt: data.reverification?.verified_at ?? null,
      expiresAt: data.reverification?.expires_at ?? null,
      method: data.reverification?.method ?? null,
    };
  }, [getBaseUrl, getAuthHeaders]);
  
  /**
   * Close modal without completing
   */
  const closeModal = useCallback(() => {
    setIsModalOpen(false);
    setError(null);
    
    // Reject pending request
    if (pendingRejectRef.current) {
      pendingRejectRef.current(new Error('Reverification cancelled'));
    }
    
    setPendingRequest(null);
    pendingResolveRef.current = null;
    pendingRejectRef.current = null;
  }, []);
  
  /**
   * Clear pending request
   */
  const clearPendingRequest = useCallback(() => {
    setPendingRequest(null);
    pendingResolveRef.current = null;
    pendingRejectRef.current = null;
  }, []);
  
  /**
   * Intercept response and check if reverification is required
   */
  const interceptResponse = useCallback(async <T>(
    response: Response,
    retryFn: () => Promise<T>
  ): Promise<boolean> => {
    if (!isReverificationRequiredResponse(response)) {
      return false;
    }
    
    const details = await extractReverificationDetails(response);
    if (!details) {
      return false;
    }
    
    // Create pending request
    const request: PendingRequest<T> = {
      id: generateRequestId(),
      retryFn,
      requiredLevel: details.requiredLevel,
      validityMinutes: details.validityMinutes,
      timestamp: Date.now(),
    };
    
    setPendingRequest(request);
    setIsModalOpen(true);
    setError(null);
    
    return true;
  }, []);
  
  /**
   * Wrap async function to handle reverification automatically
   */
  const withReverification = useCallback(<T>(fn: () => Promise<T>): Promise<T> => {
    return new Promise<T>((resolve, reject) => {
      // Execute the function
      fn()
        .then(resolve)
        .catch(async (error) => {
          // Check if it's a reverification required error
          if (isReverificationRequiredError(error)) {
            // Create pending request
            const request: PendingRequest<T> = {
              id: generateRequestId(),
              retryFn: fn,
              requiredLevel: error.requiredLevel,
              validityMinutes: error.validityMinutes,
              timestamp: Date.now(),
            };
            
            // Store resolve/reject for later
            pendingResolveRef.current = resolve as (value: unknown) => void;
            pendingRejectRef.current = reject;
            
            // Show modal
            setPendingRequest(request);
            setIsModalOpen(true);
            setError(null);
            
            // Don't reject yet - wait for reverification
            return;
          }
          
          // Check if error has response property (fetch error)
          if (error && typeof error === 'object' && 'response' in error) {
            const response = error.response as Response;
            if (isReverificationRequiredResponse(response)) {
              const details = await extractReverificationDetails(response);
              if (details) {
                const request: PendingRequest<T> = {
                  id: generateRequestId(),
                  retryFn: fn,
                  requiredLevel: details.requiredLevel,
                  validityMinutes: details.validityMinutes,
                  timestamp: Date.now(),
                };
                
                pendingResolveRef.current = resolve as (value: unknown) => void;
                pendingRejectRef.current = reject;
                
                setPendingRequest(request);
                setIsModalOpen(true);
                setError(null);
                return;
              }
            }
          }
          
          // Not a reverification error, reject normally
          reject(error);
        });
    });
  }, []);
  
  return useMemo(() => ({
    isModalOpen,
    requiredLevel,
    validityMinutes,
    pendingRequest,
    isLoading,
    error,
    lastReverification,
    verifyWithPassword,
    verifyWithMFA,
    verifyWithWebAuthn,
    getWebAuthnChallenge,
    checkStatus,
    closeModal,
    clearPendingRequest,
    withReverification,
    interceptResponse,
  }), [
    isModalOpen,
    requiredLevel,
    validityMinutes,
    pendingRequest,
    isLoading,
    error,
    lastReverification,
    verifyWithPassword,
    verifyWithMFA,
    verifyWithWebAuthn,
    getWebAuthnChallenge,
    checkStatus,
    closeModal,
    clearPendingRequest,
    withReverification,
    interceptResponse,
  ]);
}

export default useReverification;
