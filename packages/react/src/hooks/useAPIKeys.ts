/**
 * useAPIKeys Hook - API Key Management
 * Task 23.1: SDK <APIKeyManager /> component support hook
 * 
 * Provides:
 * - Create API keys with name and optional expiry
 * - List API keys (masked)
 * - Revoke API keys
 * - Copy key functionality (only on creation)
 * 
 * Validates: Requirements 2.9, 2.10 (API Key Management UI)
 */

import { useState, useEffect, useCallback, useMemo } from 'react';

/**
 * API Key status
 */
export type APIKeyStatus = 'active' | 'revoked' | 'expired';

/**
 * API Key information returned from API
 */
export interface APIKey {
  id: string;
  user_id: string;
  realm_id: string;
  tenant_id?: string;
  name: string;
  description?: string;
  key_prefix: string;
  scopes: string[];
  status: APIKeyStatus;
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
  revoked_at?: string;
}

/**
 * Input for creating an API key
 */
export interface CreateAPIKeyInput {
  name: string;
  description?: string;
  scopes?: string[];
  expires_at?: string;
}

/**
 * Result of creating an API key (includes full key once)
 */
export interface CreateAPIKeyResult {
  key: APIKey;
  full_key: string;
}

/**
 * Hook options
 */
export interface UseAPIKeysOptions {
  /** API base URL */
  apiUrl?: string;
  /** Access token for API calls */
  accessToken?: string;
  /** Auto-fetch keys on mount */
  autoFetch?: boolean;
  /** Callback when key is created */
  onKeyCreated?: (key: APIKey, fullKey: string) => void;
  /** Callback when key is revoked */
  onKeyRevoked?: (keyId: string) => void;
  /** Callback on error */
  onError?: (error: Error) => void;
}

/**
 * Hook return type
 */
export interface UseAPIKeysReturn {
  /** List of API keys */
  keys: APIKey[];
  /** Active keys only */
  activeKeys: APIKey[];
  /** Total key count */
  totalKeys: number;
  /** Loading state */
  isLoading: boolean;
  /** Error state */
  error: string | null;
  /** Fetch/refresh keys */
  fetchKeys: () => Promise<void>;
  /** Create a new API key */
  createKey: (input: CreateAPIKeyInput) => Promise<CreateAPIKeyResult>;
  /** Revoke an API key */
  revokeKey: (keyId: string) => Promise<boolean>;
  /** Clear error */
  clearError: () => void;
  /** Copy text to clipboard */
  copyToClipboard: (text: string) => Promise<boolean>;
}

/**
 * useAPIKeys Hook
 * 
 * Manages user API keys with support for creating, listing, and revoking.
 * 
 * @example
 * ```tsx
 * import { useAPIKeys } from '@zalt/react';
 * 
 * function APIKeyManager() {
 *   const { 
 *     keys, 
 *     createKey, 
 *     revokeKey,
 *     copyToClipboard 
 *   } = useAPIKeys({ accessToken });
 * 
 *   const handleCreate = async () => {
 *     const result = await createKey({ name: 'My API Key' });
 *     await copyToClipboard(result.full_key);
 *     alert('Key copied to clipboard!');
 *   };
 * 
 *   return (
 *     <div>
 *       {keys.map(key => (
 *         <div key={key.id}>
 *           {key.name} - {key.key_prefix}...
 *           <button onClick={() => revokeKey(key.id)}>Revoke</button>
 *         </div>
 *       ))}
 *     </div>
 *   );
 * }
 * ```
 */
export function useAPIKeys(options: UseAPIKeysOptions = {}): UseAPIKeysReturn {
  const {
    apiUrl = '/api',
    accessToken,
    autoFetch = true,
    onKeyCreated,
    onKeyRevoked,
    onError
  } = options;

  // State
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  /**
   * Copy text to clipboard
   */
  const copyToClipboard = useCallback(async (text: string): Promise<boolean> => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
      
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      
      const success = document.execCommand('copy');
      document.body.removeChild(textArea);
      return success;
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
      return false;
    }
  }, []);

  /**
   * Fetch API keys from API
   */
  const fetchKeys = useCallback(async () => {
    if (!accessToken) {
      setError('Access token is required');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/api-keys`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `Failed to fetch API keys (${response.status})`;
        throw new Error(errorMessage);
      }

      const data = await response.json();
      setKeys(data.keys || []);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch API keys';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, onError]);

  /**
   * Create a new API key
   */
  const createKey = useCallback(async (input: CreateAPIKeyInput): Promise<CreateAPIKeyResult> => {
    if (!accessToken) {
      const err = new Error('Access token is required');
      setError(err.message);
      throw err;
    }

    if (!input.name || input.name.trim().length === 0) {
      const err = new Error('API key name is required');
      setError(err.message);
      throw err;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/api-keys`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: input.name.trim(),
          description: input.description?.trim(),
          scopes: input.scopes,
          expires_at: input.expires_at
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `Failed to create API key (${response.status})`;
        throw new Error(errorMessage);
      }

      const data = await response.json();
      const result: CreateAPIKeyResult = {
        key: data.key,
        full_key: data.full_key
      };

      // Add the new key to local state
      setKeys(prev => [result.key, ...prev]);
      
      onKeyCreated?.(result.key, result.full_key);
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to create API key';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, onKeyCreated, onError]);

  /**
   * Revoke an API key
   */
  const revokeKey = useCallback(async (keyId: string): Promise<boolean> => {
    if (!accessToken) {
      setError('Access token is required');
      return false;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/api-keys/${keyId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `Failed to revoke API key (${response.status})`;
        throw new Error(errorMessage);
      }

      // Update the key status in local state
      setKeys(prev => prev.map(key => 
        key.id === keyId 
          ? { ...key, status: 'revoked' as APIKeyStatus, revoked_at: new Date().toISOString() }
          : key
      ));
      
      onKeyRevoked?.(keyId);
      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to revoke API key';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
      return false;
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, onKeyRevoked, onError]);

  /**
   * Computed: Active keys only
   */
  const activeKeys = useMemo(() => {
    return keys.filter(key => key.status === 'active');
  }, [keys]);

  /**
   * Computed: Total key count
   */
  const totalKeys = useMemo(() => {
    return keys.length;
  }, [keys]);

  /**
   * Auto-fetch on mount
   */
  useEffect(() => {
    if (autoFetch && accessToken) {
      fetchKeys();
    }
  }, [autoFetch, accessToken, fetchKeys]);

  return {
    keys,
    activeKeys,
    totalKeys,
    isLoading,
    error,
    fetchKeys,
    createKey,
    revokeKey,
    clearError,
    copyToClipboard
  };
}

export default useAPIKeys;
