/**
 * Zalt.io Auth React Provider
 * @zalt/auth-react - Official React SDK for Zalt.io Authentication Platform
 * 
 * Provides authentication context for React applications with SSR support.
 * 
 * @example
 * ```tsx
 * import { AuthProvider } from '@zalt/auth-react';
 * 
 * function App() {
 *   return (
 *     <AuthProvider
 *       baseUrl="https://api.zalt.io/v1"
 *       realmId="clinisyn-psychologists"
 *     >
 *       <YourApp />
 *     </AuthProvider>
 *   );
 * }
 * ```
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
  ReactNode
} from 'react';
import {
  ZaltAuthClient,
  createZaltClient,
  User,
  AuthResult,
  RegisterData,
  LoginCredentials,
  TokenStorage,
  MFASetupResult,
  MFAVerifyResult,
  MFAStatus,
  BackupCodesResult,
  WebAuthnCredential,
  Device,
  SocialAuthUrlResult,
  SocialCallbackResult
} from '../index';
import { MFARequiredError, AccountLockedError } from '../errors';
import { BrowserStorage, MemoryStorage } from '../storage';

/**
 * Authentication state
 */
export interface AuthState {
  /** Current authenticated user or null */
  user: User | null;
  /** Whether authentication is being checked */
  isLoading: boolean;
  /** Whether user is authenticated */
  isAuthenticated: boolean;
  /** Current error if any */
  error: Error | null;
  /** MFA session ID if MFA is required */
  mfaSessionId: string | null;
  /** Whether account is locked */
  isAccountLocked: boolean;
  /** Account locked until timestamp */
  lockedUntil: string | null;
}

/**
 * Authentication context value
 */
export interface AuthContextValue extends AuthState {
  /** Zalt.io client instance */
  client: ZaltAuthClient;
  
  // Core auth methods
  /** Login with email and password */
  login: (credentials: LoginCredentials) => Promise<AuthResult>;
  /** Register a new user */
  register: (data: RegisterData) => Promise<AuthResult>;
  /** Logout current user */
  logout: (allDevices?: boolean) => Promise<void>;
  /** Refresh authentication state */
  refreshAuth: () => Promise<void>;
  /** Clear current error */
  clearError: () => void;
  
  // MFA methods
  /** Setup TOTP MFA */
  setupMFA: () => Promise<MFASetupResult>;
  /** Verify TOTP code to enable MFA */
  verifyMFA: (code: string) => Promise<void>;
  /** Disable MFA */
  disableMFA: (password: string) => Promise<void>;
  /** Verify MFA during login */
  verifyMFALogin: (code: string) => Promise<MFAVerifyResult>;
  /** Get MFA status */
  getMFAStatus: () => Promise<MFAStatus>;
  /** Regenerate backup codes */
  regenerateBackupCodes: (password: string) => Promise<BackupCodesResult>;
  
  // WebAuthn methods
  /** Get WebAuthn registration options */
  getWebAuthnRegisterOptions: () => Promise<unknown>;
  /** Verify WebAuthn registration */
  verifyWebAuthnRegister: (credential: unknown, name?: string) => Promise<unknown>;
  /** Get WebAuthn authentication options */
  getWebAuthnAuthOptions: (email?: string) => Promise<unknown>;
  /** Verify WebAuthn authentication */
  verifyWebAuthnAuth: (credential: unknown) => Promise<unknown>;
  /** List WebAuthn credentials */
  listWebAuthnCredentials: () => Promise<WebAuthnCredential[]>;
  /** Delete WebAuthn credential */
  deleteWebAuthnCredential: (id: string, password: string) => Promise<void>;
  
  // Device methods
  /** List user devices */
  listDevices: () => Promise<Device[]>;
  /** Revoke a device */
  revokeDevice: (deviceId: string) => Promise<void>;
  /** Trust current device */
  trustCurrentDevice: () => Promise<void>;
  
  // Social login methods
  /** Get social auth URL */
  getSocialAuthUrl: (provider: 'google' | 'apple') => Promise<SocialAuthUrlResult>;
  /** Handle social callback */
  handleSocialCallback: (provider: 'google' | 'apple', code: string, state: string) => Promise<SocialCallbackResult>;
}

/**
 * Auth Provider props
 */
export interface AuthProviderProps {
  /** Child components */
  children: ReactNode;
  /** API base URL */
  baseUrl: string;
  /** Realm ID for multi-tenant isolation */
  realmId: string;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Number of retry attempts */
  retryAttempts?: number;
  /** Delay between retries */
  retryDelay?: number;
  /** Enable automatic token refresh */
  autoRefresh?: boolean;
  /** Token refresh threshold in seconds */
  refreshThreshold?: number;
  /** Custom token storage */
  storage?: TokenStorage;
  /** Storage key prefix for browser storage */
  storageKey?: string;
  /** Callback when user logs in */
  onLogin?: (user: User) => void;
  /** Callback when user logs out */
  onLogout?: () => void;
  /** Callback when error occurs */
  onError?: (error: Error) => void;
  /** Callback when MFA is required */
  onMFARequired?: (sessionId: string) => void;
  /** Callback when account is locked */
  onAccountLocked?: (lockedUntil: string) => void;
}

// Create context with undefined default
const AuthContext = createContext<AuthContextValue | undefined>(undefined);

/**
 * Check if we're in a browser environment
 */
const isBrowser = typeof window !== 'undefined';

/**
 * Get default storage based on environment
 */
function getDefaultStorage(storageKey: string): TokenStorage {
  if (isBrowser) {
    return new BrowserStorage(storageKey);
  }
  return new MemoryStorage();
}

/**
 * Auth Provider Component
 * 
 * Provides authentication context to child components.
 * Supports SSR with automatic storage detection.
 */
export function AuthProvider({
  children,
  baseUrl,
  realmId,
  timeout,
  retryAttempts,
  retryDelay,
  autoRefresh = true,
  refreshThreshold,
  storage,
  storageKey = 'zalt_auth',
  onLogin,
  onLogout,
  onError,
  onMFARequired,
  onAccountLocked
}: AuthProviderProps): JSX.Element {
  // State
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [mfaSessionId, setMfaSessionId] = useState<string | null>(null);
  const [isAccountLocked, setIsAccountLocked] = useState(false);
  const [lockedUntil, setLockedUntil] = useState<string | null>(null);

  // Create client instance (memoized)
  const client = useMemo(() => {
    return createZaltClient({
      baseUrl,
      realmId,
      timeout,
      retryAttempts,
      retryDelay,
      autoRefresh,
      refreshThreshold,
      storage: storage ?? getDefaultStorage(storageKey)
    });
  }, [baseUrl, realmId, timeout, retryAttempts, retryDelay, autoRefresh, refreshThreshold, storage, storageKey]);

  // Computed state
  const isAuthenticated = user !== null;

  // Clear error
  const clearError = useCallback(() => {
    setError(null);
    setMfaSessionId(null);
    setIsAccountLocked(false);
    setLockedUntil(null);
  }, []);

  // Handle errors
  const handleError = useCallback((err: Error) => {
    setError(err);
    
    if (err instanceof MFARequiredError) {
      setMfaSessionId(err.mfaSessionId);
      onMFARequired?.(err.mfaSessionId);
    } else if (err instanceof AccountLockedError) {
      setIsAccountLocked(true);
      setLockedUntil(err.lockedUntil);
      onAccountLocked?.(err.lockedUntil);
    }
    
    onError?.(err);
  }, [onError, onMFARequired, onAccountLocked]);

  // Refresh auth state
  const refreshAuth = useCallback(async () => {
    try {
      setIsLoading(true);
      const currentUser = await client.getCurrentUser();
      setUser(currentUser);
      clearError();
    } catch (err) {
      setUser(null);
      // Don't set error for auth check failures
    } finally {
      setIsLoading(false);
    }
  }, [client, clearError]);

  // Login
  const login = useCallback(async (credentials: LoginCredentials): Promise<AuthResult> => {
    try {
      setIsLoading(true);
      clearError();
      
      const result = await client.login(credentials);
      setUser(result.user);
      onLogin?.(result.user);
      
      return result;
    } catch (err) {
      handleError(err as Error);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client, clearError, handleError, onLogin]);

  // Register
  const register = useCallback(async (data: RegisterData): Promise<AuthResult> => {
    try {
      setIsLoading(true);
      clearError();
      
      const result = await client.register(data);
      if (result.user) {
        setUser(result.user);
        onLogin?.(result.user);
      }
      
      return result;
    } catch (err) {
      handleError(err as Error);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client, clearError, handleError, onLogin]);

  // Logout
  const logout = useCallback(async (allDevices: boolean = false): Promise<void> => {
    try {
      setIsLoading(true);
      await client.logout(allDevices);
      setUser(null);
      clearError();
      onLogout?.();
    } catch (err) {
      handleError(err as Error);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client, clearError, handleError, onLogout]);

  // MFA methods
  const setupMFA = useCallback(async (): Promise<MFASetupResult> => {
    try {
      return await client.mfa.setup();
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  const verifyMFA = useCallback(async (code: string): Promise<void> => {
    try {
      await client.mfa.verify(code);
      // Refresh user to get updated MFA status
      await refreshAuth();
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError, refreshAuth]);

  const disableMFA = useCallback(async (password: string): Promise<void> => {
    try {
      await client.mfa.disable(password);
      await refreshAuth();
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError, refreshAuth]);

  const verifyMFALogin = useCallback(async (code: string): Promise<MFAVerifyResult> => {
    if (!mfaSessionId) {
      throw new Error('No MFA session active');
    }
    
    try {
      setIsLoading(true);
      const result = await client.mfa.verifyLogin(mfaSessionId, code);
      setUser(result.user);
      setMfaSessionId(null);
      onLogin?.(result.user);
      return result;
    } catch (err) {
      handleError(err as Error);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client, mfaSessionId, handleError, onLogin]);

  const getMFAStatus = useCallback(async (): Promise<MFAStatus> => {
    try {
      return await client.mfa.getStatus();
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  const regenerateBackupCodes = useCallback(async (password: string): Promise<BackupCodesResult> => {
    try {
      return await client.mfa.regenerateBackupCodes(password);
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  // WebAuthn methods
  const getWebAuthnRegisterOptions = useCallback(async () => {
    try {
      return await client.webauthn.registerOptions();
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  const verifyWebAuthnRegister = useCallback(async (credential: unknown, name?: string) => {
    try {
      const result = await client.webauthn.registerVerify(credential, name);
      await refreshAuth();
      return result;
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError, refreshAuth]);

  const getWebAuthnAuthOptions = useCallback(async (email?: string) => {
    try {
      return await client.webauthn.authenticateOptions(email);
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  const verifyWebAuthnAuth = useCallback(async (credential: unknown) => {
    try {
      setIsLoading(true);
      const result = await client.webauthn.authenticateVerify(credential);
      setUser(result.user);
      onLogin?.(result.user);
      return result;
    } catch (err) {
      handleError(err as Error);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client, handleError, onLogin]);

  const listWebAuthnCredentials = useCallback(async (): Promise<WebAuthnCredential[]> => {
    try {
      return await client.webauthn.listCredentials();
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  const deleteWebAuthnCredential = useCallback(async (id: string, password: string): Promise<void> => {
    try {
      await client.webauthn.deleteCredential(id, password);
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  // Device methods
  const listDevices = useCallback(async (): Promise<Device[]> => {
    try {
      return await client.devices.list();
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  const revokeDevice = useCallback(async (deviceId: string): Promise<void> => {
    try {
      await client.devices.revoke(deviceId);
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  const trustCurrentDevice = useCallback(async (): Promise<void> => {
    try {
      await client.devices.trustCurrent();
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  // Social login methods
  const getSocialAuthUrl = useCallback(async (provider: 'google' | 'apple'): Promise<SocialAuthUrlResult> => {
    try {
      return await client.social.getAuthUrl(provider);
    } catch (err) {
      handleError(err as Error);
      throw err;
    }
  }, [client, handleError]);

  const handleSocialCallback = useCallback(async (
    provider: 'google' | 'apple',
    code: string,
    state: string
  ): Promise<SocialCallbackResult> => {
    try {
      setIsLoading(true);
      const result = await client.social.handleCallback(provider, code, state);
      setUser(result.user);
      onLogin?.(result.user);
      return result;
    } catch (err) {
      handleError(err as Error);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [client, handleError, onLogin]);

  // Check auth on mount
  useEffect(() => {
    refreshAuth();
  }, [refreshAuth]);

  // Context value
  const contextValue: AuthContextValue = useMemo(() => ({
    // State
    user,
    isLoading,
    isAuthenticated,
    error,
    mfaSessionId,
    isAccountLocked,
    lockedUntil,
    client,
    
    // Core methods
    login,
    register,
    logout,
    refreshAuth,
    clearError,
    
    // MFA methods
    setupMFA,
    verifyMFA,
    disableMFA,
    verifyMFALogin,
    getMFAStatus,
    regenerateBackupCodes,
    
    // WebAuthn methods
    getWebAuthnRegisterOptions,
    verifyWebAuthnRegister,
    getWebAuthnAuthOptions,
    verifyWebAuthnAuth,
    listWebAuthnCredentials,
    deleteWebAuthnCredential,
    
    // Device methods
    listDevices,
    revokeDevice,
    trustCurrentDevice,
    
    // Social methods
    getSocialAuthUrl,
    handleSocialCallback
  }), [
    user, isLoading, isAuthenticated, error, mfaSessionId, isAccountLocked, lockedUntil, client,
    login, register, logout, refreshAuth, clearError,
    setupMFA, verifyMFA, disableMFA, verifyMFALogin, getMFAStatus, regenerateBackupCodes,
    getWebAuthnRegisterOptions, verifyWebAuthnRegister, getWebAuthnAuthOptions, verifyWebAuthnAuth,
    listWebAuthnCredentials, deleteWebAuthnCredential,
    listDevices, revokeDevice, trustCurrentDevice,
    getSocialAuthUrl, handleSocialCallback
  ]);

  return React.createElement(
    AuthContext.Provider,
    { value: contextValue },
    children
  );
}

/**
 * Hook to access auth context
 * Must be used within AuthProvider
 * 
 * @throws Error if used outside AuthProvider
 */
export function useAuthContext(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuthContext must be used within an AuthProvider');
  }
  return context;
}

// Export context for advanced use cases
export { AuthContext };
