/**
 * Zalt.io Auth React Hook - useAuth
 * @zalt/auth-react - Official React SDK for Zalt.io Authentication Platform
 * 
 * Primary hook for authentication operations in React components.
 * 
 * @example
 * ```tsx
 * import { useAuth } from '@zalt/auth-react';
 * 
 * function LoginForm() {
 *   const { login, isLoading, error } = useAuth();
 *   
 *   const handleSubmit = async (e) => {
 *     e.preventDefault();
 *     try {
 *       await login({ email, password });
 *       // Redirect to dashboard
 *     } catch (err) {
 *       // Error is also available in error state
 *     }
 *   };
 *   
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       {error && <p className="error">{error.message}</p>}
 *       <button disabled={isLoading}>
 *         {isLoading ? 'Giriş yapılıyor...' : 'Giriş Yap'}
 *       </button>
 *     </form>
 *   );
 * }
 * ```
 */

import { useCallback } from 'react';
import { useAuthContext, AuthContextValue } from './AuthProvider';
import { LoginCredentials, RegisterData, AuthResult } from '../types';

/**
 * useAuth hook return type
 */
export interface UseAuthReturn {
  // State
  /** Whether user is authenticated */
  isAuthenticated: boolean;
  /** Whether authentication is being checked or operation in progress */
  isLoading: boolean;
  /** Current error if any */
  error: Error | null;
  /** MFA session ID if MFA is required during login */
  mfaSessionId: string | null;
  /** Whether account is locked */
  isAccountLocked: boolean;
  /** Account locked until timestamp */
  lockedUntil: string | null;
  
  // Methods
  /** Login with email and password */
  login: (credentials: LoginCredentials) => Promise<AuthResult>;
  /** Register a new user */
  register: (data: RegisterData) => Promise<AuthResult>;
  /** Logout current user */
  logout: (allDevices?: boolean) => Promise<void>;
  /** Clear current error */
  clearError: () => void;
  /** Refresh authentication state */
  refreshAuth: () => Promise<void>;
  
  // MFA methods
  /** Verify MFA code during login (when mfaSessionId is set) */
  verifyMFALogin: (code: string) => Promise<void>;
}

/**
 * Primary authentication hook
 * 
 * Provides authentication state and methods for login, register, logout.
 * Handles MFA challenges and account lockout states.
 * 
 * @returns Authentication state and methods
 * @throws Error if used outside AuthProvider
 * 
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { isAuthenticated, login, logout, isLoading } = useAuth();
 *   
 *   if (isLoading) return <Spinner />;
 *   
 *   if (isAuthenticated) {
 *     return <button onClick={() => logout()}>Çıkış Yap</button>;
 *   }
 *   
 *   return <LoginForm onSubmit={login} />;
 * }
 * ```
 */
export function useAuth(): UseAuthReturn {
  const context = useAuthContext();
  
  const {
    isAuthenticated,
    isLoading,
    error,
    mfaSessionId,
    isAccountLocked,
    lockedUntil,
    login,
    register,
    logout,
    clearError,
    refreshAuth,
    verifyMFALogin: contextVerifyMFALogin
  } = context;

  // Wrap verifyMFALogin to return void (user is set in context)
  const verifyMFALogin = useCallback(async (code: string): Promise<void> => {
    await contextVerifyMFALogin(code);
  }, [contextVerifyMFALogin]);

  return {
    // State
    isAuthenticated,
    isLoading,
    error,
    mfaSessionId,
    isAccountLocked,
    lockedUntil,
    
    // Methods
    login,
    register,
    logout,
    clearError,
    refreshAuth,
    verifyMFALogin
  };
}

/**
 * Hook for checking if user needs to complete MFA
 * 
 * @returns MFA state and verification method
 * 
 * @example
 * ```tsx
 * function MFAPage() {
 *   const { mfaRequired, verifyMFA, isLoading } = useMFA();
 *   
 *   if (!mfaRequired) {
 *     return <Navigate to="/dashboard" />;
 *   }
 *   
 *   return (
 *     <form onSubmit={(e) => {
 *       e.preventDefault();
 *       verifyMFA(code);
 *     }}>
 *       <input placeholder="6 haneli kod" />
 *       <button disabled={isLoading}>Doğrula</button>
 *     </form>
 *   );
 * }
 * ```
 */
export function useMFA() {
  const context = useAuthContext();
  
  const {
    mfaSessionId,
    isLoading,
    error,
    verifyMFALogin,
    clearError
  } = context;

  const mfaRequired = mfaSessionId !== null;

  const verifyMFA = useCallback(async (code: string): Promise<void> => {
    await verifyMFALogin(code);
  }, [verifyMFALogin]);

  return {
    /** Whether MFA verification is required */
    mfaRequired,
    /** MFA session ID */
    mfaSessionId,
    /** Whether verification is in progress */
    isLoading,
    /** Current error */
    error,
    /** Verify MFA code */
    verifyMFA,
    /** Clear error */
    clearError
  };
}

/**
 * Hook for MFA setup and management
 * 
 * @returns MFA setup methods
 * 
 * @example
 * ```tsx
 * function MFASetupPage() {
 *   const { setupMFA, verifySetup, disableMFA, getStatus } = useMFASetup();
 *   const [qrCode, setQrCode] = useState(null);
 *   
 *   const handleSetup = async () => {
 *     const result = await setupMFA();
 *     setQrCode(result.qr_code_url);
 *   };
 *   
 *   return (
 *     <div>
 *       <button onClick={handleSetup}>MFA Kur</button>
 *       {qrCode && <img src={qrCode} alt="QR Code" />}
 *     </div>
 *   );
 * }
 * ```
 */
export function useMFASetup() {
  const context = useAuthContext();
  
  return {
    /** Setup TOTP MFA - returns QR code and backup codes */
    setupMFA: context.setupMFA,
    /** Verify TOTP code to enable MFA */
    verifySetup: context.verifyMFA,
    /** Disable MFA (requires password) */
    disableMFA: context.disableMFA,
    /** Get current MFA status */
    getStatus: context.getMFAStatus,
    /** Regenerate backup codes */
    regenerateBackupCodes: context.regenerateBackupCodes,
    /** Whether operation is in progress */
    isLoading: context.isLoading,
    /** Current error */
    error: context.error
  };
}

/**
 * Hook for WebAuthn/Passkey operations
 * 
 * @returns WebAuthn methods
 * 
 * @example
 * ```tsx
 * function PasskeySetup() {
 *   const { registerPasskey, listCredentials } = useWebAuthn();
 *   
 *   const handleRegister = async () => {
 *     const options = await registerPasskey.getOptions();
 *     // Use browser WebAuthn API
 *     const credential = await navigator.credentials.create({ publicKey: options });
 *     await registerPasskey.verify(credential, 'MacBook Pro');
 *   };
 *   
 *   return <button onClick={handleRegister}>Passkey Ekle</button>;
 * }
 * ```
 */
export function useWebAuthn() {
  const context = useAuthContext();
  
  return {
    /** Register a new passkey */
    registerPasskey: {
      getOptions: context.getWebAuthnRegisterOptions,
      verify: context.verifyWebAuthnRegister
    },
    /** Authenticate with passkey */
    authenticatePasskey: {
      getOptions: context.getWebAuthnAuthOptions,
      verify: context.verifyWebAuthnAuth
    },
    /** List registered passkeys */
    listCredentials: context.listWebAuthnCredentials,
    /** Delete a passkey */
    deleteCredential: context.deleteWebAuthnCredential,
    /** Whether operation is in progress */
    isLoading: context.isLoading,
    /** Current error */
    error: context.error
  };
}

/**
 * Hook for device management
 * 
 * @returns Device management methods
 * 
 * @example
 * ```tsx
 * function DeviceList() {
 *   const { listDevices, revokeDevice } = useDevices();
 *   const [devices, setDevices] = useState([]);
 *   
 *   useEffect(() => {
 *     listDevices().then(setDevices);
 *   }, []);
 *   
 *   return (
 *     <ul>
 *       {devices.map(device => (
 *         <li key={device.id}>
 *           {device.name}
 *           <button onClick={() => revokeDevice(device.id)}>Kaldır</button>
 *         </li>
 *       ))}
 *     </ul>
 *   );
 * }
 * ```
 */
export function useDevices() {
  const context = useAuthContext();
  
  return {
    /** List all devices */
    listDevices: context.listDevices,
    /** Revoke a device */
    revokeDevice: context.revokeDevice,
    /** Trust current device (skip MFA for 30 days) */
    trustCurrentDevice: context.trustCurrentDevice,
    /** Whether operation is in progress */
    isLoading: context.isLoading,
    /** Current error */
    error: context.error
  };
}

/**
 * Hook for social login
 * 
 * @returns Social login methods
 * 
 * @example
 * ```tsx
 * function SocialLoginButtons() {
 *   const { loginWithGoogle, loginWithApple } = useSocialLogin();
 *   
 *   const handleGoogleLogin = async () => {
 *     const { auth_url } = await loginWithGoogle();
 *     window.location.href = auth_url;
 *   };
 *   
 *   return (
 *     <div>
 *       <button onClick={handleGoogleLogin}>Google ile Giriş</button>
 *       <button onClick={() => loginWithApple()}>Apple ile Giriş</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useSocialLogin() {
  const context = useAuthContext();
  
  const loginWithGoogle = useCallback(async () => {
    return context.getSocialAuthUrl('google');
  }, [context]);
  
  const loginWithApple = useCallback(async () => {
    return context.getSocialAuthUrl('apple');
  }, [context]);
  
  return {
    /** Get Google OAuth URL */
    loginWithGoogle,
    /** Get Apple OAuth URL */
    loginWithApple,
    /** Handle OAuth callback */
    handleCallback: context.handleSocialCallback,
    /** Whether operation is in progress */
    isLoading: context.isLoading,
    /** Current error */
    error: context.error
  };
}

// Default export
export default useAuth;
