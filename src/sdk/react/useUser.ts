/**
 * Zalt.io Auth React Hook - useUser
 * @zalt/auth-react - Official React SDK for Zalt.io Authentication Platform
 * 
 * Hook for accessing current user data and profile operations.
 * 
 * @example
 * ```tsx
 * import { useUser } from '@zalt/auth-react';
 * 
 * function ProfilePage() {
 *   const { user, isLoading, updateProfile } = useUser();
 *   
 *   if (isLoading) return <Spinner />;
 *   if (!user) return <Navigate to="/login" />;
 *   
 *   return (
 *     <div>
 *       <h1>Merhaba, {user.profile.first_name}!</h1>
 *       <p>Email: {user.email}</p>
 *     </div>
 *   );
 * }
 * ```
 */

import { useCallback, useState } from 'react';
import { useAuthContext } from './AuthProvider';
import { User, ProfileUpdateData, PasswordChangeData } from '../types';

/**
 * useUser hook return type
 */
export interface UseUserReturn {
  /** Current user or null if not authenticated */
  user: User | null;
  /** Whether user data is being loaded */
  isLoading: boolean;
  /** Current error if any */
  error: Error | null;
  /** Whether user is authenticated */
  isAuthenticated: boolean;
  /** Whether user's email is verified */
  isEmailVerified: boolean;
  /** Whether user has MFA enabled */
  hasMFA: boolean;
  /** Whether user has WebAuthn enabled */
  hasWebAuthn: boolean;
  
  // Profile methods
  /** Update user profile */
  updateProfile: (data: ProfileUpdateData) => Promise<User>;
  /** Change password */
  changePassword: (data: PasswordChangeData) => Promise<void>;
  /** Send email verification */
  sendVerificationEmail: () => Promise<void>;
  /** Verify email with code */
  verifyEmail: (code: string) => Promise<void>;
  /** Request password reset */
  requestPasswordReset: (email: string) => Promise<void>;
  /** Confirm password reset */
  confirmPasswordReset: (token: string, newPassword: string) => Promise<void>;
  /** Refresh user data */
  refreshUser: () => Promise<void>;
}

/**
 * Hook for accessing current user and profile operations
 * 
 * @returns User data and profile methods
 * @throws Error if used outside AuthProvider
 * 
 * @example
 * ```tsx
 * function UserProfile() {
 *   const { user, updateProfile, isLoading } = useUser();
 *   const [firstName, setFirstName] = useState(user?.profile.first_name || '');
 *   
 *   const handleSave = async () => {
 *     await updateProfile({ first_name: firstName });
 *     alert('Profil güncellendi!');
 *   };
 *   
 *   return (
 *     <div>
 *       <input 
 *         value={firstName} 
 *         onChange={(e) => setFirstName(e.target.value)} 
 *       />
 *       <button onClick={handleSave} disabled={isLoading}>
 *         Kaydet
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useUser(): UseUserReturn {
  const context = useAuthContext();
  const [localLoading, setLocalLoading] = useState(false);
  const [localError, setLocalError] = useState<Error | null>(null);
  
  const { user, isLoading: contextLoading, client, refreshAuth } = context;
  
  // Computed properties
  const isAuthenticated = user !== null;
  const isEmailVerified = user?.email_verified ?? false;
  const hasMFA = user?.mfa_enabled ?? false;
  const hasWebAuthn = user?.webauthn_enabled ?? false;
  
  // Combined loading state
  const isLoading = contextLoading || localLoading;
  const error = localError || context.error;

  // Update profile
  const updateProfile = useCallback(async (data: ProfileUpdateData): Promise<User> => {
    try {
      setLocalLoading(true);
      setLocalError(null);
      const updatedUser = await client.updateProfile(data);
      await refreshAuth(); // Refresh to get updated user
      return updatedUser;
    } catch (err) {
      setLocalError(err as Error);
      throw err;
    } finally {
      setLocalLoading(false);
    }
  }, [client, refreshAuth]);

  // Change password
  const changePassword = useCallback(async (data: PasswordChangeData): Promise<void> => {
    try {
      setLocalLoading(true);
      setLocalError(null);
      await client.changePassword(data);
    } catch (err) {
      setLocalError(err as Error);
      throw err;
    } finally {
      setLocalLoading(false);
    }
  }, [client]);

  // Send verification email
  const sendVerificationEmail = useCallback(async (): Promise<void> => {
    try {
      setLocalLoading(true);
      setLocalError(null);
      await client.sendVerificationEmail();
    } catch (err) {
      setLocalError(err as Error);
      throw err;
    } finally {
      setLocalLoading(false);
    }
  }, [client]);

  // Verify email
  const verifyEmail = useCallback(async (code: string): Promise<void> => {
    try {
      setLocalLoading(true);
      setLocalError(null);
      await client.verifyEmail({ code });
      await refreshAuth(); // Refresh to get updated email_verified status
    } catch (err) {
      setLocalError(err as Error);
      throw err;
    } finally {
      setLocalLoading(false);
    }
  }, [client, refreshAuth]);

  // Request password reset
  const requestPasswordReset = useCallback(async (email: string): Promise<void> => {
    try {
      setLocalLoading(true);
      setLocalError(null);
      await client.requestPasswordReset({ email });
    } catch (err) {
      setLocalError(err as Error);
      throw err;
    } finally {
      setLocalLoading(false);
    }
  }, [client]);

  // Confirm password reset
  const confirmPasswordReset = useCallback(async (token: string, newPassword: string): Promise<void> => {
    try {
      setLocalLoading(true);
      setLocalError(null);
      await client.confirmPasswordReset({ token, new_password: newPassword });
    } catch (err) {
      setLocalError(err as Error);
      throw err;
    } finally {
      setLocalLoading(false);
    }
  }, [client]);

  // Refresh user
  const refreshUser = useCallback(async (): Promise<void> => {
    await refreshAuth();
  }, [refreshAuth]);

  return {
    user,
    isLoading,
    error,
    isAuthenticated,
    isEmailVerified,
    hasMFA,
    hasWebAuthn,
    updateProfile,
    changePassword,
    sendVerificationEmail,
    verifyEmail,
    requestPasswordReset,
    confirmPasswordReset,
    refreshUser
  };
}

/**
 * Hook for accessing user metadata
 * 
 * @returns User metadata and update method
 * 
 * @example
 * ```tsx
 * function UserRole() {
 *   const { metadata, updateMetadata } = useUserMetadata();
 *   
 *   return (
 *     <div>
 *       <p>Rol: {metadata?.role || 'Belirlenmemiş'}</p>
 *       <p>Klinik: {metadata?.clinic_id || 'Yok'}</p>
 *     </div>
 *   );
 * }
 * ```
 */
export function useUserMetadata() {
  const { user, updateProfile, isLoading, error } = useUser();
  
  const metadata = user?.profile.metadata ?? null;
  
  const updateMetadata = useCallback(async (newMetadata: Record<string, unknown>): Promise<void> => {
    await updateProfile({
      metadata: {
        ...metadata,
        ...newMetadata
      }
    });
  }, [updateProfile, metadata]);
  
  return {
    /** User metadata object */
    metadata,
    /** Update metadata (merges with existing) */
    updateMetadata,
    /** Whether operation is in progress */
    isLoading,
    /** Current error */
    error
  };
}

/**
 * Hook for email verification flow
 * 
 * @returns Email verification state and methods
 * 
 * @example
 * ```tsx
 * function EmailVerification() {
 *   const { isVerified, sendCode, verifyCode, isLoading } = useEmailVerification();
 *   const [code, setCode] = useState('');
 *   
 *   if (isVerified) {
 *     return <p>Email doğrulandı ✅</p>;
 *   }
 *   
 *   return (
 *     <div>
 *       <button onClick={sendCode} disabled={isLoading}>
 *         Doğrulama Kodu Gönder
 *       </button>
 *       <input 
 *         value={code} 
 *         onChange={(e) => setCode(e.target.value)}
 *         placeholder="6 haneli kod"
 *       />
 *       <button onClick={() => verifyCode(code)} disabled={isLoading}>
 *         Doğrula
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useEmailVerification() {
  const { user, sendVerificationEmail, verifyEmail, isLoading, error } = useUser();
  
  const isVerified = user?.email_verified ?? false;
  const email = user?.email ?? null;
  
  return {
    /** Whether email is verified */
    isVerified,
    /** User's email address */
    email,
    /** Send verification code */
    sendCode: sendVerificationEmail,
    /** Verify with code */
    verifyCode: verifyEmail,
    /** Whether operation is in progress */
    isLoading,
    /** Current error */
    error
  };
}

/**
 * Hook for password reset flow
 * 
 * @returns Password reset methods
 * 
 * @example
 * ```tsx
 * function ForgotPassword() {
 *   const { requestReset, confirmReset, isLoading, error } = usePasswordReset();
 *   const [email, setEmail] = useState('');
 *   const [sent, setSent] = useState(false);
 *   
 *   const handleRequest = async () => {
 *     await requestReset(email);
 *     setSent(true);
 *   };
 *   
 *   if (sent) {
 *     return <p>Şifre sıfırlama linki gönderildi!</p>;
 *   }
 *   
 *   return (
 *     <div>
 *       <input 
 *         type="email"
 *         value={email}
 *         onChange={(e) => setEmail(e.target.value)}
 *         placeholder="Email adresiniz"
 *       />
 *       <button onClick={handleRequest} disabled={isLoading}>
 *         Şifre Sıfırla
 *       </button>
 *       {error && <p className="error">{error.message}</p>}
 *     </div>
 *   );
 * }
 * ```
 */
export function usePasswordReset() {
  const { requestPasswordReset, confirmPasswordReset, isLoading, error } = useUser();
  
  return {
    /** Request password reset email */
    requestReset: requestPasswordReset,
    /** Confirm reset with token and new password */
    confirmReset: confirmPasswordReset,
    /** Whether operation is in progress */
    isLoading,
    /** Current error */
    error
  };
}

// Default export
export default useUser;
