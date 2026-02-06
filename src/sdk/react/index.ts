/**
 * Zalt.io Auth React SDK
 * @zalt/auth-react - Official React SDK for Zalt.io Authentication Platform
 * 
 * React hooks and components for Zalt.io authentication.
 * Supports SSR (Next.js, Remix) and client-side rendering.
 * 
 * @packageDocumentation
 * 
 * @example
 * ```tsx
 * // 1. Wrap your app with AuthProvider
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
 * 
 * // 2. Use hooks in your components
 * import { useAuth, useUser } from '@zalt/auth-react';
 * 
 * function Dashboard() {
 *   const { isAuthenticated, logout } = useAuth();
 *   const { user } = useUser();
 *   
 *   if (!isAuthenticated) {
 *     return <Navigate to="/login" />;
 *   }
 *   
 *   return (
 *     <div>
 *       <h1>Merhaba, {user?.profile.first_name}!</h1>
 *       <button onClick={() => logout()}>Çıkış Yap</button>
 *     </div>
 *   );
 * }
 * ```
 */

// Provider
export { 
  AuthProvider, 
  useAuthContext,
  AuthContext 
} from './AuthProvider';
export type { 
  AuthProviderProps, 
  AuthContextValue, 
  AuthState 
} from './AuthProvider';

// Auth hooks
export { 
  useAuth, 
  useMFA, 
  useMFASetup, 
  useWebAuthn, 
  useDevices, 
  useSocialLogin 
} from './useAuth';
export type { UseAuthReturn } from './useAuth';

// User hooks
export { 
  useUser, 
  useUserMetadata, 
  useEmailVerification, 
  usePasswordReset 
} from './useUser';
export type { UseUserReturn } from './useUser';

// Re-export types from main SDK for convenience
export type {
  User,
  UserProfile,
  LoginCredentials,
  RegisterData,
  ProfileUpdateData,
  PasswordChangeData,
  DeviceFingerprint,
  MFASetupResult,
  MFAStatus,
  BackupCodesResult,
  WebAuthnCredential,
  Device,
  SocialAuthUrlResult,
  SocialCallbackResult
} from '../types';

// Re-export errors for error handling
export {
  ZaltAuthError,
  MFARequiredError,
  AccountLockedError,
  AuthenticationError,
  ValidationError,
  RateLimitError
} from '../errors';
