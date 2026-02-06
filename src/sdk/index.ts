/**
 * Zalt.io Auth SDK - Official TypeScript SDK for Zalt.io Authentication Platform
 * @zalt/auth-sdk
 * 
 * Enterprise-grade authentication for healthcare and beyond.
 * HIPAA/GDPR compliant, darkweb-resistant security.
 * 
 * @packageDocumentation
 * 
 * @example
 * ```typescript
 * import { createZaltClient } from '@zalt/auth-sdk';
 * 
 * const auth = createZaltClient({
 *   baseUrl: 'https://api.zalt.io/v1',
 *   realmId: 'clinisyn-psychologists'
 * });
 * 
 * // Register
 * await auth.register({
 *   email: 'dr.ayse@clinisyn.com',
 *   password: 'SecurePassword123!'
 * });
 * 
 * // Login
 * const result = await auth.login({
 *   email: 'dr.ayse@clinisyn.com',
 *   password: 'SecurePassword123!'
 * });
 * 
 * // Get current user
 * const user = await auth.getCurrentUser();
 * 
 * // Logout
 * await auth.logout();
 * ```
 */

// Main client
export { ZaltAuthClient, createZaltClient, HSDAuthClient, createHSDAuthClient } from './client';

// Types
export type {
  ZaltAuthConfig,
  HSDAuthConfig,
  TokenStorage,
  UserProfile,
  User,
  AuthResult,
  TokenResult,
  RegisterData,
  LoginCredentials,
  DeviceFingerprint,
  ProfileUpdateData,
  PasswordChangeData,
  EmailVerificationData,
  PasswordResetRequestData,
  PasswordResetConfirmData,
  APIErrorResponse,
  APISuccessResponse,
  MFASetupResult,
  MFAVerifyResult,
  MFAStatus,
  BackupCodesResult,
  WebAuthnRegistrationOptions,
  WebAuthnAuthenticationOptions,
  WebAuthnCredential,
  WebAuthnRegisterResult,
  WebAuthnAuthResult,
  Device,
  DeviceListResult,
  SocialAuthUrlResult,
  SocialCallbackResult
} from './types';

// Errors
export {
  ZaltAuthError,
  HSDAuthError,
  NetworkError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  RateLimitError,
  TokenRefreshError,
  ConfigurationError,
  MFARequiredError,
  AccountLockedError,
  isZaltAuthError,
  isHSDAuthError,
  isRetryableError
} from './errors';

// Storage implementations
export { 
  MemoryStorage, 
  BrowserStorage, 
  SessionStorage,
  CustomStorage 
} from './storage';

// React SDK (separate import for tree-shaking)
// Usage: import { AuthProvider, useAuth } from '@zalt/auth-sdk/react';
// Or: import * as ZaltReact from '@zalt/auth-sdk/react';
