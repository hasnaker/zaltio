/**
 * Zalt.io Core SDK
 * @zalt/core
 * 
 * Headless TypeScript client for Zalt.io Authentication Platform
 * Enterprise-grade authentication for healthcare and beyond.
 * HIPAA/GDPR compliant, darkweb-resistant security.
 * 
 * @packageDocumentation
 * 
 * @example
 * ```typescript
 * import { createZaltClient } from '@zalt.io/core';
 * 
 * // Initialize with your publishable key from the Zalt.io dashboard
 * const zalt = createZaltClient({
 *   publishableKey: 'pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456',
 * });
 * 
 * // Login
 * const { user, tokens } = await zalt.login({
 *   email: 'user@example.com',
 *   password: 'SecurePassword123!',
 * });
 * 
 * // Get current user
 * const currentUser = zalt.getUser();
 * 
 * // Logout
 * await zalt.logout();
 * ```
 */

// Main client
export { ZaltClient, createZaltClient, HSDAuthClient, createHSDAuthClient } from './client';

// Token manager
export { TokenManager, createTokenManager } from './token-manager';
export type { TokenManagerConfig } from './token-manager';

// Storage implementations
export {
  MemoryStorage,
  BrowserStorage,
  SessionStorage,
  CookieStorage,
  CustomStorage,
  STORAGE_KEYS,
  createAutoStorage,
} from './storage';

// Errors
export {
  ZaltError,
  HSDAuthError,
  AuthenticationError,
  AuthorizationError,
  NetworkError,
  RateLimitError,
  MFARequiredError,
  AccountLockedError,
  ValidationError,
  TokenRefreshError,
  ConfigurationError,
  // Type guards
  isZaltError,
  isHSDAuthError,
  isRetryableError,
  isMFARequiredError,
  isAuthenticationError,
  isAccountLockedError,
  isRateLimitError,
  // Factory
  createErrorFromResponse,
} from './errors';

// Types
export type {
  // Configuration
  ZaltConfig,
  TokenStorage,
  // User
  User,
  UserProfile,
  // Authentication
  LoginCredentials,
  RegisterData,
  AuthResult,
  TokenResult,
  AuthState,
  DeviceFingerprint,
  // MFA
  MFAMethod,
  MFASetupResult,
  MFAVerifyResult,
  MFAStatus,
  // SMS MFA
  SMSSetupResult,
  SMSVerifyResult,
  // WebAuthn
  WebAuthnCredential,
  WebAuthnRegistrationOptions,
  WebAuthnAuthenticationOptions,
  WebAuthnRegisterResult,
  WebAuthnAuthResult,
  // Profile
  ProfileUpdateData,
  PasswordChangeData,
  PasswordResetRequestData,
  PasswordResetConfirmData,
  // Devices
  Device,
  DeviceListResult,
  // Social Auth
  SocialProvider,
  SocialAuthUrlResult,
  SocialCallbackResult,
  // Events
  AuthStateChangeEvent,
  AuthStateChangeCallback,
  // API
  APIErrorResponse,
  APISuccessResponse,
  // JWT
  JWTClaims,
  // Error types
  ZaltErrorType,
} from './types';

// Webhook verification
export {
  verifyWebhookSignature,
  parseSignatureHeader,
  computeSignature,
  safeCompare,
  constructWebhookEvent,
  createTestSignature,
  WebhookVerificationError,
  WebhookVerificationErrorCode,
  DEFAULT_TIMESTAMP_TOLERANCE,
} from './webhooks';
export type {
  WebhookVerifyOptions,
  ParsedSignature,
  WebhookPayload,
} from './webhooks';
