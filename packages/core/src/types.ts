/**
 * Zalt Core Types
 * @zalt/core
 */

// ============================================================================
// Configuration
// ============================================================================

/**
 * Configuration options for ZaltClient
 */
export interface ZaltConfig {
  /** 
   * Publishable API key (pk_live_xxx or pk_test_xxx)
   * Get this from your Zalt.io dashboard
   */
  publishableKey: string;
  /** 
   * Realm ID for multi-tenant isolation
   * @deprecated Use publishableKey instead - realm is extracted from the key
   */
  realmId?: string;
  /** API base URL (default: https://api.zalt.io) */
  baseUrl?: string;
  /** Token storage implementation */
  storage?: TokenStorage;
  /** Enable automatic token refresh (default: true) */
  autoRefresh?: boolean;
  /** Enable debug logging (default: false) */
  debug?: boolean;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom headers to include in all requests */
  headers?: Record<string, string>;
}

// ============================================================================
// Storage
// ============================================================================

/**
 * Token storage interface - implement for custom storage
 */
export interface TokenStorage {
  get(key: string): string | null | Promise<string | null>;
  set(key: string, value: string): void | Promise<void>;
  remove(key: string): void | Promise<void>;
}

// ============================================================================
// User
// ============================================================================

/**
 * User profile information
 */
export interface UserProfile {
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  phoneNumber?: string;
  metadata?: Record<string, unknown>;
}

/**
 * User object returned from auth operations
 */
export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  profile: UserProfile;
  mfaEnabled: boolean;
  webauthnEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

// ============================================================================
// Authentication
// ============================================================================

/**
 * Login credentials
 */
export interface LoginCredentials {
  email: string;
  password: string;
  /** Device fingerprint for trusted device detection */
  deviceFingerprint?: DeviceFingerprint;
}

/**
 * Registration data
 */
export interface RegisterData {
  email: string;
  password: string;
  profile?: Partial<UserProfile>;
  /** Device fingerprint for trusted device detection */
  deviceFingerprint?: DeviceFingerprint;
}

/**
 * Device fingerprint for device trust
 */
export interface DeviceFingerprint {
  userAgent: string;
  language: string;
  timezone: string;
  screenResolution?: string;
  platform?: string;
}

/**
 * Token result from auth operations
 */
export interface TokenResult {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

/**
 * Authentication result
 */
export interface AuthResult {
  user: User;
  tokens: TokenResult;
  /** True if MFA verification is required */
  mfaRequired?: boolean;
  /** MFA session ID for verification */
  mfaSessionId?: string;
  /** Available MFA methods */
  mfaMethods?: MFAMethod[];
}

/**
 * Current authentication state
 */
export interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: ZaltErrorType | null;
}

// ============================================================================
// MFA
// ============================================================================

/**
 * Available MFA methods
 */
export type MFAMethod = 'totp' | 'webauthn' | 'sms';

/**
 * MFA setup result
 */
export interface MFASetupResult {
  /** Secret key for TOTP */
  secret: string;
  /** QR code data URL */
  qrCode: string;
  /** Backup codes */
  backupCodes: string[];
  /** Recovery key */
  recoveryKey: string;
}

/**
 * MFA verification result
 */
export interface MFAVerifyResult {
  success: boolean;
  user: User;
  tokens: TokenResult;
}

/**
 * MFA status
 */
export interface MFAStatus {
  enabled: boolean;
  methods: MFAMethod[];
  backupCodesRemaining: number;
}

// ============================================================================
// WebAuthn
// ============================================================================

/**
 * WebAuthn credential
 */
export interface WebAuthnCredential {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
  transports?: AuthenticatorTransport[];
}

/**
 * WebAuthn registration options
 */
export interface WebAuthnRegistrationOptions {
  challenge: string;
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
}

/**
 * WebAuthn authentication options
 */
export interface WebAuthnAuthenticationOptions {
  challenge: string;
  rpId: string;
  allowCredentials?: PublicKeyCredentialDescriptor[];
  timeout?: number;
  userVerification?: UserVerificationRequirement;
}

/**
 * WebAuthn registration result
 */
export interface WebAuthnRegisterResult {
  credential: WebAuthnCredential;
  user: User;
}

/**
 * WebAuthn authentication result
 */
export interface WebAuthnAuthResult {
  user: User;
  tokens: TokenResult;
}

// ============================================================================
// SMS MFA (Optional - with risk acceptance)
// ============================================================================

/**
 * SMS MFA setup result
 */
export interface SMSSetupResult {
  /** Phone number (masked) */
  phoneNumber: string;
  /** Verification required */
  verificationRequired: boolean;
  /** Security warning about SS7 */
  securityWarning: string;
}

/**
 * SMS MFA verify result
 */
export interface SMSVerifyResult {
  success: boolean;
  user: User;
  tokens: TokenResult;
}

// ============================================================================
// Profile
// ============================================================================

/**
 * Profile update data
 */
export interface ProfileUpdateData {
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  phoneNumber?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Password change data
 */
export interface PasswordChangeData {
  currentPassword: string;
  newPassword: string;
}

/**
 * Email verification data
 */
export interface EmailVerificationData {
  token: string;
}

/**
 * Password reset request
 */
export interface PasswordResetRequestData {
  email: string;
}

/**
 * Password reset confirmation
 */
export interface PasswordResetConfirmData {
  token: string;
  newPassword: string;
}

// ============================================================================
// API Response
// ============================================================================

/**
 * API error response
 */
export interface APIErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

/**
 * API success response
 */
export interface APISuccessResponse<T> {
  data: T;
}

// ============================================================================
// Devices
// ============================================================================

/**
 * Trusted device
 */
export interface Device {
  id: string;
  name: string;
  userAgent: string;
  lastUsedAt: string;
  createdAt: string;
  isCurrent: boolean;
  trusted: boolean;
}

/**
 * Device list result
 */
export interface DeviceListResult {
  devices: Device[];
}

// ============================================================================
// Social Auth
// ============================================================================

/**
 * Social auth provider
 */
export type SocialProvider = 'google' | 'github' | 'microsoft' | 'apple';

/**
 * Social auth URL result
 */
export interface SocialAuthUrlResult {
  url: string;
  state: string;
}

/**
 * Social auth callback result
 */
export interface SocialCallbackResult {
  user: User;
  tokens: TokenResult;
  isNewUser: boolean;
}

// ============================================================================
// Events
// ============================================================================

/**
 * Auth state change event
 */
export type AuthStateChangeEvent = 
  | { type: 'SIGNED_IN'; user: User }
  | { type: 'SIGNED_OUT' }
  | { type: 'TOKEN_REFRESHED' }
  | { type: 'USER_UPDATED'; user: User }
  | { type: 'SESSION_EXPIRED' }
  | { type: 'MFA_REQUIRED'; sessionId: string; methods: MFAMethod[] };

/**
 * Auth state change callback
 */
export type AuthStateChangeCallback = (event: AuthStateChangeEvent) => void;

// ============================================================================
// Error Types (for type discrimination)
// ============================================================================

/**
 * Base error type for Zalt errors
 */
export type ZaltErrorType = 
  | { code: 'AUTHENTICATION_ERROR'; message: string; statusCode: number }
  | { code: 'NETWORK_ERROR'; message: string; retryable: boolean }
  | { code: 'RATE_LIMIT_ERROR'; message: string; retryAfter: number }
  | { code: 'MFA_REQUIRED_ERROR'; message: string; sessionId: string; methods: MFAMethod[] }
  | { code: 'ACCOUNT_LOCKED_ERROR'; message: string; unlockAt?: string }
  | { code: 'VALIDATION_ERROR'; message: string; fields: Record<string, string[]> }
  | { code: 'TOKEN_REFRESH_ERROR'; message: string }
  | { code: 'CONFIGURATION_ERROR'; message: string };

// ============================================================================
// JWT Claims
// ============================================================================

/**
 * JWT claims structure
 */
export interface JWTClaims {
  sub: string;
  email: string;
  realm_id: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  jti?: string;
  mfa_verified?: boolean;
  device_id?: string;
}
