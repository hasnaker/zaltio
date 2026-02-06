/**
 * Zalt.io Auth SDK Type Definitions
 * @zalt/auth-sdk - Official TypeScript SDK for Zalt.io Authentication Platform
 * 
 * Validates: Requirements 4.1 (JavaScript SDK with TypeScript support)
 */

/**
 * SDK Configuration options
 */
export interface ZaltAuthConfig {
  /** API base URL (e.g., https://api.zalt.io/v1) */
  baseUrl: string;
  /** Realm ID for multi-tenant isolation */
  realmId: string;
  /** Request timeout in milliseconds (default: 10000) */
  timeout?: number;
  /** Number of retry attempts for failed requests (default: 3) */
  retryAttempts?: number;
  /** Delay between retries in milliseconds (default: 1000) */
  retryDelay?: number;
  /** Enable automatic token refresh (default: true) */
  autoRefresh?: boolean;
  /** Token refresh threshold in seconds before expiry (default: 300 = 5 minutes) */
  refreshThreshold?: number;
  /** Custom storage for tokens (default: in-memory) */
  storage?: TokenStorage;
}

/**
 * Token storage interface for custom implementations
 */
export interface TokenStorage {
  getAccessToken(): string | null | Promise<string | null>;
  getRefreshToken(): string | null | Promise<string | null>;
  setTokens(accessToken: string, refreshToken: string, expiresIn: number): void | Promise<void>;
  clearTokens(): void | Promise<void>;
}

/**
 * User profile information
 */
export interface UserProfile {
  first_name?: string;
  last_name?: string;
  avatar_url?: string;
  metadata?: Record<string, unknown>;
}

/**
 * User data returned from API
 */
export interface User {
  id: string;
  realm_id: string;
  email: string;
  email_verified: boolean;
  profile: UserProfile;
  created_at: string;
  updated_at: string;
  last_login: string;
  status: 'active' | 'suspended' | 'pending_verification';
  mfa_enabled?: boolean;
  webauthn_enabled?: boolean;
}

/**
 * Authentication result containing tokens and user data
 */
export interface AuthResult {
  user: User;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  mfa_required?: boolean;
  mfa_session_id?: string;
}

/**
 * Token refresh result
 */
export interface TokenResult {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/**
 * User registration data
 */
export interface RegisterData {
  email: string;
  password: string;
  profile?: UserProfile;
}

/**
 * User login credentials
 */
export interface LoginCredentials {
  email: string;
  password: string;
  device_fingerprint?: DeviceFingerprint;
}

/**
 * Device fingerprint for device trust
 */
export interface DeviceFingerprint {
  userAgent?: string;
  screen?: string;
  timezone?: string;
  language?: string;
  platform?: string;
}

/**
 * Profile update data
 */
export interface ProfileUpdateData {
  first_name?: string;
  last_name?: string;
  avatar_url?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Password change data
 */
export interface PasswordChangeData {
  current_password: string;
  new_password: string;
}

/**
 * Email verification data
 */
export interface EmailVerificationData {
  code: string;
}

/**
 * Password reset request data
 */
export interface PasswordResetRequestData {
  email: string;
}

/**
 * Password reset confirm data
 */
export interface PasswordResetConfirmData {
  token: string;
  new_password: string;
}

/**
 * API error response structure
 */
export interface APIErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
  };
}

/**
 * API success response structure
 */
export interface APISuccessResponse<T = unknown> {
  data?: T;
  message?: string;
  meta?: {
    timestamp: string;
    request_id?: string;
  };
}

// ============================================
// MFA Types
// ============================================

/**
 * TOTP MFA setup result
 */
export interface MFASetupResult {
  secret: string;
  qr_code_url: string;
  backup_codes: string[];
}

/**
 * MFA verify result after login
 */
export interface MFAVerifyResult {
  user: User;
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/**
 * MFA status for user
 */
export interface MFAStatus {
  totp_enabled: boolean;
  webauthn_enabled: boolean;
  backup_codes_remaining: number;
}

/**
 * Backup codes regeneration result
 */
export interface BackupCodesResult {
  backup_codes: string[];
}

// ============================================
// WebAuthn Types
// ============================================

/**
 * WebAuthn registration options from server
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
  pubKeyCredParams: Array<{
    type: 'public-key';
    alg: number;
  }>;
  timeout: number;
  attestation: 'none' | 'indirect' | 'direct';
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    requireResidentKey?: boolean;
    userVerification?: 'required' | 'preferred' | 'discouraged';
  };
}

/**
 * WebAuthn authentication options from server
 */
export interface WebAuthnAuthenticationOptions {
  challenge: string;
  timeout: number;
  rpId: string;
  allowCredentials: Array<{
    type: 'public-key';
    id: string;
    transports?: Array<'usb' | 'nfc' | 'ble' | 'internal'>;
  }>;
  userVerification: 'required' | 'preferred' | 'discouraged';
}

/**
 * WebAuthn credential info
 */
export interface WebAuthnCredential {
  id: string;
  name: string;
  created_at: string;
  last_used: string;
  device_type: 'platform' | 'cross-platform';
}

/**
 * WebAuthn registration verify result
 */
export interface WebAuthnRegisterResult {
  credential_id: string;
  success: boolean;
}

/**
 * WebAuthn authentication verify result
 */
export interface WebAuthnAuthResult {
  user: User;
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

// ============================================
// Device Types
// ============================================

/**
 * Device info
 */
export interface Device {
  id: string;
  name: string;
  device_type: string;
  browser: string;
  os: string;
  last_active: string;
  created_at: string;
  is_current: boolean;
  is_trusted: boolean;
  location?: {
    city?: string;
    country?: string;
  };
}

/**
 * Device list result
 */
export interface DeviceListResult {
  devices: Device[];
}

// ============================================
// Social Login Types
// ============================================

/**
 * Social auth URL result
 */
export interface SocialAuthUrlResult {
  auth_url: string;
  state: string;
}

/**
 * Social callback result
 */
export interface SocialCallbackResult {
  user: User;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  is_new_user: boolean;
}

// Legacy type aliases for backward compatibility
/** @deprecated Use ZaltAuthConfig instead */
export type HSDAuthConfig = ZaltAuthConfig;
