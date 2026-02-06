/**
 * Clinisyn x Zalt.io - Next.js Authentication Configuration
 * 
 * Bu dosya Zalt.io API entegrasyonu için gerekli tüm konfigürasyonu içerir.
 */

export const ZALT_CONFIG = {
  // API Endpoint
  apiUrl: process.env.NEXT_PUBLIC_ZALT_API_URL || 'https://api.zalt.io',
  
  // Clinisyn Realm ID
  realmId: 'clinisyn',
  
  // Token ayarları
  tokens: {
    accessTokenKey: 'zalt_access_token',
    refreshTokenKey: 'zalt_refresh_token',
    accessTokenExpiry: 15 * 60 * 1000, // 15 dakika (ms)
    refreshTokenExpiry: 7 * 24 * 60 * 60 * 1000, // 7 gün (ms)
    refreshThreshold: 60 * 1000, // Token süresi 1 dakikadan az kaldıysa yenile
  },
  
  // MFA ayarları
  mfa: {
    methods: ['totp', 'webauthn'] as const,
    sessionTimeout: 5 * 60 * 1000, // 5 dakika
  },
  
  // Rate limit ayarları (client-side tracking için)
  rateLimit: {
    login: { max: 5, window: 15 * 60 * 1000 }, // 5 deneme / 15 dk
    register: { max: 3, window: 60 * 60 * 1000 }, // 3 deneme / 1 saat
    passwordReset: { max: 3, window: 60 * 60 * 1000 }, // 3 deneme / 1 saat
  },
  
  // Redirect URLs
  redirects: {
    afterLogin: '/dashboard',
    afterLogout: '/login',
    afterMfa: '/dashboard',
    mfaSetup: '/settings/security',
  },
};

// API Endpoints
export const ZALT_ENDPOINTS = {
  // Auth
  login: '/login',
  logout: '/logout',
  register: '/register',
  refresh: '/refresh',
  
  // Password
  passwordResetRequest: '/v1/auth/password-reset/request',
  passwordResetConfirm: '/v1/auth/password-reset/confirm',
  
  // MFA - TOTP
  mfaSetup: '/v1/auth/mfa/setup',
  mfaVerify: '/v1/auth/mfa/verify',
  mfaDisable: '/v1/auth/mfa/disable',
  mfaLogin: '/v1/auth/mfa/login',
  mfaLoginVerify: '/v1/auth/mfa/login/verify',
  
  // MFA - WebAuthn
  webauthnRegisterOptions: '/v1/auth/webauthn/register/options',
  webauthnRegisterVerify: '/v1/auth/webauthn/register/verify',
  webauthnAuthOptions: '/v1/auth/webauthn/authenticate/options',
  webauthnAuthVerify: '/v1/auth/webauthn/authenticate/verify',
  webauthnCredentials: '/v1/auth/webauthn/credentials',
  
  // MFA - SMS (risk kabul gerekli)
  smsMfaRiskWarning: '/v1/auth/mfa/sms/risk-warning',
  smsMfaSetup: '/v1/auth/mfa/sms/setup',
  smsMfaSend: '/v1/auth/mfa/sms/send',
  smsMfaVerify: '/v1/auth/mfa/sms/verify',
  
  // Email Verification
  emailVerifySend: '/v1/auth/verify-email/send',
  emailVerifyConfirm: '/v1/auth/verify-email/confirm',
  
  // Discovery
  jwks: '/.well-known/jwks.json',
  openidConfig: '/.well-known/openid-configuration',
  health: '/health',
};

// Error codes
export const ZALT_ERROR_CODES = {
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  RATE_LIMITED: 'RATE_LIMITED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INVALID_TOKEN: 'INVALID_TOKEN',
  MFA_REQUIRED: 'MFA_REQUIRED',
  REALM_NOT_FOUND: 'REALM_NOT_FOUND',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  WEBAUTHN_NOT_SUPPORTED: 'WEBAUTHN_NOT_SUPPORTED',
} as const;

export type ZaltErrorCode = typeof ZALT_ERROR_CODES[keyof typeof ZALT_ERROR_CODES];
