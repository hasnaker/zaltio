/**
 * Security Configuration for HSD Auth Platform
 * Validates: Requirements 8.2, 9.2, 5.4
 * 
 * Configures encryption, security headers, and HTTPS enforcement
 */

/**
 * Encryption configuration for sensitive data at rest
 */
export const ENCRYPTION_CONFIG = {
  // AES-256-GCM for field-level encryption
  algorithm: 'aes-256-gcm' as const,
  keyLength: 32, // 256 bits
  ivLength: 16,  // 128 bits for GCM
  authTagLength: 16, // 128 bits
  
  // Fields that require encryption
  sensitiveFields: [
    'password_hash',
    'refresh_token',
    'mfa_secret',
    'recovery_codes',
    'api_key'
  ] as const,
  
  // Key derivation settings
  keyDerivation: {
    algorithm: 'pbkdf2',
    iterations: 100000,
    digest: 'sha256'
  }
} as const;

/**
 * Password hashing configuration
 * Validates: Requirements 9.2 (bcrypt/Argon2)
 * Updated for Zalt.io: Minimum 12 characters for healthcare compliance
 */
export const PASSWORD_CONFIG = {
  // bcrypt configuration (legacy, for migration)
  bcrypt: {
    saltRounds: 12,
    minLength: 12,
    maxLength: 128
  },
  
  // Password policy - Zalt.io healthcare-grade requirements
  policy: {
    minLength: 12,  // HIPAA recommendation
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  }
} as const;

/**
 * Security headers configuration
 * Validates: Requirements 5.4 (HTTPS enforcement)
 */
export const SECURITY_HEADERS = {
  // Strict Transport Security - enforce HTTPS
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  
  // Prevent MIME type sniffing
  'X-Content-Type-Options': 'nosniff',
  
  // Prevent clickjacking
  'X-Frame-Options': 'DENY',
  
  // XSS protection
  'X-XSS-Protection': '1; mode=block',
  
  // Referrer policy
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  
  // Content Security Policy
  'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
  
  // Permissions Policy
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  
  // Cache control for sensitive data
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
  'Pragma': 'no-cache',
  'Expires': '0'
} as const;

/**
 * HTTPS enforcement configuration
 */
export const HTTPS_CONFIG = {
  // Enforce HTTPS in production
  enforceHttps: process.env.NODE_ENV === 'production',
  
  // Allowed protocols
  allowedProtocols: ['https'] as const,
  
  // Redirect HTTP to HTTPS
  redirectHttp: true,
  
  // HSTS max age in seconds (1 year)
  hstsMaxAge: 31536000
} as const;

/**
 * Token security configuration
 */
export const TOKEN_SECURITY_CONFIG = {
  // JWT signing algorithm
  algorithm: 'RS256' as const,
  
  // Token expiration times
  accessTokenExpiry: 15 * 60, // 15 minutes
  refreshTokenExpiry: 7 * 24 * 60 * 60, // 7 days
  
  // Token rotation settings
  rotateRefreshToken: true,
  
  // Secure token storage requirements
  secureStorage: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict' as const
  }
} as const;

export type EncryptionConfig = typeof ENCRYPTION_CONFIG;
export type PasswordConfig = typeof PASSWORD_CONFIG;
export type SecurityHeaders = typeof SECURITY_HEADERS;
export type HttpsConfig = typeof HTTPS_CONFIG;
export type TokenSecurityConfig = typeof TOKEN_SECURITY_CONFIG;
