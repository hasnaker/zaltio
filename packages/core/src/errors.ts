/**
 * Zalt Error Classes
 * @zalt/core
 * 
 * Typed error hierarchy for discriminated union error handling
 */

import type { MFAMethod } from './types';

/**
 * Base error class for all Zalt errors
 */
export class ZaltError extends Error {
  readonly code: string;
  readonly statusCode?: number;

  constructor(message: string, code: string, statusCode?: number) {
    super(message);
    this.name = 'ZaltError';
    this.code = code;
    this.statusCode = statusCode;
    
    // Maintains proper stack trace for where error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Authentication error - invalid credentials, expired session, etc.
 */
export class AuthenticationError extends ZaltError {
  readonly code: 'INVALID_CREDENTIALS' | 'EMAIL_NOT_VERIFIED' | 'SESSION_EXPIRED';

  constructor(
    message: string,
    code: 'INVALID_CREDENTIALS' | 'EMAIL_NOT_VERIFIED' | 'SESSION_EXPIRED' = 'INVALID_CREDENTIALS',
    statusCode: number = 401
  ) {
    super(message, code, statusCode);
    this.name = 'AuthenticationError';
    this.code = code;
  }
}

/**
 * Authorization error - insufficient permissions
 */
export class AuthorizationError extends ZaltError {
  constructor(message: string = 'Insufficient permissions', statusCode: number = 403) {
    super(message, 'AUTHORIZATION_ERROR', statusCode);
    this.name = 'AuthorizationError';
  }
}

/**
 * Network error - connection failed, timeout, etc.
 */
export class NetworkError extends ZaltError {
  readonly retryable: boolean;

  constructor(message: string = 'Network request failed', retryable: boolean = true) {
    super(message, 'NETWORK_ERROR');
    this.name = 'NetworkError';
    this.retryable = retryable;
  }
}

/**
 * Rate limit error - too many requests
 */
export class RateLimitError extends ZaltError {
  readonly retryAfter: number;

  constructor(message: string = 'Too many requests', retryAfter: number = 60) {
    super(message, 'RATE_LIMIT_ERROR', 429);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * MFA required error - user needs to complete MFA
 */
export class MFARequiredError extends ZaltError {
  readonly sessionId: string;
  readonly methods: MFAMethod[];

  constructor(sessionId: string, methods: MFAMethod[] = ['totp']) {
    super('MFA verification required', 'MFA_REQUIRED', 200);
    this.name = 'MFARequiredError';
    this.sessionId = sessionId;
    this.methods = methods;
  }
}

/**
 * Account locked error - account temporarily or permanently locked
 */
export class AccountLockedError extends ZaltError {
  readonly unlockAt?: string;

  constructor(message: string = 'Account is locked', unlockAt?: string) {
    super(message, 'ACCOUNT_LOCKED', 403);
    this.name = 'AccountLockedError';
    this.unlockAt = unlockAt;
  }
}

/**
 * Validation error - invalid input data
 */
export class ValidationError extends ZaltError {
  readonly fields: Record<string, string[]>;

  constructor(message: string = 'Validation failed', fields: Record<string, string[]> = {}) {
    super(message, 'VALIDATION_ERROR', 400);
    this.name = 'ValidationError';
    this.fields = fields;
  }
}

/**
 * Token refresh error - failed to refresh tokens
 */
export class TokenRefreshError extends ZaltError {
  constructor(message: string = 'Failed to refresh token') {
    super(message, 'TOKEN_REFRESH_ERROR', 401);
    this.name = 'TokenRefreshError';
  }
}

/**
 * Configuration error - invalid SDK configuration
 */
export class ConfigurationError extends ZaltError {
  constructor(message: string) {
    super(message, 'CONFIGURATION_ERROR');
    this.name = 'ConfigurationError';
  }
}

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Check if error is a ZaltError
 */
export function isZaltError(error: unknown): error is ZaltError {
  return error instanceof ZaltError;
}

/**
 * Check if error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof NetworkError) {
    return error.retryable;
  }
  if (error instanceof RateLimitError) {
    return true;
  }
  return false;
}

/**
 * Check if error requires MFA
 */
export function isMFARequiredError(error: unknown): error is MFARequiredError {
  return error instanceof MFARequiredError;
}

/**
 * Check if error is authentication related
 */
export function isAuthenticationError(error: unknown): error is AuthenticationError {
  return error instanceof AuthenticationError;
}

/**
 * Check if account is locked
 */
export function isAccountLockedError(error: unknown): error is AccountLockedError {
  return error instanceof AccountLockedError;
}

/**
 * Check if rate limited
 */
export function isRateLimitError(error: unknown): error is RateLimitError {
  return error instanceof RateLimitError;
}

// ============================================================================
// Error Factory
// ============================================================================

/**
 * Create appropriate error from API response
 */
export function createErrorFromResponse(
  statusCode: number,
  body: { error?: { code?: string; message?: string; details?: Record<string, unknown> } }
): ZaltError {
  const message = body.error?.message || 'An error occurred';
  const code = body.error?.code || 'UNKNOWN_ERROR';
  const details = body.error?.details;

  switch (statusCode) {
    case 400:
      if (details && typeof details === 'object') {
        return new ValidationError(message, details as Record<string, string[]>);
      }
      return new ValidationError(message);

    case 401:
      if (code === 'SESSION_EXPIRED') {
        return new AuthenticationError(message, 'SESSION_EXPIRED', 401);
      }
      if (code === 'EMAIL_NOT_VERIFIED') {
        return new AuthenticationError(message, 'EMAIL_NOT_VERIFIED', 401);
      }
      return new AuthenticationError(message, 'INVALID_CREDENTIALS', 401);

    case 403:
      if (code === 'ACCOUNT_LOCKED') {
        const unlockAt = details?.unlock_at as string | undefined;
        return new AccountLockedError(message, unlockAt);
      }
      return new AuthorizationError(message, 403);

    case 429:
      const retryAfter = details?.retry_after as number || 60;
      return new RateLimitError(message, retryAfter);

    default:
      return new ZaltError(message, code, statusCode);
  }
}

// Legacy aliases for backward compatibility
export { ZaltError as HSDAuthError };
export const isHSDAuthError = isZaltError;
