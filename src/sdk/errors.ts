/**
 * Zalt.io Auth SDK Error Classes
 * @zalt/auth-sdk - Official TypeScript SDK for Zalt.io Authentication Platform
 * 
 * Validates: Requirements 4.5 (proper error handling)
 */

import { APIErrorResponse } from './types';

/**
 * Base error class for Zalt.io Auth SDK
 */
export class ZaltAuthError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly details?: Record<string, unknown>;
  public readonly requestId?: string;
  public readonly timestamp: string;

  constructor(
    code: string,
    message: string,
    statusCode: number = 500,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message);
    this.name = 'ZaltAuthError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.requestId = requestId;
    this.timestamp = new Date().toISOString();
    
    // Maintains proper stack trace for where error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ZaltAuthError);
    }
  }

  /**
   * Create error from API response
   */
  static fromAPIResponse(response: APIErrorResponse, statusCode: number): ZaltAuthError {
    const { error } = response;
    return new ZaltAuthError(
      error.code,
      error.message,
      statusCode,
      error.details,
      error.request_id
    );
  }

  /**
   * Convert to JSON for logging/serialization
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
      details: this.details,
      requestId: this.requestId,
      timestamp: this.timestamp
    };
  }
}

/**
 * Network error (connection issues, timeouts)
 */
export class NetworkError extends ZaltAuthError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('NETWORK_ERROR', message, 0, details);
    this.name = 'NetworkError';
  }
}

/**
 * Authentication error (invalid credentials, expired tokens)
 */
export class AuthenticationError extends ZaltAuthError {
  constructor(code: string, message: string, details?: Record<string, unknown>, requestId?: string) {
    super(code, message, 401, details, requestId);
    this.name = 'AuthenticationError';
  }
}

/**
 * Authorization error (insufficient permissions)
 */
export class AuthorizationError extends ZaltAuthError {
  constructor(code: string, message: string, details?: Record<string, unknown>, requestId?: string) {
    super(code, message, 403, details, requestId);
    this.name = 'AuthorizationError';
  }
}

/**
 * Validation error (invalid input)
 */
export class ValidationError extends ZaltAuthError {
  constructor(code: string, message: string, details?: Record<string, unknown>, requestId?: string) {
    super(code, message, 400, details, requestId);
    this.name = 'ValidationError';
  }
}

/**
 * Rate limit error
 */
export class RateLimitError extends ZaltAuthError {
  public readonly retryAfter?: number;

  constructor(message: string, retryAfter?: number, requestId?: string) {
    super('RATE_LIMITED', message, 429, { retry_after: retryAfter }, requestId);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Token refresh error
 */
export class TokenRefreshError extends ZaltAuthError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('TOKEN_REFRESH_FAILED', message, 401, details);
    this.name = 'TokenRefreshError';
  }
}

/**
 * Configuration error
 */
export class ConfigurationError extends ZaltAuthError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('CONFIGURATION_ERROR', message, 0, details);
    this.name = 'ConfigurationError';
  }
}

/**
 * MFA required error - thrown when login requires MFA verification
 */
export class MFARequiredError extends ZaltAuthError {
  public readonly mfaSessionId: string;
  public readonly mfaMethods: string[];

  constructor(
    message: string,
    mfaSessionId: string,
    mfaMethods: string[] = ['totp'],
    requestId?: string
  ) {
    super('MFA_REQUIRED', message, 403, { mfa_session_id: mfaSessionId, mfa_methods: mfaMethods }, requestId);
    this.name = 'MFARequiredError';
    this.mfaSessionId = mfaSessionId;
    this.mfaMethods = mfaMethods;
  }
}

/**
 * Account locked error
 */
export class AccountLockedError extends ZaltAuthError {
  public readonly lockedUntil?: string;

  constructor(message: string, lockedUntil?: string, requestId?: string) {
    super('ACCOUNT_LOCKED', message, 403, { locked_until: lockedUntil }, requestId);
    this.name = 'AccountLockedError';
    this.lockedUntil = lockedUntil;
  }
}

/**
 * Check if error is a ZaltAuthError
 */
export function isZaltAuthError(error: unknown): error is ZaltAuthError {
  return error instanceof ZaltAuthError;
}

/**
 * Check if error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof NetworkError) {
    return true;
  }
  if (error instanceof ZaltAuthError) {
    // Retry on server errors (5xx) except for specific cases
    return error.statusCode >= 500 && error.statusCode < 600;
  }
  return false;
}

// Legacy aliases for backward compatibility
/** @deprecated Use ZaltAuthError instead */
export const HSDAuthError = ZaltAuthError;
/** @deprecated Use isZaltAuthError instead */
export const isHSDAuthError = isZaltAuthError;
