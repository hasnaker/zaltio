/**
 * Error Handling Property Tests
 * @zalt/core
 * 
 * Property 3: Error Type Discrimination
 * For any API error response, the SDK SHALL throw a correctly typed error
 * that can be discriminated using `instanceof` checks.
 * 
 * Validates: Requirements 1.6, 6.2, 6.3, 6.4
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  ZaltError,
  AuthenticationError,
  AuthorizationError,
  NetworkError,
  RateLimitError,
  MFARequiredError,
  AccountLockedError,
  ValidationError,
  TokenRefreshError,
  ConfigurationError,
  isZaltError,
  isRetryableError,
  isMFARequiredError,
  isAuthenticationError,
  isAccountLockedError,
  isRateLimitError,
  createErrorFromResponse,
} from '../errors';

// ============================================================================
// Property Test: Error Type Discrimination
// ============================================================================

describe('Property 3: Error Type Discrimination', () => {
  /**
   * Feature: zalt-sdk-packages, Property 3: Error Type Discrimination
   * All errors SHALL be discriminable using instanceof checks
   */

  it('should discriminate all error types correctly', () => {
    const errorInstances = [
      new ZaltError('base error', 'BASE'),
      new AuthenticationError('auth error'),
      new AuthorizationError('authz error'),
      new NetworkError('network error'),
      new RateLimitError('rate limit'),
      new MFARequiredError('session123', ['totp']),
      new AccountLockedError('locked'),
      new ValidationError('validation'),
      new TokenRefreshError('refresh'),
      new ConfigurationError('config'),
    ];

    // All should be ZaltError
    for (const error of errorInstances) {
      expect(error instanceof ZaltError).toBe(true);
      expect(isZaltError(error)).toBe(true);
    }

    // Each should be its specific type
    expect(errorInstances[1] instanceof AuthenticationError).toBe(true);
    expect(errorInstances[2] instanceof AuthorizationError).toBe(true);
    expect(errorInstances[3] instanceof NetworkError).toBe(true);
    expect(errorInstances[4] instanceof RateLimitError).toBe(true);
    expect(errorInstances[5] instanceof MFARequiredError).toBe(true);
    expect(errorInstances[6] instanceof AccountLockedError).toBe(true);
    expect(errorInstances[7] instanceof ValidationError).toBe(true);
    expect(errorInstances[8] instanceof TokenRefreshError).toBe(true);
    expect(errorInstances[9] instanceof ConfigurationError).toBe(true);
  });

  it('should correctly identify retryable errors', () => {
    fc.assert(
      fc.property(
        fc.boolean(),
        fc.integer({ min: 1, max: 300 }),
        (retryable, retryAfter) => {
          const networkError = new NetworkError('error', retryable);
          const rateLimitError = new RateLimitError('error', retryAfter);
          const authError = new AuthenticationError('error');

          return (
            isRetryableError(networkError) === retryable &&
            isRetryableError(rateLimitError) === true &&
            isRetryableError(authError) === false
          );
        }
      ),
      { numRuns: 100 }
    );
  });

  it('should preserve error properties through discrimination', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.integer({ min: 1, max: 3600 }),
        (message, retryAfter) => {
          const error = new RateLimitError(message, retryAfter);

          // Type guard should work
          if (isRateLimitError(error)) {
            return (
              error.message === message &&
              error.retryAfter === retryAfter &&
              error.code === 'RATE_LIMIT_ERROR' &&
              error.statusCode === 429
            );
          }
          return false;
        }
      ),
      { numRuns: 100 }
    );
  });

  it('should preserve MFA error properties', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 10, maxLength: 50 }),
        fc.array(fc.constantFrom('totp', 'webauthn', 'sms'), { minLength: 1, maxLength: 3 }),
        (sessionId, methods) => {
          const error = new MFARequiredError(sessionId, methods as ('totp' | 'webauthn' | 'sms')[]);

          if (isMFARequiredError(error)) {
            return (
              error.sessionId === sessionId &&
              error.methods.length === methods.length &&
              error.methods.every((m, i) => m === methods[i])
            );
          }
          return false;
        }
      ),
      { numRuns: 100 }
    );
  });

  it('should preserve AccountLocked error properties', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.option(fc.date().map(d => d.toISOString())),
        (message, unlockAt) => {
          const error = new AccountLockedError(message, unlockAt ?? undefined);

          if (isAccountLockedError(error)) {
            return (
              error.message === message &&
              error.unlockAt === (unlockAt ?? undefined)
            );
          }
          return false;
        }
      ),
      { numRuns: 100 }
    );
  });

  it('should preserve ValidationError field details', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.dictionary(
          fc.string({ minLength: 1, maxLength: 20 }),
          fc.array(fc.string({ minLength: 1, maxLength: 50 }), { minLength: 1, maxLength: 3 })
        ),
        (message, fields) => {
          const error = new ValidationError(message, fields);

          return (
            error.message === message &&
            JSON.stringify(error.fields) === JSON.stringify(fields)
          );
        }
      ),
      { numRuns: 100 }
    );
  });
});

// ============================================================================
// Error Factory Tests
// ============================================================================

describe('createErrorFromResponse', () => {
  it('should create ValidationError for 400 status', () => {
    const error = createErrorFromResponse(400, {
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Invalid input',
        details: { email: ['Invalid format'] },
      },
    });

    expect(error instanceof ValidationError).toBe(true);
    expect(error.message).toBe('Invalid input');
  });

  it('should create AuthenticationError for 401 status', () => {
    const error = createErrorFromResponse(401, {
      error: {
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password',
      },
    });

    expect(error instanceof AuthenticationError).toBe(true);
    expect((error as AuthenticationError).code).toBe('INVALID_CREDENTIALS');
  });

  it('should create AccountLockedError for 403 with ACCOUNT_LOCKED code', () => {
    const error = createErrorFromResponse(403, {
      error: {
        code: 'ACCOUNT_LOCKED',
        message: 'Account is locked',
        details: { unlock_at: '2024-01-01T00:00:00Z' },
      },
    });

    expect(error instanceof AccountLockedError).toBe(true);
    expect((error as AccountLockedError).unlockAt).toBe('2024-01-01T00:00:00Z');
  });

  it('should create RateLimitError for 429 status', () => {
    const error = createErrorFromResponse(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        details: { retry_after: 60 },
      },
    });

    expect(error instanceof RateLimitError).toBe(true);
    expect((error as RateLimitError).retryAfter).toBe(60);
  });

  it('should create generic ZaltError for unknown status codes', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 500, max: 599 }),
        fc.string({ minLength: 1, maxLength: 100 }),
        (statusCode, message) => {
          const error = createErrorFromResponse(statusCode, {
            error: { code: 'SERVER_ERROR', message },
          });

          return (
            error instanceof ZaltError &&
            !(error instanceof AuthenticationError) &&
            !(error instanceof RateLimitError) &&
            error.message === message
          );
        }
      ),
      { numRuns: 100 }
    );
  });
});

// ============================================================================
// Type Guard Tests
// ============================================================================

describe('Type Guards', () => {
  it('isZaltError should return false for non-ZaltError', () => {
    expect(isZaltError(new Error('regular error'))).toBe(false);
    expect(isZaltError(null)).toBe(false);
    expect(isZaltError(undefined)).toBe(false);
    expect(isZaltError('string')).toBe(false);
    expect(isZaltError(123)).toBe(false);
    expect(isZaltError({})).toBe(false);
  });

  it('isZaltError should return true for all Zalt errors', () => {
    expect(isZaltError(new ZaltError('test', 'TEST'))).toBe(true);
    expect(isZaltError(new AuthenticationError('test'))).toBe(true);
    expect(isZaltError(new NetworkError('test'))).toBe(true);
    expect(isZaltError(new RateLimitError('test'))).toBe(true);
    expect(isZaltError(new MFARequiredError('session'))).toBe(true);
  });
});

// ============================================================================
// Error Properties Tests
// ============================================================================

describe('Error Properties', () => {
  it('AuthenticationError should have correct codes', () => {
    const invalid = new AuthenticationError('test', 'INVALID_CREDENTIALS');
    const notVerified = new AuthenticationError('test', 'EMAIL_NOT_VERIFIED');
    const expired = new AuthenticationError('test', 'SESSION_EXPIRED');

    expect(invalid.code).toBe('INVALID_CREDENTIALS');
    expect(notVerified.code).toBe('EMAIL_NOT_VERIFIED');
    expect(expired.code).toBe('SESSION_EXPIRED');
  });

  it('NetworkError should track retryable status', () => {
    const retryable = new NetworkError('test', true);
    const notRetryable = new NetworkError('test', false);

    expect(retryable.retryable).toBe(true);
    expect(notRetryable.retryable).toBe(false);
  });

  it('All errors should have proper name property', () => {
    expect(new ZaltError('test', 'TEST').name).toBe('ZaltError');
    expect(new AuthenticationError('test').name).toBe('AuthenticationError');
    expect(new NetworkError('test').name).toBe('NetworkError');
    expect(new RateLimitError('test').name).toBe('RateLimitError');
    expect(new MFARequiredError('session').name).toBe('MFARequiredError');
    expect(new AccountLockedError('test').name).toBe('AccountLockedError');
    expect(new ValidationError('test').name).toBe('ValidationError');
    expect(new TokenRefreshError('test').name).toBe('TokenRefreshError');
    expect(new ConfigurationError('test').name).toBe('ConfigurationError');
  });
});
