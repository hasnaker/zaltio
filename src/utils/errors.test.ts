/**
 * Property-based tests for Error Handling
 * Feature: zalt-platform, Property 4: Authentication Error Consistency
 * Validates: Requirements 2.4
 */

import * as fc from 'fast-check';
import {
  ErrorCodes,
  ErrorStatusCodes,
  ErrorMessages,
  getStatusCode,
  getDefaultMessage,
  AuthError,
  isAuthError,
  mapAWSError,
  ErrorCode
} from './errors';

/**
 * Custom generators for error testing
 */
const errorCodeArb = fc.constantFrom(...Object.values(ErrorCodes)) as fc.Arbitrary<ErrorCode>;

const httpStatusCodeArb = fc.constantFrom(400, 401, 403, 404, 405, 409, 423, 429, 500, 503);

const errorMessageArb = fc.string({ minLength: 1, maxLength: 200 }).filter(s => s.trim().length > 0);

const errorDetailsArb = fc.option(
  fc.record({
    field: fc.option(fc.string({ minLength: 1, maxLength: 50 })),
    realm_id: fc.option(fc.string({ minLength: 3, maxLength: 30 })),
    retry_after: fc.option(fc.integer({ min: 1, max: 3600 }))
  }),
  { nil: undefined }
);

describe('Error Handling - Property Tests', () => {
  /**
   * Property 4: Authentication Error Consistency
   * For any invalid authentication attempt, the system should return appropriate
   * HTTP status codes with descriptive error messages that don't leak sensitive information.
   * Validates: Requirements 2.4
   */
  describe('Property 4: Authentication Error Consistency', () => {
    it('should map every error code to a valid HTTP status code', () => {
      fc.assert(
        fc.property(errorCodeArb, (errorCode) => {
          const statusCode = getStatusCode(errorCode);
          
          // Status code should be a valid HTTP error code
          expect(statusCode).toBeGreaterThanOrEqual(400);
          expect(statusCode).toBeLessThan(600);
          
          // Status code should match the defined mapping
          expect(statusCode).toBe(ErrorStatusCodes[errorCode]);
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should provide a default message for every error code', () => {
      fc.assert(
        fc.property(errorCodeArb, (errorCode) => {
          const message = getDefaultMessage(errorCode);
          
          // Message should be a non-empty string
          expect(typeof message).toBe('string');
          expect(message.length).toBeGreaterThan(0);
          
          // Message should match the defined mapping
          expect(message).toBe(ErrorMessages[errorCode]);
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should ensure error messages do not leak sensitive information', () => {
      fc.assert(
        fc.property(errorCodeArb, (errorCode) => {
          const message = getDefaultMessage(errorCode);
          const lowerMessage = message.toLowerCase();
          
          // Messages should not contain sensitive keywords
          const sensitivePatterns = [
            'password hash',
            'secret',
            'internal server',
            'stack trace',
            'database connection',
            'sql',
            'query',
            'table name'
          ];
          
          for (const pattern of sensitivePatterns) {
            expect(lowerMessage).not.toContain(pattern);
          }
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should create AuthError with consistent properties', () => {
      fc.assert(
        fc.property(
          errorCodeArb,
          errorMessageArb,
          errorDetailsArb,
          (errorCode, customMessage, details) => {
            const error = new AuthError(errorCode, customMessage, details);
            
            // Error should have correct code
            expect(error.code).toBe(errorCode);
            
            // Error should have correct status code
            expect(error.statusCode).toBe(getStatusCode(errorCode));
            
            // Error should have the custom message
            expect(error.message).toBe(customMessage);
            
            // Error should have details if provided
            expect(error.details).toEqual(details);
            
            // Error should be identifiable as AuthError
            expect(isAuthError(error)).toBe(true);
            expect(error.name).toBe('AuthError');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should use default message when custom message not provided', () => {
      fc.assert(
        fc.property(errorCodeArb, (errorCode) => {
          const error = new AuthError(errorCode);
          
          // Error should use default message
          expect(error.message).toBe(getDefaultMessage(errorCode));
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should correctly identify AuthError instances', () => {
      fc.assert(
        fc.property(
          errorCodeArb,
          fc.anything(),
          (errorCode, randomValue) => {
            const authError = new AuthError(errorCode);
            const regularError = new Error('Regular error');
            
            // AuthError should be identified correctly
            expect(isAuthError(authError)).toBe(true);
            
            // Regular Error should not be identified as AuthError
            expect(isAuthError(regularError)).toBe(false);
            
            // Random values should not be identified as AuthError
            expect(isAuthError(randomValue)).toBe(false);
            expect(isAuthError(null)).toBe(false);
            expect(isAuthError(undefined)).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should group authentication errors under 401 status code', () => {
      const authErrorCodes: ErrorCode[] = [
        ErrorCodes.INVALID_CREDENTIALS,
        ErrorCodes.TOKEN_EXPIRED,
        ErrorCodes.INVALID_TOKEN,
        ErrorCodes.UNAUTHORIZED,
        ErrorCodes.USER_NOT_FOUND
      ];

      fc.assert(
        fc.property(
          fc.constantFrom(...authErrorCodes),
          (errorCode) => {
            const statusCode = getStatusCode(errorCode);
            
            // All authentication errors should return 401
            expect(statusCode).toBe(401);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should group validation errors under 400 status code', () => {
      const validationErrorCodes: ErrorCode[] = [
        ErrorCodes.INVALID_REQUEST,
        ErrorCodes.INVALID_JSON,
        ErrorCodes.INVALID_EMAIL,
        ErrorCodes.INVALID_PASSWORD,
        ErrorCodes.INVALID_REALM,
        ErrorCodes.INVALID_REALM_NAME,
        ErrorCodes.INVALID_DOMAIN,
        ErrorCodes.INVALID_SETTINGS,
        ErrorCodes.MISSING_REQUIRED_FIELD
      ];

      fc.assert(
        fc.property(
          fc.constantFrom(...validationErrorCodes),
          (errorCode) => {
            const statusCode = getStatusCode(errorCode);
            
            // All validation errors should return 400
            expect(statusCode).toBe(400);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should group rate limiting errors under 429 status code', () => {
      const rateLimitErrorCodes: ErrorCode[] = [
        ErrorCodes.RATE_LIMITED,
        ErrorCodes.TOO_MANY_REQUESTS
      ];

      fc.assert(
        fc.property(
          fc.constantFrom(...rateLimitErrorCodes),
          (errorCode) => {
            const statusCode = getStatusCode(errorCode);
            
            // All rate limiting errors should return 429
            expect(statusCode).toBe(429);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should map AWS errors to appropriate AuthErrors', () => {
      const awsErrorMappings = [
        { name: 'ConditionalCheckFailedException', expectedCode: ErrorCodes.CONFLICT },
        { name: 'ResourceNotFoundException', expectedCode: ErrorCodes.RESOURCE_NOT_FOUND },
        { name: 'ProvisionedThroughputExceededException', expectedCode: ErrorCodes.SERVICE_UNAVAILABLE },
        { name: 'ServiceUnavailable', expectedCode: ErrorCodes.DATABASE_UNAVAILABLE }
      ];

      fc.assert(
        fc.property(
          fc.constantFrom(...awsErrorMappings),
          ({ name, expectedCode }) => {
            const awsError = new Error('AWS Error');
            awsError.name = name;
            
            const authError = mapAWSError(awsError);
            
            // Should map to correct error code
            expect(authError.code).toBe(expectedCode);
            expect(isAuthError(authError)).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should map unknown AWS errors to INTERNAL_ERROR', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => 
            !['ConditionalCheckFailedException', 'ResourceNotFoundException', 
              'ProvisionedThroughputExceededException', 'ServiceUnavailable'].includes(s)
          ),
          (errorName) => {
            const awsError = new Error('Unknown AWS Error');
            awsError.name = errorName;
            
            const authError = mapAWSError(awsError);
            
            // Unknown errors should map to INTERNAL_ERROR
            expect(authError.code).toBe(ErrorCodes.INTERNAL_ERROR);
            expect(authError.statusCode).toBe(500);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should ensure all error codes have consistent structure', () => {
      fc.assert(
        fc.property(errorCodeArb, (errorCode) => {
          // Every error code should have a status code mapping
          expect(ErrorStatusCodes[errorCode]).toBeDefined();
          expect(typeof ErrorStatusCodes[errorCode]).toBe('number');
          
          // Every error code should have a message mapping
          expect(ErrorMessages[errorCode]).toBeDefined();
          expect(typeof ErrorMessages[errorCode]).toBe('string');
          
          // Status code should be in valid HTTP error range
          const statusCode = ErrorStatusCodes[errorCode];
          expect(statusCode).toBeGreaterThanOrEqual(400);
          expect(statusCode).toBeLessThan(600);
          
          return true;
        }),
        { numRuns: 100 }
      );
    });
  });
});
