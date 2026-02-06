/**
 * Error Handling Utilities for HSD Auth Platform
 * Validates: Requirements 2.4, 9.4
 * 
 * Provides standardized error response format and proper HTTP status codes
 */

/**
 * Standard error codes for the HSD Auth Platform
 */
export const ErrorCodes = {
  // Authentication errors (401)
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INVALID_TOKEN: 'INVALID_TOKEN',
  UNAUTHORIZED: 'UNAUTHORIZED',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  
  // Authorization errors (403)
  FORBIDDEN: 'FORBIDDEN',
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  
  // Validation errors (400)
  INVALID_REQUEST: 'INVALID_REQUEST',
  INVALID_JSON: 'INVALID_JSON',
  INVALID_EMAIL: 'INVALID_EMAIL',
  INVALID_PASSWORD: 'INVALID_PASSWORD',
  INVALID_REALM: 'INVALID_REALM',
  INVALID_REALM_NAME: 'INVALID_REALM_NAME',
  INVALID_DOMAIN: 'INVALID_DOMAIN',
  INVALID_SETTINGS: 'INVALID_SETTINGS',
  MISSING_REQUIRED_FIELD: 'MISSING_REQUIRED_FIELD',
  
  // Resource errors (404)
  REALM_NOT_FOUND: 'REALM_NOT_FOUND',
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
  RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
  
  // Conflict errors (409)
  USER_EXISTS: 'USER_EXISTS',
  REALM_EXISTS: 'REALM_EXISTS',
  CONFLICT: 'CONFLICT',
  
  // Account status errors (423)
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  ACCOUNT_SUSPENDED: 'ACCOUNT_SUSPENDED',
  
  // Rate limiting errors (429)
  RATE_LIMITED: 'RATE_LIMITED',
  TOO_MANY_REQUESTS: 'TOO_MANY_REQUESTS',
  
  // Server errors (500)
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  TOKEN_ERROR: 'TOKEN_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',
  UPDATE_FAILED: 'UPDATE_FAILED',
  
  // Service unavailable (503)
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  DATABASE_UNAVAILABLE: 'DATABASE_UNAVAILABLE',
  
  // Method not allowed (405)
  METHOD_NOT_ALLOWED: 'METHOD_NOT_ALLOWED',
  
  // Limit reached (403)
  REALM_LIMIT_REACHED: 'REALM_LIMIT_REACHED'
} as const;

export type ErrorCode = typeof ErrorCodes[keyof typeof ErrorCodes];

/**
 * HTTP status codes mapping for error codes
 */
export const ErrorStatusCodes: Record<ErrorCode, number> = {
  // 400 Bad Request
  [ErrorCodes.INVALID_REQUEST]: 400,
  [ErrorCodes.INVALID_JSON]: 400,
  [ErrorCodes.INVALID_EMAIL]: 400,
  [ErrorCodes.INVALID_PASSWORD]: 400,
  [ErrorCodes.INVALID_REALM]: 400,
  [ErrorCodes.INVALID_REALM_NAME]: 400,
  [ErrorCodes.INVALID_DOMAIN]: 400,
  [ErrorCodes.INVALID_SETTINGS]: 400,
  [ErrorCodes.MISSING_REQUIRED_FIELD]: 400,
  
  // 401 Unauthorized
  [ErrorCodes.INVALID_CREDENTIALS]: 401,
  [ErrorCodes.TOKEN_EXPIRED]: 401,
  [ErrorCodes.INVALID_TOKEN]: 401,
  [ErrorCodes.UNAUTHORIZED]: 401,
  [ErrorCodes.USER_NOT_FOUND]: 401,
  
  // 403 Forbidden
  [ErrorCodes.FORBIDDEN]: 403,
  [ErrorCodes.INSUFFICIENT_PERMISSIONS]: 403,
  [ErrorCodes.REALM_LIMIT_REACHED]: 403,
  
  // 404 Not Found
  [ErrorCodes.REALM_NOT_FOUND]: 404,
  [ErrorCodes.SESSION_NOT_FOUND]: 404,
  [ErrorCodes.RESOURCE_NOT_FOUND]: 404,
  
  // 405 Method Not Allowed
  [ErrorCodes.METHOD_NOT_ALLOWED]: 405,
  
  // 409 Conflict
  [ErrorCodes.USER_EXISTS]: 409,
  [ErrorCodes.REALM_EXISTS]: 409,
  [ErrorCodes.CONFLICT]: 409,
  
  // 423 Locked
  [ErrorCodes.ACCOUNT_LOCKED]: 423,
  [ErrorCodes.ACCOUNT_SUSPENDED]: 423,
  
  // 429 Too Many Requests
  [ErrorCodes.RATE_LIMITED]: 429,
  [ErrorCodes.TOO_MANY_REQUESTS]: 429,
  
  // 500 Internal Server Error
  [ErrorCodes.INTERNAL_ERROR]: 500,
  [ErrorCodes.TOKEN_ERROR]: 500,
  [ErrorCodes.DATABASE_ERROR]: 500,
  [ErrorCodes.UPDATE_FAILED]: 500,
  
  // 503 Service Unavailable
  [ErrorCodes.SERVICE_UNAVAILABLE]: 503,
  [ErrorCodes.DATABASE_UNAVAILABLE]: 503
};

/**
 * Default error messages (safe for client display)
 */
export const ErrorMessages: Record<ErrorCode, string> = {
  [ErrorCodes.INVALID_CREDENTIALS]: 'Invalid email or password',
  [ErrorCodes.TOKEN_EXPIRED]: 'Token has expired',
  [ErrorCodes.INVALID_TOKEN]: 'Invalid token',
  [ErrorCodes.UNAUTHORIZED]: 'Authentication required',
  [ErrorCodes.USER_NOT_FOUND]: 'User not found',
  
  [ErrorCodes.FORBIDDEN]: 'Access denied',
  [ErrorCodes.INSUFFICIENT_PERMISSIONS]: 'Insufficient permissions',
  [ErrorCodes.REALM_LIMIT_REACHED]: 'Maximum number of realms reached',
  
  [ErrorCodes.INVALID_REQUEST]: 'Invalid request',
  [ErrorCodes.INVALID_JSON]: 'Invalid JSON in request body',
  [ErrorCodes.INVALID_EMAIL]: 'Invalid email format',
  [ErrorCodes.INVALID_PASSWORD]: 'Invalid password',
  [ErrorCodes.INVALID_REALM]: 'Invalid realm ID',
  [ErrorCodes.INVALID_REALM_NAME]: 'Invalid realm name',
  [ErrorCodes.INVALID_DOMAIN]: 'Invalid domain format',
  [ErrorCodes.INVALID_SETTINGS]: 'Invalid settings',
  [ErrorCodes.MISSING_REQUIRED_FIELD]: 'Missing required field',
  
  [ErrorCodes.REALM_NOT_FOUND]: 'Realm not found',
  [ErrorCodes.SESSION_NOT_FOUND]: 'Session not found',
  [ErrorCodes.RESOURCE_NOT_FOUND]: 'Resource not found',
  
  [ErrorCodes.METHOD_NOT_ALLOWED]: 'Method not allowed',
  
  [ErrorCodes.USER_EXISTS]: 'User already exists',
  [ErrorCodes.REALM_EXISTS]: 'Realm already exists',
  [ErrorCodes.CONFLICT]: 'Resource conflict',
  
  [ErrorCodes.ACCOUNT_LOCKED]: 'Account is locked',
  [ErrorCodes.ACCOUNT_SUSPENDED]: 'Account is suspended',
  
  [ErrorCodes.RATE_LIMITED]: 'Too many requests. Please try again later.',
  [ErrorCodes.TOO_MANY_REQUESTS]: 'Too many requests. Please try again later.',
  
  [ErrorCodes.INTERNAL_ERROR]: 'An unexpected error occurred',
  [ErrorCodes.TOKEN_ERROR]: 'Token generation failed',
  [ErrorCodes.DATABASE_ERROR]: 'Database operation failed',
  [ErrorCodes.UPDATE_FAILED]: 'Update operation failed',
  
  [ErrorCodes.SERVICE_UNAVAILABLE]: 'Service temporarily unavailable',
  [ErrorCodes.DATABASE_UNAVAILABLE]: 'Database temporarily unavailable'
};

/**
 * Get HTTP status code for an error code
 */
export function getStatusCode(code: ErrorCode): number {
  return ErrorStatusCodes[code] || 500;
}

/**
 * Get default message for an error code
 */
export function getDefaultMessage(code: ErrorCode): string {
  return ErrorMessages[code] || 'An unexpected error occurred';
}

/**
 * Custom error class for HSD Auth Platform
 */
export class AuthError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, unknown>;

  constructor(
    code: ErrorCode,
    message?: string,
    details?: Record<string, unknown>
  ) {
    super(message || getDefaultMessage(code));
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = getStatusCode(code);
    this.details = details;
  }
}

/**
 * Check if an error is an AuthError
 */
export function isAuthError(error: unknown): error is AuthError {
  return error instanceof AuthError;
}

/**
 * Map common AWS errors to AuthError
 */
export function mapAWSError(error: Error): AuthError {
  const errorName = error.name;
  
  switch (errorName) {
    case 'ConditionalCheckFailedException':
      return new AuthError(ErrorCodes.CONFLICT, 'Resource already exists or was modified');
    case 'ResourceNotFoundException':
      return new AuthError(ErrorCodes.RESOURCE_NOT_FOUND, 'Resource not found');
    case 'ProvisionedThroughputExceededException':
      return new AuthError(ErrorCodes.SERVICE_UNAVAILABLE, 'Service temporarily unavailable');
    case 'ServiceUnavailable':
      return new AuthError(ErrorCodes.DATABASE_UNAVAILABLE, 'Database temporarily unavailable');
    default:
      return new AuthError(ErrorCodes.INTERNAL_ERROR, 'An unexpected error occurred');
  }
}
