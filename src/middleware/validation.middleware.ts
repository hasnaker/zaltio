/**
 * Request Validation Middleware for Zalt.io Auth Platform
 * Task 6.11: Request Validation & Size Limits
 * 
 * SECURITY CRITICAL:
 * - Prevents payload-based attacks
 * - Limits resource consumption
 * - Validates content types
 * - Protects against JSON bombs
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

/**
 * Validation configuration
 */
export interface ValidationConfig {
  // Maximum request body size in bytes
  maxBodySize: number;
  
  // Maximum JSON nesting depth
  maxJsonDepth: number;
  
  // Maximum array length
  maxArrayLength: number;
  
  // Maximum string length
  maxStringLength: number;
  
  // Maximum object keys
  maxObjectKeys: number;
  
  // Allowed content types
  allowedContentTypes: string[];
  
  // Require content type header
  requireContentType: boolean;
}

/**
 * Default validation configuration
 */
export const DEFAULT_VALIDATION_CONFIG: ValidationConfig = {
  maxBodySize: 1024 * 1024, // 1MB
  maxJsonDepth: 10,
  maxArrayLength: 1000,
  maxStringLength: 10000,
  maxObjectKeys: 100,
  allowedContentTypes: ['application/json', 'application/x-www-form-urlencoded'],
  requireContentType: true
};

/**
 * Strict validation configuration (for sensitive endpoints)
 */
export const STRICT_VALIDATION_CONFIG: ValidationConfig = {
  maxBodySize: 100 * 1024, // 100KB
  maxJsonDepth: 5,
  maxArrayLength: 100,
  maxStringLength: 1000,
  maxObjectKeys: 50,
  allowedContentTypes: ['application/json'],
  requireContentType: true
};

/**
 * File upload validation configuration
 */
export const FILE_UPLOAD_CONFIG: ValidationConfig = {
  maxBodySize: 5 * 1024 * 1024, // 5MB
  maxJsonDepth: 3,
  maxArrayLength: 10,
  maxStringLength: 100000, // Base64 encoded files
  maxObjectKeys: 20,
  allowedContentTypes: ['application/json', 'multipart/form-data'],
  requireContentType: true
};

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  error?: string;
  errorCode?: 'BODY_TOO_LARGE' | 'INVALID_CONTENT_TYPE' | 'INVALID_JSON' | 
              'JSON_TOO_DEEP' | 'ARRAY_TOO_LONG' | 'STRING_TOO_LONG' | 
              'TOO_MANY_KEYS' | 'MISSING_CONTENT_TYPE';
  statusCode?: number;
}

/**
 * Validate request body size
 */
export function validateBodySize(
  body: string | null,
  config: ValidationConfig = DEFAULT_VALIDATION_CONFIG
): ValidationResult {
  if (!body) {
    return { valid: true };
  }

  const bodySize = Buffer.byteLength(body, 'utf8');
  
  if (bodySize > config.maxBodySize) {
    return {
      valid: false,
      error: `Request body too large. Maximum size is ${Math.floor(config.maxBodySize / 1024)}KB`,
      errorCode: 'BODY_TOO_LARGE',
      statusCode: 413
    };
  }

  return { valid: true };
}

/**
 * Validate content type
 */
export function validateContentType(
  contentType: string | undefined,
  config: ValidationConfig = DEFAULT_VALIDATION_CONFIG
): ValidationResult {
  if (!contentType) {
    if (config.requireContentType) {
      return {
        valid: false,
        error: 'Content-Type header is required',
        errorCode: 'MISSING_CONTENT_TYPE',
        statusCode: 415
      };
    }
    return { valid: true };
  }

  // Extract base content type (ignore charset, boundary, etc.)
  const baseContentType = contentType.split(';')[0].trim().toLowerCase();
  
  if (!config.allowedContentTypes.includes(baseContentType)) {
    return {
      valid: false,
      error: `Content-Type '${baseContentType}' is not allowed. Allowed types: ${config.allowedContentTypes.join(', ')}`,
      errorCode: 'INVALID_CONTENT_TYPE',
      statusCode: 415
    };
  }

  return { valid: true };
}

/**
 * Calculate JSON depth
 */
export function calculateJsonDepth(obj: any, currentDepth: number = 0): number {
  if (obj === null || typeof obj !== 'object') {
    return currentDepth;
  }

  let maxDepth = currentDepth;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      const depth = calculateJsonDepth(item, currentDepth + 1);
      maxDepth = Math.max(maxDepth, depth);
    }
  } else {
    for (const key of Object.keys(obj)) {
      const depth = calculateJsonDepth(obj[key], currentDepth + 1);
      maxDepth = Math.max(maxDepth, depth);
    }
  }

  return maxDepth;
}

/**
 * Validate JSON depth
 */
export function validateJsonDepth(
  obj: any,
  config: ValidationConfig = DEFAULT_VALIDATION_CONFIG
): ValidationResult {
  const depth = calculateJsonDepth(obj);
  
  if (depth > config.maxJsonDepth) {
    return {
      valid: false,
      error: `JSON nesting too deep. Maximum depth is ${config.maxJsonDepth}`,
      errorCode: 'JSON_TOO_DEEP',
      statusCode: 400
    };
  }

  return { valid: true };
}

/**
 * Validate array lengths recursively
 */
export function validateArrayLengths(
  obj: any,
  config: ValidationConfig = DEFAULT_VALIDATION_CONFIG
): ValidationResult {
  if (obj === null || typeof obj !== 'object') {
    return { valid: true };
  }

  if (Array.isArray(obj)) {
    if (obj.length > config.maxArrayLength) {
      return {
        valid: false,
        error: `Array too long. Maximum length is ${config.maxArrayLength}`,
        errorCode: 'ARRAY_TOO_LONG',
        statusCode: 400
      };
    }

    for (const item of obj) {
      const result = validateArrayLengths(item, config);
      if (!result.valid) return result;
    }
  } else {
    for (const key of Object.keys(obj)) {
      const result = validateArrayLengths(obj[key], config);
      if (!result.valid) return result;
    }
  }

  return { valid: true };
}

/**
 * Validate string lengths recursively
 */
export function validateStringLengths(
  obj: any,
  config: ValidationConfig = DEFAULT_VALIDATION_CONFIG
): ValidationResult {
  if (typeof obj === 'string') {
    if (obj.length > config.maxStringLength) {
      return {
        valid: false,
        error: `String too long. Maximum length is ${config.maxStringLength}`,
        errorCode: 'STRING_TOO_LONG',
        statusCode: 400
      };
    }
    return { valid: true };
  }

  if (obj === null || typeof obj !== 'object') {
    return { valid: true };
  }

  if (Array.isArray(obj)) {
    for (const item of obj) {
      const result = validateStringLengths(item, config);
      if (!result.valid) return result;
    }
  } else {
    for (const key of Object.keys(obj)) {
      // Also validate key length
      if (key.length > config.maxStringLength) {
        return {
          valid: false,
          error: `Object key too long. Maximum length is ${config.maxStringLength}`,
          errorCode: 'STRING_TOO_LONG',
          statusCode: 400
        };
      }
      
      const result = validateStringLengths(obj[key], config);
      if (!result.valid) return result;
    }
  }

  return { valid: true };
}

/**
 * Validate object key count recursively
 */
export function validateObjectKeys(
  obj: any,
  config: ValidationConfig = DEFAULT_VALIDATION_CONFIG
): ValidationResult {
  if (obj === null || typeof obj !== 'object') {
    return { valid: true };
  }

  if (Array.isArray(obj)) {
    for (const item of obj) {
      const result = validateObjectKeys(item, config);
      if (!result.valid) return result;
    }
  } else {
    const keyCount = Object.keys(obj).length;
    if (keyCount > config.maxObjectKeys) {
      return {
        valid: false,
        error: `Too many object keys. Maximum is ${config.maxObjectKeys}`,
        errorCode: 'TOO_MANY_KEYS',
        statusCode: 400
      };
    }

    for (const key of Object.keys(obj)) {
      const result = validateObjectKeys(obj[key], config);
      if (!result.valid) return result;
    }
  }

  return { valid: true };
}

/**
 * Parse and validate JSON body
 */
export function parseAndValidateJson(
  body: string | null,
  config: ValidationConfig = DEFAULT_VALIDATION_CONFIG
): { valid: boolean; data?: any; error?: string; errorCode?: string; statusCode?: number } {
  if (!body) {
    return { valid: true, data: null };
  }

  // Try to parse JSON
  let parsed: any;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    return {
      valid: false,
      error: 'Invalid JSON in request body',
      errorCode: 'INVALID_JSON',
      statusCode: 400
    };
  }

  // Validate depth
  const depthResult = validateJsonDepth(parsed, config);
  if (!depthResult.valid) return depthResult;

  // Validate array lengths
  const arrayResult = validateArrayLengths(parsed, config);
  if (!arrayResult.valid) return arrayResult;

  // Validate string lengths
  const stringResult = validateStringLengths(parsed, config);
  if (!stringResult.valid) return stringResult;

  // Validate object keys
  const keysResult = validateObjectKeys(parsed, config);
  if (!keysResult.valid) return keysResult;

  return { valid: true, data: parsed };
}

/**
 * Full request validation
 */
export function validateRequest(
  event: APIGatewayProxyEvent,
  config: ValidationConfig = DEFAULT_VALIDATION_CONFIG
): ValidationResult {
  // Validate body size
  const sizeResult = validateBodySize(event.body, config);
  if (!sizeResult.valid) return sizeResult;

  // Validate content type
  const contentType = event.headers['content-type'] || event.headers['Content-Type'];
  const contentTypeResult = validateContentType(contentType, config);
  if (!contentTypeResult.valid) return contentTypeResult;

  // Parse and validate JSON if applicable
  if (event.body && contentType?.includes('application/json')) {
    const jsonResult = parseAndValidateJson(event.body, config);
    if (!jsonResult.valid) {
      return {
        valid: false,
        error: jsonResult.error,
        errorCode: jsonResult.errorCode as any,
        statusCode: jsonResult.statusCode
      };
    }
  }

  return { valid: true };
}

/**
 * Create validation error response
 */
export function createValidationErrorResponse(result: ValidationResult): APIGatewayProxyResult {
  return {
    statusCode: result.statusCode || 400,
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      error: result.error,
      code: result.errorCode
    })
  };
}

/**
 * Validation middleware wrapper
 */
export function withValidation(
  handler: (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>,
  config: ValidationConfig = DEFAULT_VALIDATION_CONFIG
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const validationResult = validateRequest(event, config);
    
    if (!validationResult.valid) {
      return createValidationErrorResponse(validationResult);
    }

    return handler(event);
  };
}

/**
 * Sanitize string input (remove potential XSS)
 */
export function sanitizeString(input: string): string {
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

/**
 * Validate UUID format
 */
export function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Validate realm ID format
 */
export function isValidRealmId(realmId: string): boolean {
  // Realm IDs: lowercase alphanumeric with hyphens, 3-50 chars
  const realmRegex = /^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/;
  return realmRegex.test(realmId);
}
