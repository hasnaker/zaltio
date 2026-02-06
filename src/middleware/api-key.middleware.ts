/**
 * API Key Validation Middleware for Zalt.io Auth Platform
 * 
 * Validates SDK API keys for end-user authentication requests:
 * - pk_live_xxx / pk_test_xxx - Publishable keys for frontend SDK
 * - sk_live_xxx / sk_test_xxx - Secret keys for backend SDK
 * 
 * Validates: Requirements 5.2 (API Key validation)
 * 
 * SECURITY:
 * - Keys are hashed with SHA-256 before storage
 * - Publishable keys can only be used for public endpoints
 * - Secret keys required for sensitive operations
 * - Rate limiting per key
 * - Audit logging for all key usage
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { validateAPIKey } from '../repositories/api-key.repository';
import { logSecurityEvent } from '../services/security-logger.service';
import { APIKey, isValidKeyFormat, APIKeyType } from '../models/api-key.model';

/**
 * API Key validation result
 */
export interface APIKeyValidationResult {
  valid: boolean;
  apiKey?: APIKey;
  error?: {
    code: string;
    message: string;
  };
}

/**
 * Middleware options
 */
export interface APIKeyMiddlewareOptions {
  /** Required key type (publishable or secret) */
  requiredType?: APIKeyType;
  /** Required environment (live or test) */
  requiredEnvironment?: 'live' | 'test';
  /** Allow both environments */
  allowBothEnvironments?: boolean;
  /** Skip validation (for public endpoints) */
  skipValidation?: boolean;
}

/**
 * Extract API key from request headers
 * Supports multiple header formats:
 * - X-API-Key: pk_live_xxx
 * - Authorization: Bearer pk_live_xxx
 * - Authorization: ApiKey pk_live_xxx
 */
export function extractAPIKey(event: APIGatewayProxyEvent): string | null {
  // Check X-API-Key header first (preferred)
  const xApiKey = event.headers?.['X-API-Key'] || event.headers?.['x-api-key'];
  if (xApiKey) {
    return xApiKey;
  }
  
  // Check Authorization header
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  if (!authHeader) {
    return null;
  }
  
  // Parse Authorization header
  const parts = authHeader.split(' ');
  if (parts.length !== 2) {
    return null;
  }
  
  const [scheme, token] = parts;
  const schemeLower = scheme.toLowerCase();
  
  // Support Bearer and ApiKey schemes
  if (schemeLower === 'bearer' || schemeLower === 'apikey') {
    return token;
  }
  
  return null;
}

/**
 * Validate API key format and type
 */
export function validateKeyFormat(
  key: string,
  options: APIKeyMiddlewareOptions = {}
): APIKeyValidationResult {
  // Check basic format
  if (!isValidKeyFormat(key)) {
    return {
      valid: false,
      error: {
        code: 'INVALID_KEY_FORMAT',
        message: 'Invalid API key format'
      }
    };
  }
  
  // Extract key type and environment from prefix
  const prefix = key.substring(0, 8); // e.g., "pk_live_"
  const isPublishable = prefix.startsWith('pk_');
  const isSecret = prefix.startsWith('sk_');
  const isLive = prefix.includes('_live_');
  const isTest = prefix.includes('_test_');
  
  // Validate required type
  if (options.requiredType) {
    if (options.requiredType === 'publishable' && !isPublishable) {
      return {
        valid: false,
        error: {
          code: 'INVALID_KEY_TYPE',
          message: 'Publishable key required for this endpoint'
        }
      };
    }
    if (options.requiredType === 'secret' && !isSecret) {
      return {
        valid: false,
        error: {
          code: 'INVALID_KEY_TYPE',
          message: 'Secret key required for this endpoint'
        }
      };
    }
  }
  
  // Validate required environment
  if (options.requiredEnvironment && !options.allowBothEnvironments) {
    if (options.requiredEnvironment === 'live' && !isLive) {
      return {
        valid: false,
        error: {
          code: 'INVALID_KEY_ENVIRONMENT',
          message: 'Live environment key required'
        }
      };
    }
    if (options.requiredEnvironment === 'test' && !isTest) {
      return {
        valid: false,
        error: {
          code: 'INVALID_KEY_ENVIRONMENT',
          message: 'Test environment key required'
        }
      };
    }
  }
  
  return { valid: true };
}


/**
 * Validate API key against database
 */
export async function validateAPIKeyFromDB(
  key: string,
  clientIP: string
): Promise<APIKeyValidationResult> {
  try {
    const apiKey = await validateAPIKey(key);
    
    if (!apiKey) {
      // Log failed validation attempt
      await logSecurityEvent({
        event_type: 'api_key_validation_failed',
        ip_address: clientIP,
        details: { 
          key_prefix: key.substring(0, 8),
          reason: 'key_not_found'
        }
      });
      
      return {
        valid: false,
        error: {
          code: 'INVALID_API_KEY',
          message: 'Invalid or expired API key'
        }
      };
    }
    
    return {
      valid: true,
      apiKey
    };
  } catch (error) {
    console.error('API key validation error:', error);
    
    return {
      valid: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Failed to validate API key'
      }
    };
  }
}

/**
 * Create error response for API key validation failures
 */
export function createAPIKeyErrorResponse(
  code: string,
  message: string,
  requestId?: string
): APIGatewayProxyResult {
  return {
    statusCode: code === 'MISSING_API_KEY' ? 401 : 403,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-API-Key',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    },
    body: JSON.stringify({
      error: {
        code,
        message,
        timestamp: new Date().toISOString(),
        request_id: requestId
      }
    })
  };
}

/**
 * Get client IP from request
 */
function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 
         event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
         'unknown';
}

/**
 * API Key validation middleware
 * 
 * Usage:
 * ```typescript
 * export async function handler(event: APIGatewayProxyEvent) {
 *   const validation = await validateAPIKeyMiddleware(event, { requiredType: 'publishable' });
 *   if (!validation.valid) {
 *     return validation.response!;
 *   }
 *   
 *   const { apiKey } = validation;
 *   // Use apiKey.customer_id, apiKey.realm_id, etc.
 * }
 * ```
 */
export async function validateAPIKeyMiddleware(
  event: APIGatewayProxyEvent,
  options: APIKeyMiddlewareOptions = {}
): Promise<{
  valid: boolean;
  apiKey?: APIKey;
  response?: APIGatewayProxyResult;
}> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);
  
  // Skip validation if configured
  if (options.skipValidation) {
    return { valid: true };
  }
  
  // Extract API key from request
  const key = extractAPIKey(event);
  
  if (!key) {
    await logSecurityEvent({
      event_type: 'api_key_missing',
      ip_address: clientIP,
      details: { path: event.path }
    });
    
    return {
      valid: false,
      response: createAPIKeyErrorResponse(
        'MISSING_API_KEY',
        'API key is required. Provide it via X-API-Key header or Authorization header.',
        requestId
      )
    };
  }
  
  // Validate key format
  const formatValidation = validateKeyFormat(key, options);
  if (!formatValidation.valid) {
    await logSecurityEvent({
      event_type: 'api_key_format_invalid',
      ip_address: clientIP,
      details: { 
        key_prefix: key.substring(0, 8),
        error: formatValidation.error?.code
      }
    });
    
    return {
      valid: false,
      response: createAPIKeyErrorResponse(
        formatValidation.error!.code,
        formatValidation.error!.message,
        requestId
      )
    };
  }
  
  // Validate key against database
  const dbValidation = await validateAPIKeyFromDB(key, clientIP);
  if (!dbValidation.valid) {
    return {
      valid: false,
      response: createAPIKeyErrorResponse(
        dbValidation.error!.code,
        dbValidation.error!.message,
        requestId
      )
    };
  }
  
  // Log successful validation
  await logSecurityEvent({
    event_type: 'api_key_validated',
    ip_address: clientIP,
    user_id: dbValidation.apiKey!.customer_id,
    realm_id: dbValidation.apiKey!.realm_id,
    details: { 
      key_id: dbValidation.apiKey!.id,
      key_type: dbValidation.apiKey!.type,
      environment: dbValidation.apiKey!.environment
    }
  });
  
  return {
    valid: true,
    apiKey: dbValidation.apiKey
  };
}

/**
 * Wrapper for handlers that require publishable key
 * Used for frontend SDK endpoints (login, register, etc.)
 */
export function requirePublishableKey(
  handler: (event: APIGatewayProxyEvent, apiKey: APIKey) => Promise<APIGatewayProxyResult>
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return async (event: APIGatewayProxyEvent) => {
    const validation = await validateAPIKeyMiddleware(event, { 
      requiredType: 'publishable',
      allowBothEnvironments: true
    });
    
    if (!validation.valid) {
      return validation.response!;
    }
    
    return handler(event, validation.apiKey!);
  };
}

/**
 * Wrapper for handlers that require secret key
 * Used for backend SDK endpoints (admin operations, etc.)
 */
export function requireSecretKey(
  handler: (event: APIGatewayProxyEvent, apiKey: APIKey) => Promise<APIGatewayProxyResult>
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return async (event: APIGatewayProxyEvent) => {
    const validation = await validateAPIKeyMiddleware(event, { 
      requiredType: 'secret',
      allowBothEnvironments: true
    });
    
    if (!validation.valid) {
      return validation.response!;
    }
    
    return handler(event, validation.apiKey!);
  };
}

/**
 * Check if request is using test environment key
 */
export function isTestEnvironment(apiKey: APIKey): boolean {
  return apiKey.environment === 'test';
}

/**
 * Check if request is using live environment key
 */
export function isLiveEnvironment(apiKey: APIKey): boolean {
  return apiKey.environment === 'live';
}
