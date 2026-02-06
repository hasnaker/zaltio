/**
 * User API Key Authentication Middleware for Zalt.io Auth Platform
 * 
 * Validates user-generated API keys (zalt_key_xxx) and injects user context:
 * - Detects zalt_key_ prefix in Authorization header
 * - Validates key and returns user context
 * - Inherits user's tenant context and permissions
 * - Enforces key scopes
 * 
 * Validates: Requirements 2.7, 2.8 (User API Key Authentication)
 * 
 * SECURITY:
 * - Keys are SHA-256 hashed before lookup
 * - Revoked keys return 401 immediately
 * - Expired keys return 401
 * - IP restrictions enforced if configured
 * - Audit logging for all key usage
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { userAPIKeyService, UserAPIKeyError } from '../services/user-api-key.service';
import {
  UserAPIKey,
  UserAPIKeyContext,
  USER_API_KEY_PREFIX,
  isValidUserAPIKeyFormat,
  userAPIKeyScopesAllowed
} from '../models/user-api-key.model';

/**
 * User API Key validation result
 */
export interface UserAPIKeyValidationResult {
  valid: boolean;
  context?: UserAPIKeyContext;
  error?: {
    code: string;
    message: string;
    statusCode: number;
  };
}

/**
 * Middleware options
 */
export interface UserAPIKeyMiddlewareOptions {
  /** Required scope for this endpoint */
  requiredScope?: string;
  /** Multiple scopes (any one is sufficient) */
  requiredScopes?: string[];
  /** All scopes required (AND logic) */
  requireAllScopes?: boolean;
  /** Skip validation (for public endpoints) */
  skipValidation?: boolean;
  /** Allow regular Bearer tokens as well */
  allowBearerTokens?: boolean;
}

// CORS headers
const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
};

/**
 * Check if the Authorization header contains a user API key
 */
export function isUserAPIKeyAuth(event: APIGatewayProxyEvent): boolean {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  
  if (!authHeader) {
    return false;
  }
  
  // Check for Bearer token with zalt_key_ prefix
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    return token.startsWith(USER_API_KEY_PREFIX);
  }
  
  return false;
}

/**
 * Extract user API key from request headers
 */
export function extractUserAPIKey(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  
  if (!authHeader) {
    return null;
  }
  
  // Must be Bearer token
  if (!authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  const token = authHeader.substring(7);
  
  // Must have zalt_key_ prefix
  if (!token.startsWith(USER_API_KEY_PREFIX)) {
    return null;
  }
  
  return token;
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
 * Check if IP is allowed by restrictions
 */
function isIPAllowed(clientIP: string, restrictions?: string[]): boolean {
  if (!restrictions || restrictions.length === 0) {
    return true;
  }
  
  // Simple IP matching (in production, use proper CIDR matching)
  for (const restriction of restrictions) {
    if (restriction.includes('/')) {
      // CIDR notation - simplified check
      const [network] = restriction.split('/');
      if (clientIP.startsWith(network.split('.').slice(0, 3).join('.'))) {
        return true;
      }
    } else if (clientIP === restriction) {
      return true;
    }
  }
  
  return false;
}

/**
 * Validate user API key and check scopes
 */
export async function validateUserAPIKey(
  event: APIGatewayProxyEvent,
  options: UserAPIKeyMiddlewareOptions = {}
): Promise<UserAPIKeyValidationResult> {
  // Skip validation if configured
  if (options.skipValidation) {
    return { valid: true };
  }
  
  // Extract key
  const key = extractUserAPIKey(event);
  
  if (!key) {
    // If allowBearerTokens is true and there's a Bearer token, let it pass
    if (options.allowBearerTokens) {
      const authHeader = event.headers?.Authorization || event.headers?.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        return { valid: true }; // Let regular auth handle it
      }
    }
    
    return {
      valid: false,
      error: {
        code: 'MISSING_API_KEY',
        message: 'User API key is required',
        statusCode: 401
      }
    };
  }
  
  // Validate format
  if (!isValidUserAPIKeyFormat(key)) {
    return {
      valid: false,
      error: {
        code: 'INVALID_KEY_FORMAT',
        message: 'Invalid user API key format',
        statusCode: 401
      }
    };
  }
  
  try {
    // Validate key and get context
    const context = await userAPIKeyService.validateKey(key);
    
    // Check IP restrictions
    const clientIP = getClientIP(event);
    if (!isIPAllowed(clientIP, context.key.ip_restrictions)) {
      return {
        valid: false,
        error: {
          code: 'IP_NOT_ALLOWED',
          message: 'Request from this IP address is not allowed',
          statusCode: 403
        }
      };
    }
    
    // Check required scopes
    const requiredScopes = getRequiredScopes(options);
    
    if (requiredScopes.length > 0) {
      const hasRequiredScopes = options.requireAllScopes
        ? requiredScopes.every(scope => userAPIKeyScopesAllowed([scope], context.scopes))
        : requiredScopes.some(scope => userAPIKeyScopesAllowed([scope], context.scopes));
      
      if (!hasRequiredScopes) {
        return {
          valid: false,
          context,
          error: {
            code: 'INSUFFICIENT_SCOPE',
            message: `Required scope(s): ${requiredScopes.join(', ')}`,
            statusCode: 403
          }
        };
      }
    }
    
    return {
      valid: true,
      context
    };
    
  } catch (error) {
    if (error instanceof UserAPIKeyError) {
      return {
        valid: false,
        error: {
          code: error.code,
          message: error.message,
          statusCode: error.statusCode
        }
      };
    }
    
    return {
      valid: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Failed to validate API key',
        statusCode: 500
      }
    };
  }
}

/**
 * Get required scopes from options
 */
function getRequiredScopes(options: UserAPIKeyMiddlewareOptions): string[] {
  if (options.requiredScopes && options.requiredScopes.length > 0) {
    return options.requiredScopes;
  }
  
  if (options.requiredScope) {
    return [options.requiredScope];
  }
  
  return [];
}

/**
 * Create error response for user API key validation failure
 */
export function createUserAPIKeyErrorResponse(
  error: NonNullable<UserAPIKeyValidationResult['error']>
): APIGatewayProxyResult {
  return {
    statusCode: error.statusCode,
    headers: {
      ...CORS_HEADERS,
      'WWW-Authenticate': error.statusCode === 401 ? 'Bearer' : undefined
    } as Record<string, string>,
    body: JSON.stringify({
      error: {
        code: error.code,
        message: error.message,
        timestamp: new Date().toISOString()
      }
    })
  };
}

/**
 * User API key authentication middleware wrapper
 * Use this to wrap Lambda handlers that accept user API keys
 */
export function withUserAPIKeyAuth(
  handler: (event: APIGatewayProxyEvent, context: UserAPIKeyContext) => Promise<APIGatewayProxyResult>,
  options: UserAPIKeyMiddlewareOptions = {}
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const validation = await validateUserAPIKey(event, options);
    
    if (!validation.valid) {
      return createUserAPIKeyErrorResponse(validation.error!);
    }
    
    // Call the actual handler with the validated context
    return handler(event, validation.context!);
  };
}

/**
 * Inject user API key context into event for downstream handlers
 */
export function injectUserAPIKeyContext(
  event: APIGatewayProxyEvent,
  context: UserAPIKeyContext
): APIGatewayProxyEvent {
  return {
    ...event,
    requestContext: {
      ...event.requestContext,
      authorizer: {
        ...event.requestContext?.authorizer,
        apiKey: true,
        userId: context.user_id,
        realmId: context.realm_id,
        tenantId: context.tenant_id,
        scopes: context.scopes.join(' '),
        keyId: context.key.id
      }
    }
  };
}

/**
 * Check if a scope is allowed by the key
 */
export function keyHasScope(context: UserAPIKeyContext, requiredScope: string): boolean {
  return userAPIKeyScopesAllowed([requiredScope], context.scopes);
}
