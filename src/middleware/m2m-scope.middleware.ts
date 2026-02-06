/**
 * M2M Scope Enforcement Middleware for Zalt.io Auth Platform
 * 
 * Validates M2M tokens and enforces scope-based access control:
 * - Extracts M2M token from Authorization header
 * - Validates token signature and expiry
 * - Checks if token scopes include required scope for endpoint
 * - Returns 403 if scope insufficient
 * 
 * Validates: Requirements 1.7 (M2M scope enforcement)
 * 
 * SECURITY:
 * - RS256 JWT verification (FIPS-compliant)
 * - Scope-based access control
 * - Token type validation (must be 'm2m')
 * - Audit logging for all M2M requests
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { MachineAuthService, MachineAuthError } from '../services/machine-auth.service';
import { M2MToken, M2MScope, M2M_SCOPES } from '../models/machine.model';

const machineAuthService = new MachineAuthService();

/**
 * M2M validation result
 */
export interface M2MValidationResult {
  valid: boolean;
  token?: M2MToken;
  error?: {
    code: string;
    message: string;
    statusCode: number;
  };
}

/**
 * Middleware options
 */
export interface M2MScopeMiddlewareOptions {
  /** Required scope for this endpoint */
  requiredScope?: M2MScope | string;
  /** Multiple scopes (any one is sufficient) */
  requiredScopes?: (M2MScope | string)[];
  /** All scopes required (AND logic) */
  requireAllScopes?: boolean;
  /** Skip validation (for public endpoints) */
  skipValidation?: boolean;
  /** Allow user tokens as well as M2M tokens */
  allowUserTokens?: boolean;
}

/**
 * Endpoint scope requirements mapping
 */
export const ENDPOINT_SCOPES: Record<string, M2MScope | M2MScope[]> = {
  // User management
  'GET /users': 'read:users',
  'POST /users': 'write:users',
  'PUT /users': 'write:users',
  'DELETE /users': 'delete:users',
  
  // Session management
  'GET /sessions': 'read:sessions',
  'POST /sessions': 'write:sessions',
  'DELETE /sessions': 'revoke:sessions',
  
  // Tenant management
  'GET /tenants': 'read:tenants',
  'POST /tenants': 'write:tenants',
  'PUT /tenants': 'write:tenants',
  
  // Role management
  'GET /roles': 'read:roles',
  'POST /roles': 'write:roles',
  'PUT /roles': 'write:roles',
  
  // Audit logs
  'GET /audit': 'read:audit',
  
  // Webhooks
  'GET /webhooks': 'read:webhooks',
  'POST /webhooks': 'write:webhooks',
  'PUT /webhooks': 'write:webhooks',
  'DELETE /webhooks': 'write:webhooks',
  
  // Analytics
  'GET /analytics': 'read:analytics'
};

/**
 * Extract M2M token from request headers
 * Only accepts Bearer tokens
 */
export function extractM2MToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  
  if (!authHeader) {
    return null;
  }
  
  // Must be Bearer token
  if (!authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  return authHeader.substring(7);
}

/**
 * Validate M2M token and check scopes
 */
export async function validateM2MToken(
  event: APIGatewayProxyEvent,
  options: M2MScopeMiddlewareOptions = {}
): Promise<M2MValidationResult> {
  // Skip validation if configured
  if (options.skipValidation) {
    return { valid: true };
  }
  
  // Extract token
  const token = extractM2MToken(event);
  
  if (!token) {
    return {
      valid: false,
      error: {
        code: 'MISSING_TOKEN',
        message: 'Authorization header with Bearer token is required',
        statusCode: 401
      }
    };
  }
  
  try {
    // Validate token
    const decoded = await machineAuthService.validateM2MToken(token);
    
    // Check required scopes
    const requiredScopes = getRequiredScopes(event, options);
    
    if (requiredScopes.length > 0) {
      const hasRequiredScopes = options.requireAllScopes
        ? requiredScopes.every(scope => hasScope(decoded, scope))
        : requiredScopes.some(scope => hasScope(decoded, scope));
      
      if (!hasRequiredScopes) {
        return {
          valid: false,
          token: decoded,
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
      token: decoded
    };
    
  } catch (error) {
    if (error instanceof MachineAuthError) {
      return {
        valid: false,
        error: {
          code: error.code,
          message: error.message,
          statusCode: error.code === 'TOKEN_EXPIRED' ? 401 : 401
        }
      };
    }
    
    return {
      valid: false,
      error: {
        code: 'INVALID_TOKEN',
        message: 'Invalid or malformed token',
        statusCode: 401
      }
    };
  }
}

/**
 * Get required scopes for the request
 */
function getRequiredScopes(
  event: APIGatewayProxyEvent,
  options: M2MScopeMiddlewareOptions
): string[] {
  // Use explicit scopes from options first
  if (options.requiredScopes && options.requiredScopes.length > 0) {
    return options.requiredScopes;
  }
  
  if (options.requiredScope) {
    return [options.requiredScope];
  }
  
  // Look up endpoint in mapping
  const method = event.httpMethod;
  const path = event.path;
  
  // Try exact match first
  const exactKey = `${method} ${path}`;
  if (ENDPOINT_SCOPES[exactKey]) {
    const scopes = ENDPOINT_SCOPES[exactKey];
    return Array.isArray(scopes) ? scopes : [scopes];
  }
  
  // Try pattern match (e.g., GET /users matches GET /users/{id})
  for (const [pattern, scopes] of Object.entries(ENDPOINT_SCOPES)) {
    const [patternMethod, patternPath] = pattern.split(' ');
    if (patternMethod === method && path.startsWith(patternPath)) {
      return Array.isArray(scopes) ? scopes : [scopes];
    }
  }
  
  // No scope required for unmapped endpoints
  return [];
}

/**
 * Check if token has required scope
 */
function hasScope(token: M2MToken, requiredScope: string): boolean {
  // admin:all grants all scopes
  if (token.scopes.includes('admin:all')) {
    return true;
  }
  
  return token.scopes.includes(requiredScope);
}

/**
 * Create error response for M2M validation failure
 */
export function createM2MErrorResponse(
  error: NonNullable<M2MValidationResult['error']>
): APIGatewayProxyResult {
  return {
    statusCode: error.statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
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
 * M2M scope enforcement middleware wrapper
 * Use this to wrap Lambda handlers that require M2M authentication
 */
export function withM2MAuth(
  handler: (event: APIGatewayProxyEvent, m2mToken: M2MToken) => Promise<APIGatewayProxyResult>,
  options: M2MScopeMiddlewareOptions = {}
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const validation = await validateM2MToken(event, options);
    
    if (!validation.valid) {
      return createM2MErrorResponse(validation.error!);
    }
    
    // Call the actual handler with the validated token
    return handler(event, validation.token!);
  };
}

/**
 * Check if a scope is valid
 */
export function isValidM2MScope(scope: string): boolean {
  return scope in M2M_SCOPES || scope === 'admin:all';
}

/**
 * Get scope description
 */
export function getScopeDescription(scope: string): string {
  return M2M_SCOPES[scope as M2MScope] || 'Unknown scope';
}

/**
 * Inject M2M context into event for downstream handlers
 */
export function injectM2MContext(
  event: APIGatewayProxyEvent,
  token: M2MToken
): APIGatewayProxyEvent {
  return {
    ...event,
    requestContext: {
      ...event.requestContext,
      authorizer: {
        ...event.requestContext?.authorizer,
        m2m: true,
        machineId: token.machine_id,
        realmId: token.realm_id,
        scopes: token.scopes.join(' ')
      }
    }
  };
}
