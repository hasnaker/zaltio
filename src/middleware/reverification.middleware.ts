/**
 * Reverification Middleware for Zalt.io Auth Platform
 * 
 * Enforces step-up authentication for sensitive operations:
 * - Checks endpoint reverification requirements
 * - Returns 403 REVERIFICATION_REQUIRED if not verified
 * - Includes required level in response
 * 
 * Validates: Requirements 3.1, 3.2 (Reverification)
 * 
 * SECURITY:
 * - Reverification expires after configured time
 * - Higher levels satisfy lower level requirements
 * - Audit logging for all reverification checks
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  ReverificationLevel,
  ReverificationConfig,
  ReverificationRequirement,
  DEFAULT_REVERIFICATION_REQUIREMENTS,
  findReverificationRequirement,
  DEFAULT_REVERIFICATION_VALIDITY
} from '../models/reverification.model';
import { ReverificationService, reverificationService } from '../services/reverification.service';

/**
 * Reverification validation result
 */
export interface ReverificationValidationResult {
  valid: boolean;
  requiresReverification: boolean;
  requiredLevel?: ReverificationLevel;
  validityMinutes?: number;
  error?: {
    code: string;
    message: string;
    statusCode: number;
    requiredLevel?: ReverificationLevel;
    validityMinutes?: number;
  };
}

/**
 * Middleware options
 */
export interface ReverificationMiddlewareOptions {
  /** Override required level for this endpoint */
  requiredLevel?: ReverificationLevel;
  /** Override validity period in minutes */
  validityMinutes?: number;
  /** Skip reverification check */
  skipReverification?: boolean;
  /** Custom reverification requirements */
  customRequirements?: ReverificationRequirement[];
  /** Service instance (for testing) */
  service?: ReverificationService;
}

/**
 * Extract session ID from request
 * Supports multiple sources:
 * - X-Session-Id header
 * - Authorization header (JWT sub claim)
 * - Cookie (zalt_session)
 */
export function extractSessionId(event: APIGatewayProxyEvent): string | null {
  // Check X-Session-Id header first (preferred)
  const sessionHeader = event.headers?.['X-Session-Id'] || event.headers?.['x-session-id'];
  if (sessionHeader) {
    return sessionHeader;
  }
  
  // Check authorizer context (from JWT validation)
  const authorizerSessionId = event.requestContext?.authorizer?.sessionId;
  if (authorizerSessionId) {
    return authorizerSessionId;
  }
  
  // Check cookie
  const cookieHeader = event.headers?.Cookie || event.headers?.cookie;
  if (cookieHeader) {
    const cookies = parseCookies(cookieHeader);
    if (cookies.zalt_session) {
      return cookies.zalt_session;
    }
  }
  
  return null;
}

/**
 * Parse cookies from header
 */
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  
  cookieHeader.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name && rest.length > 0) {
      cookies[name] = rest.join('=');
    }
  });
  
  return cookies;
}

/**
 * Get endpoint path from event
 * Normalizes path for matching against requirements
 */
export function getEndpointPath(event: APIGatewayProxyEvent): string {
  // Use resource path if available (contains path parameters)
  const path = event.resource || event.path || '';
  
  // Normalize path (remove trailing slash, ensure leading slash)
  let normalized = path.replace(/\/+$/, '');
  if (!normalized.startsWith('/')) {
    normalized = '/' + normalized;
  }
  
  return normalized;
}

/**
 * Check if endpoint requires reverification
 */
export function checkEndpointRequirement(
  event: APIGatewayProxyEvent,
  options: ReverificationMiddlewareOptions = {}
): ReverificationConfig | null {
  // If explicit level is provided, use it
  if (options.requiredLevel) {
    return {
      level: options.requiredLevel,
      validityMinutes: options.validityMinutes || DEFAULT_REVERIFICATION_VALIDITY[options.requiredLevel]
    };
  }
  
  // Look up endpoint in requirements
  const endpoint = getEndpointPath(event);
  const method = event.httpMethod;
  
  const requirement = findReverificationRequirement(
    endpoint,
    method,
    options.customRequirements
  );
  
  if (!requirement) {
    return null;
  }
  
  return {
    level: requirement.level,
    validityMinutes: requirement.validityMinutes || DEFAULT_REVERIFICATION_VALIDITY[requirement.level]
  };
}

/**
 * Validate reverification status for a request
 */
export async function validateReverification(
  event: APIGatewayProxyEvent,
  options: ReverificationMiddlewareOptions = {}
): Promise<ReverificationValidationResult> {
  // Skip if configured
  if (options.skipReverification) {
    return { valid: true, requiresReverification: false };
  }
  
  // Check if endpoint requires reverification
  const requirement = checkEndpointRequirement(event, options);
  
  if (!requirement) {
    // No reverification required for this endpoint
    return { valid: true, requiresReverification: false };
  }
  
  // Extract session ID
  const sessionId = extractSessionId(event);
  
  if (!sessionId) {
    return {
      valid: false,
      requiresReverification: true,
      requiredLevel: requirement.level,
      validityMinutes: requirement.validityMinutes,
      error: {
        code: 'SESSION_REQUIRED',
        message: 'Valid session is required for this operation',
        statusCode: 401
      }
    };
  }
  
  // Check reverification status
  const service = options.service || reverificationService;
  const isVerified = await service.checkReverification(sessionId, requirement.level);
  
  if (!isVerified) {
    // Log the reverification requirement
    logAuditEvent('reverification.required', {
      sessionId,
      endpoint: getEndpointPath(event),
      method: event.httpMethod,
      requiredLevel: requirement.level,
      ip: getClientIP(event)
    });
    
    return {
      valid: false,
      requiresReverification: true,
      requiredLevel: requirement.level,
      validityMinutes: requirement.validityMinutes,
      error: {
        code: 'REVERIFICATION_REQUIRED',
        message: `This operation requires ${requirement.level} reverification`,
        statusCode: 403,
        requiredLevel: requirement.level,
        validityMinutes: requirement.validityMinutes
      }
    };
  }
  
  // Log successful reverification check
  logAuditEvent('reverification.validated', {
    sessionId,
    endpoint: getEndpointPath(event),
    method: event.httpMethod,
    level: requirement.level,
    ip: getClientIP(event)
  });
  
  return {
    valid: true,
    requiresReverification: true,
    requiredLevel: requirement.level,
    validityMinutes: requirement.validityMinutes
  };
}

/**
 * Create error response for reverification requirement
 */
export function createReverificationErrorResponse(
  error: NonNullable<ReverificationValidationResult['error']>,
  requestId?: string
): APIGatewayProxyResult {
  const body: Record<string, unknown> = {
    error: {
      code: error.code,
      message: error.message,
      timestamp: new Date().toISOString(),
      request_id: requestId
    }
  };
  
  // Include reverification details for REVERIFICATION_REQUIRED
  if (error.code === 'REVERIFICATION_REQUIRED') {
    body.reverification = {
      required: true,
      level: error.requiredLevel,
      validityMinutes: error.validityMinutes,
      endpoints: {
        password: '/reverify/password',
        mfa: '/reverify/mfa',
        webauthn: '/reverify/webauthn'
      }
    };
  }
  
  return {
    statusCode: error.statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Session-Id',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-Reverification-Required': error.code === 'REVERIFICATION_REQUIRED' ? 'true' : 'false',
      'X-Reverification-Level': error.requiredLevel || ''
    },
    body: JSON.stringify(body)
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
 * Log audit event
 */
function logAuditEvent(
  event: string,
  data: Record<string, unknown>
): void {
  if (process.env.NODE_ENV !== 'test') {
    console.log(`[AUDIT] ${event}`, JSON.stringify({
      ...data,
      timestamp: new Date().toISOString()
    }));
  }
}

/**
 * Reverification middleware wrapper
 * Use this to wrap Lambda handlers that require reverification
 * 
 * Usage:
 * ```typescript
 * export const handler = withReverification(
 *   async (event) => {
 *     // Handler logic
 *   },
 *   { requiredLevel: 'password' }
 * );
 * ```
 */
export function withReverification(
  handler: (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>,
  options: ReverificationMiddlewareOptions = {}
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const validation = await validateReverification(event, options);
    
    if (!validation.valid) {
      return createReverificationErrorResponse(
        validation.error!,
        event.requestContext?.requestId
      );
    }
    
    // Call the actual handler
    return handler(event);
  };
}

/**
 * Middleware for checking reverification inline
 * Returns validation result for manual handling
 * 
 * Usage:
 * ```typescript
 * export async function handler(event: APIGatewayProxyEvent) {
 *   const reverification = await reverificationMiddleware(event, { requiredLevel: 'mfa' });
 *   if (!reverification.valid) {
 *     return reverification.response!;
 *   }
 *   
 *   // Continue with handler logic
 * }
 * ```
 */
export async function reverificationMiddleware(
  event: APIGatewayProxyEvent,
  options: ReverificationMiddlewareOptions = {}
): Promise<{
  valid: boolean;
  requiresReverification: boolean;
  requiredLevel?: ReverificationLevel;
  response?: APIGatewayProxyResult;
}> {
  const validation = await validateReverification(event, options);
  
  if (!validation.valid) {
    return {
      valid: false,
      requiresReverification: validation.requiresReverification,
      requiredLevel: validation.requiredLevel,
      response: createReverificationErrorResponse(
        validation.error!,
        event.requestContext?.requestId
      )
    };
  }
  
  return {
    valid: true,
    requiresReverification: validation.requiresReverification,
    requiredLevel: validation.requiredLevel
  };
}

/**
 * Require specific reverification level
 * Convenience wrapper for common use cases
 */
export function requireReverification(
  level: ReverificationLevel,
  handler: (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return withReverification(handler, { requiredLevel: level });
}

/**
 * Require password reverification
 */
export function requirePasswordReverification(
  handler: (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return requireReverification('password', handler);
}

/**
 * Require MFA reverification
 */
export function requireMFAReverification(
  handler: (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return requireReverification('mfa', handler);
}

/**
 * Require WebAuthn reverification
 */
export function requireWebAuthnReverification(
  handler: (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return requireReverification('webauthn', handler);
}

/**
 * Check if response indicates reverification is required
 * Useful for SDK to detect and handle reverification
 */
export function isReverificationRequired(response: APIGatewayProxyResult): boolean {
  return response.statusCode === 403 &&
         response.headers?.['X-Reverification-Required'] === 'true';
}

/**
 * Extract reverification details from error response
 */
export function extractReverificationDetails(response: APIGatewayProxyResult): {
  required: boolean;
  level?: ReverificationLevel;
  validityMinutes?: number;
} | null {
  if (!isReverificationRequired(response)) {
    return null;
  }
  
  try {
    const body = JSON.parse(response.body);
    return body.reverification || null;
  } catch {
    return null;
  }
}
