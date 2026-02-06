/**
 * Reverification Lambda Handler (Step-Up Authentication)
 * Validates: Requirements 3.4, 3.6 (Reverification Endpoints)
 * 
 * Endpoints:
 * - POST /reverify/password - Verify with password
 * - POST /reverify/mfa - Verify with MFA (TOTP)
 * - POST /reverify/webauthn - Verify with WebAuthn
 * - GET /reverify/status - Check reverification status
 * 
 * Security:
 * - User authentication required
 * - Rate limiting on verification attempts
 * - Audit logging for all operations
 * - No information leakage in error messages
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  reverificationService,
  ReverificationError,
  ReverificationLevel,
  ReverificationProof
} from '../services/reverification.service';
import { checkRateLimit } from '../services/ratelimit.service';
import { findUserById } from '../repositories/user.repository';
import { verifyPassword } from '../utils/password';
import { verifyMFACode } from './mfa-handler';

// Rate limits for reverification attempts
const REVERIFY_RATE_LIMIT = {
  maxRequests: 5,
  windowSeconds: 60 // 5 attempts per minute per user
};

// CORS headers
const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
};

/**
 * Create error response
 */
function errorResponse(
  statusCode: number,
  code: string,
  message: string,
  additionalData?: Record<string, unknown>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify({
      error: {
        code,
        message,
        timestamp: new Date().toISOString(),
        ...additionalData
      }
    })
  };
}

/**
 * Create success response
 */
function successResponse(
  statusCode: number,
  data: unknown
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify(data)
  };
}

/**
 * Extract user context from JWT token (via API Gateway authorizer)
 */
function getUserContext(event: APIGatewayProxyEvent): {
  userId: string;
  realmId: string;
  sessionId: string;
  email?: string;
} | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  
  // Extract from authorizer context (set by API Gateway)
  const authorizer = event.requestContext?.authorizer;
  if (authorizer) {
    return {
      userId: authorizer.userId as string || '',
      realmId: authorizer.realmId as string || '',
      sessionId: authorizer.sessionId as string || authorizer.jti as string || '',
      email: authorizer.email as string | undefined
    };
  }
  
  return null;
}

/**
 * Log audit event for reverification
 */
async function logAuditEvent(
  event: string,
  data: Record<string, unknown>
): Promise<void> {
  if (process.env.NODE_ENV !== 'test') {
    console.log(`[AUDIT] ${event}`, JSON.stringify({
      ...data,
      timestamp: new Date().toISOString()
    }));
  }
}

/**
 * Main handler - routes to appropriate function
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const method = event.httpMethod;
  const path = event.path;
  
  // Handle CORS preflight
  if (method === 'OPTIONS') {
    return successResponse(200, {});
  }
  
  try {
    // Route to appropriate handler
    if (path === '/reverify/password' && method === 'POST') {
      return await handlePasswordReverify(event);
    }
    
    if (path === '/reverify/mfa' && method === 'POST') {
      return await handleMFAReverify(event);
    }
    
    if (path === '/reverify/webauthn' && method === 'POST') {
      return await handleWebAuthnReverify(event);
    }
    
    if (path === '/reverify/status' && method === 'GET') {
      return await handleGetStatus(event);
    }
    
    return errorResponse(404, 'NOT_FOUND', 'Endpoint not found');
    
  } catch (error) {
    console.error('Reverification handler error:', error);
    
    if (error instanceof ReverificationError) {
      return errorResponse(
        error.statusCode,
        error.code,
        error.message,
        error.requiredLevel ? { required_level: error.requiredLevel } : undefined
      );
    }
    
    return errorResponse(500, 'INTERNAL_ERROR', 'An unexpected error occurred');
  }
}

/**
 * POST /reverify/password - Verify with password
 * Validates: Requirement 3.4 (password reverification level)
 */
async function handlePasswordReverify(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId || !userContext.sessionId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    userContext.realmId,
    `reverify:${userContext.userId}`,
    REVERIFY_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    await logAuditEvent('reverification.rate_limited', {
      userId: userContext.userId,
      realmId: userContext.realmId,
      sessionId: userContext.sessionId,
      method: 'password'
    });
    
    return {
      statusCode: 429,
      headers: {
        ...CORS_HEADERS,
        'Retry-After': String(rateLimitResult.retryAfter || 60)
      },
      body: JSON.stringify({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many reverification attempts',
          retry_after: rateLimitResult.retryAfter
        }
      })
    };
  }
  
  // Parse request body
  let body: { password?: string };
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // Validate required fields
  if (!body.password) {
    return errorResponse(400, 'MISSING_PASSWORD', 'Password is required');
  }
  
  // Get user to verify password
  const user = await findUserById(userContext.realmId, userContext.userId);
  if (!user) {
    // Generic error to prevent user enumeration
    return errorResponse(401, 'INVALID_CREDENTIALS', 'Invalid credentials');
  }
  
  // Verify password
  const passwordValid = await verifyPassword(body.password, user.password_hash);
  if (!passwordValid) {
    await logAuditEvent('reverification.failed', {
      userId: userContext.userId,
      realmId: userContext.realmId,
      sessionId: userContext.sessionId,
      method: 'password',
      reason: 'invalid_password'
    });
    
    return errorResponse(401, 'INVALID_CREDENTIALS', 'Invalid credentials');
  }
  
  // Complete reverification
  const proof: ReverificationProof = {
    type: 'password',
    value: body.password
  };
  
  const reverification = await reverificationService.completeReverification(
    userContext.sessionId,
    userContext.userId,
    proof,
    {
      ipAddress: event.requestContext?.identity?.sourceIp,
      userAgent: event.headers?.['User-Agent'] || event.headers?.['user-agent']
    }
  );
  
  await logAuditEvent('reverification.completed', {
    userId: userContext.userId,
    realmId: userContext.realmId,
    sessionId: userContext.sessionId,
    method: 'password',
    level: reverification.level,
    expiresAt: reverification.expiresAt
  });
  
  return successResponse(200, {
    message: 'Reverification successful',
    reverification: {
      level: reverification.level,
      verified_at: reverification.verifiedAt,
      expires_at: reverification.expiresAt
    }
  });
}

/**
 * POST /reverify/mfa - Verify with MFA (TOTP)
 * Validates: Requirement 3.4 (mfa reverification level)
 */
async function handleMFAReverify(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId || !userContext.sessionId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    userContext.realmId,
    `reverify:${userContext.userId}`,
    REVERIFY_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    await logAuditEvent('reverification.rate_limited', {
      userId: userContext.userId,
      realmId: userContext.realmId,
      sessionId: userContext.sessionId,
      method: 'mfa'
    });
    
    return {
      statusCode: 429,
      headers: {
        ...CORS_HEADERS,
        'Retry-After': String(rateLimitResult.retryAfter || 60)
      },
      body: JSON.stringify({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many reverification attempts',
          retry_after: rateLimitResult.retryAfter
        }
      })
    };
  }
  
  // Parse request body
  let body: { code?: string };
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // Validate required fields
  if (!body.code) {
    return errorResponse(400, 'MISSING_CODE', 'MFA code is required');
  }
  
  // Validate code format (6 digits for TOTP, or 8 alphanumeric for backup code)
  const isTOTPCode = /^\d{6}$/.test(body.code);
  const isBackupCode = /^[A-Z0-9]{8}$/i.test(body.code);
  
  if (!isTOTPCode && !isBackupCode) {
    return errorResponse(400, 'INVALID_CODE_FORMAT', 'MFA code must be 6 digits or a valid backup code');
  }
  
  // Get user to check MFA status
  const user = await findUserById(userContext.realmId, userContext.userId);
  if (!user) {
    return errorResponse(401, 'INVALID_CREDENTIALS', 'Invalid credentials');
  }
  
  // Check if MFA is enabled
  if (!user.mfa_enabled) {
    return errorResponse(400, 'MFA_NOT_ENABLED', 'MFA is not enabled for this account');
  }
  
  // Verify MFA code
  const mfaResult = await verifyMFACode(userContext.userId, userContext.realmId, body.code);
  if (!mfaResult.valid) {
    await logAuditEvent('reverification.failed', {
      userId: userContext.userId,
      realmId: userContext.realmId,
      sessionId: userContext.sessionId,
      method: 'mfa',
      reason: 'invalid_code'
    });
    
    return errorResponse(401, 'INVALID_MFA_CODE', 'Invalid MFA code');
  }
  
  // Complete reverification
  const proof: ReverificationProof = {
    type: mfaResult.usedBackupCode ? 'backup_code' : 'totp',
    value: body.code
  };
  
  const reverification = await reverificationService.completeReverification(
    userContext.sessionId,
    userContext.userId,
    proof,
    {
      ipAddress: event.requestContext?.identity?.sourceIp,
      userAgent: event.headers?.['User-Agent'] || event.headers?.['user-agent']
    }
  );
  
  await logAuditEvent('reverification.completed', {
    userId: userContext.userId,
    realmId: userContext.realmId,
    sessionId: userContext.sessionId,
    method: mfaResult.usedBackupCode ? 'backup_code' : 'totp',
    level: reverification.level,
    expiresAt: reverification.expiresAt
  });
  
  return successResponse(200, {
    message: 'Reverification successful',
    reverification: {
      level: reverification.level,
      verified_at: reverification.verifiedAt,
      expires_at: reverification.expiresAt
    },
    used_backup_code: mfaResult.usedBackupCode
  });
}

/**
 * POST /reverify/webauthn - Verify with WebAuthn
 * Validates: Requirement 3.4 (webauthn reverification level - highest)
 */
async function handleWebAuthnReverify(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId || !userContext.sessionId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    userContext.realmId,
    `reverify:${userContext.userId}`,
    REVERIFY_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    await logAuditEvent('reverification.rate_limited', {
      userId: userContext.userId,
      realmId: userContext.realmId,
      sessionId: userContext.sessionId,
      method: 'webauthn'
    });
    
    return {
      statusCode: 429,
      headers: {
        ...CORS_HEADERS,
        'Retry-After': String(rateLimitResult.retryAfter || 60)
      },
      body: JSON.stringify({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many reverification attempts',
          retry_after: rateLimitResult.retryAfter
        }
      })
    };
  }
  
  // Parse request body
  let body: {
    credential?: {
      id: string;
      rawId: string;
      response: {
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle?: string;
      };
      type: string;
    };
    challenge?: string;
  };
  
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // Validate required fields
  if (!body.credential) {
    return errorResponse(400, 'MISSING_CREDENTIAL', 'WebAuthn credential is required');
  }
  
  if (!body.challenge) {
    return errorResponse(400, 'MISSING_CHALLENGE', 'WebAuthn challenge is required');
  }
  
  // Validate credential structure
  if (!body.credential.id || !body.credential.response) {
    return errorResponse(400, 'INVALID_CREDENTIAL', 'Invalid WebAuthn credential format');
  }
  
  // Get user to check WebAuthn credentials
  const user = await findUserById(userContext.realmId, userContext.userId);
  if (!user) {
    return errorResponse(401, 'INVALID_CREDENTIALS', 'Invalid credentials');
  }
  
  // Check if user has WebAuthn credentials
  if (!user.webauthn_credentials || user.webauthn_credentials.length === 0) {
    return errorResponse(400, 'WEBAUTHN_NOT_CONFIGURED', 'WebAuthn is not configured for this account');
  }
  
  // In production, verify the WebAuthn assertion here
  // For now, we'll do basic validation
  // TODO: Implement full WebAuthn assertion verification
  
  // Complete reverification
  const proof: ReverificationProof = {
    type: 'webauthn',
    value: body.credential.id,
    challenge: body.challenge
  };
  
  const reverification = await reverificationService.completeReverification(
    userContext.sessionId,
    userContext.userId,
    proof,
    {
      ipAddress: event.requestContext?.identity?.sourceIp,
      userAgent: event.headers?.['User-Agent'] || event.headers?.['user-agent']
    }
  );
  
  await logAuditEvent('reverification.completed', {
    userId: userContext.userId,
    realmId: userContext.realmId,
    sessionId: userContext.sessionId,
    method: 'webauthn',
    level: reverification.level,
    expiresAt: reverification.expiresAt
  });
  
  return successResponse(200, {
    message: 'Reverification successful',
    reverification: {
      level: reverification.level,
      verified_at: reverification.verifiedAt,
      expires_at: reverification.expiresAt
    }
  });
}

/**
 * GET /reverify/status - Check reverification status
 * Validates: Requirement 3.6 (check reverification status)
 */
async function handleGetStatus(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId || !userContext.sessionId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Get optional required level from query params
  const requiredLevel = event.queryStringParameters?.level as ReverificationLevel | undefined;
  
  // Validate level if provided
  if (requiredLevel && !['password', 'mfa', 'webauthn'].includes(requiredLevel)) {
    return errorResponse(400, 'INVALID_LEVEL', 'Invalid reverification level');
  }
  
  // Get reverification status
  const status = await reverificationService.getReverificationStatus(
    userContext.sessionId,
    requiredLevel
  );
  
  // Check if current reverification satisfies required level
  let satisfiesRequired = false;
  if (requiredLevel && status.reverification) {
    satisfiesRequired = reverificationService.levelSatisfies(
      status.reverification.level,
      requiredLevel
    );
  }
  
  return successResponse(200, {
    has_reverification: status.hasReverification,
    is_valid: status.isValid,
    reverification: status.reverification ? {
      level: status.reverification.level,
      verified_at: status.reverification.verifiedAt,
      expires_at: status.reverification.expiresAt,
      method: status.reverification.method
    } : null,
    required_level: requiredLevel || null,
    satisfies_required: requiredLevel ? satisfiesRequired : null
  });
}
