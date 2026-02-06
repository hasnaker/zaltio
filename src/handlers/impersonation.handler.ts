/**
 * Impersonation Handler - Admin User Impersonation API
 * Task 11.3: Impersonation Handler (Lambda)
 * 
 * Endpoints:
 * - POST /admin/users/{id}/impersonate - Start impersonation
 * - POST /impersonation/end - End impersonation
 * - GET /impersonation/status - Check impersonation status
 * 
 * SECURITY: All impersonation endpoints require admin authentication
 * AUDIT: All actions are logged for compliance (HIPAA/GDPR)
 * 
 * Validates: Requirements 6.1, 6.9 (User Impersonation)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  ImpersonationService,
  ImpersonationError,
  ImpersonationResponse
} from '../services/impersonation.service';
import { verifyAccessToken } from '../utils/jwt';
import { checkRateLimit, RateLimitEndpoint } from '../services/ratelimit.service';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';
import { findUserById } from '../repositories/user.repository';

// Service instance
const impersonationService = new ImpersonationService();

/**
 * Response helper with security headers
 */
const response = (statusCode: number, body: unknown): APIGatewayProxyResult => ({
  statusCode,
  headers: {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store, no-cache, must-revalidate'
  },
  body: JSON.stringify(body)
});

/**
 * Extract and validate admin token
 */
async function validateAdminAuth(event: APIGatewayProxyEvent): Promise<{
  valid: boolean;
  userId?: string;
  email?: string;
  realmId?: string;
  isAdmin?: boolean;
  hasImpersonatePermission?: boolean;
  error?: string;
}> {
  const authHeader = event.headers.Authorization || event.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return { valid: false, error: 'Missing or invalid authorization header' };
  }

  const token = authHeader.substring(7);
  
  try {
    const payload = await verifyAccessToken(token);
    
    // Check if user has admin role
    const isAdmin = payload.is_admin === true;
    
    if (!isAdmin) {
      return { valid: false, error: 'Admin privileges required' };
    }

    // Check for impersonation permission (can be in permissions array or specific flag)
    const permissions = payload.permissions;
    const extendedPayload = payload as unknown as Record<string, unknown>;
    const hasImpersonatePermission = 
      extendedPayload.can_impersonate === true || 
      permissions?.includes('impersonate') ||
      permissions?.includes('admin:impersonate') ||
      isAdmin; // Admins have impersonation by default

    return {
      valid: true,
      userId: payload.sub,
      email: payload.email as string,
      realmId: payload.realm_id,
      isAdmin: true,
      hasImpersonatePermission
    };
  } catch {
    return { valid: false, error: 'Invalid or expired token' };
  }
}

/**
 * Extract impersonation session from token
 */
async function validateImpersonationToken(event: APIGatewayProxyEvent): Promise<{
  valid: boolean;
  sessionId?: string;
  adminId?: string;
  targetUserId?: string;
  realmId?: string;
  error?: string;
}> {
  const authHeader = event.headers.Authorization || event.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return { valid: false, error: 'Missing or invalid authorization header' };
  }

  const token = authHeader.substring(7);
  
  try {
    // First try to validate as impersonation token
    const session = await impersonationService.validateToken(token);
    
    if (session) {
      return {
        valid: true,
        sessionId: session.id,
        adminId: session.admin_id,
        targetUserId: session.target_user_id,
        realmId: session.realm_id
      };
    }
    
    // If not an impersonation token, try regular JWT
    const payload = await verifyAccessToken(token);
    
    // Check if JWT has impersonation claims
    const extendedPayload = payload as unknown as Record<string, unknown>;
    if (extendedPayload.is_impersonation === true) {
      return {
        valid: true,
        sessionId: extendedPayload.impersonation_session_id as string,
        adminId: extendedPayload.admin_id as string,
        targetUserId: payload.sub,
        realmId: payload.realm_id
      };
    }
    
    return { valid: false, error: 'Not an impersonation session' };
  } catch {
    return { valid: false, error: 'Invalid or expired token' };
  }
}

// ============================================================================
// IMPERSONATION HANDLERS
// ============================================================================

/**
 * POST /admin/users/{id}/impersonate - Start impersonation
 */
export async function startImpersonationHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userAgent = event.headers['User-Agent'] || event.headers['user-agent'] || 'unknown';
  const targetUserId = event.pathParameters?.id;

  if (!targetUserId) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'User ID is required' }
    });
  }

  // Validate admin auth
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Check impersonation permission
  if (!auth.hasImpersonatePermission) {
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'impersonation_denied',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.FAILURE,
      details: { 
        target_user: targetUserId,
        reason: 'Missing impersonation permission'
      }
    });

    return response(403, {
      error: { code: 'FORBIDDEN', message: 'Impersonation permission required' }
    });
  }

  // Rate limiting - strict for impersonation
  const rateLimitResult = await checkRateLimit(
    auth.realmId!,
    `${RateLimitEndpoint.API_GENERAL}:impersonate:${clientIp}`
  );

  if (!rateLimitResult.allowed) {
    return response(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many impersonation requests',
        retry_after: rateLimitResult.retryAfter
      }
    });
  }

  // Parse body
  let body: {
    reason: string;
    duration_minutes?: number;
    metadata?: {
      ticket_id?: string;
      case_id?: string;
      notes?: string;
    };
  };

  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return response(400, {
      error: { code: 'INVALID_JSON', message: 'Invalid JSON body' }
    });
  }

  // Validate reason
  if (!body.reason) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'Reason is required for impersonation' }
    });
  }

  try {
    // Get target user details
    const targetUser = await findUserById(auth.realmId!, targetUserId);
    
    if (!targetUser) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Check if target is admin (cannot impersonate admins)
    // Admin status can be determined by roles or explicit flag
    const userWithRoles = targetUser as typeof targetUser & { 
      is_admin?: boolean; 
      roles?: string[];
    };
    const isTargetAdmin = userWithRoles.is_admin === true || 
      userWithRoles.roles?.some(r => ['admin', 'owner', 'super_admin'].includes(r.toLowerCase()));
    
    if (isTargetAdmin) {
      await logAuditEvent({
        eventType: AuditEventType.ADMIN_ACTION,
        action: 'impersonation_denied',
        userId: auth.userId!,
        realmId: auth.realmId!,
        ipAddress: clientIp,
        result: AuditResult.FAILURE,
        details: { 
          target_user: targetUserId,
          reason: 'Cannot impersonate admin users'
        }
      });

      return response(403, {
        error: { code: 'CANNOT_IMPERSONATE', message: 'Cannot impersonate admin users' }
      });
    }

    // Start impersonation
    const result = await impersonationService.startImpersonation({
      realm_id: auth.realmId!,
      admin_id: auth.userId!,
      admin_email: auth.email!,
      target_user_id: targetUserId,
      target_user_email: targetUser.email,
      reason: body.reason,
      duration_minutes: body.duration_minutes,
      ip_address: clientIp,
      user_agent: userAgent,
      metadata: body.metadata
    });

    // Audit log - success
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'impersonation_started',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: {
        impersonation_session_id: result.session.id,
        target_user: targetUserId,
        target_email: targetUser.email,
        reason: body.reason,
        duration_minutes: body.duration_minutes,
        metadata: body.metadata
      }
    });

    return response(200, {
      data: {
        session: result.session,
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        expires_in: result.expires_in,
        message: 'Impersonation session started'
      }
    });
  } catch (error) {
    if (error instanceof ImpersonationError) {
      await logAuditEvent({
        eventType: AuditEventType.ADMIN_ACTION,
        action: 'impersonation_failed',
        userId: auth.userId!,
        realmId: auth.realmId!,
        ipAddress: clientIp,
        result: AuditResult.FAILURE,
        details: {
          target_user: targetUserId,
          error_code: error.code,
          error_message: error.message
        }
      });

      return response(error.statusCode, {
        error: { code: error.code, message: error.message }
      });
    }

    console.error('Start impersonation error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to start impersonation' }
    });
  }
}

/**
 * POST /impersonation/end - End impersonation
 */
export async function endImpersonationHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';

  // Validate impersonation token
  const impersonation = await validateImpersonationToken(event);
  
  // Also try admin auth (admin can end any impersonation)
  const adminAuth = await validateAdminAuth(event);

  // Parse body for session_id if admin is ending someone else's session
  let sessionId: string | undefined;
  
  if (event.body) {
    try {
      const body = JSON.parse(event.body);
      sessionId = body.session_id;
    } catch {
      // Ignore parse errors
    }
  }

  // Determine which session to end
  let targetSessionId: string;
  let endedBy: string;
  let endReason: string | undefined;

  if (impersonation.valid && !sessionId) {
    // User is ending their own impersonation session
    targetSessionId = impersonation.sessionId!;
    endedBy = impersonation.adminId!;
    endReason = 'User ended session';
  } else if (adminAuth.valid && sessionId) {
    // Admin is ending a specific session
    targetSessionId = sessionId;
    endedBy = adminAuth.userId!;
    endReason = 'Admin terminated session';
  } else if (adminAuth.valid && impersonation.valid) {
    // Admin ending their own impersonation
    targetSessionId = impersonation.sessionId!;
    endedBy = adminAuth.userId!;
    endReason = 'Admin ended session';
  } else {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: 'Valid impersonation or admin token required' }
    });
  }

  // Rate limiting
  const realmId = impersonation.realmId || adminAuth.realmId || 'unknown';
  const rateLimitResult = await checkRateLimit(
    realmId,
    `${RateLimitEndpoint.API_GENERAL}:${clientIp}`
  );

  if (!rateLimitResult.allowed) {
    return response(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        retry_after: rateLimitResult.retryAfter
      }
    });
  }

  try {
    const result = await impersonationService.endImpersonation({
      session_id: targetSessionId,
      ended_by: endedBy,
      end_reason: endReason
    });

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'impersonation_ended',
      userId: endedBy,
      realmId: realmId,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: {
        impersonation_session_id: targetSessionId,
        target_user: result.target_user_id,
        end_reason: endReason
      }
    });

    return response(200, {
      data: {
        session: result,
        message: 'Impersonation session ended'
      }
    });
  } catch (error) {
    if (error instanceof ImpersonationError) {
      return response(error.statusCode, {
        error: { code: error.code, message: error.message }
      });
    }

    console.error('End impersonation error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to end impersonation' }
    });
  }
}

/**
 * GET /impersonation/status - Check impersonation status
 */
export async function getImpersonationStatusHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';

  // Try impersonation token first
  const impersonation = await validateImpersonationToken(event);
  
  // Also accept admin token with session_id query param
  const adminAuth = await validateAdminAuth(event);
  const querySessionId = event.queryStringParameters?.session_id;

  let sessionId: string | undefined;
  let realmId: string;

  if (impersonation.valid) {
    sessionId = impersonation.sessionId;
    realmId = impersonation.realmId!;
  } else if (adminAuth.valid && querySessionId) {
    sessionId = querySessionId;
    realmId = adminAuth.realmId!;
  } else if (adminAuth.valid) {
    // Admin checking their own active impersonation
    const activeSession = await impersonationService.getActiveSessionByAdmin(adminAuth.userId!);
    if (activeSession) {
      sessionId = activeSession.id;
    }
    realmId = adminAuth.realmId!;
  } else {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: 'Valid token required' }
    });
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    realmId,
    `${RateLimitEndpoint.API_GENERAL}:${clientIp}`
  );

  if (!rateLimitResult.allowed) {
    return response(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        retry_after: rateLimitResult.retryAfter
      }
    });
  }

  try {
    if (!sessionId) {
      return response(200, {
        data: {
          is_impersonating: false
        }
      });
    }

    const status = await impersonationService.getStatus(sessionId);

    return response(200, {
      data: status
    });
  } catch (error) {
    console.error('Get impersonation status error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to get impersonation status' }
    });
  }
}

/**
 * Main router for impersonation endpoints
 */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const method = event.httpMethod;
  const path = event.path;

  // Route to appropriate handler
  if (method === 'POST' && path.match(/\/admin\/users\/[^/]+\/impersonate$/)) {
    return startImpersonationHandler(event);
  }
  
  if (method === 'POST' && path === '/impersonation/end') {
    return endImpersonationHandler(event);
  }
  
  if (method === 'GET' && path === '/impersonation/status') {
    return getImpersonationStatusHandler(event);
  }

  return response(404, {
    error: { code: 'NOT_FOUND', message: 'Endpoint not found' }
  });
}
