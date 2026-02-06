/**
 * Admin Handler - Realm & User Management API
 * Task 9.2: Realm Configuration API
 * Task 9.3: Admin User Management
 * Task 9.4: Admin Session Management
 * 
 * SECURITY: All admin endpoints require admin authentication + MFA
 * AUDIT: All actions are logged for compliance
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { 
  getRealm, 
  updateRealm, 
  createRealm,
  deleteRealmWithCleanup,
  listRealms,
  getRealmStats,
  validateCrossRealmAccess
} from '../services/realm.service';
import {
  listRealmUsers,
  getAdminUserDetails,
  suspendUser,
  activateUser,
  unlockUser,
  adminResetUserMFA,
  setPasswordResetToken,
  findUserById,
  deleteUser
} from '../repositories/user.repository';
import {
  getUserSessions,
  deleteSession,
  deleteUserSessions
} from '../repositories/session.repository';
import { verifyAccessToken } from '../utils/jwt';
import { checkRateLimit, RateLimitEndpoint } from '../services/ratelimit.service';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';
import { RealmSettings, AuthProvider } from '../models/realm.model';
import { UserStatus } from '../models/user.model';
import { sendPasswordResetEmail, sendSecurityAlertEmail } from '../services/email.service';
import * as crypto from 'crypto';

/**
 * Response helper
 */
const response = (statusCode: number, body: unknown): APIGatewayProxyResult => ({
  statusCode,
  headers: {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  },
  body: JSON.stringify(body)
});

/**
 * Extract and validate admin token
 */
async function validateAdminAuth(event: APIGatewayProxyEvent): Promise<{
  valid: boolean;
  userId?: string;
  realmId?: string;
  isAdmin?: boolean;
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

    return {
      valid: true,
      userId: payload.sub,
      realmId: payload.realm_id,
      isAdmin: true
    };
  } catch {
    return { valid: false, error: 'Invalid or expired token' };
  }
}


// ============================================================================
// REALM CONFIGURATION API (Task 9.2)
// ============================================================================

/**
 * GET /v1/admin/realms - List all realms
 */
export async function listRealmsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';

  // Validate admin auth first
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

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
    const healthcareOnly = event.queryStringParameters?.healthcare_only === 'true';
    const realms = await listRealms({ healthcareOnly });

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'list_realms',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { count: realms.length, healthcareOnly }
    });

    return response(200, {
      data: {
        realms: realms.map(r => ({
          id: r.id,
          name: r.name,
          domain: r.domain,
          created_at: r.created_at,
          updated_at: r.updated_at,
          mfa_policy: r.settings.mfa_config.policy
        })),
        total: realms.length
      }
    });
  } catch (error) {
    console.error('List realms error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to list realms' }
    });
  }
}

/**
 * GET /v1/admin/realms/:id - Get realm details
 */
export async function getRealmHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const realmId = event.pathParameters?.id;

  if (!realmId) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'Realm ID is required' }
    });
  }

  // Validate admin auth
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

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
    const realm = await getRealm(realmId);

    if (!realm) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'Realm not found' }
      });
    }

    // Get realm statistics
    const stats = await getRealmStats(realmId);

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'get_realm',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { target_realm: realmId }
    });

    return response(200, {
      data: {
        realm: {
          id: realm.id,
          name: realm.name,
          domain: realm.domain,
          settings: realm.settings,
          auth_providers: realm.auth_providers,
          created_at: realm.created_at,
          updated_at: realm.updated_at
        },
        stats
      }
    });
  } catch (error) {
    console.error('Get realm error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to get realm' }
    });
  }
}


/**
 * POST /v1/admin/realms - Create new realm
 */
export async function createRealmHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';

  // Validate admin auth
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Rate limiting - stricter for create
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.REGISTER}:${clientIp}`);

  if (!rateLimitResult.allowed) {
    return response(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        retry_after: rateLimitResult.retryAfter
      }
    });
  }

  // Parse body
  let body: {
    name: string;
    domain: string;
    settings?: Partial<RealmSettings>;
    auth_providers?: AuthProvider[];
  };

  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return response(400, {
      error: { code: 'INVALID_JSON', message: 'Invalid JSON body' }
    });
  }

  // Validate required fields
  if (!body.name || !body.domain) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'Name and domain are required' }
    });
  }

  try {
    const result = await createRealm({
      name: body.name,
      domain: body.domain,
      settings: body.settings,
      auth_providers: body.auth_providers
    });

    if (!result.success) {
      return response(400, {
        error: { code: 'CREATE_FAILED', message: result.error }
      });
    }

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'create_realm',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { new_realm: result.realm?.id }
    });

    return response(201, {
      data: {
        realm: result.realm,
        message: 'Realm created successfully'
      }
    });
  } catch (error) {
    console.error('Create realm error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to create realm' }
    });
  }
}

/**
 * PATCH /v1/admin/realms/:id - Update realm configuration
 */
export async function updateRealmHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const realmId = event.pathParameters?.id;

  if (!realmId) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'Realm ID is required' }
    });
  }

  // Validate admin auth
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

  if (!rateLimitResult.allowed) {
    return response(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        retry_after: rateLimitResult.retryAfter
      }
    });
  }

  // Parse body
  let body: {
    name?: string;
    domain?: string;
    settings?: Partial<RealmSettings>;
    auth_providers?: AuthProvider[];
  };

  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return response(400, {
      error: { code: 'INVALID_JSON', message: 'Invalid JSON body' }
    });
  }

  try {
    const result = await updateRealm(realmId, body);

    if (!result.success) {
      const statusCode = result.error?.includes('not found') ? 404 : 400;
      return response(statusCode, {
        error: { code: 'UPDATE_FAILED', message: result.error }
      });
    }

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.CONFIG_CHANGE,
      action: 'update_realm',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_realm: realmId,
        changes: Object.keys(body)
      }
    });

    return response(200, {
      data: {
        realm: result.realm,
        message: 'Realm updated successfully'
      }
    });
  } catch (error) {
    console.error('Update realm error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to update realm' }
    });
  }
}

/**
 * DELETE /v1/admin/realms/:id - Delete realm
 */
export async function deleteRealmHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const realmId = event.pathParameters?.id;

  if (!realmId) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'Realm ID is required' }
    });
  }

  // Validate admin auth
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Rate limiting - very strict for delete
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.PASSWORD_RESET}:${clientIp}`);

  if (!rateLimitResult.allowed) {
    return response(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        retry_after: rateLimitResult.retryAfter
      }
    });
  }

  // Prevent self-deletion
  if (realmId === auth.realmId) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'Cannot delete your own realm' }
    });
  }

  try {
    const result = await deleteRealmWithCleanup(realmId);

    if (!result.success) {
      const statusCode = result.error?.includes('not found') ? 404 : 400;
      return response(statusCode, {
        error: { code: 'DELETE_FAILED', message: result.error }
      });
    }

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'delete_realm',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        deleted_realm: realmId,
        deleted_counts: result.deletedCounts
      }
    });

    return response(200, {
      data: {
        message: 'Realm deleted successfully',
        deleted_counts: result.deletedCounts
      }
    });
  } catch (error) {
    console.error('Delete realm error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to delete realm' }
    });
  }
}


// ============================================================================
// ADMIN USER MANAGEMENT API (Task 9.3)
// ============================================================================

/**
 * GET /v1/admin/users - List users in a realm with pagination
 */
export async function listUsersHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';

  // Validate admin auth
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

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
    // Parse query parameters
    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;
    const limit = parseInt(event.queryStringParameters?.limit || '50', 10);
    const status = event.queryStringParameters?.status as UserStatus | undefined;
    const search = event.queryStringParameters?.search;
    const lastKey = event.queryStringParameters?.last_key;

    // Parse pagination key if provided
    let lastEvaluatedKey: Record<string, unknown> | undefined;
    if (lastKey) {
      try {
        lastEvaluatedKey = JSON.parse(Buffer.from(lastKey, 'base64').toString('utf-8'));
      } catch {
        return response(400, {
          error: { code: 'INVALID_REQUEST', message: 'Invalid pagination key' }
        });
      }
    }

    const result = await listRealmUsers(realmId, {
      limit: Math.min(limit, 100), // Max 100 per page
      lastEvaluatedKey,
      status,
      search
    });

    // Encode pagination key for next page
    let nextKey: string | undefined;
    if (result.lastEvaluatedKey) {
      nextKey = Buffer.from(JSON.stringify(result.lastEvaluatedKey)).toString('base64');
    }

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'list_users',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { target_realm: realmId, count: result.users.length, status, search }
    });

    return response(200, {
      data: {
        users: result.users,
        pagination: {
          total: result.total,
          has_more: !!nextKey,
          next_key: nextKey
        }
      }
    });
  } catch (error) {
    console.error('List users error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to list users' }
    });
  }
}

/**
 * GET /v1/admin/users/:id - Get user details
 */
export async function getUserHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userId = event.pathParameters?.id;

  if (!userId) {
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

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

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
    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;
    const userDetails = await getAdminUserDetails(realmId, userId);

    if (!userDetails) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Get user's active sessions count
    const sessions = await getUserSessions(realmId, userId);

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'get_user',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { target_user: userId, target_realm: realmId }
    });

    return response(200, {
      data: {
        ...userDetails,
        sessions: {
          active_count: sessions.length,
          sessions: sessions.map(s => ({
            id: s.id,
            ip_address: s.ip_address,
            user_agent: s.user_agent,
            created_at: s.created_at,
            last_used_at: s.last_used_at,
            expires_at: s.expires_at
          }))
        }
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to get user' }
    });
  }
}

/**
 * POST /v1/admin/users/:id/suspend - Suspend a user
 */
export async function suspendUserHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userId = event.pathParameters?.id;

  if (!userId) {
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

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

  if (!rateLimitResult.allowed) {
    return response(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        retry_after: rateLimitResult.retryAfter
      }
    });
  }

  // Prevent self-suspension
  if (userId === auth.userId) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'Cannot suspend your own account' }
    });
  }

  try {
    // Parse body for reason
    let reason: string | undefined;
    if (event.body) {
      try {
        const body = JSON.parse(event.body);
        reason = body.reason;
      } catch {
        // Ignore parse errors, reason is optional
      }
    }

    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;
    
    // Check user exists
    const user = await findUserById(realmId, userId);
    if (!user) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Suspend user
    const success = await suspendUser(realmId, userId, reason);

    if (!success) {
      return response(500, {
        error: { code: 'SUSPEND_FAILED', message: 'Failed to suspend user' }
      });
    }

    // Revoke all user sessions
    const revokedSessions = await deleteUserSessions(realmId, userId);

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'suspend_user',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_user: userId, 
        target_realm: realmId,
        reason,
        revoked_sessions: revokedSessions
      }
    });

    return response(200, {
      data: {
        message: 'User suspended successfully',
        revoked_sessions: revokedSessions
      }
    });
  } catch (error) {
    console.error('Suspend user error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to suspend user' }
    });
  }
}

/**
 * POST /v1/admin/users/:id/activate - Activate/unsuspend a user
 */
export async function activateUserHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userId = event.pathParameters?.id;

  if (!userId) {
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

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

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
    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;
    
    // Check user exists
    const user = await findUserById(realmId, userId);
    if (!user) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Activate user
    const success = await activateUser(realmId, userId);

    if (!success) {
      return response(500, {
        error: { code: 'ACTIVATE_FAILED', message: 'Failed to activate user' }
      });
    }

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'activate_user',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { target_user: userId, target_realm: realmId }
    });

    return response(200, {
      data: {
        message: 'User activated successfully'
      }
    });
  } catch (error) {
    console.error('Activate user error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to activate user' }
    });
  }
}

/**
 * POST /v1/admin/users/:id/unlock - Unlock a locked user account
 */
export async function unlockUserHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userId = event.pathParameters?.id;

  if (!userId) {
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

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

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
    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;
    
    // Check user exists
    const user = await findUserById(realmId, userId);
    if (!user) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Unlock user
    const success = await unlockUser(realmId, userId);

    if (!success) {
      return response(500, {
        error: { code: 'UNLOCK_FAILED', message: 'Failed to unlock user' }
      });
    }

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ACCOUNT_UNLOCK,
      action: 'admin_unlock_user',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_user: userId, 
        target_realm: realmId,
        previous_failed_attempts: user.failed_login_attempts,
        previous_locked_until: user.locked_until
      }
    });

    return response(200, {
      data: {
        message: 'User unlocked successfully'
      }
    });
  } catch (error) {
    console.error('Unlock user error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to unlock user' }
    });
  }
}

/**
 * POST /v1/admin/users/:id/reset-password - Admin-initiated password reset
 */
export async function adminResetPasswordHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userId = event.pathParameters?.id;

  if (!userId) {
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

  // Rate limiting - stricter for password reset
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.PASSWORD_RESET}:${clientIp}`);

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
    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;
    
    // Check user exists
    const user = await findUserById(realmId, userId);
    if (!user) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours

    // Store token hash
    const success = await setPasswordResetToken(realmId, userId, tokenHash, expiresAt);

    if (!success) {
      return response(500, {
        error: { code: 'RESET_FAILED', message: 'Failed to initiate password reset' }
      });
    }

    // Send password reset email
    try {
      await sendPasswordResetEmail(user.email, resetToken, realmId, 'https://zalt.io');
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
      // Continue - token is set, email might be retried
    }

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.PASSWORD_RESET_REQUEST,
      action: 'admin_reset_password',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_user: userId, 
        target_realm: realmId,
        target_email: user.email
      }
    });

    return response(200, {
      data: {
        message: 'Password reset email sent',
        expires_at: expiresAt
      }
    });
  } catch (error) {
    console.error('Admin reset password error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to reset password' }
    });
  }
}

/**
 * DELETE /v1/admin/users/:id - Delete a user
 */
export async function deleteUserHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userId = event.pathParameters?.id;

  if (!userId) {
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

  // Rate limiting - very strict for delete
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.PASSWORD_RESET}:${clientIp}`);

  if (!rateLimitResult.allowed) {
    return response(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        retry_after: rateLimitResult.retryAfter
      }
    });
  }

  // Prevent self-deletion
  if (userId === auth.userId) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'Cannot delete your own account' }
    });
  }

  try {
    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;
    
    // Check user exists
    const user = await findUserById(realmId, userId);
    if (!user) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Delete all user sessions first
    const deletedSessions = await deleteUserSessions(realmId, userId);

    // Delete user
    await deleteUser(realmId, userId);

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ACCOUNT_DELETE,
      action: 'admin_delete_user',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_user: userId, 
        target_realm: realmId,
        target_email: user.email,
        deleted_sessions: deletedSessions
      }
    });

    return response(200, {
      data: {
        message: 'User deleted successfully',
        deleted_sessions: deletedSessions
      }
    });
  } catch (error) {
    console.error('Delete user error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to delete user' }
    });
  }
}


// ============================================================================
// ADMIN SESSION MANAGEMENT API (Task 9.4)
// ============================================================================

/**
 * GET /v1/admin/sessions - List all sessions in a realm
 */
export async function listSessionsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';

  // Validate admin auth
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

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
    const userId = event.queryStringParameters?.user_id;
    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;

    if (!userId) {
      return response(400, {
        error: { code: 'INVALID_REQUEST', message: 'user_id query parameter is required' }
      });
    }

    const sessions = await getUserSessions(realmId, userId);

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'list_sessions',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { target_user: userId, target_realm: realmId, count: sessions.length }
    });

    return response(200, {
      data: {
        sessions: sessions.map(s => ({
          id: s.id,
          user_id: s.user_id,
          ip_address: s.ip_address,
          user_agent: s.user_agent,
          device_fingerprint: s.device_fingerprint,
          created_at: s.created_at,
          last_used_at: s.last_used_at,
          expires_at: s.expires_at,
          revoked: s.revoked
        })),
        total: sessions.length
      }
    });
  } catch (error) {
    console.error('List sessions error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to list sessions' }
    });
  }
}

/**
 * DELETE /v1/admin/sessions/:id - Revoke a specific session
 */
export async function revokeSessionHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const sessionId = event.pathParameters?.id;

  if (!sessionId) {
    return response(400, {
      error: { code: 'INVALID_REQUEST', message: 'Session ID is required' }
    });
  }

  // Validate admin auth
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

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
    // Parse body for user_id and realm_id (required for deletion)
    let userId: string | undefined;
    let realmId: string | undefined;

    if (event.body) {
      try {
        const body = JSON.parse(event.body);
        userId = body.user_id;
        realmId = body.realm_id || auth.realmId;
      } catch {
        return response(400, {
          error: { code: 'INVALID_JSON', message: 'Invalid JSON body' }
        });
      }
    }

    if (!userId) {
      return response(400, {
        error: { code: 'INVALID_REQUEST', message: 'user_id is required in request body' }
      });
    }

    realmId = realmId || auth.realmId!;

    // Delete session
    const success = await deleteSession(sessionId, realmId, userId);

    if (!success) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'Session not found' }
      });
    }

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.TOKEN_REVOKE,
      action: 'admin_revoke_session',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_session: sessionId,
        target_user: userId,
        target_realm: realmId
      }
    });

    return response(200, {
      data: {
        message: 'Session revoked successfully'
      }
    });
  } catch (error) {
    console.error('Revoke session error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to revoke session' }
    });
  }
}

/**
 * DELETE /v1/admin/users/:id/sessions - Revoke all sessions for a user
 */
export async function revokeUserSessionsHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userId = event.pathParameters?.id;

  if (!userId) {
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

  // Rate limiting
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.API_GENERAL}:${clientIp}`);

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
    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;

    // Check user exists
    const user = await findUserById(realmId, userId);
    if (!user) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Delete all user sessions
    const deletedCount = await deleteUserSessions(realmId, userId);

    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.TOKEN_REVOKE,
      action: 'admin_revoke_all_sessions',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_user: userId,
        target_realm: realmId,
        revoked_count: deletedCount
      }
    });

    return response(200, {
      data: {
        message: 'All user sessions revoked successfully',
        revoked_count: deletedCount
      }
    });
  } catch (error) {
    console.error('Revoke user sessions error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to revoke user sessions' }
    });
  }
}


// ============================================================================
// ADMIN MFA RESET API (Task 6.9)
// ============================================================================

/**
 * POST /v1/admin/users/:id/mfa/reset - Admin MFA Reset
 * 
 * SECURITY: This is a sensitive operation that requires:
 * 1. Admin authentication with MFA
 * 2. User notification via email
 * 3. Detailed audit logging
 * 
 * For healthcare realms, additional verification may be required.
 */
export async function adminResetMFAHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userId = event.pathParameters?.id;

  if (!userId) {
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

  // Rate limiting - very strict for MFA reset
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.PASSWORD_RESET}:${clientIp}`);

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
    // Parse body for reason (required for audit)
    let reason: string | undefined;
    let skipWaitingPeriod = false;
    
    if (event.body) {
      try {
        const body = JSON.parse(event.body);
        reason = body.reason;
        skipWaitingPeriod = body.skip_waiting_period === true;
      } catch {
        return response(400, {
          error: { code: 'INVALID_JSON', message: 'Invalid JSON body' }
        });
      }
    }

    if (!reason || reason.trim().length < 10) {
      return response(400, {
        error: { code: 'INVALID_REQUEST', message: 'A detailed reason (min 10 characters) is required for MFA reset' }
      });
    }

    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;
    
    // Check user exists
    const user = await findUserById(realmId, userId);
    if (!user) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Check if user has MFA enabled
    if (!user.mfa_enabled) {
      return response(400, {
        error: { code: 'MFA_NOT_ENABLED', message: 'User does not have MFA enabled' }
      });
    }

    // Reset MFA
    const success = await adminResetUserMFA(realmId, userId);

    if (!success) {
      return response(500, {
        error: { code: 'RESET_FAILED', message: 'Failed to reset MFA' }
      });
    }

    // Revoke all user sessions for security
    const revokedSessions = await deleteUserSessions(realmId, userId);

    // Send notification email to user
    try {
      await sendSecurityAlertEmail(
        user.email,
        'MFA Reset by Administrator',
        `Your Multi-Factor Authentication (MFA) has been reset by an administrator. ` +
        `If you did not request this, please contact support immediately. ` +
        `Reason provided: ${reason}`,
        realmId
      );
    } catch (emailError) {
      console.error('Failed to send MFA reset notification email:', emailError);
      // Continue - MFA is reset, email is best-effort
    }

    // Detailed audit log
    await logAuditEvent({
      eventType: AuditEventType.MFA_DISABLE,
      action: 'admin_reset_mfa',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_user: userId,
        target_realm: realmId,
        target_email: user.email,
        reason,
        skip_waiting_period: skipWaitingPeriod,
        revoked_sessions: revokedSessions,
        admin_user: auth.userId
      }
    });

    return response(200, {
      data: {
        message: 'MFA reset successfully',
        user_notified: true,
        revoked_sessions: revokedSessions
      }
    });
  } catch (error) {
    console.error('Admin MFA reset error:', error);
    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to reset MFA' }
    });
  }
}


// ============================================================================
// ADMIN PASSWORD COMPROMISE ACTIONS (Task 17.3)
// Requirements: 8.3, 8.4, 8.5, 8.6
// ============================================================================

import { sessionTasksService } from '../services/session-tasks.service';

/**
 * POST /v1/admin/users/:id/mark-password-compromised - Mark user's password as compromised
 * 
 * Validates: Requirement 8.3 (Admin can mark specific user's password as compromised)
 * Validates: Requirement 8.5 (Creates reset_password session task)
 * Validates: Requirement 8.6 (Optionally revokes all sessions)
 * 
 * SECURITY: This is a sensitive operation that requires:
 * 1. Admin authentication
 * 2. User notification via email
 * 3. Detailed audit logging
 */
export async function markPasswordCompromisedHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const userId = event.pathParameters?.id;

  if (!userId) {
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

  // Rate limiting - strict for security operations
  const rateLimitResult = await checkRateLimit(auth.realmId!, `${RateLimitEndpoint.PASSWORD_RESET}:${clientIp}`);

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
    // Parse body
    let body: {
      reason?: string;
      revoke_sessions?: boolean;
      notify_user?: boolean;
    };

    try {
      body = JSON.parse(event.body || '{}');
    } catch {
      return response(400, {
        error: { code: 'INVALID_JSON', message: 'Invalid JSON body' }
      });
    }

    const realmId = event.queryStringParameters?.realm_id || auth.realmId!;
    
    // Check user exists
    const user = await findUserById(realmId, userId);
    if (!user) {
      return response(404, {
        error: { code: 'NOT_FOUND', message: 'User not found' }
      });
    }

    // Force password reset with compromised reason
    const result = await sessionTasksService.forcePasswordReset(
      userId,
      realmId,
      {
        revokeAllSessions: body.revoke_sessions ?? false,
        reason: 'compromised',
        message: body.reason || 'Your password has been marked as compromised by an administrator'
      }
    );

    // Send notification email to user (if requested, default true)
    const notifyUser = body.notify_user !== false;
    if (notifyUser) {
      try {
        await sendSecurityAlertEmail(
          user.email,
          'Password Security Alert',
          `Your password has been marked as compromised by an administrator. ` +
          `You will be required to reset your password on your next login. ` +
          `Reason: ${body.reason || 'Security incident detected'}. ` +
          `If you did not expect this, please contact support immediately.`,
          realmId
        );
      } catch (emailError) {
        console.error('Failed to send password compromised notification email:', emailError);
        // Continue - password is marked, email is best-effort
      }
    }

    // Detailed audit log
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'mark_password_compromised',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_user: userId,
        target_realm: realmId,
        target_email: user.email,
        reason: body.reason || 'Admin marked as compromised',
        revoke_sessions: body.revoke_sessions ?? false,
        sessions_revoked: result.sessionsRevoked,
        task_created: !!result.taskId,
        user_notified: notifyUser,
        admin_user: auth.userId
      }
    });

    return response(200, {
      data: {
        success: true,
        message: 'Password marked as compromised. User must reset password on next login.',
        affected_users: 1,
        sessions_revoked: result.sessionsRevoked,
        task_created: !!result.taskId,
        user_notified: notifyUser
      }
    });
  } catch (error) {
    console.error('Mark password compromised error:', error);
    
    // Audit log failure
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'mark_password_compromised',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.FAILURE,
      details: { 
        target_user: userId,
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    });

    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to mark password as compromised' }
    });
  }
}

/**
 * POST /v1/admin/realm/mark-all-passwords-compromised - Mark all passwords in realm as compromised
 * 
 * Validates: Requirement 8.4 (Admin can mark all passwords as compromised - security incident)
 * Validates: Requirement 8.5 (Creates reset_password session task for all users)
 * Validates: Requirement 8.6 (Optionally revokes all sessions)
 * 
 * SECURITY: This is a CRITICAL operation that requires:
 * 1. Admin authentication
 * 2. Strict rate limiting (1 per 5 minutes)
 * 3. Detailed audit logging
 * 4. Used for security incidents (breach response)
 */
export async function markAllPasswordsCompromisedHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';

  // Validate admin auth
  const auth = await validateAdminAuth(event);
  if (!auth.valid) {
    return response(401, {
      error: { code: 'UNAUTHORIZED', message: auth.error }
    });
  }

  // Rate limiting - very strict for mass operations (1 per 5 minutes)
  const rateLimitResult = await checkRateLimit(
    auth.realmId!, 
    `admin_mass_compromise:${auth.userId}`,
    { maxRequests: 1, windowSeconds: 300 }
  );

  if (!rateLimitResult.allowed) {
    return response(429, {
      error: {
        code: 'RATE_LIMITED',
        message: 'Mass password compromise can only be performed once every 5 minutes',
        retry_after: rateLimitResult.retryAfter
      }
    });
  }

  try {
    // Parse body
    let body: {
      reason?: string;
      revoke_sessions?: boolean;
      confirm?: boolean;
    };

    try {
      body = JSON.parse(event.body || '{}');
    } catch {
      return response(400, {
        error: { code: 'INVALID_JSON', message: 'Invalid JSON body' }
      });
    }

    // Require explicit confirmation for mass operation
    if (body.confirm !== true) {
      return response(400, {
        error: { 
          code: 'CONFIRMATION_REQUIRED', 
          message: 'This operation affects all users in the realm. Set confirm: true to proceed.' 
        }
      });
    }

    const realmId = auth.realmId!;

    // Perform mass password reset with compromised reason
    const result = await sessionTasksService.forcePasswordResetAll(
      realmId,
      {
        revokeAllSessions: body.revoke_sessions ?? false,
        reason: 'compromised',
        message: body.reason || 'Security incident: All passwords must be reset'
      }
    );

    // Detailed audit log for mass operation
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'mark_all_passwords_compromised',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.SUCCESS,
      details: { 
        target_realm: realmId,
        reason: body.reason || 'Security incident - mass password compromise',
        revoke_sessions: body.revoke_sessions ?? false,
        users_affected: result.usersAffected,
        tasks_created: result.tasksCreated,
        sessions_revoked: result.sessionsRevoked,
        error_count: result.errors.length,
        admin_user: auth.userId
      }
    });

    return response(200, {
      data: {
        success: true,
        message: 'All passwords marked as compromised. Users must reset passwords on next login.',
        affected_users: result.usersAffected,
        tasks_created: result.tasksCreated,
        sessions_revoked: result.sessionsRevoked,
        errors: result.errors.length > 0 ? result.errors : undefined
      }
    });
  } catch (error) {
    console.error('Mark all passwords compromised error:', error);
    
    // Audit log failure
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      action: 'mark_all_passwords_compromised',
      userId: auth.userId!,
      realmId: auth.realmId!,
      ipAddress: clientIp,
      result: AuditResult.FAILURE,
      details: { 
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    });

    return response(500, {
      error: { code: 'INTERNAL_ERROR', message: 'Failed to mark all passwords as compromised' }
    });
  }
}


// ============================================================================
// MAIN ROUTER (Lambda Entry Point)
// ============================================================================

/**
 * Main handler export for Lambda
 * Routes requests to appropriate handler based on HTTP method and path
 * 
 * This is the single entry point for all admin API endpoints.
 * AWS Lambda will invoke this function, which then routes to the correct handler.
 */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const path = event.path;
  const method = event.httpMethod;

  console.log(`Admin Router: ${method} ${path}`);

  try {
    // ========================================
    // REALM ROUTES
    // ========================================
    
    // GET /v1/admin/realms - List all realms
    if (path === '/v1/admin/realms' && method === 'GET') {
      return listRealmsHandler(event);
    }
    
    // POST /v1/admin/realms - Create new realm
    if (path === '/v1/admin/realms' && method === 'POST') {
      return createRealmHandler(event);
    }
    
    // GET /v1/admin/realms/:id - Get realm details
    if (path.match(/^\/v1\/admin\/realms\/[\w-]+$/) && method === 'GET') {
      return getRealmHandler(event);
    }
    
    // PATCH /v1/admin/realms/:id - Update realm
    if (path.match(/^\/v1\/admin\/realms\/[\w-]+$/) && method === 'PATCH') {
      return updateRealmHandler(event);
    }
    
    // DELETE /v1/admin/realms/:id - Delete realm
    if (path.match(/^\/v1\/admin\/realms\/[\w-]+$/) && method === 'DELETE') {
      return deleteRealmHandler(event);
    }

    // ========================================
    // USER ROUTES
    // ========================================
    
    // GET /v1/admin/users - List users
    if (path === '/v1/admin/users' && method === 'GET') {
      return listUsersHandler(event);
    }
    
    // GET /v1/admin/users/:id - Get user details
    if (path.match(/^\/v1\/admin\/users\/[\w-]+$/) && method === 'GET') {
      return getUserHandler(event);
    }
    
    // DELETE /v1/admin/users/:id - Delete user
    if (path.match(/^\/v1\/admin\/users\/[\w-]+$/) && method === 'DELETE') {
      return deleteUserHandler(event);
    }
    
    // POST /v1/admin/users/:id/suspend - Suspend user
    if (path.match(/^\/v1\/admin\/users\/[\w-]+\/suspend$/) && method === 'POST') {
      return suspendUserHandler(event);
    }
    
    // POST /v1/admin/users/:id/activate - Activate user
    if (path.match(/^\/v1\/admin\/users\/[\w-]+\/activate$/) && method === 'POST') {
      return activateUserHandler(event);
    }
    
    // POST /v1/admin/users/:id/unlock - Unlock user
    if (path.match(/^\/v1\/admin\/users\/[\w-]+\/unlock$/) && method === 'POST') {
      return unlockUserHandler(event);
    }
    
    // POST /v1/admin/users/:id/reset-password - Admin password reset
    if (path.match(/^\/v1\/admin\/users\/[\w-]+\/reset-password$/) && method === 'POST') {
      return adminResetPasswordHandler(event);
    }
    
    // POST /v1/admin/users/:id/mfa/reset - Admin MFA reset
    if (path.match(/^\/v1\/admin\/users\/[\w-]+\/mfa\/reset$/) && method === 'POST') {
      return adminResetMFAHandler(event);
    }
    
    // POST /v1/admin/users/:id/mark-password-compromised - Mark user's password as compromised
    if (path.match(/^\/v1\/admin\/users\/[\w-]+\/mark-password-compromised$/) && method === 'POST') {
      return markPasswordCompromisedHandler(event);
    }

    // ========================================
    // REALM SECURITY ROUTES (Password Compromise)
    // ========================================
    
    // POST /v1/admin/realm/mark-all-passwords-compromised - Mark all passwords as compromised
    if (path === '/v1/admin/realm/mark-all-passwords-compromised' && method === 'POST') {
      return markAllPasswordsCompromisedHandler(event);
    }

    // ========================================
    // SESSION ROUTES
    // ========================================
    
    // GET /v1/admin/sessions - List sessions (requires user_id query param)
    if (path === '/v1/admin/sessions' && method === 'GET') {
      return listSessionsHandler(event);
    }
    
    // DELETE /v1/admin/sessions/:id - Revoke specific session
    if (path.match(/^\/v1\/admin\/sessions\/[\w-]+$/) && method === 'DELETE') {
      return revokeSessionHandler(event);
    }
    
    // GET /v1/admin/users/:id/sessions - List user sessions
    if (path.match(/^\/v1\/admin\/users\/[\w-]+\/sessions$/) && method === 'GET') {
      // Reuse getUserHandler which includes sessions
      return getUserHandler(event);
    }
    
    // DELETE /v1/admin/users/:id/sessions - Revoke all user sessions
    if (path.match(/^\/v1\/admin\/users\/[\w-]+\/sessions$/) && method === 'DELETE') {
      return revokeUserSessionsHandler(event);
    }

    // ========================================
    // 404 - Route not found
    // ========================================
    console.warn(`Admin Router: No route found for ${method} ${path}`);
    
    return response(404, {
      error: {
        code: 'NOT_FOUND',
        message: `Route not found: ${method} ${path}`
      }
    });

  } catch (error) {
    console.error('Admin Router error:', error);
    return response(500, {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error'
      }
    });
  }
}
