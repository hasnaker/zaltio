/**
 * Session Tasks Lambda Handler (Post-Login Requirements)
 * Validates: Requirements 4.7, 4.8 (Session Tasks Endpoints)
 * 
 * Endpoints:
 * - GET /session/tasks - Get pending tasks
 * - POST /session/tasks/{id}/complete - Complete task
 * - POST /session/tasks/{id}/skip - Skip non-blocking task
 * - POST /admin/users/{id}/force-password-reset - Force password reset
 * - POST /admin/realm/force-password-reset - Mass password reset
 * 
 * Security:
 * - User authentication required for user endpoints
 * - Admin authentication required for admin endpoints
 * - Rate limiting on admin endpoints (5/min)
 * - Audit logging for all operations
 * - No information leakage in error messages
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  sessionTasksService,
  SessionTasksError,
  SessionTask,
  SessionTaskType
} from '../services/session-tasks.service';
import { checkRateLimit } from '../services/ratelimit.service';
import { findUserById } from '../repositories/user.repository';
import { verifyPassword, hashPassword, validatePasswordPolicy } from '../utils/password';

// Rate limits
const ADMIN_RATE_LIMIT = {
  maxRequests: 5,
  windowSeconds: 60 // 5 attempts per minute per admin
};

const TASK_COMPLETE_RATE_LIMIT = {
  maxRequests: 10,
  windowSeconds: 60 // 10 attempts per minute per user
};

// CORS headers
const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
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
  role?: string;
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
      email: authorizer.email as string | undefined,
      role: authorizer.role as string | undefined
    };
  }
  
  return null;
}

/**
 * Check if user has admin role
 */
function isAdmin(userContext: { role?: string }): boolean {
  return userContext.role === 'admin' || userContext.role === 'super_admin';
}

/**
 * Log audit event
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
    // User endpoints
    if (path === '/session/tasks' && method === 'GET') {
      return await handleGetPendingTasks(event);
    }
    
    // POST /session/tasks/{id}/complete
    const completeMatch = path.match(/^\/session\/tasks\/([^/]+)\/complete$/);
    if (completeMatch && method === 'POST') {
      return await handleCompleteTask(event, completeMatch[1]);
    }
    
    // POST /session/tasks/{id}/skip
    const skipMatch = path.match(/^\/session\/tasks\/([^/]+)\/skip$/);
    if (skipMatch && method === 'POST') {
      return await handleSkipTask(event, skipMatch[1]);
    }
    
    // Admin endpoints
    // POST /admin/users/{id}/force-password-reset
    const forceResetMatch = path.match(/^\/admin\/users\/([^/]+)\/force-password-reset$/);
    if (forceResetMatch && method === 'POST') {
      return await handleForcePasswordReset(event, forceResetMatch[1]);
    }
    
    // POST /admin/realm/force-password-reset
    if (path === '/admin/realm/force-password-reset' && method === 'POST') {
      return await handleMassPasswordReset(event);
    }
    
    return errorResponse(404, 'NOT_FOUND', 'Endpoint not found');
    
  } catch (error) {
    console.error('Session tasks handler error:', error);
    
    if (error instanceof SessionTasksError) {
      return errorResponse(
        error.statusCode,
        error.code,
        error.message
      );
    }
    
    return errorResponse(500, 'INTERNAL_ERROR', 'An unexpected error occurred');
  }
}

/**
 * GET /session/tasks - Get pending tasks for current session
 * Validates: Requirement 4.7 (Dashboard shows pending tasks)
 */
async function handleGetPendingTasks(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId || !userContext.sessionId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Get pending tasks
  const tasks = await sessionTasksService.getPendingTasksResponse(userContext.sessionId);
  
  // Check if there are blocking tasks
  const hasBlockingTasks = await sessionTasksService.hasBlockingTasks(userContext.sessionId);
  
  await logAuditEvent('session_tasks.listed', {
    userId: userContext.userId,
    realmId: userContext.realmId,
    sessionId: userContext.sessionId,
    taskCount: tasks.length,
    hasBlockingTasks
  });
  
  return successResponse(200, {
    tasks,
    has_blocking_tasks: hasBlockingTasks,
    count: tasks.length
  });
}

/**
 * POST /session/tasks/{id}/complete - Complete a session task
 * Validates: Requirement 4.9 (Task completion removes blocking)
 */
async function handleCompleteTask(
  event: APIGatewayProxyEvent,
  taskId: string
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId || !userContext.sessionId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    userContext.realmId,
    `task_complete:${userContext.userId}`,
    TASK_COMPLETE_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    await logAuditEvent('session_tasks.rate_limited', {
      userId: userContext.userId,
      realmId: userContext.realmId,
      sessionId: userContext.sessionId,
      taskId
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
          message: 'Too many task completion attempts',
          retry_after: rateLimitResult.retryAfter
        }
      })
    };
  }
  
  // Parse request body
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // Get the task first to determine type-specific validation
  const task = await sessionTasksService.getTask(userContext.sessionId, taskId);
  if (!task) {
    return errorResponse(404, 'TASK_NOT_FOUND', 'Session task not found');
  }
  
  // Validate completion data based on task type
  const validationResult = await validateTaskCompletion(task, body, userContext);
  if (!validationResult.valid) {
    return errorResponse(400, validationResult.code!, validationResult.message!);
  }
  
  // Complete the task
  const completedTask = await sessionTasksService.completeTask(
    userContext.sessionId,
    taskId
  );
  
  if (!completedTask) {
    return errorResponse(400, 'TASK_COMPLETION_FAILED', 'Failed to complete task');
  }
  
  // Get remaining tasks count
  const remainingTasks = await sessionTasksService.getPendingTaskCount(userContext.sessionId);
  
  await logAuditEvent('session_tasks.completed', {
    userId: userContext.userId,
    realmId: userContext.realmId,
    sessionId: userContext.sessionId,
    taskId,
    taskType: completedTask.type,
    remainingTasks
  });
  
  return successResponse(200, {
    message: 'Task completed successfully',
    task: {
      id: completedTask.id,
      type: completedTask.type,
      status: completedTask.status,
      completed_at: completedTask.completed_at
    },
    remaining_tasks: remainingTasks
  });
}

/**
 * POST /session/tasks/{id}/skip - Skip a non-blocking task
 */
async function handleSkipTask(
  event: APIGatewayProxyEvent,
  taskId: string
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId || !userContext.sessionId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Skip the task
  const skippedTask = await sessionTasksService.skipTask(
    userContext.sessionId,
    taskId
  );
  
  if (!skippedTask) {
    return errorResponse(400, 'TASK_SKIP_FAILED', 'Failed to skip task');
  }
  
  await logAuditEvent('session_tasks.skipped', {
    userId: userContext.userId,
    realmId: userContext.realmId,
    sessionId: userContext.sessionId,
    taskId,
    taskType: skippedTask.type
  });
  
  return successResponse(200, {
    message: 'Task skipped',
    task: {
      id: skippedTask.id,
      type: skippedTask.type,
      status: skippedTask.status,
      completed_at: skippedTask.completed_at
    }
  });
}

/**
 * POST /admin/users/{id}/force-password-reset - Force password reset for a user
 * Validates: Requirement 4.7 (Admin can force password reset)
 */
async function handleForcePasswordReset(
  event: APIGatewayProxyEvent,
  targetUserId: string
): Promise<APIGatewayProxyResult> {
  // Verify admin authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  if (!isAdmin(userContext)) {
    return errorResponse(403, 'FORBIDDEN', 'Admin access required');
  }
  
  // Rate limiting for admin endpoints
  const rateLimitResult = await checkRateLimit(
    userContext.realmId,
    `admin_force_reset:${userContext.userId}`,
    ADMIN_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    await logAuditEvent('admin.force_reset.rate_limited', {
      adminId: userContext.userId,
      realmId: userContext.realmId,
      targetUserId
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
          message: 'Too many admin requests',
          retry_after: rateLimitResult.retryAfter
        }
      })
    };
  }
  
  // Parse request body
  let body: {
    reason?: 'compromised' | 'expired' | 'admin_forced' | 'policy';
    revoke_sessions?: boolean;
    notify_user?: boolean;
    message?: string;
  };
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // Validate target user exists
  const targetUser = await findUserById(userContext.realmId, targetUserId);
  if (!targetUser) {
    return errorResponse(404, 'USER_NOT_FOUND', 'User not found');
  }
  
  // Force password reset
  const result = await sessionTasksService.forcePasswordReset(
    targetUserId,
    userContext.realmId,
    {
      revokeAllSessions: body.revoke_sessions ?? false,
      reason: body.reason ?? 'admin_forced',
      message: body.message
    }
  );
  
  await logAuditEvent('admin.force_password_reset', {
    adminId: userContext.userId,
    realmId: userContext.realmId,
    targetUserId,
    reason: body.reason ?? 'admin_forced',
    sessionsRevoked: result.sessionsRevoked,
    taskCreated: !!result.taskId
  });
  
  return successResponse(200, {
    message: 'Password reset forced',
    user_id: targetUserId,
    sessions_revoked: result.sessionsRevoked,
    task_created: !!result.taskId
  });
}

/**
 * POST /admin/realm/force-password-reset - Mass password reset for all users
 * Validates: Requirement 4.8 (Admin can force mass password reset)
 */
async function handleMassPasswordReset(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Verify admin authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  if (!isAdmin(userContext)) {
    return errorResponse(403, 'FORBIDDEN', 'Admin access required');
  }
  
  // Rate limiting for admin endpoints (stricter for mass operations)
  const rateLimitResult = await checkRateLimit(
    userContext.realmId,
    `admin_mass_reset:${userContext.userId}`,
    { maxRequests: 1, windowSeconds: 300 } // 1 per 5 minutes
  );
  
  if (!rateLimitResult.allowed) {
    await logAuditEvent('admin.mass_reset.rate_limited', {
      adminId: userContext.userId,
      realmId: userContext.realmId
    });
    
    return {
      statusCode: 429,
      headers: {
        ...CORS_HEADERS,
        'Retry-After': String(rateLimitResult.retryAfter || 300)
      },
      body: JSON.stringify({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Mass password reset can only be performed once every 5 minutes',
          retry_after: rateLimitResult.retryAfter
        }
      })
    };
  }
  
  // Parse request body
  let body: {
    realm_id?: string;
    reason?: 'compromised' | 'policy';
    revoke_all_sessions?: boolean;
    notify_users?: boolean;
    message?: string;
  };
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // Use provided realm_id or default to admin's realm
  const targetRealmId = body.realm_id || userContext.realmId;
  
  // Validate realm_id matches admin's realm (security check)
  if (targetRealmId !== userContext.realmId) {
    return errorResponse(403, 'FORBIDDEN', 'Cannot perform mass reset on different realm');
  }
  
  // Perform mass password reset
  const result = await sessionTasksService.forcePasswordResetAll(
    targetRealmId,
    {
      revokeAllSessions: body.revoke_all_sessions ?? false,
      reason: body.reason ?? 'compromised',
      message: body.message ?? 'Security incident: All passwords must be reset'
    }
  );
  
  await logAuditEvent('admin.mass_password_reset', {
    adminId: userContext.userId,
    realmId: targetRealmId,
    reason: body.reason ?? 'compromised',
    usersAffected: result.usersAffected,
    tasksCreated: result.tasksCreated,
    sessionsRevoked: result.sessionsRevoked,
    errorCount: result.errors.length
  });
  
  return successResponse(200, {
    message: 'Mass password reset initiated',
    realm_id: targetRealmId,
    users_affected: result.usersAffected,
    tasks_created: result.tasksCreated,
    sessions_revoked: result.sessionsRevoked,
    errors: result.errors.length > 0 ? result.errors : undefined
  });
}

/**
 * Validate task completion data based on task type
 */
async function validateTaskCompletion(
  task: SessionTask,
  body: Record<string, unknown>,
  userContext: { userId: string; realmId: string }
): Promise<{ valid: boolean; code?: string; message?: string }> {
  switch (task.type) {
    case 'reset_password': {
      const newPassword = body.new_password as string;
      if (!newPassword) {
        return { valid: false, code: 'MISSING_PASSWORD', message: 'New password is required' };
      }
      
      // Validate password strength
      const passwordValidation = validatePasswordPolicy(newPassword);
      if (!passwordValidation.valid) {
        return { 
          valid: false, 
          code: 'WEAK_PASSWORD', 
          message: passwordValidation.errors?.join(', ') || 'Password does not meet requirements'
        };
      }
      
      // In production, we would also update the user's password here
      // For now, we just validate the input
      return { valid: true };
    }
    
    case 'setup_mfa': {
      const mfaMethod = body.mfa_method as string;
      const verificationCode = body.verification_code as string;
      
      if (!mfaMethod) {
        return { valid: false, code: 'MISSING_MFA_METHOD', message: 'MFA method is required' };
      }
      
      if (!verificationCode) {
        return { valid: false, code: 'MISSING_VERIFICATION_CODE', message: 'Verification code is required' };
      }
      
      // Validate MFA method
      const validMethods = ['totp', 'webauthn'];
      if (!validMethods.includes(mfaMethod)) {
        return { valid: false, code: 'INVALID_MFA_METHOD', message: 'Invalid MFA method' };
      }
      
      // In production, we would verify the MFA setup here
      return { valid: true };
    }
    
    case 'choose_organization': {
      const organizationId = body.organization_id as string;
      if (!organizationId) {
        return { valid: false, code: 'MISSING_ORGANIZATION', message: 'Organization ID is required' };
      }
      
      // Validate organization is in the available list
      const availableOrgs = task.metadata?.available_organizations || [];
      const validOrg = availableOrgs.some(org => org.id === organizationId);
      if (!validOrg) {
        return { valid: false, code: 'INVALID_ORGANIZATION', message: 'Invalid organization selection' };
      }
      
      return { valid: true };
    }
    
    case 'accept_terms': {
      const accepted = body.accepted as boolean;
      if (accepted !== true) {
        return { valid: false, code: 'TERMS_NOT_ACCEPTED', message: 'Terms must be accepted' };
      }
      
      // Optionally validate terms version
      const termsVersion = body.terms_version as string;
      const requiredVersion = task.metadata?.terms_version;
      if (requiredVersion && termsVersion !== requiredVersion) {
        return { valid: false, code: 'INVALID_TERMS_VERSION', message: 'Invalid terms version' };
      }
      
      return { valid: true };
    }
    
    case 'custom': {
      // Custom tasks may have their own validation via webhook
      // For now, we accept any completion data
      return { valid: true };
    }
    
    default:
      return { valid: true };
  }
}
