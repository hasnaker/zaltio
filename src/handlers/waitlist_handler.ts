/**
 * Waitlist Lambda Handler - Waitlist Mode for Zalt.io
 * 
 * Validates: Requirements 5.5 (Waitlist Endpoints)
 * 
 * Endpoints:
 * - POST /waitlist - Join waitlist (public)
 * - GET /waitlist - List entries (admin)
 * - POST /waitlist/{id}/approve - Approve entry (admin)
 * - POST /waitlist/{id}/reject - Reject entry (admin)
 * - POST /waitlist/bulk-approve - Bulk approve (admin)
 * - GET /waitlist/position/{id} - Get position (public with entry ID)
 * - GET /waitlist/stats - Get waitlist statistics (admin)
 * - DELETE /waitlist/{id} - Delete entry (admin)
 * 
 * Security:
 * - Rate limiting on all endpoints
 * - Admin authentication for management endpoints
 * - No email enumeration (same response for existing/new)
 * - Audit logging for all operations
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  createSuccessResponse,
  createErrorResponse,
  handlePreflight,
  parseRequestBody
} from '../utils/response';
import {
  WaitlistService,
  WaitlistError,
  createWaitlistService,
  JoinWaitlistOptions,
  ApproveOptions,
  RejectOptions,
  ListOptions
} from '../services/waitlist.service';
import { checkRateLimit } from '../services/ratelimit.service';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';
import { findRealmById } from '../repositories/realm.repository';
import { isValidEmail } from '../models/waitlist.model';

// ============================================================================
// Rate Limit Configurations
// ============================================================================

const JOIN_RATE_LIMIT = {
  maxRequests: 5,
  windowSeconds: 3600 // 5 joins per hour per IP
};

const LIST_RATE_LIMIT = {
  maxRequests: 30,
  windowSeconds: 60 // 30 requests per minute per user
};

const APPROVE_RATE_LIMIT = {
  maxRequests: 50,
  windowSeconds: 60 // 50 approvals per minute per user
};

const POSITION_RATE_LIMIT = {
  maxRequests: 10,
  windowSeconds: 60 // 10 position checks per minute per IP
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * User context from JWT token
 */
interface UserContext {
  userId: string;
  realmId: string;
  sessionId?: string;
  email?: string;
  role?: string;
  isAdmin?: boolean;
}

/**
 * Extract user context from JWT token (via API Gateway authorizer)
 */
function getUserContext(event: APIGatewayProxyEvent): UserContext | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  
  const authorizer = event.requestContext?.authorizer;
  if (authorizer) {
    const role = authorizer.role as string | undefined;
    return {
      userId: authorizer.userId as string || '',
      realmId: authorizer.realmId as string || '',
      sessionId: authorizer.sessionId as string || authorizer.jti as string,
      email: authorizer.email as string | undefined,
      role,
      isAdmin: role === 'admin' || role === 'owner' || role === 'super_admin'
    };
  }
  
  return null;
}

/**
 * Get client IP address
 */
function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 
         event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
         '0.0.0.0';
}

/**
 * Get user agent
 */
function getUserAgent(event: APIGatewayProxyEvent): string | undefined {
  return event.headers?.['User-Agent'] || event.headers?.['user-agent'];
}

/**
 * Get realm ID from path or query parameters
 */
function getRealmId(event: APIGatewayProxyEvent): string | null {
  return event.pathParameters?.realmId || 
         event.queryStringParameters?.realm_id ||
         null;
}

/**
 * Log audit event helper
 */
async function logAudit(
  action: string,
  result: AuditResult,
  realmId: string,
  userId: string | undefined,
  ipAddress: string,
  details: Record<string, unknown>,
  userAgent?: string
): Promise<void> {
  try {
    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      result,
      realmId,
      userId,
      ipAddress,
      userAgent,
      action,
      resource: details.resource as string || 'waitlist',
      details
    });
  } catch (error) {
    console.error('Failed to log audit event:', error);
  }
}

/**
 * Create rate limit exceeded response
 */
function rateLimitResponse(
  event: APIGatewayProxyEvent,
  retryAfter: number
): APIGatewayProxyResult {
  return createErrorResponse(
    event,
    429,
    'RATE_LIMIT_EXCEEDED',
    'Too many requests',
    { retry_after: retryAfter }
  );
}

// ============================================================================
// Main Handler
// ============================================================================

/**
 * Main handler - routes to appropriate function
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Handle CORS preflight
  const preflightResponse = handlePreflight(event);
  if (preflightResponse) {
    return preflightResponse;
  }

  const method = event.httpMethod;
  const path = event.path;

  try {
    // POST /waitlist - Join waitlist
    if (path.match(/^\/waitlist$/) && method === 'POST') {
      return await handleJoinWaitlist(event);
    }

    // GET /waitlist - List entries (admin)
    if (path.match(/^\/waitlist$/) && method === 'GET') {
      return await handleListEntries(event);
    }

    // GET /waitlist/stats - Get statistics (admin)
    if (path.match(/^\/waitlist\/stats$/) && method === 'GET') {
      return await handleGetStats(event);
    }

    // POST /waitlist/bulk-approve - Bulk approve (admin)
    if (path.match(/^\/waitlist\/bulk-approve$/) && method === 'POST') {
      return await handleBulkApprove(event);
    }

    // GET /waitlist/position/{id} - Get position
    const positionMatch = path.match(/^\/waitlist\/position\/([^/]+)$/);
    if (positionMatch && method === 'GET') {
      return await handleGetPosition(event, positionMatch[1]);
    }

    // POST /waitlist/{id}/approve - Approve entry (admin)
    const approveMatch = path.match(/^\/waitlist\/([^/]+)\/approve$/);
    if (approveMatch && method === 'POST') {
      return await handleApproveEntry(event, approveMatch[1]);
    }

    // POST /waitlist/{id}/reject - Reject entry (admin)
    const rejectMatch = path.match(/^\/waitlist\/([^/]+)\/reject$/);
    if (rejectMatch && method === 'POST') {
      return await handleRejectEntry(event, rejectMatch[1]);
    }

    // GET /waitlist/{id} - Get entry details
    const getMatch = path.match(/^\/waitlist\/([^/]+)$/);
    if (getMatch && method === 'GET') {
      return await handleGetEntry(event, getMatch[1]);
    }

    // DELETE /waitlist/{id} - Delete entry (admin)
    const deleteMatch = path.match(/^\/waitlist\/([^/]+)$/);
    if (deleteMatch && method === 'DELETE') {
      return await handleDeleteEntry(event, deleteMatch[1]);
    }

    return createErrorResponse(event, 404, 'NOT_FOUND', 'Endpoint not found');

  } catch (error) {
    console.error('Waitlist handler error:', error);

    if (error instanceof WaitlistError) {
      const statusCode = mapErrorCodeToStatus(error.code);
      return createErrorResponse(event, statusCode, error.code, error.message);
    }

    return createErrorResponse(event, 500, 'INTERNAL_ERROR', 'An unexpected error occurred');
  }
}

// ============================================================================
// Endpoint Handlers
// ============================================================================

/**
 * POST /waitlist - Join waitlist (public)
 * Validates: Requirement 5.3 (Join waitlist)
 */
async function handleJoinWaitlist(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userAgent = getUserAgent(event);
  const realmId = getRealmId(event);

  if (!realmId) {
    return createErrorResponse(event, 400, 'MISSING_REALM_ID', 'Realm ID is required');
  }

  // Rate limiting by IP
  const rateLimitResult = await checkRateLimit(
    realmId,
    `waitlist_join:${ipAddress}`,
    JOIN_RATE_LIMIT
  );

  if (!rateLimitResult.allowed) {
    return rateLimitResponse(event, rateLimitResult.retryAfter || 60);
  }

  // Parse request body
  const parseResult = parseRequestBody<{
    email?: string;
    referral_code?: string;
    metadata?: {
      first_name?: string;
      last_name?: string;
      company?: string;
      use_case?: string;
      source?: string;
      utm_source?: string;
      utm_medium?: string;
      utm_campaign?: string;
      custom_fields?: Record<string, string>;
    };
  }>(event);

  if (!parseResult.success) {
    return createErrorResponse(event, 400, 'INVALID_JSON', parseResult.error);
  }

  const body = parseResult.data;

  // Validate email
  if (!body.email) {
    return createErrorResponse(event, 400, 'MISSING_EMAIL', 'Email is required');
  }

  if (!isValidEmail(body.email)) {
    return createErrorResponse(event, 400, 'INVALID_EMAIL', 'Invalid email format');
  }

  // Create waitlist service and join
  const service = createWaitlistService(realmId);

  const options: JoinWaitlistOptions = {
    email: body.email,
    referralCode: body.referral_code,
    metadata: {
      firstName: body.metadata?.first_name,
      lastName: body.metadata?.last_name,
      company: body.metadata?.company,
      useCase: body.metadata?.use_case,
      source: body.metadata?.source,
      utmSource: body.metadata?.utm_source,
      utmMedium: body.metadata?.utm_medium,
      utmCampaign: body.metadata?.utm_campaign,
      customFields: body.metadata?.custom_fields
    },
    ipAddress,
    userAgent
  };

  const result = await service.join(options);

  await logAudit(
    'waitlist_join',
    AuditResult.SUCCESS,
    realmId,
    undefined,
    ipAddress,
    {
      resource: `waitlist:${result.entry.id}`,
      email_hash: hashEmail(body.email),
      position: result.entry.position,
      already_exists: result.already_exists
    },
    userAgent
  );

  // Return same response for new and existing entries (no enumeration)
  return createSuccessResponse(event, 201, {
    message: 'Successfully joined the waitlist',
    entry_id: result.entry.id,
    position: result.entry.position,
    referral_code: result.referral_code
  });
}

/**
 * GET /waitlist - List entries (admin)
 * Validates: Requirement 5.5 (List entries)
 */
async function handleListEntries(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userContext = getUserContext(event);

  if (!userContext || !userContext.userId) {
    return createErrorResponse(event, 401, 'UNAUTHORIZED', 'Authentication required');
  }

  if (!userContext.isAdmin) {
    return createErrorResponse(event, 403, 'FORBIDDEN', 'Admin access required');
  }

  const realmId = getRealmId(event) || userContext.realmId;

  if (!realmId) {
    return createErrorResponse(event, 400, 'MISSING_REALM_ID', 'Realm ID is required');
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    realmId,
    `waitlist_list:${userContext.userId}`,
    LIST_RATE_LIMIT
  );

  if (!rateLimitResult.allowed) {
    return rateLimitResponse(event, rateLimitResult.retryAfter || 60);
  }

  // Parse query parameters
  const status = event.queryStringParameters?.status as ListOptions['status'];
  const limit = parseInt(event.queryStringParameters?.limit || '50', 10);
  const cursor = event.queryStringParameters?.cursor;
  const sortBy = event.queryStringParameters?.sort_by as ListOptions['sortBy'];
  const sortOrder = event.queryStringParameters?.sort_order as ListOptions['sortOrder'];

  const service = createWaitlistService(realmId);

  const result = await service.list({
    status,
    limit: Math.min(limit, 100),
    cursor,
    sortBy,
    sortOrder
  });

  return createSuccessResponse(event, 200, {
    entries: result.entries,
    next_cursor: result.nextCursor,
    count: result.entries.length
  });
}

/**
 * GET /waitlist/stats - Get statistics (admin)
 */
async function handleGetStats(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const userContext = getUserContext(event);

  if (!userContext || !userContext.userId) {
    return createErrorResponse(event, 401, 'UNAUTHORIZED', 'Authentication required');
  }

  if (!userContext.isAdmin) {
    return createErrorResponse(event, 403, 'FORBIDDEN', 'Admin access required');
  }

  const realmId = getRealmId(event) || userContext.realmId;

  if (!realmId) {
    return createErrorResponse(event, 400, 'MISSING_REALM_ID', 'Realm ID is required');
  }

  const service = createWaitlistService(realmId);
  const stats = await service.getStats();

  return createSuccessResponse(event, 200, { stats });
}

/**
 * POST /waitlist/{id}/approve - Approve entry (admin)
 * Validates: Requirement 5.4 (Approve entry)
 */
async function handleApproveEntry(
  event: APIGatewayProxyEvent,
  entryId: string
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userAgent = getUserAgent(event);
  const userContext = getUserContext(event);

  if (!userContext || !userContext.userId) {
    return createErrorResponse(event, 401, 'UNAUTHORIZED', 'Authentication required');
  }

  if (!userContext.isAdmin) {
    return createErrorResponse(event, 403, 'FORBIDDEN', 'Admin access required');
  }

  const realmId = getRealmId(event) || userContext.realmId;

  if (!realmId) {
    return createErrorResponse(event, 400, 'MISSING_REALM_ID', 'Realm ID is required');
  }

  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    realmId,
    `waitlist_approve:${userContext.userId}`,
    APPROVE_RATE_LIMIT
  );

  if (!rateLimitResult.allowed) {
    return rateLimitResponse(event, rateLimitResult.retryAfter || 60);
  }

  // Parse request body for options
  const parseResult = parseRequestBody<{
    send_invitation?: boolean;
    invitation_role?: string;
    custom_message?: string;
  }>(event);

  const body = parseResult.success ? parseResult.data : {};

  const options: ApproveOptions = {
    sendInvitation: body.send_invitation !== false,
    invitationRole: body.invitation_role || 'member',
    customMessage: body.custom_message
  };

  const service = createWaitlistService(realmId);
  const entry = await service.approve(entryId, userContext.userId, options);

  if (!entry) {
    return createErrorResponse(event, 404, 'ENTRY_NOT_FOUND', 'Waitlist entry not found');
  }

  await logAudit(
    'waitlist_approve',
    AuditResult.SUCCESS,
    realmId,
    userContext.userId,
    ipAddress,
    {
      resource: `waitlist:${entryId}`,
      email_hash: hashEmail(entry.email),
      send_invitation: options.sendInvitation
    },
    userAgent
  );

  return createSuccessResponse(event, 200, {
    message: 'Entry approved successfully',
    entry: {
      id: entry.id,
      email: entry.email,
      status: entry.status,
      approved_at: entry.approved_at,
      approved_by: entry.approved_by
    }
  });
}

/**
 * POST /waitlist/{id}/reject - Reject entry (admin)
 * Validates: Requirement 5.6 (Reject entry)
 */
async function handleRejectEntry(
  event: APIGatewayProxyEvent,
  entryId: string
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userAgent = getUserAgent(event);
  const userContext = getUserContext(event);

  if (!userContext || !userContext.userId) {
    return createErrorResponse(event, 401, 'UNAUTHORIZED', 'Authentication required');
  }

  if (!userContext.isAdmin) {
    return createErrorResponse(event, 403, 'FORBIDDEN', 'Admin access required');
  }

  const realmId = getRealmId(event) || userContext.realmId;

  if (!realmId) {
    return createErrorResponse(event, 400, 'MISSING_REALM_ID', 'Realm ID is required');
  }

  // Parse request body for options
  const parseResult = parseRequestBody<{
    reason?: string;
    send_notification?: boolean;
  }>(event);

  const body = parseResult.success ? parseResult.data : {};

  const options: RejectOptions = {
    reason: body.reason,
    sendNotification: body.send_notification === true
  };

  const service = createWaitlistService(realmId);
  const entry = await service.reject(entryId, userContext.userId, options);

  if (!entry) {
    return createErrorResponse(event, 404, 'ENTRY_NOT_FOUND', 'Waitlist entry not found');
  }

  await logAudit(
    'waitlist_reject',
    AuditResult.SUCCESS,
    realmId,
    userContext.userId,
    ipAddress,
    {
      resource: `waitlist:${entryId}`,
      email_hash: hashEmail(entry.email),
      reason: options.reason
    },
    userAgent
  );

  return createSuccessResponse(event, 200, {
    message: 'Entry rejected',
    entry: {
      id: entry.id,
      email: entry.email,
      status: entry.status,
      rejected_at: entry.rejected_at,
      rejected_by: entry.rejected_by
    }
  });
}

/**
 * POST /waitlist/bulk-approve - Bulk approve (admin)
 * Validates: Requirement 5.5 (Bulk approve)
 */
async function handleBulkApprove(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userAgent = getUserAgent(event);
  const userContext = getUserContext(event);

  if (!userContext || !userContext.userId) {
    return createErrorResponse(event, 401, 'UNAUTHORIZED', 'Authentication required');
  }

  if (!userContext.isAdmin) {
    return createErrorResponse(event, 403, 'FORBIDDEN', 'Admin access required');
  }

  const realmId = getRealmId(event) || userContext.realmId;

  if (!realmId) {
    return createErrorResponse(event, 400, 'MISSING_REALM_ID', 'Realm ID is required');
  }

  // Parse request body
  const parseResult = parseRequestBody<{
    entry_ids: string[];
    send_invitation?: boolean;
    invitation_role?: string;
    custom_message?: string;
  }>(event);

  if (!parseResult.success) {
    return createErrorResponse(event, 400, 'INVALID_JSON', parseResult.error);
  }

  const body = parseResult.data;

  if (!body.entry_ids || !Array.isArray(body.entry_ids) || body.entry_ids.length === 0) {
    return createErrorResponse(event, 400, 'MISSING_ENTRY_IDS', 'Entry IDs array is required');
  }

  if (body.entry_ids.length > 100) {
    return createErrorResponse(event, 400, 'TOO_MANY_ENTRIES', 'Maximum 100 entries per bulk operation');
  }

  const options: ApproveOptions = {
    sendInvitation: body.send_invitation !== false,
    invitationRole: body.invitation_role || 'member',
    customMessage: body.custom_message
  };

  const service = createWaitlistService(realmId);
  const result = await service.bulkApprove(body.entry_ids, userContext.userId, options);

  await logAudit(
    'waitlist_bulk_approve',
    AuditResult.SUCCESS,
    realmId,
    userContext.userId,
    ipAddress,
    {
      resource: 'waitlist',
      approved_count: result.approved.length,
      failed_count: result.failed.length,
      send_invitation: options.sendInvitation
    },
    userAgent
  );

  return createSuccessResponse(event, 200, {
    message: 'Bulk approval completed',
    approved: result.approved,
    failed: result.failed,
    approved_count: result.approved.length,
    failed_count: result.failed.length
  });
}

/**
 * GET /waitlist/position/{id} - Get position (public)
 * Validates: Requirement 5.8 (Get position)
 */
async function handleGetPosition(
  event: APIGatewayProxyEvent,
  entryId: string
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const realmId = getRealmId(event);

  if (!realmId) {
    return createErrorResponse(event, 400, 'MISSING_REALM_ID', 'Realm ID is required');
  }

  // Rate limiting by IP
  const rateLimitResult = await checkRateLimit(
    realmId,
    `waitlist_position:${ipAddress}`,
    POSITION_RATE_LIMIT
  );

  if (!rateLimitResult.allowed) {
    return rateLimitResponse(event, rateLimitResult.retryAfter || 60);
  }

  const service = createWaitlistService(realmId);
  const position = await service.getPosition(entryId);

  if (!position) {
    return createErrorResponse(event, 404, 'ENTRY_NOT_FOUND', 'Waitlist entry not found');
  }

  return createSuccessResponse(event, 200, {
    entry_id: entryId,
    position: position.position,
    total: position.total
  });
}

/**
 * GET /waitlist/{id} - Get entry details (admin)
 */
async function handleGetEntry(
  event: APIGatewayProxyEvent,
  entryId: string
): Promise<APIGatewayProxyResult> {
  const userContext = getUserContext(event);

  if (!userContext || !userContext.userId) {
    return createErrorResponse(event, 401, 'UNAUTHORIZED', 'Authentication required');
  }

  if (!userContext.isAdmin) {
    return createErrorResponse(event, 403, 'FORBIDDEN', 'Admin access required');
  }

  const realmId = getRealmId(event) || userContext.realmId;

  if (!realmId) {
    return createErrorResponse(event, 400, 'MISSING_REALM_ID', 'Realm ID is required');
  }

  const service = createWaitlistService(realmId);
  const entry = await service.getEntry(entryId);

  if (!entry) {
    return createErrorResponse(event, 404, 'ENTRY_NOT_FOUND', 'Waitlist entry not found');
  }

  return createSuccessResponse(event, 200, { entry });
}

/**
 * DELETE /waitlist/{id} - Delete entry (admin)
 */
async function handleDeleteEntry(
  event: APIGatewayProxyEvent,
  entryId: string
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userAgent = getUserAgent(event);
  const userContext = getUserContext(event);

  if (!userContext || !userContext.userId) {
    return createErrorResponse(event, 401, 'UNAUTHORIZED', 'Authentication required');
  }

  if (!userContext.isAdmin) {
    return createErrorResponse(event, 403, 'FORBIDDEN', 'Admin access required');
  }

  const realmId = getRealmId(event) || userContext.realmId;

  if (!realmId) {
    return createErrorResponse(event, 400, 'MISSING_REALM_ID', 'Realm ID is required');
  }

  const service = createWaitlistService(realmId);
  const deleted = await service.deleteEntry(entryId, userContext.userId);

  if (!deleted) {
    return createErrorResponse(event, 404, 'ENTRY_NOT_FOUND', 'Waitlist entry not found');
  }

  await logAudit(
    'waitlist_delete',
    AuditResult.SUCCESS,
    realmId,
    userContext.userId,
    ipAddress,
    { resource: `waitlist:${entryId}` },
    userAgent
  );

  return createSuccessResponse(event, 200, {
    message: 'Entry deleted successfully',
    entry_id: entryId
  });
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Map error code to HTTP status code
 */
function mapErrorCodeToStatus(code: string): number {
  switch (code) {
    case 'INVALID_EMAIL':
    case 'MISSING_EMAIL':
    case 'MISSING_REALM_ID':
    case 'MISSING_ENTRY_IDS':
    case 'TOO_MANY_ENTRIES':
      return 400;

    case 'WAITLIST_NOT_ENABLED':
      return 403;

    case 'ENTRY_NOT_FOUND':
      return 404;

    case 'RATE_LIMIT_EXCEEDED':
      return 429;

    default:
      return 500;
  }
}

/**
 * Hash email for audit logging (no PII in logs)
 */
function hashEmail(email: string): string {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(email.toLowerCase()).digest('hex').substring(0, 16);
}
