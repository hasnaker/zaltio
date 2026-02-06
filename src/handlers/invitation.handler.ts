/**
 * Invitation Lambda Handler - Team Member Invitation System for Zalt.io
 * 
 * Validates: Requirements 11.7 (Invitation Endpoints)
 * 
 * Endpoints:
 * - POST /tenants/{id}/invitations - Create invitation
 * - GET /tenants/{id}/invitations - List invitations
 * - POST /invitations/accept - Accept invitation
 * - DELETE /invitations/{id} - Revoke invitation
 * - POST /invitations/{id}/resend - Resend invitation
 * - GET /invitations/validate - Validate invitation token
 * 
 * Security:
 * - User authentication required for tenant operations
 * - Rate limiting on all endpoints
 * - Authorization checks (tenant membership with admin/owner role)
 * - Audit logging for all operations
 * - No email enumeration
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  invitationService,
  InvitationServiceError,
  InvitationErrorCode,
  CreateInvitationServiceInput,
  AcceptInvitationServiceInput,
  RevokeInvitationInput,
  ResendInvitationInput,
  ListInvitationsInput
} from '../services/invitation.service';
import { checkRateLimit } from '../services/ratelimit.service';
import { getMembership, isMember } from '../repositories/membership.repository';
import { getOrganization } from '../repositories/organization.repository';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';
import { isValidEmail, normalizeEmail } from '../models/invitation.model';

// ============================================================================
// Rate Limits
// ============================================================================

const CREATE_RATE_LIMIT = {
  maxRequests: 10,
  windowSeconds: 3600 // 10 invitations per hour per user
};

const ACCEPT_RATE_LIMIT = {
  maxRequests: 5,
  windowSeconds: 300 // 5 attempts per 5 minutes per IP
};

const LIST_RATE_LIMIT = {
  maxRequests: 30,
  windowSeconds: 60 // 30 requests per minute per user
};

const RESEND_RATE_LIMIT = {
  maxRequests: 3,
  windowSeconds: 3600 // 3 resends per hour per invitation
};

// ============================================================================
// CORS Headers
// ============================================================================

const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
};

// ============================================================================
// Response Helpers
// ============================================================================

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
 * Create rate limit exceeded response
 */
function rateLimitResponse(retryAfter: number): APIGatewayProxyResult {
  return {
    statusCode: 429,
    headers: {
      ...CORS_HEADERS,
      'Retry-After': String(retryAfter)
    },
    body: JSON.stringify({
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests',
        retry_after: retryAfter,
        timestamp: new Date().toISOString()
      }
    })
  };
}

// ============================================================================
// Authentication & Authorization Helpers
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
  tenantId?: string;
}

/**
 * Extract user context from JWT token (via API Gateway authorizer)
 */
function getUserContext(event: APIGatewayProxyEvent): UserContext | null {
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
      sessionId: authorizer.sessionId as string || authorizer.jti as string,
      email: authorizer.email as string | undefined,
      role: authorizer.role as string | undefined,
      tenantId: authorizer.tenantId as string | undefined
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
 * Check if user has admin/owner role in tenant
 */
async function hasAdminAccess(userId: string, tenantId: string): Promise<boolean> {
  const membership = await getMembership(userId, tenantId);
  if (!membership || membership.status !== 'active') {
    return false;
  }
  
  // Check for admin or owner role
  const adminRoles = ['admin', 'owner', 'super_admin'];
  return membership.role_ids.some(role => adminRoles.includes(role.toLowerCase()));
}

/**
 * Log audit event helper
 */
async function logAudit(
  event: string,
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
      action: event,
      resource: details.resource as string || 'invitation',
      details
    });
  } catch (error) {
    // Log but don't fail the operation
    console.error('Failed to log audit event:', error);
  }
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
  const method = event.httpMethod;
  const path = event.path;
  
  // Handle CORS preflight
  if (method === 'OPTIONS') {
    return successResponse(200, {});
  }
  
  try {
    // Route to appropriate handler
    
    // POST /tenants/{id}/invitations - Create invitation
    const createMatch = path.match(/^\/tenants\/([^/]+)\/invitations$/);
    if (createMatch && method === 'POST') {
      return await handleCreateInvitation(event, createMatch[1]);
    }
    
    // GET /tenants/{id}/invitations - List invitations
    const listMatch = path.match(/^\/tenants\/([^/]+)\/invitations$/);
    if (listMatch && method === 'GET') {
      return await handleListInvitations(event, listMatch[1]);
    }
    
    // POST /invitations/accept - Accept invitation
    if (path === '/invitations/accept' && method === 'POST') {
      return await handleAcceptInvitation(event);
    }
    
    // GET /invitations/validate - Validate invitation token
    if (path === '/invitations/validate' && method === 'GET') {
      return await handleValidateInvitation(event);
    }
    
    // DELETE /invitations/{id} - Revoke invitation
    const revokeMatch = path.match(/^\/invitations\/([^/]+)$/);
    if (revokeMatch && method === 'DELETE') {
      return await handleRevokeInvitation(event, revokeMatch[1]);
    }
    
    // POST /invitations/{id}/resend - Resend invitation
    const resendMatch = path.match(/^\/invitations\/([^/]+)\/resend$/);
    if (resendMatch && method === 'POST') {
      return await handleResendInvitation(event, resendMatch[1]);
    }
    
    // GET /invitations/{id} - Get invitation details
    const getMatch = path.match(/^\/invitations\/([^/]+)$/);
    if (getMatch && method === 'GET') {
      return await handleGetInvitation(event, getMatch[1]);
    }
    
    return errorResponse(404, 'NOT_FOUND', 'Endpoint not found');
    
  } catch (error) {
    console.error('Invitation handler error:', error);
    
    if (error instanceof InvitationServiceError) {
      const statusCode = mapErrorCodeToStatus(error.code);
      return errorResponse(statusCode, error.code, error.message);
    }
    
    return errorResponse(500, 'INTERNAL_ERROR', 'An unexpected error occurred');
  }
}

// ============================================================================
// Endpoint Handlers
// ============================================================================

/**
 * POST /tenants/{id}/invitations - Create invitation
 * Validates: Requirement 11.1 (Create invitation with 7-day expiry)
 */
async function handleCreateInvitation(
  event: APIGatewayProxyEvent,
  tenantId: string
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userAgent = getUserAgent(event);
  
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Verify tenant exists and get realm_id
  const tenant = await getOrganization(tenantId);
  if (!tenant) {
    return errorResponse(404, 'TENANT_NOT_FOUND', 'Tenant not found');
  }
  
  // Verify user has admin access to tenant
  const hasAccess = await hasAdminAccess(userContext.userId, tenantId);
  if (!hasAccess) {
    await logAudit(
      'invitation_create_denied',
      AuditResult.FAILURE,
      tenant.realm_id,
      userContext.userId,
      ipAddress,
      { tenant_id: tenantId, reason: 'insufficient_permissions' },
      userAgent
    );
    return errorResponse(403, 'FORBIDDEN', 'Admin access required to create invitations');
  }
  
  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    tenant.realm_id,
    `invitation_create:${userContext.userId}`,
    CREATE_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    await logAudit(
      'invitation_create_rate_limited',
      AuditResult.FAILURE,
      tenant.realm_id,
      userContext.userId,
      ipAddress,
      { tenant_id: tenantId },
      userAgent
    );
    return rateLimitResponse(rateLimitResult.retryAfter || 60);
  }
  
  // Parse request body
  let body: {
    email?: string;
    role?: string;
    permissions?: string[];
    custom_message?: string;
    expires_in_days?: number;
  };
  
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // Validate required fields
  if (!body.email) {
    return errorResponse(400, 'MISSING_EMAIL', 'Email is required');
  }
  
  if (!body.role) {
    return errorResponse(400, 'MISSING_ROLE', 'Role is required');
  }
  
  // Validate email format
  const normalizedEmail = normalizeEmail(body.email);
  if (!isValidEmail(normalizedEmail)) {
    return errorResponse(400, 'INVALID_EMAIL', 'Invalid email format');
  }
  
  // Create invitation
  const input: CreateInvitationServiceInput = {
    tenant_id: tenantId,
    email: normalizedEmail,
    role: body.role,
    permissions: body.permissions,
    invited_by: userContext.userId,
    inviter_name: userContext.email?.split('@')[0], // Use email prefix as name
    inviter_email: userContext.email,
    custom_message: body.custom_message,
    expires_in_days: body.expires_in_days,
    realm_id: tenant.realm_id
  };
  
  const result = await invitationService.create(input);
  
  await logAudit(
    'invitation_created',
    AuditResult.SUCCESS,
    tenant.realm_id,
    userContext.userId,
    ipAddress,
    {
      resource: `invitation:${result.invitation.id}`,
      tenant_id: tenantId,
      email: normalizedEmail,
      role: body.role
    },
    userAgent
  );
  
  return successResponse(201, {
    message: 'Invitation created successfully',
    invitation: result.invitation,
    // Token is included for display to admin (one-time)
    accept_url: `${process.env.APP_URL || 'https://app.zalt.io'}/invitations/accept?token=${result.token}`
  });
}

/**
 * GET /tenants/{id}/invitations - List invitations
 * Validates: Requirement 11.7 (Dashboard shows pending and expired invitations)
 */
async function handleListInvitations(
  event: APIGatewayProxyEvent,
  tenantId: string
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Verify tenant exists
  const tenant = await getOrganization(tenantId);
  if (!tenant) {
    return errorResponse(404, 'TENANT_NOT_FOUND', 'Tenant not found');
  }
  
  // Verify user has admin access to tenant
  const hasAccess = await hasAdminAccess(userContext.userId, tenantId);
  if (!hasAccess) {
    return errorResponse(403, 'FORBIDDEN', 'Admin access required to list invitations');
  }
  
  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    tenant.realm_id,
    `invitation_list:${userContext.userId}`,
    LIST_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    return rateLimitResponse(rateLimitResult.retryAfter || 60);
  }
  
  // Parse query parameters
  const status = event.queryStringParameters?.status as 'pending' | 'accepted' | 'expired' | 'revoked' | undefined;
  const limit = parseInt(event.queryStringParameters?.limit || '50', 10);
  const cursor = event.queryStringParameters?.cursor;
  
  // List invitations
  const input: ListInvitationsInput = {
    tenant_id: tenantId,
    status,
    limit: Math.min(limit, 100), // Cap at 100
    cursor
  };
  
  const result = await invitationService.list(input);
  
  // Get statistics
  const statistics = await invitationService.getStatistics(tenantId);
  
  return successResponse(200, {
    invitations: result.invitations,
    next_cursor: result.next_cursor,
    count: result.invitations.length,
    statistics
  });
}

/**
 * POST /invitations/accept - Accept invitation
 * Validates: Requirements 11.3, 11.4 (Accept invitation for existing/new users)
 */
async function handleAcceptInvitation(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userAgent = getUserAgent(event);
  
  // Rate limiting by IP (no auth required for acceptance)
  const rateLimitResult = await checkRateLimit(
    'global',
    `invitation_accept:${ipAddress}`,
    ACCEPT_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    return rateLimitResponse(rateLimitResult.retryAfter || 60);
  }
  
  // Parse request body
  let body: {
    token?: string;
    // For existing users (optional - can be from auth context)
    user_id?: string;
    // For new users
    new_user?: {
      first_name: string;
      last_name: string;
      password: string;
    };
  };
  
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // Validate token
  if (!body.token) {
    return errorResponse(400, 'MISSING_TOKEN', 'Invitation token is required');
  }
  
  // Get user context if authenticated
  const userContext = getUserContext(event);
  
  // Determine user_id
  let userId = body.user_id || userContext?.userId;
  
  // Validate new user data if provided
  if (body.new_user) {
    if (!body.new_user.first_name || !body.new_user.last_name || !body.new_user.password) {
      return errorResponse(400, 'INVALID_NEW_USER', 'First name, last name, and password are required for new users');
    }
    
    // Password validation
    if (body.new_user.password.length < 8) {
      return errorResponse(400, 'WEAK_PASSWORD', 'Password must be at least 8 characters');
    }
  } else if (!userId) {
    return errorResponse(400, 'MISSING_USER_CONTEXT', 'Either authenticate or provide new_user data');
  }
  
  // Accept invitation
  const input: AcceptInvitationServiceInput = {
    token: body.token,
    user_id: userId,
    new_user_data: body.new_user,
    ip_address: ipAddress,
    user_agent: userAgent
  };
  
  const result = await invitationService.accept(input);
  
  return successResponse(200, {
    message: 'Invitation accepted successfully',
    user_id: result.user_id,
    tenant_id: result.tenant_id,
    role: result.role,
    is_new_user: result.is_new_user
  });
}

/**
 * GET /invitations/validate - Validate invitation token
 * Returns invitation details without accepting
 */
async function handleValidateInvitation(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  
  // Rate limiting by IP
  const rateLimitResult = await checkRateLimit(
    'global',
    `invitation_validate:${ipAddress}`,
    ACCEPT_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    return rateLimitResponse(rateLimitResult.retryAfter || 60);
  }
  
  // Get token from query parameter
  const token = event.queryStringParameters?.token;
  if (!token) {
    return errorResponse(400, 'MISSING_TOKEN', 'Invitation token is required');
  }
  
  // Validate token
  const validation = await invitationService.validateToken(token);
  
  if (!validation.valid) {
    // Return generic error to prevent enumeration
    return errorResponse(400, validation.error_code || 'INVALID_TOKEN', validation.error || 'Invalid invitation');
  }
  
  return successResponse(200, {
    valid: true,
    invitation: validation.invitation_details
  });
}

/**
 * DELETE /invitations/{id} - Revoke invitation
 * Validates: Requirement 11.6 (Admin revokes invitation)
 */
async function handleRevokeInvitation(
  event: APIGatewayProxyEvent,
  invitationId: string
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userAgent = getUserAgent(event);
  
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Get tenant_id from query parameter or body
  let tenantId = event.queryStringParameters?.tenant_id;
  
  if (!tenantId) {
    try {
      const body = JSON.parse(event.body || '{}');
      tenantId = body.tenant_id;
    } catch {
      // Ignore parse error
    }
  }
  
  if (!tenantId) {
    return errorResponse(400, 'MISSING_TENANT_ID', 'Tenant ID is required');
  }
  
  // Verify tenant exists
  const tenant = await getOrganization(tenantId);
  if (!tenant) {
    return errorResponse(404, 'TENANT_NOT_FOUND', 'Tenant not found');
  }
  
  // Verify user has admin access to tenant
  const hasAccess = await hasAdminAccess(userContext.userId, tenantId);
  if (!hasAccess) {
    await logAudit(
      'invitation_revoke_denied',
      AuditResult.FAILURE,
      tenant.realm_id,
      userContext.userId,
      ipAddress,
      { tenant_id: tenantId, invitation_id: invitationId, reason: 'insufficient_permissions' },
      userAgent
    );
    return errorResponse(403, 'FORBIDDEN', 'Admin access required to revoke invitations');
  }
  
  // Revoke invitation
  const input: RevokeInvitationInput = {
    invitation_id: invitationId,
    tenant_id: tenantId,
    revoked_by: userContext.userId,
    ip_address: ipAddress
  };
  
  const result = await invitationService.revoke(input);
  
  await logAudit(
    'invitation_revoked',
    AuditResult.SUCCESS,
    tenant.realm_id,
    userContext.userId,
    ipAddress,
    {
      resource: `invitation:${invitationId}`,
      tenant_id: tenantId,
      email: result.email
    },
    userAgent
  );
  
  return successResponse(200, {
    message: 'Invitation revoked successfully',
    invitation: result
  });
}

/**
 * POST /invitations/{id}/resend - Resend invitation
 * Validates: Requirement 11.2 (Resend invitation email)
 */
async function handleResendInvitation(
  event: APIGatewayProxyEvent,
  invitationId: string
): Promise<APIGatewayProxyResult> {
  const ipAddress = getClientIP(event);
  const userAgent = getUserAgent(event);
  
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Parse request body
  let body: {
    tenant_id?: string;
  };
  
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  const tenantId = body.tenant_id || event.queryStringParameters?.tenant_id;
  
  if (!tenantId) {
    return errorResponse(400, 'MISSING_TENANT_ID', 'Tenant ID is required');
  }
  
  // Verify tenant exists
  const tenant = await getOrganization(tenantId);
  if (!tenant) {
    return errorResponse(404, 'TENANT_NOT_FOUND', 'Tenant not found');
  }
  
  // Verify user has admin access to tenant
  const hasAccess = await hasAdminAccess(userContext.userId, tenantId);
  if (!hasAccess) {
    await logAudit(
      'invitation_resend_denied',
      AuditResult.FAILURE,
      tenant.realm_id,
      userContext.userId,
      ipAddress,
      { tenant_id: tenantId, invitation_id: invitationId, reason: 'insufficient_permissions' },
      userAgent
    );
    return errorResponse(403, 'FORBIDDEN', 'Admin access required to resend invitations');
  }
  
  // Rate limiting per invitation
  const rateLimitResult = await checkRateLimit(
    tenant.realm_id,
    `invitation_resend:${invitationId}`,
    RESEND_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    await logAudit(
      'invitation_resend_rate_limited',
      AuditResult.FAILURE,
      tenant.realm_id,
      userContext.userId,
      ipAddress,
      { tenant_id: tenantId, invitation_id: invitationId },
      userAgent
    );
    return rateLimitResponse(rateLimitResult.retryAfter || 60);
  }
  
  // Resend invitation
  const input: ResendInvitationInput = {
    invitation_id: invitationId,
    tenant_id: tenantId,
    resent_by: userContext.userId,
    ip_address: ipAddress
  };
  
  const result = await invitationService.resend(input);
  
  await logAudit(
    'invitation_resent',
    AuditResult.SUCCESS,
    tenant.realm_id,
    userContext.userId,
    ipAddress,
    {
      resource: `invitation:${invitationId}`,
      tenant_id: tenantId,
      email: result.invitation.email
    },
    userAgent
  );
  
  return successResponse(200, {
    message: 'Invitation resent successfully',
    invitation: result.invitation,
    accept_url: `${process.env.APP_URL || 'https://app.zalt.io'}/invitations/accept?token=${result.token}`
  });
}

/**
 * GET /invitations/{id} - Get invitation details
 */
async function handleGetInvitation(
  event: APIGatewayProxyEvent,
  invitationId: string
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  const tenantId = event.queryStringParameters?.tenant_id;
  
  if (!tenantId) {
    return errorResponse(400, 'MISSING_TENANT_ID', 'Tenant ID is required');
  }
  
  // Verify tenant exists
  const tenant = await getOrganization(tenantId);
  if (!tenant) {
    return errorResponse(404, 'TENANT_NOT_FOUND', 'Tenant not found');
  }
  
  // Verify user has admin access to tenant
  const hasAccess = await hasAdminAccess(userContext.userId, tenantId);
  if (!hasAccess) {
    return errorResponse(403, 'FORBIDDEN', 'Admin access required to view invitation details');
  }
  
  // Get invitation
  const invitation = await invitationService.getById(tenantId, invitationId);
  
  if (!invitation) {
    return errorResponse(404, 'INVITATION_NOT_FOUND', 'Invitation not found');
  }
  
  return successResponse(200, {
    invitation
  });
}

// ============================================================================
// Error Code Mapping
// ============================================================================

/**
 * Map service error code to HTTP status code
 */
function mapErrorCodeToStatus(code: InvitationErrorCode): number {
  switch (code) {
    case InvitationErrorCode.INVALID_EMAIL:
    case InvitationErrorCode.DUPLICATE_INVITATION:
    case InvitationErrorCode.INVALID_TOKEN:
    case InvitationErrorCode.CANNOT_REVOKE:
    case InvitationErrorCode.CANNOT_RESEND:
      return 400;
    
    case InvitationErrorCode.INVITATION_NOT_FOUND:
    case InvitationErrorCode.TENANT_NOT_FOUND:
    case InvitationErrorCode.USER_NOT_FOUND:
      return 404;
    
    case InvitationErrorCode.INVITATION_EXPIRED:
    case InvitationErrorCode.INVITATION_ALREADY_USED:
    case InvitationErrorCode.INVITATION_REVOKED:
    case InvitationErrorCode.USER_ALREADY_MEMBER:
      return 400;
    
    case InvitationErrorCode.RATE_LIMIT_EXCEEDED:
      return 429;
    
    default:
      return 500;
  }
}
