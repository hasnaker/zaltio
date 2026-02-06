/**
 * Membership Handler - CRUD endpoints for organization memberships
 * Validates: Requirements 2.1, 2.2, 2.4, 2.6
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  createMembership,
  getMembership,
  listOrganizationMembers,
  updateMembership,
  deleteMembership,
} from '../repositories/membership.repository';
import { getOrganization } from '../repositories/organization.repository';
import { validateRoleIds } from '../repositories/role.repository';
import { checkPermission, clearPermissionCache } from '../services/permission.service';
import { PERMISSIONS } from '../utils/permissions';

// Response helpers
const response = (statusCode: number, body: unknown): APIGatewayProxyResult => ({
  statusCode,
  headers: {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Realm-ID',
  },
  body: JSON.stringify(body),
});

const success = (data: unknown) => response(200, data);
const created = (data: unknown) => response(201, data);
const badRequest = (message: string) => response(400, { error: message, code: 'BAD_REQUEST' });
const unauthorized = () => response(401, { error: 'Unauthorized', code: 'UNAUTHORIZED' });
const forbidden = (message = 'Permission denied') => response(403, { error: message, code: 'FORBIDDEN' });
const notFound = (message = 'Not found') => response(404, { error: message, code: 'NOT_FOUND' });
const serverError = (message = 'Internal server error') => response(500, { error: message, code: 'INTERNAL_ERROR' });

/**
 * Extract user info from JWT
 */
function extractUserFromEvent(event: APIGatewayProxyEvent): { userId: string; realmId: string } | null {
  const authHeader = event.headers['Authorization'] || event.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }

  const realmId = event.headers['X-Realm-ID'] || event.headers['x-realm-id'];
  
  try {
    const token = authHeader.substring(7);
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return {
      userId: payload.sub || payload.user_id,
      realmId: realmId || payload.realm_id,
    };
  } catch {
    return null;
  }
}

/**
 * Main handler - routes requests to appropriate function
 */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const method = event.httpMethod;
  const path = event.path;
  const orgId = event.pathParameters?.orgId || event.pathParameters?.id;
  const memberId = event.pathParameters?.memberId || event.pathParameters?.userId;

  try {
    const user = extractUserFromEvent(event);
    if (!user) {
      return unauthorized();
    }

    // Verify organization exists and belongs to realm
    if (orgId) {
      const org = await getOrganization(orgId);
      if (!org || org.realm_id !== user.realmId) {
        return notFound('Organization not found');
      }
    }

    // Route to appropriate handler
    if (method === 'POST' && path.includes('/members') && !memberId) {
      return await handleInvite(event, orgId!, user);
    }

    if (method === 'GET' && path.includes('/members') && !memberId) {
      return await handleList(event, orgId!, user);
    }

    if (method === 'GET' && memberId) {
      return await handleGet(orgId!, memberId, user);
    }

    if (method === 'PATCH' && memberId) {
      return await handleUpdate(event, orgId!, memberId, user);
    }

    if (method === 'DELETE' && memberId) {
      return await handleRemove(orgId!, memberId, user);
    }

    return notFound('Endpoint not found');
  } catch (error) {
    console.error('Membership handler error:', error);
    return serverError();
  }
}


/**
 * POST /admin/organizations/:orgId/members - Invite member
 */
async function handleInvite(
  event: APIGatewayProxyEvent,
  orgId: string,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  // Check permission
  const canInvite = await checkPermission(user.userId, orgId, PERMISSIONS.MEMBERS_INVITE);
  if (!canInvite) {
    return forbidden();
  }

  // Parse body
  let body: {
    user_id?: string;
    email?: string;
    role_ids?: string[];
    direct_permissions?: string[];
    is_default?: boolean;
  };

  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return badRequest('Invalid JSON body');
  }

  // Validate required fields
  if (!body.user_id && !body.email) {
    return badRequest('Either user_id or email is required');
  }

  // For now, we require user_id (email invite would need user lookup/creation)
  if (!body.user_id) {
    return badRequest('user_id is required (email invites not yet supported)');
  }

  // Validate role IDs if provided
  if (body.role_ids && body.role_ids.length > 0) {
    const { invalid } = await validateRoleIds(body.role_ids);
    if (invalid.length > 0) {
      return badRequest(`Invalid role IDs: ${invalid.join(', ')}`);
    }
  }

  try {
    const membership = await createMembership({
      user_id: body.user_id,
      org_id: orgId,
      realm_id: user.realmId,
      role_ids: body.role_ids,
      direct_permissions: body.direct_permissions,
      is_default: body.is_default,
      invited_by: user.userId,
    });

    console.log('Member invited:', {
      org_id: orgId,
      user_id: body.user_id,
      invited_by: user.userId,
    });

    return created(membership);
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('already a member')) {
        return badRequest(error.message);
      }
      if (error.message.includes('user limit')) {
        return badRequest(error.message);
      }
    }
    throw error;
  }
}

/**
 * GET /admin/organizations/:orgId/members - List members
 */
async function handleList(
  event: APIGatewayProxyEvent,
  orgId: string,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  // Check permission
  const canRead = await checkPermission(user.userId, orgId, PERMISSIONS.MEMBERS_READ);
  if (!canRead) {
    return forbidden();
  }

  const status = event.queryStringParameters?.status as 'active' | 'invited' | 'suspended' | undefined;
  const limit = parseInt(event.queryStringParameters?.limit || '50', 10);
  const cursor = event.queryStringParameters?.cursor;

  if (limit < 1 || limit > 100) {
    return badRequest('Limit must be between 1 and 100');
  }

  const result = await listOrganizationMembers({
    org_id: orgId,
    status,
    limit,
    cursor,
  });

  return success(result);
}

/**
 * GET /admin/organizations/:orgId/members/:memberId - Get member
 */
async function handleGet(
  orgId: string,
  memberId: string,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  // Check permission (can read own membership without permission)
  if (memberId !== user.userId) {
    const canRead = await checkPermission(user.userId, orgId, PERMISSIONS.MEMBERS_READ);
    if (!canRead) {
      return forbidden();
    }
  }

  const membership = await getMembership(memberId, orgId);
  if (!membership) {
    return notFound('Member not found');
  }

  return success(membership);
}

/**
 * PATCH /admin/organizations/:orgId/members/:memberId - Update member
 */
async function handleUpdate(
  event: APIGatewayProxyEvent,
  orgId: string,
  memberId: string,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  // Check permission
  const canUpdate = await checkPermission(user.userId, orgId, PERMISSIONS.ROLES_ASSIGN);
  if (!canUpdate) {
    return forbidden();
  }

  // Parse body
  let body: {
    role_ids?: string[];
    direct_permissions?: string[];
    is_default?: boolean;
    status?: 'active' | 'suspended';
  };

  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return badRequest('Invalid JSON body');
  }

  // Validate role IDs if provided
  if (body.role_ids && body.role_ids.length > 0) {
    const { invalid } = await validateRoleIds(body.role_ids);
    if (invalid.length > 0) {
      return badRequest(`Invalid role IDs: ${invalid.join(', ')}`);
    }
  }

  const updated = await updateMembership(memberId, orgId, body);
  if (!updated) {
    return notFound('Member not found');
  }

  // Clear permission cache for this user
  clearPermissionCache(memberId, orgId);

  console.log('Member updated:', {
    org_id: orgId,
    user_id: memberId,
    updated_by: user.userId,
    changes: Object.keys(body),
  });

  return success(updated);
}

/**
 * DELETE /admin/organizations/:orgId/members/:memberId - Remove member
 */
async function handleRemove(
  orgId: string,
  memberId: string,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  // Check permission
  const canRemove = await checkPermission(user.userId, orgId, PERMISSIONS.MEMBERS_REMOVE);
  if (!canRemove) {
    return forbidden();
  }

  // Prevent self-removal if owner
  if (memberId === user.userId) {
    // Check if user is the only owner
    const membership = await getMembership(memberId, orgId);
    if (membership?.role_ids.includes('role_owner')) {
      return badRequest('Cannot remove yourself as the only owner');
    }
  }

  const deleted = await deleteMembership(memberId, orgId);
  if (!deleted) {
    return notFound('Member not found');
  }

  // Clear permission cache
  clearPermissionCache(memberId, orgId);

  // TODO: Invalidate user sessions for this org
  console.log('Member removed:', {
    org_id: orgId,
    user_id: memberId,
    removed_by: user.userId,
  });

  return success({ message: 'Member removed', user_id: memberId, org_id: orgId });
}
