/**
 * Role Handler - CRUD endpoints for roles
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  createRole,
  getRole,
  listRoles,
  updateRole,
  deleteRole,
  getEffectivePermissions,
} from '../repositories/role.repository';
import { isSystemRole, SYSTEM_ROLES } from '../models/role.model';
import { checkPermission } from '../services/permission.service';
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
function extractUserFromEvent(event: APIGatewayProxyEvent): { userId: string; realmId: string; orgId?: string } | null {
  const authHeader = event.headers['Authorization'] || event.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }

  const realmId = event.headers['X-Realm-ID'] || event.headers['x-realm-id'];
  const orgId = event.headers['X-Org-ID'] || event.headers['x-org-id'];
  
  try {
    const token = authHeader.substring(7);
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return {
      userId: payload.sub || payload.user_id,
      realmId: realmId || payload.realm_id,
      orgId: orgId || payload.org_id,
    };
  } catch {
    return null;
  }
}

/**
 * Main handler
 */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const method = event.httpMethod;
  const path = event.path;
  const roleId = event.pathParameters?.id || event.pathParameters?.roleId;

  try {
    const user = extractUserFromEvent(event);
    if (!user) {
      return unauthorized();
    }

    // Route to appropriate handler
    if (method === 'POST' && path.endsWith('/roles')) {
      return await handleCreate(event, user);
    }

    if (method === 'GET' && path.endsWith('/roles')) {
      return await handleList(event, user);
    }

    if (method === 'GET' && path.endsWith('/system-roles')) {
      return handleSystemRoles();
    }

    if (method === 'GET' && roleId && path.includes('/permissions')) {
      return await handleGetPermissions(roleId);
    }

    if (method === 'GET' && roleId) {
      return await handleGet(roleId, user);
    }

    if (method === 'PATCH' && roleId) {
      return await handleUpdate(event, roleId, user);
    }

    if (method === 'DELETE' && roleId) {
      return await handleDelete(roleId, user);
    }

    return notFound('Endpoint not found');
  } catch (error) {
    console.error('Role handler error:', error);
    return serverError();
  }
}

/**
 * GET /admin/roles/system - List system roles
 */
function handleSystemRoles(): APIGatewayProxyResult {
  const roles = Object.values(SYSTEM_ROLES).map(role => ({
    id: role.id,
    name: role.name,
    description: role.description,
    permissions: role.permissions,
    is_system: true,
  }));

  return success({ roles });
}

/**
 * POST /admin/roles - Create role
 */
async function handleCreate(
  event: APIGatewayProxyEvent,
  user: { userId: string; realmId: string; orgId?: string }
): Promise<APIGatewayProxyResult> {
  // Check permission
  if (user.orgId) {
    const canCreate = await checkPermission(user.userId, user.orgId, PERMISSIONS.ROLES_CREATE);
    if (!canCreate) {
      return forbidden();
    }
  }

  let body: {
    name?: string;
    description?: string;
    permissions?: string[];
    org_id?: string;
    inherits_from?: string[];
  };

  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return badRequest('Invalid JSON body');
  }

  // Validate required fields
  if (!body.name || typeof body.name !== 'string') {
    return badRequest('Name is required');
  }

  if (body.name.length < 2 || body.name.length > 50) {
    return badRequest('Name must be between 2 and 50 characters');
  }

  // Validate permissions format
  if (body.permissions) {
    for (const perm of body.permissions) {
      if (typeof perm !== 'string' || !perm.includes(':')) {
        if (perm !== '*') {
          return badRequest(`Invalid permission format: ${perm}`);
        }
      }
    }
  }

  try {
    const role = await createRole({
      realm_id: user.realmId,
      org_id: body.org_id || user.orgId,
      name: body.name,
      description: body.description,
      permissions: body.permissions || [],
      inherits_from: body.inherits_from,
    });

    console.log('Role created:', {
      role_id: role.id,
      realm_id: role.realm_id,
      created_by: user.userId,
    });

    return created(role);
  } catch (error) {
    if (error instanceof Error && error.message.includes('already exists')) {
      return badRequest(error.message);
    }
    throw error;
  }
}

/**
 * GET /admin/roles - List roles
 */
async function handleList(
  event: APIGatewayProxyEvent,
  user: { userId: string; realmId: string; orgId?: string }
): Promise<APIGatewayProxyResult> {
  const orgId = event.queryStringParameters?.org_id || user.orgId;
  const includeSystem = event.queryStringParameters?.include_system !== 'false';
  const limit = parseInt(event.queryStringParameters?.limit || '50', 10);
  const cursor = event.queryStringParameters?.cursor;

  if (limit < 1 || limit > 100) {
    return badRequest('Limit must be between 1 and 100');
  }

  const result = await listRoles({
    realm_id: user.realmId,
    org_id: orgId,
    include_system: includeSystem,
    limit,
    cursor,
  });

  return success(result);
}

/**
 * GET /admin/roles/:id - Get role
 */
async function handleGet(
  roleId: string,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  const role = await getRole(roleId);

  if (!role) {
    return notFound('Role not found');
  }

  // Verify realm isolation (system roles have realm_id = '*')
  if (role.realm_id !== '*' && role.realm_id !== user.realmId) {
    return notFound('Role not found');
  }

  return success(role);
}

/**
 * GET /admin/roles/:id/permissions - Get effective permissions
 */
async function handleGetPermissions(roleId: string): Promise<APIGatewayProxyResult> {
  const permissions = await getEffectivePermissions(roleId);

  if (permissions.length === 0 && !isSystemRole(roleId)) {
    const role = await getRole(roleId);
    if (!role) {
      return notFound('Role not found');
    }
  }

  return success({ role_id: roleId, permissions });
}

/**
 * PATCH /admin/roles/:id - Update role
 */
async function handleUpdate(
  event: APIGatewayProxyEvent,
  roleId: string,
  user: { userId: string; realmId: string; orgId?: string }
): Promise<APIGatewayProxyResult> {
  // Check if system role
  if (isSystemRole(roleId)) {
    return forbidden('System roles cannot be modified');
  }

  // Get existing role
  const existing = await getRole(roleId);
  if (!existing) {
    return notFound('Role not found');
  }

  // Verify realm isolation
  if (existing.realm_id !== user.realmId) {
    return notFound('Role not found');
  }

  // Check permission
  if (existing.org_id) {
    const canUpdate = await checkPermission(user.userId, existing.org_id, PERMISSIONS.ROLES_UPDATE);
    if (!canUpdate) {
      return forbidden();
    }
  }

  let body: {
    name?: string;
    description?: string;
    permissions?: string[];
    inherits_from?: string[];
  };

  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return badRequest('Invalid JSON body');
  }

  // Validate name if provided
  if (body.name !== undefined) {
    if (typeof body.name !== 'string' || body.name.length < 2 || body.name.length > 50) {
      return badRequest('Name must be between 2 and 50 characters');
    }
  }

  try {
    const updated = await updateRole(roleId, body);

    console.log('Role updated:', {
      role_id: roleId,
      updated_by: user.userId,
      changes: Object.keys(body),
    });

    return success(updated);
  } catch (error) {
    if (error instanceof Error && error.message.includes('already exists')) {
      return badRequest(error.message);
    }
    throw error;
  }
}

/**
 * DELETE /admin/roles/:id - Delete role
 */
async function handleDelete(
  roleId: string,
  user: { userId: string; realmId: string; orgId?: string }
): Promise<APIGatewayProxyResult> {
  // Check if system role
  if (isSystemRole(roleId)) {
    return forbidden('System roles cannot be deleted');
  }

  // Get existing role
  const existing = await getRole(roleId);
  if (!existing) {
    return notFound('Role not found');
  }

  // Verify realm isolation
  if (existing.realm_id !== user.realmId) {
    return notFound('Role not found');
  }

  // Check permission
  if (existing.org_id) {
    const canDelete = await checkPermission(user.userId, existing.org_id, PERMISSIONS.ROLES_DELETE);
    if (!canDelete) {
      return forbidden();
    }
  }

  try {
    const deleted = await deleteRole(roleId);

    if (!deleted) {
      return serverError('Failed to delete role');
    }

    console.log('Role deleted:', {
      role_id: roleId,
      deleted_by: user.userId,
    });

    return success({ message: 'Role deleted', id: roleId });
  } catch (error) {
    if (error instanceof Error && error.message.includes('cannot be deleted')) {
      return forbidden(error.message);
    }
    throw error;
  }
}
