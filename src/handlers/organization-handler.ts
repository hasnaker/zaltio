/**
 * Organization Handler - CRUD endpoints for organizations
 * Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  createOrganization,
  getOrganization,
  listOrganizations,
  updateOrganization,
  deleteOrganization,
} from '../repositories/organization.repository';
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
 * Extract user info from JWT (simplified - real impl uses JWT verification)
 */
function extractUserFromEvent(event: APIGatewayProxyEvent): { userId: string; realmId: string } | null {
  const authHeader = event.headers['Authorization'] || event.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }

  // In production, this would verify the JWT and extract claims
  // For now, we'll use headers for testing
  const realmId = event.headers['X-Realm-ID'] || event.headers['x-realm-id'];
  
  // Decode JWT payload (simplified)
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
  const orgId = event.pathParameters?.id || event.pathParameters?.orgId;

  try {
    // Extract user from JWT
    const user = extractUserFromEvent(event);
    if (!user) {
      return unauthorized();
    }

    // Route to appropriate handler
    if (method === 'POST' && path.endsWith('/organizations')) {
      return await handleCreate(event, user);
    }

    if (method === 'GET' && path.endsWith('/organizations')) {
      return await handleList(event, user);
    }

    if (method === 'GET' && orgId) {
      return await handleGet(orgId, user);
    }

    if (method === 'PATCH' && orgId) {
      return await handleUpdate(event, orgId, user);
    }

    if (method === 'DELETE' && orgId) {
      return await handleDelete(orgId, user);
    }

    return notFound('Endpoint not found');
  } catch (error) {
    console.error('Organization handler error:', error);
    return serverError();
  }
}


/**
 * POST /admin/organizations - Create organization
 */
async function handleCreate(
  event: APIGatewayProxyEvent,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  // Parse body
  let body: {
    name?: string;
    slug?: string;
    logo_url?: string;
    custom_data?: Record<string, unknown>;
    settings?: {
      user_limit?: number;
      mfa_required?: boolean;
      allowed_domains?: string[];
      default_role_id?: string;
    };
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

  if (body.name.length < 2 || body.name.length > 100) {
    return badRequest('Name must be between 2 and 100 characters');
  }

  // Validate slug if provided
  if (body.slug) {
    if (!/^[a-z0-9-]+$/.test(body.slug)) {
      return badRequest('Slug must contain only lowercase letters, numbers, and hyphens');
    }
    if (body.slug.length < 2 || body.slug.length > 50) {
      return badRequest('Slug must be between 2 and 50 characters');
    }
  }

  try {
    const org = await createOrganization({
      realm_id: user.realmId,
      name: body.name,
      slug: body.slug,
      logo_url: body.logo_url,
      custom_data: body.custom_data,
      settings: body.settings,
    });

    // TODO: Add audit log
    console.log('Organization created:', {
      org_id: org.id,
      realm_id: org.realm_id,
      created_by: user.userId,
    });

    return created(org);
  } catch (error) {
    if (error instanceof Error && error.message.includes('already exists')) {
      return badRequest(error.message);
    }
    throw error;
  }
}

/**
 * GET /admin/organizations - List organizations
 */
async function handleList(
  event: APIGatewayProxyEvent,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  const status = event.queryStringParameters?.status as 'active' | 'suspended' | 'deleted' | undefined;
  const limit = parseInt(event.queryStringParameters?.limit || '50', 10);
  const cursor = event.queryStringParameters?.cursor;

  // Validate limit
  if (limit < 1 || limit > 100) {
    return badRequest('Limit must be between 1 and 100');
  }

  const result = await listOrganizations({
    realm_id: user.realmId,
    status,
    limit,
    cursor,
  });

  return success(result);
}

/**
 * GET /admin/organizations/:id - Get organization
 */
async function handleGet(
  orgId: string,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  const org = await getOrganization(orgId);

  if (!org) {
    return notFound('Organization not found');
  }

  // Verify realm isolation
  if (org.realm_id !== user.realmId) {
    return notFound('Organization not found');
  }

  return success(org);
}

/**
 * PATCH /admin/organizations/:id - Update organization
 */
async function handleUpdate(
  event: APIGatewayProxyEvent,
  orgId: string,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  // Get existing org first
  const existing = await getOrganization(orgId);
  if (!existing) {
    return notFound('Organization not found');
  }

  // Verify realm isolation
  if (existing.realm_id !== user.realmId) {
    return notFound('Organization not found');
  }

  // Check permission
  const hasPermissionResult = await checkPermission(user.userId, orgId, PERMISSIONS.ORGS_UPDATE);
  if (!hasPermissionResult) {
    return forbidden();
  }

  // Parse body
  let body: {
    name?: string;
    slug?: string;
    logo_url?: string;
    custom_data?: Record<string, unknown>;
    settings?: {
      user_limit?: number;
      mfa_required?: boolean;
      allowed_domains?: string[];
      default_role_id?: string;
    };
    status?: 'active' | 'suspended';
  };

  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return badRequest('Invalid JSON body');
  }

  // Validate fields if provided
  if (body.name !== undefined) {
    if (typeof body.name !== 'string' || body.name.length < 2 || body.name.length > 100) {
      return badRequest('Name must be between 2 and 100 characters');
    }
  }

  if (body.slug !== undefined) {
    if (!/^[a-z0-9-]+$/.test(body.slug)) {
      return badRequest('Slug must contain only lowercase letters, numbers, and hyphens');
    }
  }

  try {
    const updated = await updateOrganization(orgId, body);

    // TODO: Add audit log
    console.log('Organization updated:', {
      org_id: orgId,
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
 * DELETE /admin/organizations/:id - Soft delete organization
 */
async function handleDelete(
  orgId: string,
  user: { userId: string; realmId: string }
): Promise<APIGatewayProxyResult> {
  // Get existing org first
  const existing = await getOrganization(orgId);
  if (!existing) {
    return notFound('Organization not found');
  }

  // Verify realm isolation
  if (existing.realm_id !== user.realmId) {
    return notFound('Organization not found');
  }

  // Check permission
  const hasPermissionResult = await checkPermission(user.userId, orgId, PERMISSIONS.ORGS_DELETE);
  if (!hasPermissionResult) {
    return forbidden();
  }

  const deleted = await deleteOrganization(orgId);

  if (!deleted) {
    return serverError('Failed to delete organization');
  }

  // TODO: Add audit log
  console.log('Organization deleted:', {
    org_id: orgId,
    deleted_by: user.userId,
  });

  return success({ message: 'Organization deleted', id: orgId });
}
