/**
 * Organization Switch Handler - Switch between organizations and get user's orgs
 * Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { getUserMemberships, getMembership } from '../repositories/membership.repository';
import { getOrganization } from '../repositories/organization.repository';
import { getUserPermissions } from '../services/permission.service';
import { generateTokenPair, verifyAccessToken } from '../utils/jwt';

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
const badRequest = (message: string) => response(400, { error: message, code: 'BAD_REQUEST' });
const unauthorized = () => response(401, { error: 'Unauthorized', code: 'UNAUTHORIZED' });
const forbidden = (message = 'Permission denied') => response(403, { error: message, code: 'FORBIDDEN' });
const notFound = (message = 'Not found') => response(404, { error: message, code: 'NOT_FOUND' });
const serverError = (message = 'Internal server error') => response(500, { error: message, code: 'INTERNAL_ERROR' });

/**
 * Extract and verify user from JWT
 */
async function extractUserFromEvent(event: APIGatewayProxyEvent): Promise<{
  userId: string;
  realmId: string;
  email: string;
} | null> {
  const authHeader = event.headers['Authorization'] || event.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }

  try {
    const token = authHeader.substring(7);
    const payload = await verifyAccessToken(token);
    return {
      userId: payload.sub,
      realmId: payload.realm_id,
      email: payload.email,
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

  try {
    const user = await extractUserFromEvent(event);
    if (!user) {
      return unauthorized();
    }

    // GET /v1/auth/organizations - List user's organizations
    if (method === 'GET' && path.endsWith('/organizations')) {
      return await handleListOrganizations(user);
    }

    // POST /v1/auth/switch-organization - Switch to another organization
    if (method === 'POST' && path.includes('/switch-organization')) {
      return await handleSwitchOrganization(event, user);
    }

    // GET /v1/auth/permissions - Get current permissions (for large permission sets)
    if (method === 'GET' && path.endsWith('/permissions')) {
      return await handleGetPermissions(event, user);
    }

    return notFound('Endpoint not found');
  } catch (error) {
    console.error('Org switch handler error:', error);
    return serverError();
  }
}

/**
 * GET /v1/auth/organizations - List user's organizations with roles
 */
async function handleListOrganizations(user: {
  userId: string;
  realmId: string;
  email: string;
}): Promise<APIGatewayProxyResult> {
  const memberships = await getUserMemberships({
    user_id: user.userId,
    realm_id: user.realmId,
    status: 'active',
  });

  const organizations = await Promise.all(
    memberships.map(async (membership) => {
      const org = await getOrganization(membership.org_id);
      return {
        id: membership.org_id,
        name: org?.name || 'Unknown',
        slug: org?.slug,
        logo_url: org?.logo_url,
        roles: membership.role_ids,
        is_default: membership.is_default,
        joined_at: membership.joined_at,
      };
    })
  );

  return success({
    organizations,
    total: organizations.length,
  });
}

/**
 * POST /v1/auth/switch-organization - Switch to another organization
 */
async function handleSwitchOrganization(
  event: APIGatewayProxyEvent,
  user: { userId: string; realmId: string; email: string }
): Promise<APIGatewayProxyResult> {
  let body: { org_id?: string };

  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return badRequest('Invalid JSON body');
  }

  if (!body.org_id) {
    return badRequest('org_id is required');
  }

  // Verify membership
  const membership = await getMembership(user.userId, body.org_id);
  if (!membership || membership.status !== 'active') {
    return forbidden('Not a member of this organization');
  }

  // Verify organization is in same realm
  const org = await getOrganization(body.org_id);
  if (!org || org.realm_id !== user.realmId) {
    return notFound('Organization not found');
  }

  if (org.status !== 'active') {
    return forbidden('Organization is not active');
  }

  // Get permissions for new organization
  const permissions = await getUserPermissions(user.userId, body.org_id);

  // Get all user's org IDs
  const allMemberships = await getUserMemberships({
    user_id: user.userId,
    realm_id: user.realmId,
    status: 'active',
  });
  const orgIds = allMemberships.map(m => m.org_id);

  // Generate new token pair with organization context
  const tokenPair = await generateTokenPair(
    user.userId,
    user.realmId,
    user.email,
    {
      orgId: body.org_id,
      orgIds,
      roles: membership.role_ids,
      permissions,
    }
  );

  // Audit log
  console.log('Organization switched:', {
    event: 'org_switch',
    user_id: user.userId,
    realm_id: user.realmId,
    new_org_id: body.org_id,
    timestamp: new Date().toISOString(),
  });

  return success({
    ...tokenPair,
    organization: {
      id: org.id,
      name: org.name,
      slug: org.slug,
    },
    roles: membership.role_ids,
    permissions: permissions.length <= 50 ? permissions : undefined,
    permissions_url: permissions.length > 50 ? 'https://api.zalt.io/v1/auth/permissions' : undefined,
  });
}

/**
 * GET /v1/auth/permissions - Get current user's permissions
 * Used when permissions > 50 and not included in JWT
 */
async function handleGetPermissions(
  event: APIGatewayProxyEvent,
  user: { userId: string; realmId: string; email: string }
): Promise<APIGatewayProxyResult> {
  const orgId = event.queryStringParameters?.org_id ||
    event.headers['X-Org-ID'] ||
    event.headers['x-org-id'];

  if (!orgId) {
    return badRequest('org_id is required (query param or X-Org-ID header)');
  }

  // Verify membership
  const membership = await getMembership(user.userId, orgId);
  if (!membership || membership.status !== 'active') {
    return forbidden('Not a member of this organization');
  }

  const permissions = await getUserPermissions(user.userId, orgId);

  return success({
    user_id: user.userId,
    org_id: orgId,
    permissions,
    roles: membership.role_ids,
  });
}
