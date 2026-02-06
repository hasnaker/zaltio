/**
 * Tediyat Permissions Handler
 * GET /api/v1/auth/permissions?tenant_id=xxx
 * 
 * Returns full permission set for users with >50 permissions
 * Validates: Requirements 23.1
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { getMembership } from '../../services/tediyat/membership.service';
import { getEffectivePermissions } from '../../services/tediyat/role.service';

const TEDIYAT_REALM_ID = 'tediyat';

function extractBearerToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.['Authorization'] || event.headers?.['authorization'];
  return authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;
}

function createResponse(statusCode: number, body: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body),
  };
}

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const token = extractBearerToken(event);
    if (!token) return createResponse(401, { success: false, error: { code: 'UNAUTHORIZED' } });

    let tokenPayload;
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, { success: false, error: { code: 'INVALID_TOKEN' } });
    }

    if (tokenPayload.realm_id !== TEDIYAT_REALM_ID) {
      return createResponse(403, { success: false, error: { code: 'FORBIDDEN' } });
    }

    const userId = tokenPayload.sub;
    const tenantId = event.queryStringParameters?.tenant_id;

    if (!tenantId) {
      return createResponse(400, { success: false, error: { code: 'TENANT_ID_REQUIRED' } });
    }

    // Get user's membership in tenant
    const membershipResult = await getMembership(tenantId, userId);
    if (!membershipResult.success || !membershipResult.data) {
      return createResponse(403, { success: false, error: { code: 'NOT_A_MEMBER' } });
    }

    const membership = membershipResult.data;

    // Get effective permissions for user's role
    const permissions = await getEffectivePermissions(membership.role_id);

    return createResponse(200, {
      success: true,
      data: {
        tenant_id: tenantId,
        role_id: membership.role_id,
        permissions,
        total: permissions.length,
      },
    });
  } catch (error) {
    console.error('Permissions handler error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR' } });
  }
}
