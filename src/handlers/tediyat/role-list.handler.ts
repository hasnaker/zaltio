/**
 * Tediyat Role List Handler
 * GET /api/v1/tenants/{tenantId}/roles
 * 
 * Validates: Requirements 16.1-16.6
 * Returns system roles + custom roles for tenant
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import * as membershipService from '../../services/tediyat/membership.service';
import * as roleService from '../../services/tediyat/role.service';

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

    const tenantId = event.pathParameters?.tenantId;
    if (!tenantId) return createResponse(400, { success: false, error: { code: 'INVALID_TENANT_ID' } });

    const userId = tokenPayload.sub;
    const userMembership = await membershipService.getMembership(userId, tenantId);
    
    if (!userMembership.success || !userMembership.data) {
      return createResponse(403, { success: false, error: { code: 'FORBIDDEN' } });
    }

    // Get system roles
    const systemRoles = roleService.getSystemRoles();

    // Get custom roles for tenant
    const customRolesResult = await roleService.listTenantRoles(tenantId);
    const customRoles = customRolesResult.success ? customRolesResult.data || [] : [];

    return createResponse(200, {
      success: true,
      data: {
        systemRoles: systemRoles.map(r => ({
          id: r.id,
          name: r.name,
          description: r.description,
          permissions: r.permissions,
          isSystem: true,
        })),
        customRoles: customRoles.map(r => ({
          id: r.id,
          name: r.name,
          description: r.description,
          permissions: r.permissions,
          isSystem: false,
        })),
      },
    });
  } catch (error) {
    console.error('Role list error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR' } });
  }
}
