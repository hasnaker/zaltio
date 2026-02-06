/**
 * Tediyat Tenant List Handler
 * Lists all tenants for authenticated user
 * 
 * GET /api/v1/tenants
 * Validates: Requirements 10.1-10.3
 * Property 15: Tenant List Completeness
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import * as membershipService from '../../services/tediyat/membership.service';
import * as tenantService from '../../services/tediyat/tenant.service';

const TEDIYAT_REALM_ID = 'tediyat';

function extractBearerToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.['Authorization'] || event.headers?.['authorization'];
  return authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;
}

function createResponse(statusCode: number, body: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
    },
    body: JSON.stringify(body),
  };
}

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const token = extractBearerToken(event);
    if (!token) {
      return createResponse(401, { success: false, error: { code: 'UNAUTHORIZED', message: 'Token gerekli' } });
    }

    let tokenPayload;
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, { success: false, error: { code: 'INVALID_TOKEN', message: 'Geçersiz token' } });
    }

    if (tokenPayload.realm_id !== TEDIYAT_REALM_ID) {
      return createResponse(403, { success: false, error: { code: 'FORBIDDEN', message: 'Yetki yok' } });
    }

    const userId = tokenPayload.sub;
    const membershipsResult = await membershipService.listUserMemberships(userId);
    const memberships = membershipsResult.success ? membershipsResult.data || [] : [];

    const tenantsResult = await tenantService.listUserTenants(userId, memberships);
    const tenants = (tenantsResult.data || []).map((t) => ({
      id: t.id,
      name: t.name,
      slug: t.slug,
      role: t.role,
      role_name: t.role_name,
      is_default: t.is_default,
      created_at: t.created_at,
    }));

    return createResponse(200, {
      success: true,
      data: { tenants, total: tenants.length },
    });
  } catch (error) {
    console.error('Tenant list error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR', message: 'Hata oluştu' } });
  }
}
