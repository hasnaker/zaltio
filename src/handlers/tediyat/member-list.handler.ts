/**
 * Tediyat Member List Handler
 * GET /api/v1/tenants/{tenantId}/members
 * 
 * Validates: Requirements 14.1-14.4
 * Property 18: Member List Authorization
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import * as membershipService from '../../services/tediyat/membership.service';

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
      return createResponse(403, { success: false, error: { code: 'FORBIDDEN', message: 'Bu şirkete erişiminiz yok' } });
    }

    const page = parseInt(event.queryStringParameters?.page || '1', 10);
    const pageSize = parseInt(event.queryStringParameters?.page_size || '50', 10);

    const result = await membershipService.listTenantMembers(
      tenantId,
      userId,
      userMembership.data.role_id,
      page,
      Math.min(pageSize, 100)
    );

    if (!result.success) {
      if (result.code === 'FORBIDDEN') {
        return createResponse(403, { success: false, error: { code: 'FORBIDDEN', message: result.error } });
      }
      return createResponse(500, { success: false, error: { code: 'LIST_FAILED' } });
    }

    return createResponse(200, { success: true, data: result.data });
  } catch (error) {
    console.error('Member list error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR' } });
  }
}
