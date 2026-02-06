/**
 * Tediyat Member Remove Handler
 * DELETE /api/v1/tenants/{tenantId}/members/{userId}
 * 
 * Validates: Requirements 15.1-15.4
 * Property 19: Owner Protection on Removal
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
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
  const clientIP = event.requestContext?.identity?.sourceIp || 'unknown';

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
    const targetUserId = event.pathParameters?.userId;
    if (!tenantId || !targetUserId) {
      return createResponse(400, { success: false, error: { code: 'INVALID_PARAMS' } });
    }

    const requestingUserId = tokenPayload.sub;
    const userMembership = await membershipService.getMembership(requestingUserId, tenantId);
    
    if (!userMembership.success || !userMembership.data) {
      return createResponse(403, { success: false, error: { code: 'FORBIDDEN' } });
    }

    const result = await membershipService.deleteMembership(
      targetUserId,
      tenantId,
      requestingUserId,
      userMembership.data.role_id
    );

    if (!result.success) {
      if (result.code === 'CANNOT_REMOVE_OWNER') {
        return createResponse(400, { success: false, error: { code: 'CANNOT_REMOVE_OWNER', message: result.error } });
      }
      const statusCode = result.code === 'FORBIDDEN' ? 403 : result.code === 'MEMBERSHIP_NOT_FOUND' ? 404 : 500;
      return createResponse(statusCode, { success: false, error: { code: result.code, message: result.error } });
    }

    await logSecurityEvent({
      event_type: 'member_removed',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      user_id: requestingUserId,
      details: { tenant_id: tenantId, removed_user: targetUserId },
    });

    return createResponse(200, { success: true, data: { message: 'Üye başarıyla kaldırıldı' } });
  } catch (error) {
    console.error('Member remove error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR' } });
  }
}
