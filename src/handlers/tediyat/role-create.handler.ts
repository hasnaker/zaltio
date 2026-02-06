/**
 * Tediyat Role Create Handler
 * POST /api/v1/tenants/{tenantId}/roles
 * 
 * Validates: Requirements 17.1-17.4
 * Creates custom role for tenant
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
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
    if (!tenantId) return createResponse(400, { success: false, error: { code: 'INVALID_TENANT_ID' } });

    if (!event.body) return createResponse(400, { success: false, error: { code: 'INVALID_REQUEST' } });

    let request;
    try {
      request = JSON.parse(event.body);
    } catch {
      return createResponse(400, { success: false, error: { code: 'INVALID_JSON' } });
    }

    if (!request.name || request.name.trim().length < 2) {
      return createResponse(400, { success: false, error: { code: 'INVALID_NAME', message: 'Rol adı en az 2 karakter olmalı' } });
    }

    if (!request.permissions || !Array.isArray(request.permissions)) {
      return createResponse(400, { success: false, error: { code: 'INVALID_PERMISSIONS', message: 'Yetkiler gerekli' } });
    }

    const userId = tokenPayload.sub;
    const userMembership = await membershipService.getMembership(userId, tenantId);
    
    if (!userMembership.success || !userMembership.data) {
      return createResponse(403, { success: false, error: { code: 'FORBIDDEN' } });
    }

    // Only owner/admin can create roles
    if (!['role_owner', 'role_admin'].includes(userMembership.data.role_id)) {
      return createResponse(403, { success: false, error: { code: 'FORBIDDEN', message: 'Rol oluşturma yetkisi yok' } });
    }

    const result = await roleService.createCustomRole(
      {
        tenant_id: tenantId,
        name: request.name.trim(),
        description: request.description,
        permissions: request.permissions,
        inherits_from: request.inherits_from,
      },
      userMembership.data.role_id
    );

    if (!result.success) {
      const statusCode = result.code === 'ROLE_EXISTS' ? 409 : 400;
      return createResponse(statusCode, { success: false, error: { code: result.code, message: result.error } });
    }

    await logSecurityEvent({
      event_type: 'role_created',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      user_id: userId,
      details: { tenant_id: tenantId, role_name: request.name },
    });

    return createResponse(201, {
      success: true,
      data: { role: result.data },
    });
  } catch (error) {
    console.error('Role create error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR' } });
  }
}
