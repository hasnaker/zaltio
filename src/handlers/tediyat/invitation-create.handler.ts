/**
 * Tediyat Invitation Create Handler
 * POST /api/v1/tenants/{tenantId}/invitations
 * 
 * Validates: Requirements 12.1-12.4
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { validateEmail } from '../../utils/validation';
import { logSecurityEvent } from '../../services/security-logger.service';
import * as membershipService from '../../services/tediyat/membership.service';
import * as invitationService from '../../services/tediyat/invitation.service';

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

    const emailValidation = validateEmail(request.email);
    if (!emailValidation.valid) {
      return createResponse(400, { success: false, error: { code: 'INVALID_EMAIL' } });
    }

    if (!request.role_id) {
      return createResponse(400, { success: false, error: { code: 'INVALID_ROLE', message: 'Rol gerekli' } });
    }

    const requestingUserId = tokenPayload.sub;
    const userMembership = await membershipService.getMembership(requestingUserId, tenantId);
    
    if (!userMembership.success || !userMembership.data) {
      return createResponse(403, { success: false, error: { code: 'FORBIDDEN' } });
    }

    // Only owner/admin can invite
    if (!['role_owner', 'role_admin'].includes(userMembership.data.role_id)) {
      return createResponse(403, { success: false, error: { code: 'FORBIDDEN', message: 'Davet yetkisi yok' } });
    }

    const result = await invitationService.createInvitation(
      {
        tenant_id: tenantId,
        tenant_name: request.tenant_name || 'Tediyat',
        email: request.email,
        role_id: request.role_id,
        role_name: request.role_name || request.role_id,
        invited_by: requestingUserId,
        invited_by_name: request.inviter_name || 'Tediyat User',
      },
      userMembership.data.role_id
    );

    if (!result.success) {
      return createResponse(400, { success: false, error: { code: result.code || 'CREATE_FAILED', message: result.error } });
    }

    await logSecurityEvent({
      event_type: 'invitation_created',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      user_id: requestingUserId,
      details: { tenant_id: tenantId, invited_email: request.email.substring(0, 3) + '***' },
    });

    const invitation = result.data?.invitation;
    return createResponse(201, {
      success: true,
      data: {
        invitation: {
          id: invitation?.id,
          email: invitation?.email,
          role_id: invitation?.role_id,
          status: invitation?.status,
          expires_at: invitation?.expires_at,
        },
        inviteUrl: result.data?.inviteUrl,
      },
    });
  } catch (error) {
    console.error('Invitation create error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR' } });
  }
}
