/**
 * Tediyat Invitation Accept Handler
 * POST /api/v1/invitations/{token}/accept
 * 
 * Validates: Requirements 13.1-13.4
 * Supports both existing and new users
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { findUserByEmail, createUser } from '../../repositories/user.repository';
import { validateEmail, validatePassword } from '../../utils/validation';
import { validatePasswordPolicy, checkPasswordPwned } from '../../utils/password';
import { generateTokenPair } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
import { createSession } from '../../repositories/session.repository';
import * as invitationService from '../../services/tediyat/invitation.service';
import * as membershipService from '../../services/tediyat/membership.service';
import * as tenantService from '../../services/tediyat/tenant.service';

const TEDIYAT_REALM_ID = 'tediyat';
const TEDIYAT_TOKEN_CONFIG = { accessTokenExpiry: 3600, refreshTokenExpiry: 30 * 24 * 60 * 60 };

function createResponse(statusCode: number, body: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body),
  };
}

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIP = event.requestContext?.identity?.sourceIp || 'unknown';
  const userAgent = event.headers?.['User-Agent'] || 'unknown';

  try {
    const invitationToken = event.pathParameters?.token;
    if (!invitationToken) {
      return createResponse(400, { success: false, error: { code: 'INVALID_TOKEN' } });
    }

    if (!event.body) {
      return createResponse(400, { success: false, error: { code: 'INVALID_REQUEST' } });
    }

    let request;
    try {
      request = JSON.parse(event.body);
    } catch {
      return createResponse(400, { success: false, error: { code: 'INVALID_JSON' } });
    }

    // Get invitation by token
    const invitationResult = await invitationService.getInvitationByToken(invitationToken);
    if (!invitationResult.success || !invitationResult.data) {
      return createResponse(404, { success: false, error: { code: 'INVITATION_NOT_FOUND' } });
    }

    const invitation = invitationResult.data;

    // Check if invitation is still valid
    if (!invitationService.canAcceptInvitation(invitation)) {
      return createResponse(400, { success: false, error: { code: 'INVITATION_EXPIRED' } });
    }

    // Check if user exists
    let user = await findUserByEmail(TEDIYAT_REALM_ID, invitation.email);
    let isNewUser = false;

    if (!user) {
      // New user - require password
      if (!request.password) {
        return createResponse(400, { success: false, error: { code: 'PASSWORD_REQUIRED', message: 'Yeni kullanıcı için şifre gerekli' } });
      }

      const policyValidation = validatePasswordPolicy(request.password);
      if (!policyValidation.valid) {
        return createResponse(400, { success: false, error: { code: 'PASSWORD_TOO_WEAK', message: policyValidation.errors.join(', ') } });
      }

      const pwnedCount = await checkPasswordPwned(request.password);
      if (pwnedCount > 0) {
        return createResponse(400, { success: false, error: { code: 'PASSWORD_COMPROMISED' } });
      }

      // Create new user
      const newUser = await createUser({
        realm_id: TEDIYAT_REALM_ID,
        email: invitation.email,
        password: request.password,
        profile: {
          first_name: request.firstName || '',
          last_name: request.lastName || '',
        },
      });
      user = newUser as any;
      isNewUser = true;
    }

    if (!user) {
      return createResponse(500, { success: false, error: { code: 'USER_CREATE_FAILED' } });
    }

    // Accept invitation and create membership
    const acceptResult = await invitationService.acceptInvitation(invitationToken, user.id);
    if (!acceptResult.success) {
      return createResponse(400, { success: false, error: { code: acceptResult.code || 'ACCEPT_FAILED', message: acceptResult.error } });
    }

    // Get tenant info
    const tenantResult = await tenantService.getTenant(invitation.tenant_id);
    const tenant = tenantResult.data;

    // Generate tokens
    const tokenPair = await generateTokenPair(user.id, TEDIYAT_REALM_ID, user.email, {
      accessTokenExpiry: TEDIYAT_TOKEN_CONFIG.accessTokenExpiry,
      orgId: invitation.tenant_id,
      roles: [invitation.role_id],
    });

    // Create session
    try {
      await createSession(
        { user_id: user.id, realm_id: TEDIYAT_REALM_ID, ip_address: clientIP, user_agent: userAgent },
        tokenPair.access_token,
        tokenPair.refresh_token,
        TEDIYAT_TOKEN_CONFIG.refreshTokenExpiry
      );
    } catch (e) {
      console.warn('Session creation failed:', e);
    }

    await logSecurityEvent({
      event_type: 'invitation_accepted',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      user_id: user.id,
      details: { tenant_id: invitation.tenant_id, is_new_user: isNewUser },
    });

    return createResponse(200, {
      success: true,
      data: {
        user: { id: user.id, email: user.email, isNewUser },
        tenant: tenant ? { id: tenant.id, name: tenant.name, slug: tenant.slug } : null,
        membership: { role: invitation.role_id, role_name: invitation.role_name },
        tokens: { accessToken: tokenPair.access_token, refreshToken: tokenPair.refresh_token, expiresIn: TEDIYAT_TOKEN_CONFIG.accessTokenExpiry },
      },
    });
  } catch (error) {
    console.error('Invitation accept error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR' } });
  }
}
