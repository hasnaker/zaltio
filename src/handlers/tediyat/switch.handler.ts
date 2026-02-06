/**
 * Tediyat Tenant Switch Handler
 * Switches user context to a different tenant
 * 
 * Validates: Requirements 11.1-11.4
 * Property 16: Tenant Switch Authorization
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { generateTokenPair } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
import * as membershipService from '../../services/tediyat/membership.service';
import * as tenantService from '../../services/tediyat/tenant.service';
import { getEffectiveRolePermissions, TEDIYAT_SYSTEM_ROLES, getSystemRole } from '../../models/tediyat/role.model';

const TEDIYAT_REALM_ID = 'tediyat';

const TEDIYAT_TOKEN_CONFIG = {
  accessTokenExpiry: 3600, // 1 hour
};

interface SwitchRequest {
  tenant_id: string;
}

interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
  };
}

interface SuccessResponse {
  success: true;
  data: {
    accessToken: string;
    tenant: {
      id: string;
      name: string;
      slug: string;
    };
    role: string;
    role_name: string;
    permissions: string[];
  };
}

function createErrorResponse(
  statusCode: number,
  code: string,
  message: string,
  details?: Record<string, unknown>,
  requestId?: string
): APIGatewayProxyResult {
  const response: ErrorResponse = {
    success: false,
    error: {
      code,
      message,
      details,
      timestamp: new Date().toISOString(),
      request_id: requestId,
    },
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
    body: JSON.stringify(response),
  };
}

function createSuccessResponse(
  statusCode: number,
  data: SuccessResponse['data']
): APIGatewayProxyResult {
  const response: SuccessResponse = {
    success: true,
    data,
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
    body: JSON.stringify(response),
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return (
    event.requestContext?.identity?.sourceIp ||
    event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
    'unknown'
  );
}

function extractBearerToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.['Authorization'] || event.headers?.['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7);
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Extract and verify token
    const token = extractBearerToken(event);
    if (!token) {
      return createErrorResponse(
        401,
        'UNAUTHORIZED',
        'Yetkilendirme token\'ı gerekli',
        undefined,
        requestId
      );
    }

    let tokenPayload;
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch (error) {
      return createErrorResponse(
        401,
        'INVALID_TOKEN',
        'Geçersiz veya süresi dolmuş token',
        undefined,
        requestId
      );
    }

    // Verify realm
    if (tokenPayload.realm_id !== TEDIYAT_REALM_ID) {
      return createErrorResponse(
        403,
        'FORBIDDEN',
        'Bu işlem için yetkiniz yok',
        undefined,
        requestId
      );
    }

    // Parse request body
    if (!event.body) {
      return createErrorResponse(
        400,
        'INVALID_REQUEST',
        'İstek gövdesi gerekli',
        undefined,
        requestId
      );
    }

    let request: SwitchRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return createErrorResponse(
        400,
        'INVALID_JSON',
        'Geçersiz JSON formatı',
        undefined,
        requestId
      );
    }

    // Validate tenant_id
    if (!request.tenant_id || typeof request.tenant_id !== 'string') {
      return createErrorResponse(
        400,
        'INVALID_TENANT_ID',
        'Geçerli bir şirket ID\'si gerekli',
        { field: 'tenant_id' },
        requestId
      );
    }

    const userId = tokenPayload.sub;

    // Check membership in target tenant
    const membershipResult = await membershipService.getMembership(userId, request.tenant_id);
    
    if (!membershipResult.success || !membershipResult.data) {
      await logSecurityEvent({
        event_type: 'tenant_switch_denied',
        ip_address: clientIP,
        realm_id: TEDIYAT_REALM_ID,
        user_id: userId,
        details: { 
          target_tenant: request.tenant_id,
          reason: 'no_membership',
        },
      });

      return createErrorResponse(
        403,
        'FORBIDDEN',
        'Bu şirkete erişim yetkiniz yok',
        undefined,
        requestId
      );
    }

    const membership = membershipResult.data;

    // Get tenant details
    const tenantResult = await tenantService.getTenant(request.tenant_id);
    
    if (!tenantResult.success || !tenantResult.data) {
      return createErrorResponse(
        404,
        'TENANT_NOT_FOUND',
        'Şirket bulunamadı',
        undefined,
        requestId
      );
    }

    const tenant = tenantResult.data;

    // Get role and permissions
    const role = getSystemRole(membership.role_id);
    const permissions = role 
      ? getEffectiveRolePermissions(role, TEDIYAT_SYSTEM_ROLES)
      : membership.direct_permissions || [];

    // Generate new token with tenant context
    const tokenPair = await generateTokenPair(
      userId,
      TEDIYAT_REALM_ID,
      tokenPayload.email,
      {
        accessTokenExpiry: TEDIYAT_TOKEN_CONFIG.accessTokenExpiry,
        orgId: tenant.id,
        roles: [membership.role_id],
        permissions: permissions.length <= 50 ? permissions : undefined,
      }
    );

    // Update default tenant if requested
    await membershipService.setDefaultTenant(userId, tenant.id);

    // Log successful switch
    await logSecurityEvent({
      event_type: 'tenant_switch_success',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      user_id: userId,
      details: {
        from_tenant: tokenPayload.org_id,
        to_tenant: tenant.id,
        role: membership.role_id,
      },
    });

    return createSuccessResponse(200, {
      accessToken: tokenPair.access_token,
      tenant: {
        id: tenant.id,
        name: tenant.name,
        slug: tenant.slug,
      },
      role: membership.role_id,
      role_name: role?.name || membership.role_name,
      permissions,
    });
  } catch (error) {
    console.error('Tenant switch error:', error);

    await logSecurityEvent({
      event_type: 'tenant_switch_error',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      details: { error: (error as Error).message },
    });

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'Beklenmeyen bir hata oluştu',
      undefined,
      requestId
    );
  }
}
