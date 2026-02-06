/**
 * Tediyat Tenant Create Handler
 * Creates a new tenant for authenticated user
 * 
 * POST /api/v1/tenants
 * Validates: Requirements 9.1-9.5
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
import * as tenantService from '../../services/tediyat/tenant.service';
import * as membershipService from '../../services/tediyat/membership.service';
import { TEDIYAT_SYSTEM_ROLES } from '../../models/tediyat/role.model';

const TEDIYAT_REALM_ID = 'tediyat';

interface CreateTenantRequest {
  name: string;
  slug?: string;
  metadata?: {
    taxNumber?: string;
    address?: string;
    city?: string;
    country?: string;
    phone?: string;
    email?: string;
  };
}

interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
  };
}

interface SuccessResponse {
  success: true;
  data: {
    tenant: {
      id: string;
      name: string;
      slug: string;
    };
    membership: {
      role: string;
      role_name: string;
    };
  };
}

function createErrorResponse(
  statusCode: number,
  code: string,
  message: string,
  details?: Record<string, unknown>
): APIGatewayProxyResult {
  const response: ErrorResponse = {
    success: false,
    error: { code, message, details, timestamp: new Date().toISOString() },
  };
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
    },
    body: JSON.stringify(response),
  };
}

function createSuccessResponse(statusCode: number, data: SuccessResponse['data']): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
    },
    body: JSON.stringify({ success: true, data }),
  };
}

function extractBearerToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.['Authorization'] || event.headers?.['authorization'];
  return authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() || 'unknown';
}

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);

  try {
    const token = extractBearerToken(event);
    if (!token) return createErrorResponse(401, 'UNAUTHORIZED', 'Yetkilendirme token\'ı gerekli');

    let tokenPayload;
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createErrorResponse(401, 'INVALID_TOKEN', 'Geçersiz veya süresi dolmuş token');
    }

    if (tokenPayload.realm_id !== TEDIYAT_REALM_ID) {
      return createErrorResponse(403, 'FORBIDDEN', 'Bu işlem için yetkiniz yok');
    }

    if (!event.body) return createErrorResponse(400, 'INVALID_REQUEST', 'İstek gövdesi gerekli');

    let request: CreateTenantRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return createErrorResponse(400, 'INVALID_JSON', 'Geçersiz JSON formatı');
    }

    if (!request.name || request.name.trim().length < 2) {
      return createErrorResponse(400, 'INVALID_NAME', 'Şirket adı en az 2 karakter olmalı');
    }

    const userId = tokenPayload.sub;

    const tenantResult = await tenantService.createTenant({
      name: request.name.trim(),
      slug: request.slug,
      metadata: request.metadata,
      owner_user_id: userId,
    });

    if (!tenantResult.success || !tenantResult.data) {
      if (tenantResult.code === 'SLUG_EXISTS') {
        return createErrorResponse(409, 'SLUG_EXISTS', tenantResult.error || 'Bu slug kullanımda');
      }
      return createErrorResponse(500, 'CREATE_FAILED', tenantResult.error || 'Şirket oluşturulamadı');
    }

    const tenant = tenantResult.data;

    const membershipResult = await membershipService.createMembership({
      user_id: userId,
      tenant_id: tenant.id,
      realm_id: TEDIYAT_REALM_ID,
      role_id: 'role_owner',
      role_name: TEDIYAT_SYSTEM_ROLES.owner.name,
      is_default: false,
    });

    if (!membershipResult.success) {
      return createErrorResponse(500, 'MEMBERSHIP_FAILED', 'Üyelik oluşturulamadı');
    }

    await logSecurityEvent({
      event_type: 'tenant_created',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      user_id: userId,
      details: { tenant_id: tenant.id, tenant_name: tenant.name },
    });

    return createSuccessResponse(201, {
      tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug },
      membership: { role: 'role_owner', role_name: TEDIYAT_SYSTEM_ROLES.owner.name },
    });
  } catch (error) {
    console.error('Tenant create error:', error);
    await logSecurityEvent({
      event_type: 'tenant_create_error',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      details: { error: (error as Error).message },
    });
    return createErrorResponse(500, 'INTERNAL_ERROR', 'Beklenmeyen bir hata oluştu');
  }
}
