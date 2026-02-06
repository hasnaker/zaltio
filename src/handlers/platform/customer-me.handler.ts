/**
 * Platform Customer Me Lambda Handler
 * GET /platform/me
 * 
 * Returns authenticated customer's profile, realms, and usage
 * Requires valid JWT token in Authorization header
 * 
 * Validates: Requirements 2.2 (Customer profile)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { getCustomerById } from '../../repositories/customer.repository';
import { listAPIKeysByCustomer } from '../../repositories/api-key.repository';
import { verifyAccessToken } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
import { CustomerResponse } from '../../models/customer.model';
import { APIKeyResponse } from '../../models/api-key.model';

interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
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
    error: {
      code,
      message,
      details,
      timestamp: new Date().toISOString(),
      request_id: requestId
    }
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    },
    body: JSON.stringify(response)
  };
}

function createSuccessResponse(
  statusCode: number,
  data: unknown
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-store, no-cache, must-revalidate'
    },
    body: JSON.stringify(data)
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 
         event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
         'unknown';
}

/**
 * Extract Bearer token from Authorization header
 */
function extractBearerToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  if (!authHeader) return null;
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }
  
  return parts[1];
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Extract and validate token
    const token = extractBearerToken(event);
    if (!token) {
      return createErrorResponse(
        401,
        'UNAUTHORIZED',
        'Authorization header with Bearer token is required',
        undefined,
        requestId
      );
    }

    // Verify JWT token
    let payload;
    try {
      payload = await verifyAccessToken(token);
    } catch (error) {
      await logSecurityEvent({
        event_type: 'invalid_token',
        ip_address: clientIP,
        details: { error: (error as Error).message }
      });

      return createErrorResponse(
        401,
        'INVALID_TOKEN',
        'Invalid or expired token',
        undefined,
        requestId
      );
    }

    // Get customer by ID from token
    const customerId = payload.sub;
    const customer = await getCustomerById(customerId);

    if (!customer) {
      await logSecurityEvent({
        event_type: 'customer_not_found',
        ip_address: clientIP,
        user_id: customerId,
        details: { reason: 'token_valid_but_customer_deleted' }
      });

      return createErrorResponse(
        404,
        'CUSTOMER_NOT_FOUND',
        'Customer account not found',
        undefined,
        requestId
      );
    }

    // Check if account is active
    if (customer.status === 'suspended') {
      return createErrorResponse(
        403,
        'ACCOUNT_SUSPENDED',
        'Your account has been suspended. Please contact support.',
        undefined,
        requestId
      );
    }

    // Get customer's API keys (masked)
    const apiKeys = await listAPIKeysByCustomer(customerId);
    const maskedKeys: APIKeyResponse[] = apiKeys.map(key => ({
      id: key.id,
      type: key.type,
      environment: key.environment,
      key_prefix: key.key_prefix,
      key_hint: key.key_hint,
      name: key.name,
      description: key.description,
      status: key.status,
      last_used_at: key.last_used_at,
      usage_count: key.usage_count,
      created_at: key.created_at,
      expires_at: key.expires_at
    }));

    // Build response (exclude sensitive data)
    const customerResponse: CustomerResponse = {
      id: customer.id,
      email: customer.email,
      email_verified: customer.email_verified,
      profile: customer.profile,
      billing: {
        plan: customer.billing.plan,
        plan_started_at: customer.billing.plan_started_at,
        plan_expires_at: customer.billing.plan_expires_at,
        payment_method_last4: customer.billing.payment_method_last4,
        payment_method_brand: customer.billing.payment_method_brand
      },
      usage_limits: customer.usage_limits,
      status: customer.status,
      created_at: customer.created_at,
      default_realm_id: customer.default_realm_id
    };

    return createSuccessResponse(200, {
      customer: customerResponse,
      api_keys: maskedKeys,
      // TODO: Add realms list when realm repository is updated
      realms: customer.default_realm_id ? [{
        id: customer.default_realm_id,
        is_default: true
      }] : []
    });

  } catch (error) {
    console.error('Customer me error:', error);

    await logSecurityEvent({
      event_type: 'customer_me_error',
      ip_address: clientIP,
      details: { error: (error as Error).message }
    });

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'An unexpected error occurred',
      undefined,
      requestId
    );
  }
}
