/**
 * Get Current User Lambda Handler
 * Validates: Requirements 2.1, 9.5
 * 
 * SECURITY FEATURES:
 * - Bearer token validation
 * - Password hash NEVER returned
 * - Sensitive data masking
 * - Audit logging
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../utils/jwt';
import { findUserById } from '../repositories/user.repository';
import { logSecurityEvent } from '../services/security-logger.service';

interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
  };
}

interface UserProfile {
  first_name?: string;
  last_name?: string;
  avatar_url?: string;
  [key: string]: unknown;
}

interface SafeUserResponse {
  id: string;
  realm_id: string;
  email: string;
  email_verified: boolean;
  profile: UserProfile;
  status: string;
  mfa_enabled: boolean;
  created_at: string;
  updated_at: string;
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
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-store, no-cache, must-revalidate'
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

/**
 * Extract Bearer token from Authorization header
 */
function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader) return null;
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }
  
  return parts[1];
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 
         event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
         'unknown';
}

/**
 * Sanitize user object - remove sensitive fields
 * SECURITY: Password hash and other sensitive data MUST NEVER be returned
 */
function sanitizeUser(user: Record<string, unknown>): SafeUserResponse {
  return {
    id: user.id as string,
    realm_id: user.realm_id as string,
    email: user.email as string,
    email_verified: user.email_verified as boolean || false,
    profile: (user.profile as UserProfile) || {},
    status: user.status as string || 'active',
    mfa_enabled: user.mfa_enabled as boolean || false,
    created_at: user.created_at as string,
    updated_at: user.updated_at as string
  };
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Extract access token from Authorization header
    const authHeader = event.headers?.Authorization || event.headers?.authorization;
    const accessToken = extractBearerToken(authHeader);

    if (!accessToken) {
      return createErrorResponse(
        401,
        'UNAUTHORIZED',
        'Authorization header with Bearer token is required',
        undefined,
        requestId
      );
    }

    // Verify the access token
    let payload;
    try {
      payload = await verifyAccessToken(accessToken);
    } catch (error) {
      const errorMessage = (error as Error).message;
      
      if (errorMessage.includes('expired')) {
        return createErrorResponse(
          401,
          'TOKEN_EXPIRED',
          'Access token has expired',
          undefined,
          requestId
        );
      }
      
      return createErrorResponse(
        401,
        'INVALID_TOKEN',
        'Invalid access token',
        undefined,
        requestId
      );
    }

    // Fetch user from database
    const user = await findUserById(payload.realm_id, payload.sub);

    if (!user) {
      await logSecurityEvent({
        event_type: 'user_not_found',
        ip_address: clientIP,
        realm_id: payload.realm_id,
        user_id: payload.sub,
        details: { reason: 'user_deleted_or_not_found' }
      });

      return createErrorResponse(
        404,
        'USER_NOT_FOUND',
        'User not found',
        undefined,
        requestId
      );
    }

    // Check if user is suspended
    if (user.status === 'suspended') {
      return createErrorResponse(
        403,
        'ACCOUNT_SUSPENDED',
        'Account is suspended',
        undefined,
        requestId
      );
    }

    // Return sanitized user data (NO password hash!)
    const safeUser = sanitizeUser(user as unknown as Record<string, unknown>);

    return createSuccessResponse(200, {
      user: safeUser
    });
  } catch (error) {
    console.error('Get current user error:', error);

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'An unexpected error occurred',
      undefined,
      requestId
    );
  }
}
