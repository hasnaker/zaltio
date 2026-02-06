/**
 * User Logout Lambda Handler
 * Validates: Requirements 2.1, 9.5
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../utils/jwt';
import {
  findSessionByRefreshToken,
  deleteSession,
  deleteUserSessions
} from '../repositories/session.repository';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';

interface LogoutRequest {
  refresh_token?: string;
  logout_all?: boolean;
}

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
      'Access-Control-Allow-Headers': 'Content-Type,Authorization'
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
      'Access-Control-Allow-Headers': 'Content-Type,Authorization'
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

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;

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
      console.log(`[DEBUG] Verifying access token: ${accessToken.substring(0, 50)}...`);
      payload = await verifyAccessToken(accessToken);
      console.log(`[DEBUG] Token verified successfully for user: ${payload.sub}`);
    } catch (error) {
      const errorMessage = (error as Error).message;
      console.log(`[DEBUG] Token verification failed: ${errorMessage}`);
      
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

    // Parse request body (optional)
    let request: LogoutRequest = {};
    if (event.body) {
      try {
        request = JSON.parse(event.body);
      } catch {
        return createErrorResponse(
          400,
          'INVALID_JSON',
          'Invalid JSON in request body',
          undefined,
          requestId
        );
      }
    }

    // Handle logout_all - terminate all user sessions
    if (request.logout_all === true) {
      const deletedCount = await deleteUserSessions(payload.realm_id, payload.sub);
      
      // Audit log for logout all
      await logAuditEvent({
        eventType: AuditEventType.LOGOUT,
        result: AuditResult.SUCCESS,
        realmId: payload.realm_id,
        userId: payload.sub,
        ipAddress: event.requestContext?.identity?.sourceIp || 'unknown',
        userAgent: event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown',
        action: 'logout_all',
        details: {
          sessions_terminated: deletedCount
        }
      });
      
      return createSuccessResponse(200, {
        message: 'All sessions terminated successfully',
        sessions_terminated: deletedCount
      });
    }

    // Handle single session logout
    if (request.refresh_token) {
      // Find session by refresh token and delete it
      const session = await findSessionByRefreshToken(request.refresh_token);
      
      if (session) {
        // Verify the session belongs to the authenticated user
        if (session.user_id !== payload.sub || session.realm_id !== payload.realm_id) {
          return createErrorResponse(
            403,
            'FORBIDDEN',
            'Cannot terminate session belonging to another user',
            undefined,
            requestId
          );
        }
        
        await deleteSession(session.id, session.realm_id, session.user_id);
        
        // Audit log for single session logout
        await logAuditEvent({
          eventType: AuditEventType.LOGOUT,
          result: AuditResult.SUCCESS,
          realmId: payload.realm_id,
          userId: payload.sub,
          sessionId: session.id,
          ipAddress: event.requestContext?.identity?.sourceIp || 'unknown',
          userAgent: event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown',
          action: 'logout_single',
          details: {
            success: true
          }
        });
      }
      
      return createSuccessResponse(200, {
        message: 'Session terminated successfully'
      });
    }

    // If no refresh_token provided, just acknowledge logout
    // The client should discard their tokens
    // Audit log for logout without refresh token
    await logAuditEvent({
      eventType: AuditEventType.LOGOUT,
      result: AuditResult.SUCCESS,
      realmId: payload.realm_id,
      userId: payload.sub,
      ipAddress: event.requestContext?.identity?.sourceIp || 'unknown',
      userAgent: event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown',
      action: 'logout_no_token',
      details: {
        success: true,
        no_refresh_token: true
      }
    });

    return createSuccessResponse(200, {
      message: 'Logout successful. Please discard your tokens.'
    });
  } catch (error) {
    console.error('Logout error:', error);

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'An unexpected error occurred',
      undefined,
      requestId
    );
  }
}
