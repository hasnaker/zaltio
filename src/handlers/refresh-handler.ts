/**
 * Token Refresh Lambda Handler
 * Validates: Requirements 2.3, 9.5
 * 
 * Implements 30-second grace period for token rotation (Siberci recommendation)
 * This handles network delays where client retries with old token
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import crypto from 'crypto';
import { verifyRefreshToken, generateTokenPair } from '../utils/jwt';
import { findUserById } from '../repositories/user.repository';
import { findRealmById, getRealmSettings } from '../repositories/realm.repository';
import {
  findSessionByRefreshToken,
  findSessionByOldRefreshToken,
  updateSessionTokens,
  createSession
} from '../repositories/session.repository';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';

// Grace period in seconds (Siberci recommendation: 30 seconds)
const GRACE_PERIOD_SECONDS = 30;

interface RefreshRequest {
  refresh_token: string;
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


export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const sourceIp = event.requestContext?.identity?.sourceIp || 'unknown';
  const userAgent = event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown';

  try {
    // Parse request body
    if (!event.body) {
      return createErrorResponse(
        400,
        'INVALID_REQUEST',
        'Request body is required',
        undefined,
        requestId
      );
    }

    let request: RefreshRequest;
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

    // Validate refresh token is provided
    if (!request.refresh_token || typeof request.refresh_token !== 'string') {
      return createErrorResponse(
        400,
        'INVALID_TOKEN',
        'Refresh token is required',
        { field: 'refresh_token' },
        requestId
      );
    }

    // Hash the refresh token for lookup
    const refreshTokenHash = crypto
      .createHash('sha256')
      .update(request.refresh_token)
      .digest('hex');

    // Verify the refresh token
    let payload;
    try {
      payload = await verifyRefreshToken(request.refresh_token);
    } catch (error) {
      const errorMessage = (error as Error).message;
      
      if (errorMessage.includes('expired')) {
        return createErrorResponse(
          401,
          'TOKEN_EXPIRED',
          'Refresh token has expired. Please log in again.',
          undefined,
          requestId
        );
      }
      
      return createErrorResponse(
        401,
        'INVALID_TOKEN',
        'Invalid refresh token',
        undefined,
        requestId
      );
    }

    // Check if realm still exists
    const realm = await findRealmById(payload.realm_id);
    if (!realm) {
      return createErrorResponse(
        404,
        'REALM_NOT_FOUND',
        'Authentication service unavailable',
        undefined,
        requestId
      );
    }

    // Check if user still exists and is active
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createErrorResponse(
        401,
        'USER_NOT_FOUND',
        'User account not found',
        undefined,
        requestId
      );
    }

    if (user.status === 'suspended') {
      return createErrorResponse(
        423,
        'ACCOUNT_LOCKED',
        'Account is suspended. Please contact support.',
        undefined,
        requestId
      );
    }

    // Try to find session by current refresh token
    console.log(`[DEBUG] Looking for session with refresh token hash: ${refreshTokenHash.substring(0, 16)}...`);
    let existingSession = await findSessionByRefreshToken(request.refresh_token);
    console.log(`[DEBUG] Session found: ${existingSession ? existingSession.id : 'null'}`);
    
    // GRACE PERIOD: If not found, check if this is an old token within grace period
    if (!existingSession) {
      const sessionByOldToken = await findSessionByOldRefreshToken(refreshTokenHash);
      
      if (sessionByOldToken && sessionByOldToken.rotated_at) {
        const rotatedAt = new Date(sessionByOldToken.rotated_at).getTime();
        const now = Date.now();
        const gracePeriodMs = GRACE_PERIOD_SECONDS * 1000;
        
        // Check if within grace period
        if (now - rotatedAt <= gracePeriodMs) {
          console.log(`[GRACE_PERIOD] Allowing old token refresh for session ${sessionByOldToken.id}`);
          
          // Return the SAME new tokens (idempotent response)
          // This prevents token confusion when client retries
          return createSuccessResponse(200, {
            message: 'Token refreshed successfully',
            tokens: {
              access_token: sessionByOldToken.access_token,
              refresh_token: sessionByOldToken.refresh_token,
              expires_in: 900 // 15 minutes
            },
            grace_period_used: true
          });
        } else {
          // Grace period expired - old token is truly invalid
          console.log(`[SECURITY] Grace period expired for session ${sessionByOldToken.id}`);
          return createErrorResponse(
            401,
            'TOKEN_ROTATED',
            'Refresh token has been rotated. Please log in again.',
            undefined,
            requestId
          );
        }
      }
      
      // Token not found anywhere - completely invalid
      return createErrorResponse(
        401,
        'INVALID_TOKEN',
        'Invalid refresh token',
        undefined,
        requestId
      );
    }

    // Get realm settings for token expiration
    const realmSettings = await getRealmSettings(payload.realm_id);

    // Generate new token pair
    const tokenPair = await generateTokenPair(
      user.id,
      user.realm_id,
      user.email,
      { accessTokenExpiry: realmSettings.session_timeout }
    );

    // Update session with new tokens and store old token hash for grace period
    await updateSessionTokens(
      existingSession.id,
      existingSession.realm_id,
      existingSession.user_id,
      tokenPair.access_token,
      tokenPair.refresh_token,
      refreshTokenHash // Store old token hash for grace period
    );

    // Audit log for token refresh
    await logAuditEvent({
      eventType: AuditEventType.TOKEN_REFRESH,
      result: AuditResult.SUCCESS,
      realmId: payload.realm_id,
      userId: user.id,
      sessionId: existingSession.id,
      ipAddress: sourceIp,
      userAgent: userAgent,
      action: 'refresh_token',
      details: {
        success: true
      }
    });

    return createSuccessResponse(200, {
      message: 'Token refreshed successfully',
      tokens: tokenPair
    });
  } catch (error) {
    console.error('Token refresh error:', error);

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'An unexpected error occurred',
      undefined,
      requestId
    );
  }
}
