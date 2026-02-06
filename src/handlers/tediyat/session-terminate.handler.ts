/**
 * Tediyat Session Terminate Handler
 * DELETE /api/v1/auth/sessions/{sessionId}
 * DELETE /api/v1/auth/sessions?all=true
 * 
 * Validates: Requirements 21.1-21.3
 * Property 24: Session Termination Effectiveness
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
import { deleteSession, deleteAllUserSessions, getUserSessions } from '../../repositories/session.repository';

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

    const userId = tokenPayload.sub;
    const currentSessionId = tokenPayload.jti;
    const terminateAll = event.queryStringParameters?.all === 'true';
    const targetSessionId = event.pathParameters?.sessionId;

    if (terminateAll) {
      // Terminate all sessions except current
      const sessions = await getUserSessions(TEDIYAT_REALM_ID, userId);
      let terminatedCount = 0;

      for (const session of sessions) {
        if (session.id !== currentSessionId) {
          await deleteSession(session.id);
          terminatedCount++;
        }
      }

      await logSecurityEvent({
        event_type: 'sessions_terminated_all',
        ip_address: clientIP,
        realm_id: TEDIYAT_REALM_ID,
        user_id: userId,
        details: { terminated_count: terminatedCount, preserved_current: true },
      });

      return createResponse(200, {
        success: true,
        data: { message: `${terminatedCount} oturum sonlandırıldı`, terminated_count: terminatedCount },
      });
    }

    if (!targetSessionId) {
      return createResponse(400, { success: false, error: { code: 'INVALID_SESSION_ID' } });
    }

    // Cannot terminate current session via this endpoint
    if (targetSessionId === currentSessionId) {
      return createResponse(400, { success: false, error: { code: 'CANNOT_TERMINATE_CURRENT', message: 'Mevcut oturumu sonlandırmak için logout kullanın' } });
    }

    // Terminate specific session
    const deleted = await deleteSession(targetSessionId);
    
    if (!deleted) {
      return createResponse(404, { success: false, error: { code: 'SESSION_NOT_FOUND' } });
    }

    await logSecurityEvent({
      event_type: 'session_terminated',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      user_id: userId,
      details: { terminated_session: targetSessionId },
    });

    return createResponse(200, {
      success: true,
      data: { message: 'Oturum sonlandırıldı' },
    });
  } catch (error) {
    console.error('Session terminate error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR' } });
  }
}
