/**
 * Tediyat Session List Handler
 * GET /api/v1/auth/sessions
 * 
 * Validates: Requirements 20.1-20.4
 * Property 23: Session List Completeness
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { getUserSessions } from '../../repositories/session.repository';

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

    // Get all user sessions
    const sessions = await getUserSessions(TEDIYAT_REALM_ID, userId);

    const formattedSessions = sessions.map(session => ({
      id: session.id,
      device_info: session.device_fingerprint ? JSON.parse(session.device_fingerprint) : null,
      ip_address: session.ip_address ? maskIP(session.ip_address) : null,
      user_agent: session.user_agent,
      created_at: session.created_at,
      last_activity: session.last_used_at || session.created_at,
      is_current: session.id === currentSessionId,
    }));

    return createResponse(200, {
      success: true,
      data: {
        sessions: formattedSessions,
        total: formattedSessions.length,
      },
    });
  } catch (error) {
    console.error('Session list error:', error);
    return createResponse(500, { success: false, error: { code: 'INTERNAL_ERROR' } });
  }
}

function maskIP(ip: string): string {
  if (!ip || ip === 'unknown') return 'unknown';
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.*.*`;
  }
  return ip.substring(0, ip.length / 2) + '***';
}
