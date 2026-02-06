/**
 * Tediyat Session Handlers Tests
 * Property 23: Session List Completeness
 * Property 24: Session Termination Effectiveness
 * 
 * Validates: Requirements 20.1-20.4, 21.1-21.3
 */

jest.mock('../../../utils/jwt');
jest.mock('../../../services/security-logger.service');
jest.mock('../../../repositories/session.repository');

import { handler as listHandler } from '../session-list.handler';
import { handler as terminateHandler } from '../session-terminate.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';
import * as jwtUtils from '../../../utils/jwt';
import * as securityLogger from '../../../services/security-logger.service';
import * as sessionRepo from '../../../repositories/session.repository';

const mockVerifyAccessToken = jwtUtils.verifyAccessToken as jest.Mock;
const mockLogSecurityEvent = securityLogger.logSecurityEvent as jest.Mock;
const mockListUserSessions = sessionRepo.getUserSessions as jest.Mock;
const mockDeleteSession = sessionRepo.deleteSession as jest.Mock;

function createMockEvent(
  method: string,
  pathParams?: Record<string, string> | null,
  queryParams?: Record<string, string> | null,
  token?: string
): APIGatewayProxyEvent {
  return {
    body: null,
    headers: { 'Authorization': token ? `Bearer ${token}` : undefined } as any,
    httpMethod: method,
    isBase64Encoded: false,
    path: '/v1/tediyat/auth/sessions',
    pathParameters: pathParams || null,
    queryStringParameters: queryParams || null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: { requestId: 'test', identity: { sourceIp: '127.0.0.1' } } as any,
    resource: '',
    multiValueHeaders: {},
  };
}

describe('Tediyat Session Handlers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'user_xxx',
      email: 'test@example.com',
      realm_id: 'tediyat',
      jti: 'current_session_id',
    });
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('Session List Handler', () => {
    beforeEach(() => {
      mockListUserSessions.mockResolvedValue([
        {
          id: 'current_session_id',
          user_id: 'user_xxx',
          ip_address: '192.168.1.100',
          user_agent: 'Mozilla/5.0',
          created_at: '2026-01-28T10:00:00Z',
          last_used_at: '2026-01-28T11:00:00Z',
        },
        {
          id: 'other_session_id',
          user_id: 'user_xxx',
          ip_address: '10.0.0.50',
          user_agent: 'Chrome/120',
          created_at: '2026-01-27T10:00:00Z',
          device_fingerprint: JSON.stringify({ platform: 'Windows' }),
        },
      ]);
    });

    it('should return all user sessions', async () => {
      const event = createMockEvent('GET', null, null, 'valid_token');
      const response = await listHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(body.data.sessions).toHaveLength(2);
      expect(body.data.total).toBe(2);
    });

    it('should mark current session', async () => {
      const event = createMockEvent('GET', null, null, 'valid_token');
      const response = await listHandler(event);
      const body = JSON.parse(response.body);

      const currentSession = body.data.sessions.find((s: any) => s.is_current);
      expect(currentSession).toBeDefined();
      expect(currentSession.id).toBe('current_session_id');
    });

    it('should mask IP addresses', async () => {
      const event = createMockEvent('GET', null, null, 'valid_token');
      const response = await listHandler(event);
      const body = JSON.parse(response.body);

      body.data.sessions.forEach((session: any) => {
        if (session.ip_address && session.ip_address !== 'unknown') {
          expect(session.ip_address).toContain('*');
        }
      });
    });

    it('should include device info when available', async () => {
      const event = createMockEvent('GET', null, null, 'valid_token');
      const response = await listHandler(event);
      const body = JSON.parse(response.body);

      const sessionWithDevice = body.data.sessions.find((s: any) => s.device_info);
      expect(sessionWithDevice).toBeDefined();
      expect(sessionWithDevice.device_info.platform).toBe('Windows');
    });

    it('should reject without token', async () => {
      const event = createMockEvent('GET');
      const response = await listHandler(event);
      expect(response.statusCode).toBe(401);
    });
  });

  describe('Session Terminate Handler', () => {
    beforeEach(() => {
      mockDeleteSession.mockResolvedValue(true);
      mockListUserSessions.mockResolvedValue([
        { id: 'current_session_id', user_id: 'user_xxx' },
        { id: 'session_2', user_id: 'user_xxx' },
        { id: 'session_3', user_id: 'user_xxx' },
      ]);
    });

    it('should terminate specific session', async () => {
      const event = createMockEvent('DELETE', { sessionId: 'session_2' }, null, 'valid_token');
      const response = await terminateHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(mockDeleteSession).toHaveBeenCalledWith('session_2');
    });

    it('should terminate all sessions except current', async () => {
      const event = createMockEvent('DELETE', null, { all: 'true' }, 'valid_token');
      const response = await terminateHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(body.data.terminated_count).toBe(2);
      expect(mockDeleteSession).toHaveBeenCalledTimes(2);
      expect(mockDeleteSession).not.toHaveBeenCalledWith('current_session_id');
    });

    it('should prevent terminating current session', async () => {
      const event = createMockEvent('DELETE', { sessionId: 'current_session_id' }, null, 'valid_token');
      const response = await terminateHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('CANNOT_TERMINATE_CURRENT');
    });

    it('should return 404 for non-existent session', async () => {
      mockDeleteSession.mockResolvedValue(false);

      const event = createMockEvent('DELETE', { sessionId: 'nonexistent' }, null, 'valid_token');
      const response = await terminateHandler(event);

      expect(response.statusCode).toBe(404);
    });

    it('should log session termination', async () => {
      const event = createMockEvent('DELETE', { sessionId: 'session_2' }, null, 'valid_token');
      await terminateHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_terminated',
          realm_id: 'tediyat',
        })
      );
    });
  });
});
