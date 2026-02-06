/**
 * Admin Session Management E2E Tests
 * Task 9.4: Admin Session Management
 * 
 * Tests admin endpoints for session management:
 * - GET /v1/admin/sessions
 * - DELETE /v1/admin/sessions/:id
 * - DELETE /v1/admin/users/:id/sessions
 */

import {
  listSessionsHandler,
  revokeSessionHandler,
  revokeUserSessionsHandler
} from '../../handlers/admin-handler';
import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({ allowed: true, remaining: 100, resetAt: Date.now() + 60000 }),
  RateLimitEndpoint: {
    API_GENERAL: 'api_general',
    PASSWORD_RESET: 'password_reset'
  }
}));

jest.mock('../../services/audit.service', () => ({
  logAuditEvent: jest.fn().mockResolvedValue({}),
  AuditEventType: {
    ADMIN_ACTION: 'admin_action',
    TOKEN_REVOKE: 'token_revoke'
  },
  AuditResult: {
    SUCCESS: 'success',
    FAILURE: 'failure'
  }
}));

jest.mock('../../repositories/user.repository', () => ({
  findUserById: jest.fn()
}));

jest.mock('../../repositories/session.repository', () => ({
  getUserSessions: jest.fn(),
  deleteSession: jest.fn(),
  deleteUserSessions: jest.fn()
}));

import { verifyAccessToken } from '../../utils/jwt';
import { checkRateLimit } from '../../services/ratelimit.service';
import { logAuditEvent } from '../../services/audit.service';
import { findUserById } from '../../repositories/user.repository';
import { getUserSessions, deleteSession, deleteUserSessions } from '../../repositories/session.repository';

const mockVerifyAccessToken = verifyAccessToken as jest.Mock;
const mockCheckRateLimit = checkRateLimit as jest.Mock;
const mockLogAuditEvent = logAuditEvent as jest.Mock;
const mockFindUserById = findUserById as jest.Mock;
const mockGetUserSessions = getUserSessions as jest.Mock;
const mockDeleteSession = deleteSession as jest.Mock;
const mockDeleteUserSessions = deleteUserSessions as jest.Mock;

/**
 * Create mock API Gateway event
 */
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/v1/admin/sessions',
    headers: {
      Authorization: 'Bearer valid-admin-token'
    },
    pathParameters: null,
    queryStringParameters: null,
    body: null,
    isBase64Encoded: false,
    requestContext: {
      identity: {
        sourceIp: '192.168.1.1'
      }
    } as APIGatewayProxyEvent['requestContext'],
    resource: '',
    stageVariables: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    ...overrides
  };
}

/**
 * Create mock session
 */
function createMockSession(overrides: Partial<{
  id: string;
  user_id: string;
  realm_id: string;
  ip_address: string;
}> = {}) {
  return {
    id: overrides.id || 'session-123',
    user_id: overrides.user_id || 'user-123',
    realm_id: overrides.realm_id || 'test-realm',
    ip_address: overrides.ip_address || '192.168.1.100',
    user_agent: 'Mozilla/5.0 Chrome/120.0',
    device_fingerprint: 'fp-abc123',
    created_at: '2026-01-15T10:00:00Z',
    last_used_at: '2026-01-15T11:00:00Z',
    expires_at: '2026-01-22T10:00:00Z',
    revoked: false
  };
}

/**
 * Create mock user
 */
function createMockUser(overrides: Partial<{
  id: string;
  realm_id: string;
  email: string;
}> = {}) {
  return {
    id: overrides.id || 'user-123',
    realm_id: overrides.realm_id || 'test-realm',
    email: overrides.email || 'test@example.com',
    email_verified: true,
    profile: { first_name: 'Test', last_name: 'User', metadata: {} },
    created_at: '2026-01-15T10:00:00Z',
    updated_at: '2026-01-15T10:00:00Z',
    last_login: '2026-01-15T10:00:00Z',
    status: 'active'
  };
}

describe('Admin Session Management E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default admin auth
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'admin-user-id',
      realm_id: 'test-realm',
      is_admin: true
    });
    
    // Default rate limit
    mockCheckRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 100,
      resetAt: Date.now() + 60000
    });
  });

  describe('GET /v1/admin/sessions - List Sessions', () => {
    it('should list user sessions', async () => {
      const mockSessions = [
        createMockSession({ id: 'session-1' }),
        createMockSession({ id: 'session-2' })
      ];
      mockGetUserSessions.mockResolvedValue(mockSessions);

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-123' }
      });

      const response = await listSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.sessions).toHaveLength(2);
      expect(body.data.total).toBe(2);
    });

    it('should require user_id parameter', async () => {
      const event = createMockEvent({
        queryStringParameters: null
      });

      const response = await listSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
      expect(body.error.message).toContain('user_id');
    });

    it('should return session details without sensitive data', async () => {
      const mockSession = createMockSession();
      mockGetUserSessions.mockResolvedValue([mockSession]);

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-123' }
      });

      const response = await listSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      const session = body.data.sessions[0];
      expect(session.id).toBeDefined();
      expect(session.ip_address).toBeDefined();
      expect(session.user_agent).toBeDefined();
      expect(session.created_at).toBeDefined();
      expect(session.access_token).toBeUndefined(); // Should not expose tokens
      expect(session.refresh_token).toBeUndefined();
    });

    it('should reject non-admin users', async () => {
      mockVerifyAccessToken.mockResolvedValue({
        sub: 'regular-user',
        realm_id: 'test-realm',
        is_admin: false
      });

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-123' }
      });

      const response = await listSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should enforce rate limiting', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 60000,
        retryAfter: 60
      });

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-123' }
      });

      const response = await listSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });

    it('should audit session list requests', async () => {
      mockGetUserSessions.mockResolvedValue([]);

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-123' }
      });

      await listSessionsHandler(event);

      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'list_sessions',
          details: expect.objectContaining({
            target_user: 'user-123'
          })
        })
      );
    });
  });

  describe('DELETE /v1/admin/sessions/:id - Revoke Session', () => {
    it('should revoke a specific session', async () => {
      mockDeleteSession.mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'session-123' },
        body: JSON.stringify({ user_id: 'user-123', realm_id: 'test-realm' })
      });

      const response = await revokeSessionHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.message).toContain('revoked');
      expect(mockDeleteSession).toHaveBeenCalledWith('session-123', 'test-realm', 'user-123');
    });

    it('should require session ID', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: null,
        body: JSON.stringify({ user_id: 'user-123' })
      });

      const response = await revokeSessionHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should require user_id in body', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'session-123' },
        body: JSON.stringify({})
      });

      const response = await revokeSessionHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
      expect(body.error.message).toContain('user_id');
    });

    it('should return 404 for non-existent session', async () => {
      mockDeleteSession.mockResolvedValue(false);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'non-existent' },
        body: JSON.stringify({ user_id: 'user-123' })
      });

      const response = await revokeSessionHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should audit session revocation', async () => {
      mockDeleteSession.mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'session-123' },
        body: JSON.stringify({ user_id: 'user-123' })
      });

      await revokeSessionHandler(event);

      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'admin_revoke_session',
          details: expect.objectContaining({
            target_session: 'session-123',
            target_user: 'user-123'
          })
        })
      );
    });

    it('should handle invalid JSON body', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'session-123' },
        body: 'invalid-json'
      });

      const response = await revokeSessionHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });
  });

  describe('DELETE /v1/admin/users/:id/sessions - Revoke All User Sessions', () => {
    it('should revoke all sessions for a user', async () => {
      mockFindUserById.mockResolvedValue(createMockUser());
      mockDeleteUserSessions.mockResolvedValue(5);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'user-123' }
      });

      const response = await revokeUserSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.message).toContain('revoked');
      expect(body.data.revoked_count).toBe(5);
    });

    it('should require user ID', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: null
      });

      const response = await revokeUserSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should return 404 for non-existent user', async () => {
      mockFindUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'non-existent' }
      });

      const response = await revokeUserSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should audit bulk session revocation', async () => {
      mockFindUserById.mockResolvedValue(createMockUser());
      mockDeleteUserSessions.mockResolvedValue(3);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'user-123' }
      });

      await revokeUserSessionsHandler(event);

      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'admin_revoke_all_sessions',
          details: expect.objectContaining({
            target_user: 'user-123',
            revoked_count: 3
          })
        })
      );
    });

    it('should handle user with no sessions', async () => {
      mockFindUserById.mockResolvedValue(createMockUser());
      mockDeleteUserSessions.mockResolvedValue(0);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'user-123' }
      });

      const response = await revokeUserSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.revoked_count).toBe(0);
    });
  });

  describe('Security Tests', () => {
    it('should reject requests without authorization', async () => {
      const event = createMockEvent({
        headers: {},
        queryStringParameters: { user_id: 'user-123' }
      });

      const response = await listSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject requests with invalid token', async () => {
      mockVerifyAccessToken.mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-123' }
      });

      const response = await listSessionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should include security headers', async () => {
      mockGetUserSessions.mockResolvedValue([]);

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-123' }
      });

      const response = await listSessionsHandler(event);

      expect(response.headers).toMatchObject({
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
      });
    });

    it('should use realm from query param if provided', async () => {
      mockGetUserSessions.mockResolvedValue([]);

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-123', realm_id: 'other-realm' }
      });

      await listSessionsHandler(event);

      expect(mockGetUserSessions).toHaveBeenCalledWith('other-realm', 'user-123');
    });
  });
});
