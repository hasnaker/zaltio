/**
 * Admin Password Compromise Handler Tests
 * Validates: Requirements 8.3, 8.4, 8.5, 8.6 (Compromised Password Detection)
 * 
 * Tests for:
 * - POST /v1/admin/users/{id}/mark-password-compromised - Mark single user's password as compromised
 * - POST /v1/admin/realm/mark-all-passwords-compromised - Mark all passwords in realm as compromised
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (using real service mocks)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from './admin-handler';
import * as jwt from '../utils/jwt';
import * as ratelimit from '../services/ratelimit.service';
import * as userRepository from '../repositories/user.repository';
import * as sessionRepository from '../repositories/session.repository';
import * as emailService from '../services/email.service';
import * as audit from '../services/audit.service';
import * as realmService from '../services/realm.service';

// Mock dependencies
jest.mock('../utils/jwt');
jest.mock('../services/ratelimit.service');
jest.mock('../repositories/user.repository');
jest.mock('../repositories/session.repository');
jest.mock('../services/email.service');
jest.mock('../services/audit.service');
jest.mock('../services/realm.service');

// Mock session tasks service with proper structure
const mockForcePasswordReset = jest.fn();
const mockForcePasswordResetAll = jest.fn();
jest.mock('../services/session-tasks.service', () => ({
  sessionTasksService: {
    forcePasswordReset: (...args: unknown[]) => mockForcePasswordReset(...args),
    forcePasswordResetAll: (...args: unknown[]) => mockForcePasswordResetAll(...args)
  }
}));

const mockJwt = jwt as jest.Mocked<typeof jwt>;
const mockRatelimit = ratelimit as jest.Mocked<typeof ratelimit>;
const mockUserRepository = userRepository as jest.Mocked<typeof userRepository>;
const mockSessionRepository = sessionRepository as jest.Mocked<typeof sessionRepository>;
const mockEmailService = emailService as jest.Mocked<typeof emailService>;
const mockAudit = audit as jest.Mocked<typeof audit>;

// Test data
const mockAdminUserId = 'admin_user_123';
const mockRealmId = 'realm_test123';
const mockTargetUserId = 'user_target_456';

/**
 * Create mock API Gateway event for admin
 */
function createMockAdminEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'POST',
    path: '/v1/admin/users/user_target_456/mark-password-compromised',
    headers: {
      Authorization: 'Bearer admin_token'
    },
    body: null,
    queryStringParameters: null,
    pathParameters: { id: mockTargetUserId },
    multiValueHeaders: {},
    isBase64Encoded: false,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    resource: '',
    requestContext: {
      accountId: '123456789',
      apiId: 'api-id',
      authorizer: null,
      protocol: 'HTTP/1.1',
      httpMethod: 'POST',
      identity: {
        sourceIp: '192.168.1.1',
        accessKey: null, accountId: null, apiKey: null, apiKeyId: null,
        caller: null, clientCert: null, cognitoAuthenticationProvider: null,
        cognitoAuthenticationType: null, cognitoIdentityId: null,
        cognitoIdentityPoolId: null, principalOrgId: null, user: null,
        userAgent: null, userArn: null
      },
      path: '/v1/admin/users/user_target_456/mark-password-compromised',
      stage: 'test',
      requestId: 'request-id',
      requestTimeEpoch: Date.now(),
      resourceId: 'resource-id',
      resourcePath: '/v1/admin/users/{id}/mark-password-compromised'
    },
    ...overrides
  } as APIGatewayProxyEvent;
}

describe('Admin Password Compromise Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mocks - set up in beforeEach to ensure they're reset properly
    mockRatelimit.checkRateLimit.mockResolvedValue({ allowed: true, remaining: 99, resetAt: Date.now() + 60000 });
    mockJwt.verifyAccessToken.mockResolvedValue({
      sub: mockAdminUserId,
      realm_id: mockRealmId,
      is_admin: true
    } as any);
    mockAudit.logAuditEvent.mockResolvedValue({} as any);
    mockEmailService.sendSecurityAlertEmail.mockResolvedValue({} as any);
    mockSessionRepository.getUserSessions.mockResolvedValue([]);
    mockSessionRepository.deleteUserSessions.mockResolvedValue(0);
  });

  describe('POST /v1/admin/users/{id}/mark-password-compromised', () => {
    it('should mark user password as compromised successfully', async () => {
      // Setup mocks
      mockUserRepository.findUserById.mockResolvedValue({
        id: mockTargetUserId,
        email: 'target@example.com',
        realm_id: mockRealmId
      } as any);
      mockForcePasswordReset.mockResolvedValue({
        userId: mockTargetUserId,
        taskId: 'task_123',
        sessionsRevoked: 2
      });

      const event = createMockAdminEvent({
        body: JSON.stringify({
          reason: 'Security incident - credential leak detected',
          revoke_sessions: true
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.data.success).toBe(true);
      expect(body.data.affected_users).toBe(1);
      expect(body.data.sessions_revoked).toBe(2);
      expect(body.data.task_created).toBe(true);
      expect(body.data.message).toContain('Password marked as compromised');
    });

    it('should call forcePasswordReset with correct parameters', async () => {
      mockUserRepository.findUserById.mockResolvedValue({
        id: mockTargetUserId,
        email: 'target@example.com',
        realm_id: mockRealmId
      } as any);
      mockForcePasswordReset.mockResolvedValue({
        userId: mockTargetUserId,
        taskId: 'task_123',
        sessionsRevoked: 0
      });

      const event = createMockAdminEvent({
        body: JSON.stringify({
          reason: 'Test reason',
          revoke_sessions: true
        })
      });

      await handler(event);

      expect(mockForcePasswordReset).toHaveBeenCalledWith(
        mockTargetUserId,
        mockRealmId,
        expect.objectContaining({
          revokeAllSessions: true,
          reason: 'compromised',
          message: 'Test reason'
        })
      );
    });

    it('should send security alert email by default', async () => {
      mockUserRepository.findUserById.mockResolvedValue({
        id: mockTargetUserId,
        email: 'target@example.com',
        realm_id: mockRealmId
      } as any);
      mockForcePasswordReset.mockResolvedValue({
        userId: mockTargetUserId,
        taskId: 'task_123',
        sessionsRevoked: 0
      });

      const event = createMockAdminEvent({
        body: JSON.stringify({
          reason: 'Security incident'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.data.user_notified).toBe(true);
      expect(mockEmailService.sendSecurityAlertEmail).toHaveBeenCalledWith(
        'target@example.com',
        'Password Security Alert',
        expect.stringContaining('compromised'),
        mockRealmId
      );
    });

    it('should not send email when notify_user is false', async () => {
      mockUserRepository.findUserById.mockResolvedValue({
        id: mockTargetUserId,
        email: 'target@example.com',
        realm_id: mockRealmId
      } as any);
      mockForcePasswordReset.mockResolvedValue({
        userId: mockTargetUserId,
        taskId: 'task_123',
        sessionsRevoked: 0
      });

      const event = createMockAdminEvent({
        body: JSON.stringify({
          reason: 'Security incident',
          notify_user: false
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.data.user_notified).toBe(false);
      expect(mockEmailService.sendSecurityAlertEmail).not.toHaveBeenCalled();
    });

    it('should return 404 for non-existent user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(null);

      const event = createMockAdminEvent({
        body: JSON.stringify({ reason: 'Test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('User not found');
    });

    it('should return 401 for unauthenticated request', async () => {
      mockJwt.verifyAccessToken.mockRejectedValue(new Error('Invalid token'));

      const event = createMockAdminEvent({
        headers: {}
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 for non-admin user', async () => {
      mockJwt.verifyAccessToken.mockResolvedValue({
        sub: 'regular_user',
        realm_id: mockRealmId,
        is_admin: false
      } as any);

      const event = createMockAdminEvent({
        body: JSON.stringify({ reason: 'Test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 429 when rate limited', async () => {
      mockRatelimit.checkRateLimit.mockResolvedValue({ allowed: false, retryAfter: 60, remaining: 0, resetAt: Date.now() + 60000 });

      const event = createMockAdminEvent({
        body: JSON.stringify({ reason: 'Test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });

    it('should return 400 for invalid JSON body', async () => {
      const event = createMockAdminEvent({
        body: 'invalid json'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });

    it('should return 404 when route does not match (empty user ID)', async () => {
      // When user ID is empty, the route regex doesn't match, so it returns 404
      const event = createMockAdminEvent({
        path: '/v1/admin/users//mark-password-compromised',
        pathParameters: {}
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      // Route doesn't match, so 404 is returned
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should log audit event on success', async () => {
      mockUserRepository.findUserById.mockResolvedValue({
        id: mockTargetUserId,
        email: 'target@example.com',
        realm_id: mockRealmId
      } as any);
      mockForcePasswordReset.mockResolvedValue({
        userId: mockTargetUserId,
        taskId: 'task_123',
        sessionsRevoked: 3
      });

      const event = createMockAdminEvent({
        body: JSON.stringify({
          reason: 'Security incident',
          revoke_sessions: true
        })
      });

      await handler(event);

      expect(mockAudit.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'mark_password_compromised',
          result: 'success',
          details: expect.objectContaining({
            target_user: mockTargetUserId,
            sessions_revoked: 3,
            task_created: true
          })
        })
      );
    });

    it('should use default reason when not provided', async () => {
      mockUserRepository.findUserById.mockResolvedValue({
        id: mockTargetUserId,
        email: 'target@example.com',
        realm_id: mockRealmId
      } as any);
      mockForcePasswordReset.mockResolvedValue({
        userId: mockTargetUserId,
        taskId: 'task_123',
        sessionsRevoked: 0
      });

      const event = createMockAdminEvent({
        body: JSON.stringify({})
      });

      await handler(event);

      expect(mockForcePasswordReset).toHaveBeenCalledWith(
        mockTargetUserId,
        mockRealmId,
        expect.objectContaining({
          message: expect.stringContaining('marked as compromised by an administrator')
        })
      );
    });

    it('should handle email sending failure gracefully', async () => {
      mockUserRepository.findUserById.mockResolvedValue({
        id: mockTargetUserId,
        email: 'target@example.com',
        realm_id: mockRealmId
      } as any);
      mockForcePasswordReset.mockResolvedValue({
        userId: mockTargetUserId,
        taskId: 'task_123',
        sessionsRevoked: 0
      });
      mockEmailService.sendSecurityAlertEmail.mockRejectedValue(new Error('Email service unavailable'));

      const event = createMockAdminEvent({
        body: JSON.stringify({ reason: 'Test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      // Should still succeed even if email fails
      expect(result.statusCode).toBe(200);
      expect(body.data.success).toBe(true);
    });
  });

  describe('POST /v1/admin/realm/mark-all-passwords-compromised', () => {
    it('should mark all passwords as compromised with confirmation', async () => {
      mockForcePasswordResetAll.mockResolvedValue({
        realmId: mockRealmId,
        usersAffected: 100,
        tasksCreated: 95,
        sessionsRevoked: 200,
        errors: []
      });

      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({
          reason: 'Security incident - potential breach',
          revoke_sessions: true,
          confirm: true
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.data.success).toBe(true);
      expect(body.data.affected_users).toBe(100);
      expect(body.data.tasks_created).toBe(95);
      expect(body.data.sessions_revoked).toBe(200);
      expect(body.data.message).toContain('All passwords marked as compromised');
    });

    it('should require confirmation for mass operation', async () => {
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({
          reason: 'Security incident',
          revoke_sessions: true
          // confirm: true is missing
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('CONFIRMATION_REQUIRED');
      expect(body.error.message).toContain('confirm: true');
    });

    it('should call forcePasswordResetAll with correct parameters', async () => {
      mockForcePasswordResetAll.mockResolvedValue({
        realmId: mockRealmId,
        usersAffected: 50,
        tasksCreated: 50,
        sessionsRevoked: 100,
        errors: []
      });

      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({
          reason: 'Breach detected',
          revoke_sessions: true,
          confirm: true
        })
      });

      await handler(event);

      expect(mockForcePasswordResetAll).toHaveBeenCalledWith(
        mockRealmId,
        expect.objectContaining({
          revokeAllSessions: true,
          reason: 'compromised',
          message: 'Breach detected'
        })
      );
    });

    it('should return 429 when rate limited (stricter limit)', async () => {
      mockRatelimit.checkRateLimit.mockResolvedValue({ allowed: false, retryAfter: 300, remaining: 0, resetAt: Date.now() + 300000 });

      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({ confirm: true })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(429);
      expect(body.error.message).toContain('5 minutes');
    });

    it('should include errors in response when some users fail', async () => {
      mockForcePasswordResetAll.mockResolvedValue({
        realmId: mockRealmId,
        usersAffected: 98,
        tasksCreated: 95,
        sessionsRevoked: 190,
        errors: [
          { userId: 'user_1', error: 'Database error' },
          { userId: 'user_2', error: 'Session error' }
        ]
      });

      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({ confirm: true })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.data.errors).toHaveLength(2);
      expect(body.data.errors[0].userId).toBe('user_1');
    });

    it('should not include errors array when no errors', async () => {
      mockForcePasswordResetAll.mockResolvedValue({
        realmId: mockRealmId,
        usersAffected: 100,
        tasksCreated: 100,
        sessionsRevoked: 200,
        errors: []
      });

      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({ confirm: true })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.data.errors).toBeUndefined();
    });

    it('should log audit event for mass operation', async () => {
      mockForcePasswordResetAll.mockResolvedValue({
        realmId: mockRealmId,
        usersAffected: 100,
        tasksCreated: 100,
        sessionsRevoked: 200,
        errors: []
      });

      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({
          reason: 'Security incident',
          revoke_sessions: true,
          confirm: true
        })
      });

      await handler(event);

      expect(mockAudit.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'mark_all_passwords_compromised',
          result: 'success',
          details: expect.objectContaining({
            target_realm: mockRealmId,
            users_affected: 100,
            tasks_created: 100,
            sessions_revoked: 200
          })
        })
      );
    });

    it('should use default message when reason not provided', async () => {
      mockForcePasswordResetAll.mockResolvedValue({
        realmId: mockRealmId,
        usersAffected: 50,
        tasksCreated: 50,
        sessionsRevoked: 100,
        errors: []
      });

      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({ confirm: true })
      });

      await handler(event);

      expect(mockForcePasswordResetAll).toHaveBeenCalledWith(
        mockRealmId,
        expect.objectContaining({
          message: 'Security incident: All passwords must be reset'
        })
      );
    });

    it('should return 401 for non-admin user', async () => {
      mockJwt.verifyAccessToken.mockResolvedValue({
        sub: 'regular_user',
        realm_id: mockRealmId,
        is_admin: false
      } as any);

      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({ confirm: true })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 400 for invalid JSON body', async () => {
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: 'invalid json'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });

    it('should handle service errors gracefully', async () => {
      mockForcePasswordResetAll.mockRejectedValue(new Error('Database connection failed'));

      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/v1/admin/realm/mark-all-passwords-compromised',
        pathParameters: null,
        body: JSON.stringify({ confirm: true })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(500);
      expect(body.error.code).toBe('INTERNAL_ERROR');
    });
  });

  describe('Security headers', () => {
    it('should include security headers in response', async () => {
      mockUserRepository.findUserById.mockResolvedValue({
        id: mockTargetUserId,
        email: 'target@example.com',
        realm_id: mockRealmId
      } as any);
      mockForcePasswordReset.mockResolvedValue({
        userId: mockTargetUserId,
        taskId: 'task_123',
        sessionsRevoked: 0
      });

      const event = createMockAdminEvent({
        body: JSON.stringify({ reason: 'Test' })
      });

      const result = await handler(event);

      expect(result.headers).toHaveProperty('X-Content-Type-Options', 'nosniff');
      expect(result.headers).toHaveProperty('X-Frame-Options', 'DENY');
      expect(result.headers).toHaveProperty('Strict-Transport-Security');
    });
  });
});
