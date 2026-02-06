/**
 * Admin MFA Reset E2E Tests
 * Task 6.9: Admin MFA Reset Procedure
 * 
 * Tests the admin MFA reset functionality including:
 * - Admin authentication requirements
 * - Reason validation
 * - User notification
 * - Session revocation
 * - Audit logging
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { adminResetMFAHandler } from '../../handlers/admin-handler';

// Mock dependencies
jest.mock('../../utils/jwt');
jest.mock('../../services/ratelimit.service');
jest.mock('../../services/audit.service');
jest.mock('../../repositories/user.repository');
jest.mock('../../repositories/session.repository');
jest.mock('../../services/email.service');

import * as jwt from '../../utils/jwt';
import * as ratelimit from '../../services/ratelimit.service';
import * as audit from '../../services/audit.service';
import * as userRepository from '../../repositories/user.repository';
import * as sessionRepository from '../../repositories/session.repository';
import * as emailService from '../../services/email.service';

const mockJwt = jwt as jest.Mocked<typeof jwt>;
const mockRatelimit = ratelimit as jest.Mocked<typeof ratelimit>;
const mockAudit = audit as jest.Mocked<typeof audit>;
const mockUserRepository = userRepository as jest.Mocked<typeof userRepository>;
const mockSessionRepository = sessionRepository as jest.Mocked<typeof sessionRepository>;
const mockEmailService = emailService as jest.Mocked<typeof emailService>;

const createMockEvent = (overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent => ({
  body: null,
  headers: { Authorization: 'Bearer valid-admin-token' },
  multiValueHeaders: {},
  httpMethod: 'POST',
  isBase64Encoded: false,
  path: '/v1/admin/users/user-1/mfa/reset',
  pathParameters: { id: 'user-1' },
  queryStringParameters: null,
  multiValueQueryStringParameters: null,
  stageVariables: null,
  requestContext: {
    accountId: '123456789',
    apiId: 'api-id',
    authorizer: null,
    protocol: 'HTTP/1.1',
    httpMethod: 'POST',
    identity: {
      sourceIp: '127.0.0.1',
      accessKey: null, accountId: null, apiKey: null, apiKeyId: null,
      caller: null, clientCert: null, cognitoAuthenticationProvider: null,
      cognitoAuthenticationType: null, cognitoIdentityId: null,
      cognitoIdentityPoolId: null, principalOrgId: null, user: null,
      userAgent: null, userArn: null
    },
    path: '/v1/admin/users/user-1/mfa/reset',
    stage: 'test',
    requestId: 'request-id',
    requestTimeEpoch: Date.now(),
    resourceId: 'resource-id',
    resourcePath: '/v1/admin/users/{id}/mfa/reset'
  },
  resource: '/v1/admin/users/{id}/mfa/reset',
  ...overrides
});

describe('Admin MFA Reset E2E Tests', () => {
  const mockUser = {
    id: 'user-1',
    email: 'user@clinisyn.com',
    status: 'active',
    realm_id: 'clinisyn-psychologists',
    mfa_enabled: true,
    mfa_secret: 'encrypted-secret'
  };

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mocks
    mockRatelimit.checkRateLimit.mockResolvedValue({ allowed: true, remaining: 99, resetAt: Date.now() + 60000 });
    mockJwt.verifyAccessToken.mockResolvedValue({
      sub: 'admin-user-1',
      realm_id: 'clinisyn-psychologists',
      is_admin: true
    } as any);
    mockAudit.logAuditEvent.mockResolvedValue({} as any);
  });

  describe('POST /v1/admin/users/:id/mfa/reset - Reset MFA', () => {
    it('should reset MFA for user with valid reason', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(3);
      mockEmailService.sendSecurityAlertEmail.mockResolvedValue({ success: true, messageId: 'msg-123' });

      const event = createMockEvent({
        body: JSON.stringify({ 
          reason: 'User lost their phone and cannot access authenticator app'
        })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.message).toContain('MFA reset');
      expect(body.data.user_notified).toBe(true);
      expect(body.data.revoked_sessions).toBe(3);
    });

    it('should require admin authentication', async () => {
      mockJwt.verifyAccessToken.mockResolvedValue({
        sub: 'regular-user',
        realm_id: 'clinisyn-psychologists',
        is_admin: false
      } as any);

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should require user ID parameter', async () => {
      const event = createMockEvent({
        pathParameters: null,
        body: JSON.stringify({ reason: 'User lost access to authenticator' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toContain('User ID');
    });

    it('should require a detailed reason (min 10 chars)', async () => {
      const event = createMockEvent({
        body: JSON.stringify({ reason: 'lost' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toContain('reason');
    });

    it('should return 404 for non-existent user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(null);

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should return error if user has no MFA enabled', async () => {
      mockUserRepository.findUserById.mockResolvedValue({ ...mockUser, mfa_enabled: false } as any);

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MFA_NOT_ENABLED');
    });

    it('should revoke all user sessions after MFA reset', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(5);
      mockEmailService.sendSecurityAlertEmail.mockResolvedValue({ success: true, messageId: 'msg-123' });

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      await adminResetMFAHandler(event);

      expect(mockSessionRepository.deleteUserSessions).toHaveBeenCalledWith(
        'clinisyn-psychologists',
        'user-1'
      );
    });

    it('should send security alert email to user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(1);
      mockEmailService.sendSecurityAlertEmail.mockResolvedValue({ success: true, messageId: 'msg-123' });

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      await adminResetMFAHandler(event);

      expect(mockEmailService.sendSecurityAlertEmail).toHaveBeenCalledWith(
        'user@clinisyn.com',
        'MFA Reset by Administrator',
        expect.stringContaining('Multi-Factor Authentication'),
        'clinisyn-psychologists'
      );
    });

    it('should continue even if email notification fails', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(1);
      mockEmailService.sendSecurityAlertEmail.mockRejectedValue(new Error('SES error'));

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(200); // Still succeeds
    });

    it('should enforce rate limiting', async () => {
      mockRatelimit.checkRateLimit.mockResolvedValue({ 
        allowed: false, 
        remaining: 0,
        retryAfter: 3600,
        resetAt: Date.now() + 3600000
      });

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(429);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('RATE_LIMITED');
    });
  });

  describe('Audit Logging', () => {
    it('should log detailed audit event on successful reset', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(2);
      mockEmailService.sendSecurityAlertEmail.mockResolvedValue({ success: true, messageId: 'msg-123' });

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      await adminResetMFAHandler(event);

      expect(mockAudit.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'mfa_disable',
          action: 'admin_reset_mfa',
          result: 'success',
          details: expect.objectContaining({
            target_user: 'user-1',
            target_email: 'user@clinisyn.com',
            reason: 'User lost access to authenticator app',
            revoked_sessions: 2
          })
        })
      );
    });

    it('should include admin user ID in audit log', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(1);
      mockEmailService.sendSecurityAlertEmail.mockResolvedValue({ success: true, messageId: 'msg-123' });

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      await adminResetMFAHandler(event);

      expect(mockAudit.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'admin-user-1',
          details: expect.objectContaining({
            admin_user: 'admin-user-1'
          })
        })
      );
    });
  });

  describe('Security Tests', () => {
    it('should reject requests without authorization header', async () => {
      const event = createMockEvent({
        headers: {},
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(401);
    });

    it('should reject requests with invalid token', async () => {
      mockJwt.verifyAccessToken.mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(401);
    });

    it('should include security headers in response', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(1);
      mockEmailService.sendSecurityAlertEmail.mockResolvedValue({ success: true, messageId: 'msg-123' });

      const event = createMockEvent({
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.headers).toMatchObject({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Strict-Transport-Security': expect.stringContaining('max-age')
      });
    });

    it('should handle invalid JSON body', async () => {
      const event = createMockEvent({
        body: 'invalid json'
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_JSON');
    });

    it('should use realm from query param if provided', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(1);
      mockEmailService.sendSecurityAlertEmail.mockResolvedValue({ success: true, messageId: 'msg-123' });

      const event = createMockEvent({
        queryStringParameters: { realm_id: 'other-realm' },
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      await adminResetMFAHandler(event);

      expect(mockUserRepository.findUserById).toHaveBeenCalledWith('other-realm', 'user-1');
    });
  });
});
