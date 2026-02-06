/**
 * Admin User Management E2E Tests
 * Task 9.3: Admin User Management
 * 
 * Tests admin endpoints for user management:
 * - GET /v1/admin/users (pagination)
 * - GET /v1/admin/users/:id
 * - POST /v1/admin/users/:id/suspend
 * - POST /v1/admin/users/:id/activate
 * - POST /v1/admin/users/:id/unlock
 * - POST /v1/admin/users/:id/reset-password
 * - DELETE /v1/admin/users/:id
 */

import {
  listUsersHandler,
  getUserHandler,
  suspendUserHandler,
  activateUserHandler,
  unlockUserHandler,
  adminResetPasswordHandler,
  deleteUserHandler
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
    ACCOUNT_UNLOCK: 'account_unlock',
    ACCOUNT_DELETE: 'account_delete',
    PASSWORD_RESET_REQUEST: 'password_reset_request',
    TOKEN_REVOKE: 'token_revoke'
  },
  AuditResult: {
    SUCCESS: 'success',
    FAILURE: 'failure'
  }
}));

jest.mock('../../repositories/user.repository', () => ({
  listRealmUsers: jest.fn(),
  getAdminUserDetails: jest.fn(),
  suspendUser: jest.fn(),
  activateUser: jest.fn(),
  unlockUser: jest.fn(),
  adminResetUserMFA: jest.fn(),
  setPasswordResetToken: jest.fn(),
  findUserById: jest.fn(),
  deleteUser: jest.fn()
}));

jest.mock('../../repositories/session.repository', () => ({
  getUserSessions: jest.fn(),
  deleteSession: jest.fn(),
  deleteUserSessions: jest.fn()
}));

jest.mock('../../services/email.service', () => ({
  sendPasswordResetEmail: jest.fn().mockResolvedValue({ success: true, messageId: 'test-id' })
}));

import { verifyAccessToken } from '../../utils/jwt';
import { checkRateLimit } from '../../services/ratelimit.service';
import { logAuditEvent } from '../../services/audit.service';
import {
  listRealmUsers,
  getAdminUserDetails,
  suspendUser,
  activateUser,
  unlockUser,
  setPasswordResetToken,
  findUserById,
  deleteUser
} from '../../repositories/user.repository';
import { getUserSessions, deleteUserSessions } from '../../repositories/session.repository';
import { sendPasswordResetEmail } from '../../services/email.service';

const mockVerifyAccessToken = verifyAccessToken as jest.Mock;
const mockCheckRateLimit = checkRateLimit as jest.Mock;
const mockLogAuditEvent = logAuditEvent as jest.Mock;
const mockListRealmUsers = listRealmUsers as jest.Mock;
const mockGetAdminUserDetails = getAdminUserDetails as jest.Mock;
const mockSuspendUser = suspendUser as jest.Mock;
const mockActivateUser = activateUser as jest.Mock;
const mockUnlockUser = unlockUser as jest.Mock;
const mockSetPasswordResetToken = setPasswordResetToken as jest.Mock;
const mockFindUserById = findUserById as jest.Mock;
const mockDeleteUser = deleteUser as jest.Mock;
const mockGetUserSessions = getUserSessions as jest.Mock;
const mockDeleteUserSessions = deleteUserSessions as jest.Mock;
const mockSendPasswordResetEmail = sendPasswordResetEmail as jest.Mock;

/**
 * Create mock API Gateway event
 */
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/v1/admin/users',
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
 * Create mock user
 */
function createMockUser(overrides: Partial<{
  id: string;
  realm_id: string;
  email: string;
  status: string;
  mfa_enabled: boolean;
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
    status: overrides.status || 'active',
    mfa_enabled: overrides.mfa_enabled ?? false
  };
}

describe('Admin User Management E2E Tests', () => {
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

  describe('GET /v1/admin/users - List Users', () => {
    it('should list users with pagination', async () => {
      const mockUsers = [
        createMockUser({ id: 'user-1', email: 'user1@example.com' }),
        createMockUser({ id: 'user-2', email: 'user2@example.com' })
      ];

      mockListRealmUsers.mockResolvedValue({
        users: mockUsers,
        lastEvaluatedKey: { pk: 'next-key' },
        total: 2
      });

      const event = createMockEvent({
        queryStringParameters: { limit: '10' }
      });

      const response = await listUsersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.users).toHaveLength(2);
      expect(body.data.pagination.has_more).toBe(true);
      expect(body.data.pagination.next_key).toBeDefined();
    });

    it('should filter users by status', async () => {
      mockListRealmUsers.mockResolvedValue({
        users: [createMockUser({ status: 'suspended' })],
        total: 1
      });

      const event = createMockEvent({
        queryStringParameters: { status: 'suspended' }
      });

      const response = await listUsersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(mockListRealmUsers).toHaveBeenCalledWith(
        'test-realm',
        expect.objectContaining({ status: 'suspended' })
      );
    });

    it('should search users by email', async () => {
      mockListRealmUsers.mockResolvedValue({
        users: [createMockUser({ email: 'search@example.com' })],
        total: 1
      });

      const event = createMockEvent({
        queryStringParameters: { search: 'search' }
      });

      const response = await listUsersHandler(event);

      expect(response.statusCode).toBe(200);
      expect(mockListRealmUsers).toHaveBeenCalledWith(
        'test-realm',
        expect.objectContaining({ search: 'search' })
      );
    });

    it('should reject non-admin users', async () => {
      mockVerifyAccessToken.mockResolvedValue({
        sub: 'regular-user',
        realm_id: 'test-realm',
        is_admin: false
      });

      const event = createMockEvent();
      const response = await listUsersHandler(event);
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

      const event = createMockEvent();
      const response = await listUsersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });

    it('should handle pagination key correctly', async () => {
      mockListRealmUsers.mockResolvedValue({
        users: [],
        total: 0
      });

      const lastKey = Buffer.from(JSON.stringify({ pk: 'test-key' })).toString('base64');
      const event = createMockEvent({
        queryStringParameters: { last_key: lastKey }
      });

      const response = await listUsersHandler(event);

      expect(response.statusCode).toBe(200);
      expect(mockListRealmUsers).toHaveBeenCalledWith(
        'test-realm',
        expect.objectContaining({ lastEvaluatedKey: { pk: 'test-key' } })
      );
    });

    it('should reject invalid pagination key', async () => {
      const event = createMockEvent({
        queryStringParameters: { last_key: 'invalid-base64!' }
      });

      const response = await listUsersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });
  });

  describe('GET /v1/admin/users/:id - Get User Details', () => {
    it('should return user details with security info', async () => {
      const mockUser = createMockUser({ mfa_enabled: true });
      mockGetAdminUserDetails.mockResolvedValue({
        user: mockUser,
        security: {
          mfa_enabled: true,
          webauthn_enabled: false,
          webauthn_credential_count: 0,
          failed_login_attempts: 2,
          locked_until: null,
          password_changed_at: '2026-01-10T10:00:00Z'
        }
      });
      mockGetUserSessions.mockResolvedValue([
        { id: 'session-1', ip_address: '192.168.1.1', user_agent: 'Chrome', created_at: '2026-01-15T10:00:00Z' }
      ]);

      const event = createMockEvent({
        pathParameters: { id: 'user-123' }
      });

      const response = await getUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.user.id).toBe('user-123');
      expect(body.data.security.mfa_enabled).toBe(true);
      expect(body.data.sessions.active_count).toBe(1);
    });

    it('should return 404 for non-existent user', async () => {
      mockGetAdminUserDetails.mockResolvedValue(null);

      const event = createMockEvent({
        pathParameters: { id: 'non-existent' }
      });

      const response = await getUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should require user ID', async () => {
      const event = createMockEvent({
        pathParameters: null
      });

      const response = await getUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });
  });

  describe('POST /v1/admin/users/:id/suspend - Suspend User', () => {
    it('should suspend user and revoke sessions', async () => {
      mockFindUserById.mockResolvedValue(createMockUser());
      mockSuspendUser.mockResolvedValue(true);
      mockDeleteUserSessions.mockResolvedValue(3);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-123' },
        body: JSON.stringify({ reason: 'Policy violation' })
      });

      const response = await suspendUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.message).toContain('suspended');
      expect(body.data.revoked_sessions).toBe(3);
      expect(mockSuspendUser).toHaveBeenCalledWith('test-realm', 'user-123', 'Policy violation');
    });

    it('should prevent self-suspension', async () => {
      mockVerifyAccessToken.mockResolvedValue({
        sub: 'user-123',
        realm_id: 'test-realm',
        is_admin: true
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-123' }
      });

      const response = await suspendUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.message).toContain('Cannot suspend your own account');
    });

    it('should return 404 for non-existent user', async () => {
      mockFindUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'non-existent' }
      });

      const response = await suspendUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('POST /v1/admin/users/:id/activate - Activate User', () => {
    it('should activate suspended user', async () => {
      mockFindUserById.mockResolvedValue(createMockUser({ status: 'suspended' }));
      mockActivateUser.mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-123' }
      });

      const response = await activateUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.message).toContain('activated');
      expect(mockActivateUser).toHaveBeenCalledWith('test-realm', 'user-123');
    });

    it('should return 404 for non-existent user', async () => {
      mockFindUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'non-existent' }
      });

      const response = await activateUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('POST /v1/admin/users/:id/unlock - Unlock User', () => {
    it('should unlock locked user', async () => {
      mockFindUserById.mockResolvedValue(createMockUser({
        ...createMockUser(),
        failed_login_attempts: 5,
        locked_until: '2026-01-15T12:00:00Z'
      } as any));
      mockUnlockUser.mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-123' }
      });

      const response = await unlockUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.message).toContain('unlocked');
      expect(mockUnlockUser).toHaveBeenCalledWith('test-realm', 'user-123');
    });

    it('should log unlock event with previous state', async () => {
      const lockedUser = {
        ...createMockUser(),
        failed_login_attempts: 5,
        locked_until: '2026-01-15T12:00:00Z'
      };
      mockFindUserById.mockResolvedValue(lockedUser);
      mockUnlockUser.mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-123' }
      });

      await unlockUserHandler(event);

      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'admin_unlock_user',
          details: expect.objectContaining({
            previous_failed_attempts: 5,
            previous_locked_until: '2026-01-15T12:00:00Z'
          })
        })
      );
    });
  });

  describe('POST /v1/admin/users/:id/reset-password - Admin Password Reset', () => {
    it('should initiate password reset and send email', async () => {
      mockFindUserById.mockResolvedValue(createMockUser());
      mockSetPasswordResetToken.mockResolvedValue(true);
      mockSendPasswordResetEmail.mockResolvedValue({ success: true });

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-123' }
      });

      const response = await adminResetPasswordHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.message).toContain('Password reset email sent');
      expect(body.data.expires_at).toBeDefined();
      expect(mockSendPasswordResetEmail).toHaveBeenCalled();
    });

    it('should return 404 for non-existent user', async () => {
      mockFindUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'non-existent' }
      });

      const response = await adminResetPasswordHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should continue even if email fails', async () => {
      mockFindUserById.mockResolvedValue(createMockUser());
      mockSetPasswordResetToken.mockResolvedValue(true);
      mockSendPasswordResetEmail.mockRejectedValue(new Error('Email failed'));

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-123' }
      });

      const response = await adminResetPasswordHandler(event);
      const body = JSON.parse(response.body);

      // Should still succeed - token is set
      expect(response.statusCode).toBe(200);
      expect(body.data.message).toContain('Password reset email sent');
    });
  });

  describe('DELETE /v1/admin/users/:id - Delete User', () => {
    it('should delete user and all sessions', async () => {
      mockFindUserById.mockResolvedValue(createMockUser());
      mockDeleteUserSessions.mockResolvedValue(2);
      mockDeleteUser.mockResolvedValue(undefined);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'user-123' }
      });

      const response = await deleteUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.message).toContain('deleted');
      expect(body.data.deleted_sessions).toBe(2);
      expect(mockDeleteUser).toHaveBeenCalledWith('test-realm', 'user-123');
    });

    it('should prevent self-deletion', async () => {
      mockVerifyAccessToken.mockResolvedValue({
        sub: 'user-123',
        realm_id: 'test-realm',
        is_admin: true
      });

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'user-123' }
      });

      const response = await deleteUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.message).toContain('Cannot delete your own account');
    });

    it('should return 404 for non-existent user', async () => {
      mockFindUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'non-existent' }
      });

      const response = await deleteUserHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should log deletion with user email', async () => {
      const user = createMockUser({ email: 'deleted@example.com' });
      mockFindUserById.mockResolvedValue(user);
      mockDeleteUserSessions.mockResolvedValue(0);
      mockDeleteUser.mockResolvedValue(undefined);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'user-123' }
      });

      await deleteUserHandler(event);

      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'admin_delete_user',
          details: expect.objectContaining({
            target_email: 'deleted@example.com'
          })
        })
      );
    });
  });

  describe('Security Tests', () => {
    it('should reject requests without authorization header', async () => {
      const event = createMockEvent({
        headers: {}
      });

      const response = await listUsersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject requests with invalid token', async () => {
      mockVerifyAccessToken.mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent();
      const response = await listUsersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should include security headers in response', async () => {
      mockListRealmUsers.mockResolvedValue({ users: [], total: 0 });

      const event = createMockEvent();
      const response = await listUsersHandler(event);

      expect(response.headers).toMatchObject({
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Strict-Transport-Security': expect.stringContaining('max-age=')
      });
    });

    it('should audit all admin actions', async () => {
      mockListRealmUsers.mockResolvedValue({ users: [], total: 0 });

      const event = createMockEvent();
      await listUsersHandler(event);

      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'list_users',
          userId: 'admin-user-id',
          realmId: 'test-realm'
        })
      );
    });
  });
});
