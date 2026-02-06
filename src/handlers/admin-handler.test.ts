/**
 * Admin Handler Tests - Realm Configuration API & User/Session Management
 * Task 9.2: Realm Configuration API
 * Task 9.3: Admin User Management
 * Task 9.4: Admin Session Management
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  listRealmsHandler,
  getRealmHandler,
  createRealmHandler,
  updateRealmHandler,
  deleteRealmHandler,
  listUsersHandler,
  getUserHandler,
  suspendUserHandler,
  activateUserHandler,
  unlockUserHandler,
  adminResetPasswordHandler,
  deleteUserHandler,
  listSessionsHandler,
  revokeSessionHandler,
  revokeUserSessionsHandler,
  adminResetMFAHandler
} from './admin-handler';
import * as realmService from '../services/realm.service';
import * as userRepository from '../repositories/user.repository';
import * as sessionRepository from '../repositories/session.repository';
import * as emailService from '../services/email.service';
import * as jwt from '../utils/jwt';
import * as ratelimit from '../services/ratelimit.service';
import * as audit from '../services/audit.service';
import { DEFAULT_REALM_SETTINGS } from '../models/realm.model';

// UserStatus is a type alias, use string literals directly

// Mock dependencies
jest.mock('../services/realm.service');
jest.mock('../repositories/user.repository');
jest.mock('../repositories/session.repository');
jest.mock('../services/email.service');
jest.mock('../utils/jwt');
jest.mock('../services/ratelimit.service');
jest.mock('../services/audit.service');

const mockRealmService = realmService as jest.Mocked<typeof realmService>;
const mockUserRepository = userRepository as jest.Mocked<typeof userRepository>;
const mockSessionRepository = sessionRepository as jest.Mocked<typeof sessionRepository>;
const mockEmailService = emailService as jest.Mocked<typeof emailService>;
const mockJwt = jwt as jest.Mocked<typeof jwt>;
const mockRatelimit = ratelimit as jest.Mocked<typeof ratelimit>;
const mockAudit = audit as jest.Mocked<typeof audit>;

const createMockEvent = (overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent => ({
  body: null,
  headers: { Authorization: 'Bearer valid-admin-token' },
  multiValueHeaders: {},
  httpMethod: 'GET',
  isBase64Encoded: false,
  path: '/v1/admin/realms',
  pathParameters: null,
  queryStringParameters: null,
  multiValueQueryStringParameters: null,
  stageVariables: null,
  requestContext: {
    accountId: '123456789',
    apiId: 'api-id',
    authorizer: null,
    protocol: 'HTTP/1.1',
    httpMethod: 'GET',
    identity: {
      sourceIp: '127.0.0.1',
      accessKey: null, accountId: null, apiKey: null, apiKeyId: null,
      caller: null, clientCert: null, cognitoAuthenticationProvider: null,
      cognitoAuthenticationType: null, cognitoIdentityId: null,
      cognitoIdentityPoolId: null, principalOrgId: null, user: null,
      userAgent: null, userArn: null
    },
    path: '/v1/admin/realms',
    stage: 'test',
    requestId: 'request-id',
    requestTimeEpoch: Date.now(),
    resourceId: 'resource-id',
    resourcePath: '/v1/admin/realms'
  },
  resource: '/v1/admin/realms',
  ...overrides
});


describe('Admin Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mocks
    mockRatelimit.checkRateLimit.mockResolvedValue({ allowed: true, remaining: 99, resetAt: Date.now() + 60000 });
    mockJwt.verifyAccessToken.mockResolvedValue({
      sub: 'admin-user-1',
      realm_id: 'admin-realm',
      is_admin: true
    } as any);
    mockAudit.logAuditEvent.mockResolvedValue({} as any);
  });

  describe('listRealmsHandler', () => {
    it('should return list of realms for admin', async () => {
      const mockRealms = [
        { id: 'realm-1', name: 'Realm 1', domain: 'realm1.com', settings: DEFAULT_REALM_SETTINGS, auth_providers: [], created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
        { id: 'realm-2', name: 'Realm 2', domain: 'realm2.com', settings: DEFAULT_REALM_SETTINGS, auth_providers: [], created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
      ];
      mockRealmService.listRealms.mockResolvedValue(mockRealms);

      const event = createMockEvent();
      const result = await listRealmsHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.realms).toHaveLength(2);
      expect(body.data.total).toBe(2);
    });

    it('should return 401 for non-admin user', async () => {
      mockJwt.verifyAccessToken.mockResolvedValue({
        sub: 'regular-user',
        realm_id: 'test-realm'
      } as any);

      const event = createMockEvent();
      const result = await listRealmsHandler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 for missing auth header', async () => {
      const event = createMockEvent({ headers: {} });
      const result = await listRealmsHandler(event);

      expect(result.statusCode).toBe(401);
    });

    it('should return 429 when rate limited', async () => {
      mockRatelimit.checkRateLimit.mockResolvedValue({ 
        allowed: false, 
        remaining: 0,
        retryAfter: 60,
        resetAt: Date.now() + 60000
      });

      const event = createMockEvent();
      const result = await listRealmsHandler(event);

      expect(result.statusCode).toBe(429);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('RATE_LIMITED');
    });

    it('should filter healthcare realms when requested', async () => {
      mockRealmService.listRealms.mockResolvedValue([]);

      const event = createMockEvent({
        queryStringParameters: { healthcare_only: 'true' }
      });
      await listRealmsHandler(event);

      expect(mockRealmService.listRealms).toHaveBeenCalledWith({ healthcareOnly: true });
    });

    it('should log audit event', async () => {
      mockRealmService.listRealms.mockResolvedValue([]);

      const event = createMockEvent();
      await listRealmsHandler(event);

      expect(mockAudit.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'admin_action',
          action: 'list_realms'
        })
      );
    });
  });

  describe('getRealmHandler', () => {
    it('should return realm details', async () => {
      const mockRealm = {
        id: 'test-realm',
        name: 'Test Realm',
        domain: 'test.com',
        settings: DEFAULT_REALM_SETTINGS,
        auth_providers: [],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      mockRealmService.getRealm.mockResolvedValue(mockRealm);
      mockRealmService.getRealmStats.mockResolvedValue({
        realmId: 'test-realm',
        userCount: 100,
        activeSessionCount: 50,
        deviceCount: 0,
        mfaEnabledUsers: 80,
        webauthnEnabledUsers: 20,
        createdAt: mockRealm.created_at
      });

      const event = createMockEvent({
        pathParameters: { id: 'test-realm' }
      });
      const result = await getRealmHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.realm.id).toBe('test-realm');
      expect(body.data.stats).toBeDefined();
    });

    it('should return 404 for non-existent realm', async () => {
      mockRealmService.getRealm.mockResolvedValue(null);

      const event = createMockEvent({
        pathParameters: { id: 'non-existent' }
      });
      const result = await getRealmHandler(event);

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should return 400 for missing realm ID', async () => {
      const event = createMockEvent({
        pathParameters: null
      });
      const result = await getRealmHandler(event);

      expect(result.statusCode).toBe(400);
    });
  });

  describe('createRealmHandler', () => {
    it('should create new realm', async () => {
      const mockRealm = {
        id: 'new-realm',
        name: 'new-realm',
        domain: 'new.example.com',
        settings: DEFAULT_REALM_SETTINGS,
        auth_providers: [],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      mockRealmService.createRealm.mockResolvedValue({ success: true, realm: mockRealm });

      const event = createMockEvent({
        httpMethod: 'POST',
        body: JSON.stringify({
          name: 'new-realm',
          domain: 'new.example.com'
        })
      });
      const result = await createRealmHandler(event);

      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.data.realm.id).toBe('new-realm');
    });

    it('should return 400 for missing required fields', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        body: JSON.stringify({ name: 'test' }) // Missing domain
      });
      const result = await createRealmHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toContain('required');
    });

    it('should return 400 for invalid JSON', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        body: 'invalid json'
      });
      const result = await createRealmHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_JSON');
    });

    it('should return 400 when creation fails', async () => {
      mockRealmService.createRealm.mockResolvedValue({ 
        success: false, 
        error: 'Realm already exists' 
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        body: JSON.stringify({
          name: 'existing-realm',
          domain: 'existing.example.com'
        })
      });
      const result = await createRealmHandler(event);

      expect(result.statusCode).toBe(400);
    });
  });

  describe('updateRealmHandler', () => {
    it('should update realm configuration', async () => {
      const mockRealm = {
        id: 'test-realm',
        name: 'test-realm',
        domain: 'updated.example.com',
        settings: DEFAULT_REALM_SETTINGS,
        auth_providers: [],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      mockRealmService.updateRealm.mockResolvedValue({ success: true, realm: mockRealm });

      const event = createMockEvent({
        httpMethod: 'PATCH',
        pathParameters: { id: 'test-realm' },
        body: JSON.stringify({ domain: 'updated.example.com' })
      });
      const result = await updateRealmHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.realm.domain).toBe('updated.example.com');
    });

    it('should return 404 for non-existent realm', async () => {
      mockRealmService.updateRealm.mockResolvedValue({ 
        success: false, 
        error: 'Realm not found' 
      });

      const event = createMockEvent({
        httpMethod: 'PATCH',
        pathParameters: { id: 'non-existent' },
        body: JSON.stringify({ domain: 'new.example.com' })
      });
      const result = await updateRealmHandler(event);

      expect(result.statusCode).toBe(404);
    });

    it('should log config change audit event', async () => {
      mockRealmService.updateRealm.mockResolvedValue({ 
        success: true, 
        realm: { id: 'test-realm' } as any 
      });

      const event = createMockEvent({
        httpMethod: 'PATCH',
        pathParameters: { id: 'test-realm' },
        body: JSON.stringify({ domain: 'new.example.com' })
      });
      await updateRealmHandler(event);

      expect(mockAudit.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'config_change',
          action: 'update_realm'
        })
      );
    });
  });

  describe('deleteRealmHandler', () => {
    it('should delete realm', async () => {
      mockRealmService.deleteRealmWithCleanup.mockResolvedValue({ 
        success: true, 
        deletedCounts: { users: 10, sessions: 5, devices: 0, auditLogs: 0 }
      });

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'realm-to-delete' }
      });
      const result = await deleteRealmHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.deleted_counts).toBeDefined();
    });

    it('should prevent self-deletion', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'admin-realm' } // Same as admin's realm
      });
      const result = await deleteRealmHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toContain('Cannot delete your own realm');
    });

    it('should return 404 for non-existent realm', async () => {
      mockRealmService.deleteRealmWithCleanup.mockResolvedValue({ 
        success: false, 
        error: 'Realm not found' 
      });

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'non-existent' }
      });
      const result = await deleteRealmHandler(event);

      expect(result.statusCode).toBe(404);
    });

    it('should have strict rate limiting', async () => {
      mockRatelimit.checkRateLimit.mockResolvedValue({ 
        allowed: false, 
        remaining: 0,
        retryAfter: 3600,
        resetAt: Date.now() + 3600000
      });

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'test-realm' }
      });
      const result = await deleteRealmHandler(event);

      expect(result.statusCode).toBe(429);
    });
  });

  // ============================================================================
  // ADMIN USER MANAGEMENT TESTS (Task 9.3)
  // ============================================================================

  describe('listUsersHandler', () => {
    const mockUsers = [
      { id: 'user-1', email: 'user1@test.com', status: 'active', realm_id: 'admin-realm' },
      { id: 'user-2', email: 'user2@test.com', status: 'active', realm_id: 'admin-realm' }
    ];

    it('should list users with pagination', async () => {
      mockUserRepository.listRealmUsers.mockResolvedValue({
        users: mockUsers as any,
        total: 2,
        lastEvaluatedKey: undefined
      });

      const event = createMockEvent({
        queryStringParameters: { limit: '50' }
      });
      const result = await listUsersHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.users).toHaveLength(2);
      expect(body.data.pagination.total).toBe(2);
    });

    it('should filter users by status', async () => {
      mockUserRepository.listRealmUsers.mockResolvedValue({
        users: [mockUsers[0]] as any,
        total: 1,
        lastEvaluatedKey: undefined
      });

      const event = createMockEvent({
        queryStringParameters: { status: 'active' }
      });
      await listUsersHandler(event);

      expect(mockUserRepository.listRealmUsers).toHaveBeenCalledWith(
        'admin-realm',
        expect.objectContaining({ status: 'active' })
      );
    });

    it('should return 401 for non-admin', async () => {
      mockJwt.verifyAccessToken.mockResolvedValue({
        sub: 'regular-user',
        realm_id: 'test-realm'
      } as any);

      const event = createMockEvent();
      const result = await listUsersHandler(event);

      expect(result.statusCode).toBe(401);
    });
  });

  describe('getUserHandler', () => {
    const mockUser = {
      id: 'user-1',
      email: 'user@test.com',
      status: 'active',
      realm_id: 'admin-realm',
      mfa_enabled: true,
      failed_login_attempts: 0
    };

    it('should return user details with sessions', async () => {
      mockUserRepository.getAdminUserDetails.mockResolvedValue(mockUser as any);
      mockSessionRepository.getUserSessions.mockResolvedValue([
        { id: 'session-1', user_id: 'user-1', realm_id: 'admin-realm' } as any
      ]);

      const event = createMockEvent({
        pathParameters: { id: 'user-1' }
      });
      const result = await getUserHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.id).toBe('user-1');
      expect(body.data.sessions.active_count).toBe(1);
    });

    it('should return 404 for non-existent user', async () => {
      mockUserRepository.getAdminUserDetails.mockResolvedValue(null);

      const event = createMockEvent({
        pathParameters: { id: 'non-existent' }
      });
      const result = await getUserHandler(event);

      expect(result.statusCode).toBe(404);
    });

    it('should return 400 for missing user ID', async () => {
      const event = createMockEvent({
        pathParameters: null
      });
      const result = await getUserHandler(event);

      expect(result.statusCode).toBe(400);
    });
  });

  describe('suspendUserHandler', () => {
    const mockUser = {
      id: 'user-1',
      email: 'user@test.com',
      status: 'active',
      realm_id: 'admin-realm'
    };

    it('should suspend user and revoke sessions', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.suspendUser.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(3);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' },
        body: JSON.stringify({ reason: 'Policy violation' })
      });
      const result = await suspendUserHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.revoked_sessions).toBe(3);
    });

    it('should prevent self-suspension', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'admin-user-1' } // Same as admin's user ID
      });
      const result = await suspendUserHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toContain('Cannot suspend your own account');
    });

    it('should return 404 for non-existent user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'non-existent' }
      });
      const result = await suspendUserHandler(event);

      expect(result.statusCode).toBe(404);
    });
  });

  describe('activateUserHandler', () => {
    const mockUser = {
      id: 'user-1',
      email: 'user@test.com',
      status: 'suspended',
      realm_id: 'admin-realm'
    };

    it('should activate suspended user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.activateUser.mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' }
      });
      const result = await activateUserHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.message).toContain('activated');
    });

    it('should return 404 for non-existent user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'non-existent' }
      });
      const result = await activateUserHandler(event);

      expect(result.statusCode).toBe(404);
    });
  });

  describe('unlockUserHandler', () => {
    const mockUser = {
      id: 'user-1',
      email: 'user@test.com',
      status: 'active',
      realm_id: 'admin-realm',
      failed_login_attempts: 5,
      locked_until: new Date(Date.now() + 3600000).toISOString()
    };

    it('should unlock locked user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.unlockUser.mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' }
      });
      const result = await unlockUserHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.message).toContain('unlocked');
    });

    it('should log unlock with previous state', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.unlockUser.mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' }
      });
      await unlockUserHandler(event);

      expect(mockAudit.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'admin_unlock_user',
          details: expect.objectContaining({
            previous_failed_attempts: 5
          })
        })
      );
    });
  });

  describe('adminResetPasswordHandler', () => {
    const mockUser = {
      id: 'user-1',
      email: 'user@test.com',
      status: 'active',
      realm_id: 'admin-realm'
    };

    it('should initiate password reset and send email', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.setPasswordResetToken.mockResolvedValue(true);
      mockEmailService.sendPasswordResetEmail.mockResolvedValue({ success: true, messageId: 'test-id' });

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' }
      });
      const result = await adminResetPasswordHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.message).toContain('reset email sent');
      expect(mockEmailService.sendPasswordResetEmail).toHaveBeenCalled();
    });

    it('should return 404 for non-existent user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'non-existent' }
      });
      const result = await adminResetPasswordHandler(event);

      expect(result.statusCode).toBe(404);
    });

    it('should continue even if email fails', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.setPasswordResetToken.mockResolvedValue(true);
      mockEmailService.sendPasswordResetEmail.mockRejectedValue(new Error('Email failed'));

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' }
      });
      const result = await adminResetPasswordHandler(event);

      expect(result.statusCode).toBe(200); // Still succeeds
    });
  });

  describe('deleteUserHandler', () => {
    const mockUser = {
      id: 'user-1',
      email: 'user@test.com',
      status: 'active',
      realm_id: 'admin-realm'
    };

    it('should delete user and all sessions', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(2);
      mockUserRepository.deleteUser.mockResolvedValue();

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'user-1' }
      });
      const result = await deleteUserHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.deleted_sessions).toBe(2);
    });

    it('should prevent self-deletion', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'admin-user-1' }
      });
      const result = await deleteUserHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toContain('Cannot delete your own account');
    });

    it('should return 404 for non-existent user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'non-existent' }
      });
      const result = await deleteUserHandler(event);

      expect(result.statusCode).toBe(404);
    });
  });

  // ============================================================================
  // ADMIN SESSION MANAGEMENT TESTS (Task 9.4)
  // ============================================================================

  describe('listSessionsHandler', () => {
    const mockSessions = [
      { id: 'session-1', user_id: 'user-1', realm_id: 'admin-realm', ip_address: '1.2.3.4' },
      { id: 'session-2', user_id: 'user-1', realm_id: 'admin-realm', ip_address: '5.6.7.8' }
    ];

    it('should list user sessions', async () => {
      mockSessionRepository.getUserSessions.mockResolvedValue(mockSessions as any);

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-1' }
      });
      const result = await listSessionsHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.sessions).toHaveLength(2);
      expect(body.data.total).toBe(2);
    });

    it('should require user_id parameter', async () => {
      const event = createMockEvent({
        queryStringParameters: null
      });
      const result = await listSessionsHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toContain('user_id');
    });

    it('should return 401 for non-admin', async () => {
      mockJwt.verifyAccessToken.mockResolvedValue({
        sub: 'regular-user',
        realm_id: 'test-realm'
      } as any);

      const event = createMockEvent({
        queryStringParameters: { user_id: 'user-1' }
      });
      const result = await listSessionsHandler(event);

      expect(result.statusCode).toBe(401);
    });
  });

  describe('revokeSessionHandler', () => {
    it('should revoke a specific session', async () => {
      mockSessionRepository.deleteSession.mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'session-1' },
        body: JSON.stringify({ user_id: 'user-1' })
      });
      const result = await revokeSessionHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.message).toContain('revoked');
    });

    it('should require session ID', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: null,
        body: JSON.stringify({ user_id: 'user-1' })
      });
      const result = await revokeSessionHandler(event);

      expect(result.statusCode).toBe(400);
    });

    it('should require user_id in body', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'session-1' },
        body: JSON.stringify({})
      });
      const result = await revokeSessionHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toContain('user_id');
    });

    it('should return 404 for non-existent session', async () => {
      mockSessionRepository.deleteSession.mockResolvedValue(false);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'non-existent' },
        body: JSON.stringify({ user_id: 'user-1' })
      });
      const result = await revokeSessionHandler(event);

      expect(result.statusCode).toBe(404);
    });
  });

  describe('revokeUserSessionsHandler', () => {
    const mockUser = {
      id: 'user-1',
      email: 'user@test.com',
      status: 'active',
      realm_id: 'admin-realm'
    };

    it('should revoke all sessions for a user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(5);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'user-1' }
      });
      const result = await revokeUserSessionsHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.revoked_count).toBe(5);
    });

    it('should require user ID', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: null
      });
      const result = await revokeUserSessionsHandler(event);

      expect(result.statusCode).toBe(400);
    });

    it('should return 404 for non-existent user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'non-existent' }
      });
      const result = await revokeUserSessionsHandler(event);

      expect(result.statusCode).toBe(404);
    });
  });

  // ============================================================================
  // ADMIN MFA RESET TESTS (Task 6.9)
  // ============================================================================

  describe('adminResetMFAHandler', () => {
    const mockUser = {
      id: 'user-1',
      email: 'user@test.com',
      status: 'active',
      realm_id: 'admin-realm',
      mfa_enabled: true
    };

    it('should reset MFA and revoke sessions', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(2);
      mockEmailService.sendSecurityAlertEmail.mockResolvedValue({ success: true, messageId: 'test-id' });

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' },
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.data.message).toContain('MFA reset');
      expect(body.data.revoked_sessions).toBe(2);
    });

    it('should require a detailed reason', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' },
        body: JSON.stringify({ reason: 'short' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toContain('reason');
    });

    it('should return 404 for non-existent user', async () => {
      mockUserRepository.findUserById.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'non-existent' },
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(404);
    });

    it('should return error if user has no MFA enabled', async () => {
      mockUserRepository.findUserById.mockResolvedValue({ ...mockUser, mfa_enabled: false } as any);

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' },
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('MFA_NOT_ENABLED');
    });

    it('should continue even if email notification fails', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(1);
      mockEmailService.sendSecurityAlertEmail.mockRejectedValue(new Error('Email failed'));

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' },
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      const result = await adminResetMFAHandler(event);

      expect(result.statusCode).toBe(200); // Still succeeds
    });

    it('should log detailed audit event', async () => {
      mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
      mockUserRepository.adminResetUserMFA.mockResolvedValue(true);
      mockSessionRepository.deleteUserSessions.mockResolvedValue(1);
      mockEmailService.sendSecurityAlertEmail.mockResolvedValue({ success: true, messageId: 'test-id' });

      const event = createMockEvent({
        httpMethod: 'POST',
        pathParameters: { id: 'user-1' },
        body: JSON.stringify({ reason: 'User lost access to authenticator app' })
      });
      await adminResetMFAHandler(event);

      expect(mockAudit.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'mfa_disable',
          action: 'admin_reset_mfa',
          details: expect.objectContaining({
            reason: 'User lost access to authenticator app',
            target_user: 'user-1'
          })
        })
      );
    });
  });
});
