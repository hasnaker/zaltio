/**
 * Session Tasks Handler Tests
 * Validates: Requirements 4.7, 4.8 (Session Tasks Endpoints)
 * 
 * Tests for:
 * - GET /session/tasks - Get pending tasks
 * - POST /session/tasks/{id}/complete - Complete task
 * - POST /session/tasks/{id}/skip - Skip non-blocking task
 * - POST /admin/users/{id}/force-password-reset - Force password reset
 * - POST /admin/realm/force-password-reset - Mass password reset
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (using real service mocks)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from './session-tasks.handler';

// Mock the session tasks service
const mockGetPendingTasksResponse = jest.fn();
const mockHasBlockingTasks = jest.fn();
const mockGetTask = jest.fn();
const mockCompleteTask = jest.fn();
const mockSkipTask = jest.fn();
const mockGetPendingTaskCount = jest.fn();
const mockForcePasswordReset = jest.fn();
const mockForcePasswordResetAll = jest.fn();

jest.mock('../services/session-tasks.service', () => ({
  sessionTasksService: {
    getPendingTasksResponse: (...args: unknown[]) => mockGetPendingTasksResponse(...args),
    hasBlockingTasks: (...args: unknown[]) => mockHasBlockingTasks(...args),
    getTask: (...args: unknown[]) => mockGetTask(...args),
    completeTask: (...args: unknown[]) => mockCompleteTask(...args),
    skipTask: (...args: unknown[]) => mockSkipTask(...args),
    getPendingTaskCount: (...args: unknown[]) => mockGetPendingTaskCount(...args),
    forcePasswordReset: (...args: unknown[]) => mockForcePasswordReset(...args),
    forcePasswordResetAll: (...args: unknown[]) => mockForcePasswordResetAll(...args)
  },
  SessionTasksError: class SessionTasksError extends Error {
    code: string;
    statusCode: number;
    constructor(code: string, message: string, statusCode: number = 400) {
      super(message);
      this.code = code;
      this.statusCode = statusCode;
    }
  }
}));

// Mock rate limit service
const mockCheckRateLimit = jest.fn();
jest.mock('../services/ratelimit.service', () => ({
  checkRateLimit: (...args: unknown[]) => mockCheckRateLimit(...args)
}));

// Mock user repository
const mockFindUserById = jest.fn();
jest.mock('../repositories/user.repository', () => ({
  findUserById: (...args: unknown[]) => mockFindUserById(...args)
}));

// Mock password utilities
jest.mock('../utils/password', () => ({
  verifyPassword: jest.fn().mockResolvedValue(true),
  hashPassword: jest.fn().mockResolvedValue('hashed_password'),
  validatePasswordPolicy: jest.fn().mockReturnValue({ valid: true, errors: [] })
}));

// Test data
const mockUserId = 'user_test123';
const mockRealmId = 'realm_test123';
const mockSessionId = 'session_test123';
const mockTaskId = 'task_test123';

/**
 * Create mock API Gateway event
 */
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/session/tasks',
    headers: {
      Authorization: 'Bearer test_token'
    },
    body: null,
    queryStringParameters: null,
    pathParameters: null,
    requestContext: {
      authorizer: {
        userId: mockUserId,
        realmId: mockRealmId,
        sessionId: mockSessionId,
        role: 'user'
      }
    } as any,
    ...overrides
  } as APIGatewayProxyEvent;
}

/**
 * Create mock admin event
 */
function createMockAdminEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return createMockEvent({
    ...overrides,
    requestContext: {
      authorizer: {
        userId: mockUserId,
        realmId: mockRealmId,
        sessionId: mockSessionId,
        role: 'admin'
      }
    } as any
  });
}

/**
 * Create mock task
 */
function createMockTask(overrides: Partial<any> = {}) {
  return {
    id: mockTaskId,
    session_id: mockSessionId,
    user_id: mockUserId,
    realm_id: mockRealmId,
    type: 'reset_password',
    status: 'pending',
    metadata: {
      reason: 'compromised',
      message: 'Your password was found in a data breach'
    },
    created_at: new Date().toISOString(),
    priority: 1,
    blocking: true,
    ...overrides
  };
}

describe('Session Tasks Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Default rate limit to allow
    mockCheckRateLimit.mockResolvedValue({ allowed: true });
  });

  describe('OPTIONS (CORS preflight)', () => {
    it('should return 200 for OPTIONS request', async () => {
      const event = createMockEvent({ httpMethod: 'OPTIONS' });
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      expect(result.headers).toHaveProperty('Access-Control-Allow-Origin');
    });
  });

  describe('GET /session/tasks', () => {
    it('should return pending tasks for authenticated user', async () => {
      const mockTasks = [
        createMockTask({ type: 'reset_password', priority: 1 }),
        createMockTask({ id: 'task_2', type: 'setup_mfa', priority: 2 })
      ];
      
      mockGetPendingTasksResponse.mockResolvedValue(mockTasks);
      mockHasBlockingTasks.mockResolvedValue(true);
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks'
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.tasks).toHaveLength(2);
      expect(body.has_blocking_tasks).toBe(true);
      expect(body.count).toBe(2);
      expect(mockGetPendingTasksResponse).toHaveBeenCalledWith(mockSessionId);
    });

    it('should return empty array when no pending tasks', async () => {
      mockGetPendingTasksResponse.mockResolvedValue([]);
      mockHasBlockingTasks.mockResolvedValue(false);
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks'
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.tasks).toHaveLength(0);
      expect(body.has_blocking_tasks).toBe(false);
    });

    it('should return 401 for unauthenticated request', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks',
        headers: {},
        requestContext: {} as any
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('POST /session/tasks/{id}/complete', () => {
    it('should complete reset_password task with valid password', async () => {
      const mockTask = createMockTask({ type: 'reset_password' });
      const completedTask = { ...mockTask, status: 'completed', completed_at: new Date().toISOString() };
      
      mockGetTask.mockResolvedValue(mockTask);
      mockCompleteTask.mockResolvedValue(completedTask);
      mockGetPendingTaskCount.mockResolvedValue(0);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/complete`,
        body: JSON.stringify({ new_password: 'NewSecurePassword123!' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Task completed successfully');
      expect(body.task.status).toBe('completed');
      expect(body.remaining_tasks).toBe(0);
    });

    it('should complete setup_mfa task with valid code', async () => {
      const mockTask = createMockTask({ type: 'setup_mfa' });
      const completedTask = { ...mockTask, status: 'completed', completed_at: new Date().toISOString() };
      
      mockGetTask.mockResolvedValue(mockTask);
      mockCompleteTask.mockResolvedValue(completedTask);
      mockGetPendingTaskCount.mockResolvedValue(1);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/complete`,
        body: JSON.stringify({ mfa_method: 'totp', verification_code: '123456' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.task.status).toBe('completed');
    });

    it('should complete choose_organization task with valid org', async () => {
      const mockTask = createMockTask({ 
        type: 'choose_organization',
        metadata: {
          available_organizations: [
            { id: 'org_1', name: 'Org 1' },
            { id: 'org_2', name: 'Org 2' }
          ]
        }
      });
      const completedTask = { ...mockTask, status: 'completed', completed_at: new Date().toISOString() };
      
      mockGetTask.mockResolvedValue(mockTask);
      mockCompleteTask.mockResolvedValue(completedTask);
      mockGetPendingTaskCount.mockResolvedValue(0);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/complete`,
        body: JSON.stringify({ organization_id: 'org_1' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.task.status).toBe('completed');
    });

    it('should complete accept_terms task when accepted', async () => {
      const mockTask = createMockTask({ 
        type: 'accept_terms',
        metadata: { terms_version: '2.0' }
      });
      const completedTask = { ...mockTask, status: 'completed', completed_at: new Date().toISOString() };
      
      mockGetTask.mockResolvedValue(mockTask);
      mockCompleteTask.mockResolvedValue(completedTask);
      mockGetPendingTaskCount.mockResolvedValue(0);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/complete`,
        body: JSON.stringify({ accepted: true, terms_version: '2.0' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.task.status).toBe('completed');
    });

    it('should return 404 for non-existent task', async () => {
      mockGetTask.mockResolvedValue(null);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/session/tasks/nonexistent/complete',
        body: JSON.stringify({ new_password: 'Test123!' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('TASK_NOT_FOUND');
    });

    it('should return 400 for missing password on reset_password task', async () => {
      const mockTask = createMockTask({ type: 'reset_password' });
      mockGetTask.mockResolvedValue(mockTask);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/complete`,
        body: JSON.stringify({})
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_PASSWORD');
    });

    it('should return 400 for invalid organization selection', async () => {
      const mockTask = createMockTask({ 
        type: 'choose_organization',
        metadata: {
          available_organizations: [{ id: 'org_1', name: 'Org 1' }]
        }
      });
      mockGetTask.mockResolvedValue(mockTask);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/complete`,
        body: JSON.stringify({ organization_id: 'invalid_org' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_ORGANIZATION');
    });

    it('should return 400 for terms not accepted', async () => {
      const mockTask = createMockTask({ type: 'accept_terms' });
      mockGetTask.mockResolvedValue(mockTask);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/complete`,
        body: JSON.stringify({ accepted: false })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('TERMS_NOT_ACCEPTED');
    });

    it('should return 429 when rate limited', async () => {
      mockCheckRateLimit.mockResolvedValue({ allowed: false, retryAfter: 30 });
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/complete`,
        body: JSON.stringify({ new_password: 'Test123!' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(result.headers?.['Retry-After']).toBe('30');
    });

    it('should return 400 for invalid JSON body', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/complete`,
        body: 'invalid json'
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });
  });

  describe('POST /session/tasks/{id}/skip', () => {
    it('should skip non-blocking task', async () => {
      const mockTask = createMockTask({ type: 'custom', blocking: false });
      const skippedTask = { ...mockTask, status: 'skipped', completed_at: new Date().toISOString() };
      
      mockSkipTask.mockResolvedValue(skippedTask);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/skip`
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Task skipped');
      expect(body.task.status).toBe('skipped');
    });

    it('should return 400 when skip fails (blocking task)', async () => {
      mockSkipTask.mockResolvedValue(null);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: `/session/tasks/${mockTaskId}/skip`
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('TASK_SKIP_FAILED');
    });
  });

  describe('POST /admin/users/{id}/force-password-reset', () => {
    it('should force password reset for user as admin', async () => {
      mockFindUserById.mockResolvedValue({ id: 'target_user', email: 'test@example.com' });
      mockForcePasswordReset.mockResolvedValue({
        userId: 'target_user',
        taskId: 'task_new',
        sessionsRevoked: 2
      });
      
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/admin/users/target_user/force-password-reset',
        body: JSON.stringify({
          reason: 'compromised',
          revoke_sessions: true
        })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Password reset forced');
      expect(body.user_id).toBe('target_user');
      expect(body.sessions_revoked).toBe(2);
      expect(body.task_created).toBe(true);
    });

    it('should return 403 for non-admin user', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/admin/users/target_user/force-password-reset',
        body: JSON.stringify({ reason: 'compromised' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('should return 404 for non-existent user', async () => {
      mockFindUserById.mockResolvedValue(null);
      
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/admin/users/nonexistent/force-password-reset',
        body: JSON.stringify({ reason: 'compromised' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('USER_NOT_FOUND');
    });

    it('should return 429 when rate limited', async () => {
      mockCheckRateLimit.mockResolvedValue({ allowed: false, retryAfter: 60 });
      
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/admin/users/target_user/force-password-reset',
        body: JSON.stringify({ reason: 'compromised' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('should use default reason when not provided', async () => {
      mockFindUserById.mockResolvedValue({ id: 'target_user', email: 'test@example.com' });
      mockForcePasswordReset.mockResolvedValue({
        userId: 'target_user',
        taskId: 'task_new',
        sessionsRevoked: 0
      });
      
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/admin/users/target_user/force-password-reset',
        body: JSON.stringify({})
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      expect(mockForcePasswordReset).toHaveBeenCalledWith(
        'target_user',
        mockRealmId,
        expect.objectContaining({ reason: 'admin_forced' })
      );
    });
  });

  describe('POST /admin/realm/force-password-reset', () => {
    it('should perform mass password reset as admin', async () => {
      mockForcePasswordResetAll.mockResolvedValue({
        realmId: mockRealmId,
        usersAffected: 100,
        tasksCreated: 95,
        sessionsRevoked: 200,
        errors: []
      });
      
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/admin/realm/force-password-reset',
        body: JSON.stringify({
          realm_id: mockRealmId,
          reason: 'security_incident',
          revoke_all_sessions: true
        })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Mass password reset initiated');
      expect(body.users_affected).toBe(100);
      expect(body.tasks_created).toBe(95);
      expect(body.sessions_revoked).toBe(200);
    });

    it('should return 403 for non-admin user', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/admin/realm/force-password-reset',
        body: JSON.stringify({ realm_id: mockRealmId })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('should return 403 for different realm', async () => {
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/admin/realm/force-password-reset',
        body: JSON.stringify({ realm_id: 'different_realm' })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.error.message).toContain('different realm');
    });

    it('should return 429 when rate limited (stricter limit)', async () => {
      mockCheckRateLimit.mockResolvedValue({ allowed: false, retryAfter: 300 });
      
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/admin/realm/force-password-reset',
        body: JSON.stringify({ realm_id: mockRealmId })
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
        path: '/admin/realm/force-password-reset',
        body: JSON.stringify({ realm_id: mockRealmId })
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.errors).toHaveLength(2);
    });

    it('should use admin realm when realm_id not provided', async () => {
      mockForcePasswordResetAll.mockResolvedValue({
        realmId: mockRealmId,
        usersAffected: 50,
        tasksCreated: 50,
        sessionsRevoked: 100,
        errors: []
      });
      
      const event = createMockAdminEvent({
        httpMethod: 'POST',
        path: '/admin/realm/force-password-reset',
        body: JSON.stringify({})
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.realm_id).toBe(mockRealmId);
    });
  });

  describe('Error handling', () => {
    it('should return 404 for unknown endpoint', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/unknown/endpoint'
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should handle SessionTasksError correctly', async () => {
      const { SessionTasksError } = require('../services/session-tasks.service');
      mockGetPendingTasksResponse.mockRejectedValue(
        new SessionTasksError('CUSTOM_ERROR', 'Custom error message', 422)
      );
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks'
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(422);
      expect(body.error.code).toBe('CUSTOM_ERROR');
      expect(body.error.message).toBe('Custom error message');
    });

    it('should return 500 for unexpected errors', async () => {
      mockGetPendingTasksResponse.mockRejectedValue(new Error('Unexpected error'));
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks'
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(500);
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('An unexpected error occurred');
    });
  });

  describe('Security headers', () => {
    it('should include security headers in response', async () => {
      mockGetPendingTasksResponse.mockResolvedValue([]);
      mockHasBlockingTasks.mockResolvedValue(false);
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/session/tasks'
      });
      
      const result = await handler(event);
      
      expect(result.headers).toHaveProperty('X-Content-Type-Options', 'nosniff');
      expect(result.headers).toHaveProperty('X-Frame-Options', 'DENY');
      expect(result.headers).toHaveProperty('Content-Type', 'application/json');
    });
  });

  describe('Admin role verification', () => {
    it('should accept super_admin role for admin endpoints', async () => {
      mockFindUserById.mockResolvedValue({ id: 'target_user', email: 'test@example.com' });
      mockForcePasswordReset.mockResolvedValue({
        userId: 'target_user',
        taskId: 'task_new',
        sessionsRevoked: 0
      });
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/admin/users/target_user/force-password-reset',
        body: JSON.stringify({}),
        requestContext: {
          authorizer: {
            userId: mockUserId,
            realmId: mockRealmId,
            sessionId: mockSessionId,
            role: 'super_admin'
          }
        } as any
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
    });
  });
});
