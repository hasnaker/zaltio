/**
 * Tests for Background Breach Check Job Handler
 * Task 17.4: Implement background breach check job
 * 
 * Tests cover:
 * - Batch processing of users
 * - HIBP API integration
 * - Session task creation for compromised passwords
 * - Email notification sending
 * - Error handling and resilience
 * - Rate limiting compliance
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (for integration tests)
 * Unit tests use mocks for isolation
 * 
 * _Requirements: 8.7, 8.8_
 */

import { Context, ScheduledEvent } from 'aws-lambda';
import {
  handler,
  BreachCheckJobConfig,
  BreachCheckJobResult,
  _testing,
} from './breach-check-job.handler';

// Mock dependencies
jest.mock('../services/hibp.service', () => ({
  createHIBPService: jest.fn(() => ({
    checkPasswordHash: jest.fn(),
    getCacheStats: jest.fn(() => ({
      size: 10,
      hits: 5,
      misses: 5,
      hitRate: 0.5,
      apiCalls: 5,
      apiErrors: 0,
    })),
  })),
}));

jest.mock('../services/session-tasks.service', () => ({
  sessionTasksService: {
    forcePasswordReset: jest.fn(),
  },
}));

jest.mock('../services/email.service', () => ({
  sendBreachNotificationEmail: jest.fn(),
}));

jest.mock('../repositories/user.repository', () => ({
  listRealmUsers: jest.fn(),
  findUserById: jest.fn(),
  updateUserBreachStatus: jest.fn(),
}));

jest.mock('../repositories/session.repository', () => ({
  getUserSessions: jest.fn(),
}));

jest.mock('../repositories/realm.repository', () => ({
  listRealms: jest.fn(),
}));

jest.mock('../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn(),
}));

// Import mocked modules
import { createHIBPService } from '../services/hibp.service';
import { sessionTasksService } from '../services/session-tasks.service';
import { sendBreachNotificationEmail } from '../services/email.service';
import { listRealmUsers, findUserById, updateUserBreachStatus } from '../repositories/user.repository';
import { getUserSessions } from '../repositories/session.repository';
import { listRealms } from '../repositories/realm.repository';
import { logSecurityEvent } from '../services/security-logger.service';

const mockCreateHIBPService = createHIBPService as jest.Mock;
const mockSessionTasksService = sessionTasksService as jest.Mocked<typeof sessionTasksService>;
const mockSendBreachNotificationEmail = sendBreachNotificationEmail as jest.Mock;
const mockListRealmUsers = listRealmUsers as jest.Mock;
const mockFindUserById = findUserById as jest.Mock;
const mockUpdateUserBreachStatus = updateUserBreachStatus as jest.Mock;
const mockGetUserSessions = getUserSessions as jest.Mock;
const mockListRealms = listRealms as jest.Mock;
const mockLogSecurityEvent = logSecurityEvent as jest.Mock;

// Test utilities
function createMockContext(): Context {
  return {
    awsRequestId: 'test-request-id',
    functionName: 'breach-check-job',
    functionVersion: '1',
    invokedFunctionArn: 'arn:aws:lambda:eu-central-1:123456789:function:breach-check-job',
    memoryLimitInMB: '256',
    logGroupName: '/aws/lambda/breach-check-job',
    logStreamName: '2026/01/25/[$LATEST]abc123',
    callbackWaitsForEmptyEventLoop: true,
    getRemainingTimeInMillis: () => 300000,
    done: jest.fn(),
    fail: jest.fn(),
    succeed: jest.fn(),
  };
}

function createMockEvent(detail?: Partial<BreachCheckJobConfig>): ScheduledEvent {
  return {
    version: '0',
    id: 'test-event-id',
    'detail-type': 'Scheduled Event',
    source: 'aws.events',
    account: '123456789',
    time: new Date().toISOString(),
    region: 'eu-central-1',
    resources: ['arn:aws:events:eu-central-1:123456789:rule/breach-check-daily'],
    detail: detail || {},
  };
}

function createMockUser(overrides: Partial<{
  id: string;
  realm_id: string;
  email: string;
  password_sha1_hash: string | undefined;
  password_breach_checked_at: string;
  password_compromised: boolean;
}> = {}) {
  const base = {
    id: overrides.id || 'user-123',
    realm_id: overrides.realm_id || 'realm-123',
    email: overrides.email || 'test@example.com',
    password_breach_checked_at: overrides.password_breach_checked_at,
    password_compromised: overrides.password_compromised || false,
  };
  
  // Only include password_sha1_hash if not explicitly set to undefined
  if (overrides.password_sha1_hash !== undefined) {
    return {
      ...base,
      password_sha1_hash: overrides.password_sha1_hash,
    };
  } else if (!('password_sha1_hash' in overrides)) {
    // Default case - include the hash
    return {
      ...base,
      password_sha1_hash: '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8',
    };
  }
  
  // Explicitly set to undefined - don't include the field
  return base;
}

function createMockRealm(id: string = 'realm-123') {
  return {
    id,
    name: `Test Realm ${id}`,
    domain: `${id}.zalt.io`,
  };
}

describe('Breach Check Job Handler', () => {
  let mockHibpService: {
    checkPasswordHash: jest.Mock;
    getCacheStats: jest.Mock;
  };

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup default mock HIBP service
    mockHibpService = {
      checkPasswordHash: jest.fn().mockResolvedValue({
        isCompromised: false,
        count: 0,
        fromCache: false,
      }),
      getCacheStats: jest.fn().mockReturnValue({
        size: 10,
        hits: 5,
        misses: 5,
        hitRate: 0.5,
        apiCalls: 5,
        apiErrors: 0,
      }),
    };
    mockCreateHIBPService.mockReturnValue(mockHibpService);
    
    // Setup default mocks
    mockListRealms.mockResolvedValue([createMockRealm()]);
    mockListRealmUsers.mockResolvedValue({ users: [], lastEvaluatedKey: undefined });
    mockUpdateUserBreachStatus.mockResolvedValue(true);
    mockGetUserSessions.mockResolvedValue([]);
    mockLogSecurityEvent.mockResolvedValue(undefined);
    mockSendBreachNotificationEmail.mockResolvedValue({ success: true });
    mockSessionTasksService.forcePasswordReset.mockResolvedValue({
      userId: 'user-123',
      taskId: 'task-123',
      sessionsRevoked: 0,
    });
  });

  describe('handler', () => {
    it('should complete successfully with no users', async () => {
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({ users: [], lastEvaluatedKey: undefined });

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.completed).toBe(true);
      expect(result.usersChecked).toBe(0);
      expect(result.breachesFound).toBe(0);
      expect(result.realmsProcessed).toBe(1);
    });

    it('should process users and detect breaches', async () => {
      const mockUser = createMockUser();
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);
      mockHibpService.checkPasswordHash.mockResolvedValue({
        isCompromised: true,
        count: 1000,
        fromCache: false,
      });
      mockGetUserSessions.mockResolvedValue([{ id: 'session-123' }]);

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.usersChecked).toBe(1);
      expect(result.breachesFound).toBe(1);
      expect(mockUpdateUserBreachStatus).toHaveBeenCalledWith(
        mockUser.realm_id,
        mockUser.id,
        expect.objectContaining({
          password_compromised: true,
          password_breach_count: 1000,
        })
      );
    });

    it('should send notification email when breach detected', async () => {
      const mockUser = createMockUser();
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);
      mockHibpService.checkPasswordHash.mockResolvedValue({
        isCompromised: true,
        count: 500,
        fromCache: false,
      });
      mockGetUserSessions.mockResolvedValue([{ id: 'session-123' }]);

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.emailsSent).toBe(1);
      expect(mockSendBreachNotificationEmail).toHaveBeenCalledWith(
        mockUser.email,
        mockUser.realm_id,
        expect.objectContaining({
          breachCount: 500,
        })
      );
    });

    it('should create session task when breach detected', async () => {
      const mockUser = createMockUser();
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);
      mockHibpService.checkPasswordHash.mockResolvedValue({
        isCompromised: true,
        count: 100,
        fromCache: false,
      });
      mockGetUserSessions.mockResolvedValue([{ id: 'session-123' }]);

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.tasksCreated).toBe(1);
      expect(mockSessionTasksService.forcePasswordReset).toHaveBeenCalledWith(
        mockUser.id,
        mockUser.realm_id,
        expect.objectContaining({
          reason: 'compromised',
          revokeAllSessions: false,
        })
      );
    });

    it('should skip users without SHA-1 hash', async () => {
      const mockUser = createMockUser({ password_sha1_hash: undefined });
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.usersChecked).toBe(1);
      expect(result.breachesFound).toBe(0);
      expect(mockHibpService.checkPasswordHash).not.toHaveBeenCalled();
    });

    it('should skip users already marked as compromised', async () => {
      const mockUser = createMockUser({
        password_compromised: true,
        password_breach_checked_at: new Date().toISOString(),
      });
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.usersChecked).toBe(0); // Skipped
      expect(mockHibpService.checkPasswordHash).not.toHaveBeenCalled();
    });

    it('should respect maxUsersPerInvocation limit', async () => {
      const users = Array.from({ length: 10 }, (_, i) => ({
        id: `user-${i}`,
        email: `user${i}@example.com`,
      }));
      
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users,
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockImplementation((realmId, userId) =>
        createMockUser({ id: userId, realm_id: realmId })
      );

      const result = await handler(
        createMockEvent({ maxUsersPerInvocation: 5 }),
        createMockContext()
      );

      expect(result.usersChecked).toBe(5);
      expect(result.completed).toBe(false);
    });

    it('should process multiple realms', async () => {
      const realms = [createMockRealm('realm-1'), createMockRealm('realm-2')];
      mockListRealms.mockResolvedValue(realms);
      mockListRealmUsers.mockResolvedValue({ users: [], lastEvaluatedKey: undefined });

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.realmsProcessed).toBe(2);
    });

    it('should handle HIBP API errors gracefully', async () => {
      const mockUser = createMockUser();
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);
      mockHibpService.checkPasswordHash.mockRejectedValue(new Error('API timeout'));

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.usersChecked).toBe(1);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0].error).toContain('API timeout');
    });

    it('should log security events', async () => {
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({ users: [], lastEvaluatedKey: undefined });

      await handler(createMockEvent(), createMockContext());

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'breach_check_job_started',
        })
      );
      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'breach_check_job_completed',
        })
      );
    });

    it('should use custom configuration from event', async () => {
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({ users: [], lastEvaluatedKey: undefined });

      const customConfig: Partial<BreachCheckJobConfig> = {
        batchSize: 50,
        maxUsersPerInvocation: 500,
        sendNotifications: false,
      };

      await handler(createMockEvent(customConfig), createMockContext());

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          details: expect.objectContaining({
            config: expect.objectContaining({
              batchSize: 50,
              maxUsersPerInvocation: 500,
            }),
          }),
        })
      );
    });
  });

  describe('needsBreachCheck', () => {
    const { needsBreachCheck } = _testing;

    it('should return true for users never checked', () => {
      const user = createMockUser({ password_breach_checked_at: undefined });
      expect(needsBreachCheck(user, 7)).toBe(true);
    });

    it('should return false for users already compromised', () => {
      const user = createMockUser({
        password_compromised: true,
        password_breach_checked_at: new Date().toISOString(),
      });
      expect(needsBreachCheck(user, 7)).toBe(false);
    });

    it('should return true if enough days have passed', () => {
      const eightDaysAgo = new Date();
      eightDaysAgo.setDate(eightDaysAgo.getDate() - 8);
      
      const user = createMockUser({
        password_breach_checked_at: eightDaysAgo.toISOString(),
      });
      expect(needsBreachCheck(user, 7)).toBe(true);
    });

    it('should return false if not enough days have passed', () => {
      const threeDaysAgo = new Date();
      threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);
      
      const user = createMockUser({
        password_breach_checked_at: threeDaysAgo.toISOString(),
      });
      expect(needsBreachCheck(user, 7)).toBe(false);
    });
  });

  describe('processUser', () => {
    const { processUser } = _testing;

    it('should return early for users without SHA-1 hash', async () => {
      const user = createMockUser({ password_sha1_hash: undefined });
      const config = _testing.DEFAULT_CONFIG;

      const result = await processUser(user, mockHibpService as any, config);

      expect(result.breachFound).toBe(false);
      expect(mockHibpService.checkPasswordHash).not.toHaveBeenCalled();
    });

    it('should update breach status after check', async () => {
      const user = createMockUser();
      const config = _testing.DEFAULT_CONFIG;
      mockHibpService.checkPasswordHash.mockResolvedValue({
        isCompromised: false,
        count: 0,
        fromCache: false,
      });

      await processUser(user, mockHibpService as any, config);

      expect(mockUpdateUserBreachStatus).toHaveBeenCalledWith(
        user.realm_id,
        user.id,
        expect.objectContaining({
          password_compromised: false,
        })
      );
    });

    it('should handle errors gracefully', async () => {
      const user = createMockUser();
      const config = _testing.DEFAULT_CONFIG;
      mockHibpService.checkPasswordHash.mockRejectedValue(new Error('Network error'));

      const result = await processUser(user, mockHibpService as any, config);

      expect(result.error).toBe('Network error');
      expect(result.breachFound).toBe(false);
    });
  });

  describe('Rate Limiting', () => {
    it('should apply delay between API calls', async () => {
      const users = Array.from({ length: 3 }, (_, i) => ({
        id: `user-${i}`,
        email: `user${i}@example.com`,
      }));
      
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users,
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockImplementation((realmId, userId) =>
        createMockUser({ id: userId, realm_id: realmId })
      );

      const startTime = Date.now();
      await handler(
        createMockEvent({ apiDelayMs: 50, maxUsersPerInvocation: 3 }),
        createMockContext()
      );
      const elapsed = Date.now() - startTime;

      // Should have at least 2 delays (between 3 users)
      expect(elapsed).toBeGreaterThanOrEqual(100);
    });
  });

  describe('Email Notifications', () => {
    it('should not send email when sendNotifications is false', async () => {
      const mockUser = createMockUser();
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);
      mockHibpService.checkPasswordHash.mockResolvedValue({
        isCompromised: true,
        count: 100,
        fromCache: false,
      });
      mockGetUserSessions.mockResolvedValue([{ id: 'session-123' }]);

      const result = await handler(
        createMockEvent({ sendNotifications: false }),
        createMockContext()
      );

      expect(result.breachesFound).toBe(1);
      expect(result.emailsSent).toBe(0);
      expect(mockSendBreachNotificationEmail).not.toHaveBeenCalled();
    });

    it('should handle email send failure gracefully', async () => {
      const mockUser = createMockUser();
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);
      mockHibpService.checkPasswordHash.mockResolvedValue({
        isCompromised: true,
        count: 100,
        fromCache: false,
      });
      mockGetUserSessions.mockResolvedValue([{ id: 'session-123' }]);
      mockSendBreachNotificationEmail.mockRejectedValue(new Error('SES error'));

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.breachesFound).toBe(1);
      expect(result.emailsSent).toBe(0);
      // Job should continue despite email failure
      expect(result.completed).toBe(true);
    });
  });

  describe('Session Tasks', () => {
    it('should not create task when createSessionTasks is false', async () => {
      const mockUser = createMockUser();
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);
      mockHibpService.checkPasswordHash.mockResolvedValue({
        isCompromised: true,
        count: 100,
        fromCache: false,
      });
      mockGetUserSessions.mockResolvedValue([{ id: 'session-123' }]);

      const result = await handler(
        createMockEvent({ createSessionTasks: false }),
        createMockContext()
      );

      expect(result.breachesFound).toBe(1);
      expect(result.tasksCreated).toBe(0);
      expect(mockSessionTasksService.forcePasswordReset).not.toHaveBeenCalled();
    });

    it('should not create task when user has no active sessions', async () => {
      const mockUser = createMockUser();
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);
      mockHibpService.checkPasswordHash.mockResolvedValue({
        isCompromised: true,
        count: 100,
        fromCache: false,
      });
      mockGetUserSessions.mockResolvedValue([]); // No active sessions

      const result = await handler(createMockEvent(), createMockContext());

      expect(result.breachesFound).toBe(1);
      expect(result.tasksCreated).toBe(0);
      expect(mockSessionTasksService.forcePasswordReset).not.toHaveBeenCalled();
    });
  });

  describe('Audit Logging', () => {
    it('should log breach detection event', async () => {
      const mockUser = createMockUser();
      mockListRealms.mockResolvedValue([createMockRealm()]);
      mockListRealmUsers.mockResolvedValue({
        users: [{ id: mockUser.id, email: mockUser.email }],
        lastEvaluatedKey: undefined,
      });
      mockFindUserById.mockResolvedValue(mockUser);
      mockHibpService.checkPasswordHash.mockResolvedValue({
        isCompromised: true,
        count: 500,
        fromCache: false,
      });
      mockGetUserSessions.mockResolvedValue([{ id: 'session-123' }]);

      await handler(createMockEvent(), createMockContext());

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'password_breach_detected',
          realm_id: mockUser.realm_id,
          user_id: mockUser.id,
          details: expect.objectContaining({
            breach_count: 500,
            detection_method: 'background_job',
          }),
        })
      );
    });
  });
});
