/**
 * Session Tasks Service Tests
 * Tests for session task management operations
 * 
 * Validates: Requirements 4.2, 4.3, 4.4, 4.5, 4.7, 4.8, 4.9 (Session Tasks)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (DynamoDB mocked for unit tests)
 */

// Mock repositories
const mockCreateSessionTask = jest.fn();
const mockGetSessionTaskById = jest.fn();
const mockGetSessionTasks = jest.fn();
const mockGetPendingSessionTasks = jest.fn();
const mockGetPendingBlockingTasks = jest.fn();
const mockHasBlockingTasks = jest.fn();
const mockCompleteSessionTask = jest.fn();
const mockSkipSessionTask = jest.fn();
const mockDeleteAllSessionTasks = jest.fn();
const mockCreateSessionTasks = jest.fn();
const mockGetSessionTaskByType = jest.fn();
const mockCountPendingTasks = jest.fn();
const mockCountPendingBlockingTasks = jest.fn();

jest.mock('../repositories/session-task.repository', () => ({
  createSessionTask: (...args: unknown[]) => mockCreateSessionTask(...args),
  getSessionTaskById: (...args: unknown[]) => mockGetSessionTaskById(...args),
  getSessionTasks: (...args: unknown[]) => mockGetSessionTasks(...args),
  getPendingSessionTasks: (...args: unknown[]) => mockGetPendingSessionTasks(...args),
  getPendingBlockingTasks: (...args: unknown[]) => mockGetPendingBlockingTasks(...args),
  hasBlockingTasks: (...args: unknown[]) => mockHasBlockingTasks(...args),
  completeSessionTask: (...args: unknown[]) => mockCompleteSessionTask(...args),
  skipSessionTask: (...args: unknown[]) => mockSkipSessionTask(...args),
  deleteAllSessionTasks: (...args: unknown[]) => mockDeleteAllSessionTasks(...args),
  createSessionTasks: (...args: unknown[]) => mockCreateSessionTasks(...args),
  getSessionTaskByType: (...args: unknown[]) => mockGetSessionTaskByType(...args),
  countPendingTasks: (...args: unknown[]) => mockCountPendingTasks(...args),
  countPendingBlockingTasks: (...args: unknown[]) => mockCountPendingBlockingTasks(...args)
}));

const mockGetUserSessions = jest.fn();
const mockDeleteUserSessions = jest.fn();

jest.mock('../repositories/session.repository', () => ({
  getUserSessions: (...args: unknown[]) => mockGetUserSessions(...args),
  deleteUserSessions: (...args: unknown[]) => mockDeleteUserSessions(...args)
}));

const mockListRealmUsers = jest.fn();

jest.mock('../repositories/user.repository', () => ({
  listRealmUsers: (...args: unknown[]) => mockListRealmUsers(...args)
}));


// Import after mocks
import { SessionTasksService, SessionTasksError } from './session-tasks.service';
import { SessionTask, SessionTaskType } from '../models/session-task.model';

describe('SessionTasksService', () => {
  let service: SessionTasksService;
  
  const mockSessionId = 'session_test123';
  const mockUserId = 'user_abc123';
  const mockRealmId = 'realm_test';
  const mockTaskId = 'task_def456789012';
  
  const createMockTask = (overrides: Partial<SessionTask> = {}): SessionTask => ({
    id: mockTaskId,
    session_id: mockSessionId,
    user_id: mockUserId,
    realm_id: mockRealmId,
    type: 'reset_password',
    status: 'pending',
    created_at: '2026-01-01T00:00:00Z',
    priority: 1,
    blocking: true,
    ...overrides
  });
  
  beforeEach(() => {
    service = new SessionTasksService();
    jest.clearAllMocks();
  });

  describe('createTask', () => {
    it('should create a new session task', async () => {
      const mockTask = createMockTask();
      mockGetSessionTaskByType.mockResolvedValue(null);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      
      const result = await service.createTask(
        mockSessionId,
        mockUserId,
        mockRealmId,
        'reset_password',
        { reason: 'compromised' }
      );
      
      expect(result).toEqual(mockTask);
      expect(mockCreateSessionTask).toHaveBeenCalledWith(
        expect.objectContaining({
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'reset_password'
        })
      );
    });
    
    it('should throw error if task of same type already exists', async () => {
      mockGetSessionTaskByType.mockResolvedValue(createMockTask());
      
      await expect(
        service.createTask(mockSessionId, mockUserId, mockRealmId, 'reset_password')
      ).rejects.toThrow(SessionTasksError);
      
      try {
        await service.createTask(mockSessionId, mockUserId, mockRealmId, 'reset_password');
      } catch (error) {
        expect((error as SessionTasksError).code).toBe('TASK_ALREADY_EXISTS');
      }
    });
    
    it('should throw error for empty session ID', async () => {
      await expect(
        service.createTask('', mockUserId, mockRealmId, 'reset_password')
      ).rejects.toThrow('Session ID is required');
    });
    
    it('should throw error for empty user ID', async () => {
      await expect(
        service.createTask(mockSessionId, '', mockRealmId, 'reset_password')
      ).rejects.toThrow('User ID is required');
    });
    
    it('should throw error for empty realm ID', async () => {
      await expect(
        service.createTask(mockSessionId, mockUserId, '', 'reset_password')
      ).rejects.toThrow('Realm ID is required');
    });
  });

  describe('getPendingTasks', () => {
    it('should return pending tasks sorted by priority', async () => {
      const tasks = [
        createMockTask({ id: 'task_1', type: 'choose_organization', priority: 4 }),
        createMockTask({ id: 'task_2', type: 'reset_password', priority: 1 }),
        createMockTask({ id: 'task_3', type: 'setup_mfa', priority: 2 })
      ];
      mockGetPendingSessionTasks.mockResolvedValue(tasks);
      
      const result = await service.getPendingTasks(mockSessionId);
      
      expect(result).toHaveLength(3);
      expect(result[0].priority).toBe(1);
      expect(result[1].priority).toBe(2);
      expect(result[2].priority).toBe(4);
    });
    
    it('should return empty array when no pending tasks', async () => {
      mockGetPendingSessionTasks.mockResolvedValue([]);
      
      const result = await service.getPendingTasks(mockSessionId);
      
      expect(result).toEqual([]);
    });
    
    it('should throw error for empty session ID', async () => {
      await expect(service.getPendingTasks('')).rejects.toThrow('Session ID is required');
    });
  });

  describe('completeTask', () => {
    it('should complete a pending task', async () => {
      const pendingTask = createMockTask({ status: 'pending' });
      const completedTask = createMockTask({ status: 'completed', completed_at: '2026-01-01T01:00:00Z' });
      
      mockGetSessionTaskById.mockResolvedValue(pendingTask);
      mockCompleteSessionTask.mockResolvedValue(completedTask);
      
      const result = await service.completeTask(mockSessionId, mockTaskId);
      
      expect(result).toEqual(completedTask);
      expect(result?.status).toBe('completed');
    });
    
    it('should throw error if task not found', async () => {
      mockGetSessionTaskById.mockResolvedValue(null);
      
      try {
        await service.completeTask(mockSessionId, 'nonexistent');
        fail('Expected error to be thrown');
      } catch (error) {
        expect((error as SessionTasksError).code).toBe('TASK_NOT_FOUND');
        expect((error as SessionTasksError).statusCode).toBe(404);
      }
    });
    
    it('should throw error if task already completed', async () => {
      mockGetSessionTaskById.mockResolvedValue(
        createMockTask({ status: 'completed' })
      );
      
      try {
        await service.completeTask(mockSessionId, mockTaskId);
        fail('Expected error to be thrown');
      } catch (error) {
        expect((error as SessionTasksError).code).toBe('TASK_NOT_PENDING');
      }
    });
    
    it('should throw error for empty session ID', async () => {
      await expect(
        service.completeTask('', mockTaskId)
      ).rejects.toThrow('Session ID is required');
    });
    
    it('should throw error for empty task ID', async () => {
      await expect(
        service.completeTask(mockSessionId, '')
      ).rejects.toThrow('Task ID is required');
    });
  });


  describe('skipTask', () => {
    it('should skip a non-blocking task', async () => {
      const nonBlockingTask = createMockTask({ type: 'custom', blocking: false });
      const skippedTask = createMockTask({ 
        type: 'custom', 
        blocking: false, 
        status: 'skipped',
        completed_at: '2026-01-01T01:00:00Z'
      });
      
      mockGetSessionTaskById.mockResolvedValue(nonBlockingTask);
      mockSkipSessionTask.mockResolvedValue(skippedTask);
      
      const result = await service.skipTask(mockSessionId, mockTaskId);
      
      expect(result).toEqual(skippedTask);
      expect(result?.status).toBe('skipped');
    });
    
    it('should throw error when trying to skip blocking task', async () => {
      mockGetSessionTaskById.mockResolvedValue(
        createMockTask({ blocking: true })
      );
      
      try {
        await service.skipTask(mockSessionId, mockTaskId);
        fail('Expected error to be thrown');
      } catch (error) {
        expect((error as SessionTasksError).code).toBe('TASK_BLOCKING');
      }
    });
    
    it('should throw error if task not found', async () => {
      mockGetSessionTaskById.mockResolvedValue(null);
      
      try {
        await service.skipTask(mockSessionId, 'nonexistent');
        fail('Expected error to be thrown');
      } catch (error) {
        expect((error as SessionTasksError).code).toBe('TASK_NOT_FOUND');
        expect((error as SessionTasksError).statusCode).toBe(404);
      }
    });
    
    it('should throw error if task already completed', async () => {
      mockGetSessionTaskById.mockResolvedValue(
        createMockTask({ status: 'completed', blocking: false })
      );
      
      try {
        await service.skipTask(mockSessionId, mockTaskId);
        fail('Expected error to be thrown');
      } catch (error) {
        expect((error as SessionTasksError).code).toBe('TASK_NOT_PENDING');
      }
    });
  });

  describe('hasBlockingTasks', () => {
    it('should return true when blocking tasks exist', async () => {
      mockHasBlockingTasks.mockResolvedValue(true);
      
      const result = await service.hasBlockingTasks(mockSessionId);
      
      expect(result).toBe(true);
    });
    
    it('should return false when no blocking tasks', async () => {
      mockHasBlockingTasks.mockResolvedValue(false);
      
      const result = await service.hasBlockingTasks(mockSessionId);
      
      expect(result).toBe(false);
    });
    
    it('should return false for empty session ID', async () => {
      const result = await service.hasBlockingTasks('');
      
      expect(result).toBe(false);
    });
  });

  describe('forcePasswordReset', () => {
    it('should create reset_password task for user with active sessions', async () => {
      const mockSessions = [
        { id: 'session_1', user_id: mockUserId, realm_id: mockRealmId },
        { id: 'session_2', user_id: mockUserId, realm_id: mockRealmId }
      ];
      const mockTask = createMockTask({ type: 'reset_password' });
      
      mockGetUserSessions.mockResolvedValue(mockSessions);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      mockCreateSessionTasks.mockResolvedValue([mockTask]);
      mockDeleteUserSessions.mockResolvedValue(0);
      
      const result = await service.forcePasswordReset(mockUserId, mockRealmId);
      
      expect(result.userId).toBe(mockUserId);
      expect(result.taskId).toBe(mockTaskId);
      expect(result.sessionsRevoked).toBe(0);
      expect(mockCreateSessionTask).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'reset_password',
          blocking: true,
          priority: 1
        })
      );
    });
    
    it('should revoke all sessions when option is set', async () => {
      const mockSessions = [
        { id: 'session_1', user_id: mockUserId, realm_id: mockRealmId }
      ];
      const mockTask = createMockTask({ type: 'reset_password' });
      
      mockGetUserSessions.mockResolvedValue(mockSessions);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      mockDeleteUserSessions.mockResolvedValue(3);
      
      const result = await service.forcePasswordReset(mockUserId, mockRealmId, {
        revokeAllSessions: true
      });
      
      expect(result.sessionsRevoked).toBe(3);
      expect(mockDeleteUserSessions).toHaveBeenCalledWith(mockRealmId, mockUserId);
    });
    
    it('should handle user with no active sessions', async () => {
      mockGetUserSessions.mockResolvedValue([]);
      
      const result = await service.forcePasswordReset(mockUserId, mockRealmId);
      
      expect(result.taskId).toBe('');
      expect(result.sessionsRevoked).toBe(0);
      expect(mockCreateSessionTask).not.toHaveBeenCalled();
    });
    
    it('should include reason in task metadata', async () => {
      const mockSessions = [
        { id: 'session_1', user_id: mockUserId, realm_id: mockRealmId }
      ];
      const mockTask = createMockTask({ type: 'reset_password' });
      
      mockGetUserSessions.mockResolvedValue(mockSessions);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      
      await service.forcePasswordReset(mockUserId, mockRealmId, {
        reason: 'compromised',
        message: 'Your password was found in a breach'
      });
      
      expect(mockCreateSessionTask).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({
            reason: 'compromised',
            message: 'Your password was found in a breach'
          })
        })
      );
    });
    
    it('should throw error for empty user ID', async () => {
      await expect(
        service.forcePasswordReset('', mockRealmId)
      ).rejects.toThrow('User ID is required');
    });
    
    it('should throw error for empty realm ID', async () => {
      await expect(
        service.forcePasswordReset(mockUserId, '')
      ).rejects.toThrow('Realm ID is required');
    });
  });


  describe('forcePasswordResetAll', () => {
    it('should create reset_password tasks for all users in realm', async () => {
      const mockUsers = [
        { id: 'user_1', email: 'user1@test.com', realm_id: mockRealmId },
        { id: 'user_2', email: 'user2@test.com', realm_id: mockRealmId }
      ];
      const mockSessions = [
        { id: 'session_1', user_id: 'user_1', realm_id: mockRealmId }
      ];
      const mockTask = createMockTask();
      
      mockListRealmUsers.mockResolvedValue({
        users: mockUsers,
        lastEvaluatedKey: undefined,
        total: 2
      });
      mockGetUserSessions.mockResolvedValue(mockSessions);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      mockDeleteUserSessions.mockResolvedValue(0);
      
      const result = await service.forcePasswordResetAll(mockRealmId);
      
      expect(result.realmId).toBe(mockRealmId);
      expect(result.usersAffected).toBe(2);
      expect(result.errors).toHaveLength(0);
    });
    
    it('should handle pagination for large user sets', async () => {
      const mockUsers1 = [
        { id: 'user_1', email: 'user1@test.com', realm_id: mockRealmId }
      ];
      const mockUsers2 = [
        { id: 'user_2', email: 'user2@test.com', realm_id: mockRealmId }
      ];
      const mockSessions = [
        { id: 'session_1', user_id: 'user_1', realm_id: mockRealmId }
      ];
      const mockTask = createMockTask();
      
      mockListRealmUsers
        .mockResolvedValueOnce({
          users: mockUsers1,
          lastEvaluatedKey: { pk: 'next' },
          total: 1
        })
        .mockResolvedValueOnce({
          users: mockUsers2,
          lastEvaluatedKey: undefined,
          total: 1
        });
      mockGetUserSessions.mockResolvedValue(mockSessions);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      mockDeleteUserSessions.mockResolvedValue(0);
      
      const result = await service.forcePasswordResetAll(mockRealmId);
      
      expect(result.usersAffected).toBe(2);
      expect(mockListRealmUsers).toHaveBeenCalledTimes(2);
    });
    
    it('should revoke all sessions when option is set', async () => {
      const mockUsers = [
        { id: 'user_1', email: 'user1@test.com', realm_id: mockRealmId }
      ];
      const mockSessions = [
        { id: 'session_1', user_id: 'user_1', realm_id: mockRealmId }
      ];
      const mockTask = createMockTask();
      
      mockListRealmUsers.mockResolvedValue({
        users: mockUsers,
        lastEvaluatedKey: undefined,
        total: 1
      });
      mockGetUserSessions.mockResolvedValue(mockSessions);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      mockDeleteUserSessions.mockResolvedValue(2);
      
      const result = await service.forcePasswordResetAll(mockRealmId, {
        revokeAllSessions: true
      });
      
      expect(result.sessionsRevoked).toBe(2);
    });
    
    it('should collect errors for failed user operations', async () => {
      const mockUsers = [
        { id: 'user_1', email: 'user1@test.com', realm_id: mockRealmId },
        { id: 'user_2', email: 'user2@test.com', realm_id: mockRealmId }
      ];
      
      mockListRealmUsers.mockResolvedValue({
        users: mockUsers,
        lastEvaluatedKey: undefined,
        total: 2
      });
      mockGetUserSessions
        .mockResolvedValueOnce([{ id: 'session_1', user_id: 'user_1', realm_id: mockRealmId }])
        .mockRejectedValueOnce(new Error('Database error'));
      mockCreateSessionTask.mockResolvedValue(createMockTask());
      
      const result = await service.forcePasswordResetAll(mockRealmId);
      
      expect(result.usersAffected).toBe(1);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].userId).toBe('user_2');
    });
    
    it('should throw error for empty realm ID', async () => {
      await expect(
        service.forcePasswordResetAll('')
      ).rejects.toThrow('Realm ID is required');
    });
  });

  describe('createMfaSetupTask', () => {
    it('should create MFA setup task', async () => {
      const mockTask = createMockTask({ type: 'setup_mfa' });
      mockGetSessionTaskByType.mockResolvedValue(null);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      
      const result = await service.createMfaSetupTask(
        mockSessionId,
        mockUserId,
        mockRealmId,
        ['totp', 'webauthn']
      );
      
      expect(result.type).toBe('setup_mfa');
      expect(mockCreateSessionTask).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'setup_mfa',
          metadata: expect.objectContaining({
            required_mfa_methods: ['totp', 'webauthn']
          })
        })
      );
    });
  });

  describe('createChooseOrganizationTask', () => {
    it('should create organization selection task', async () => {
      const mockTask = createMockTask({ type: 'choose_organization' });
      const organizations = [
        { id: 'org_1', name: 'Org 1', role: 'admin' },
        { id: 'org_2', name: 'Org 2', role: 'member' }
      ];
      
      mockGetSessionTaskByType.mockResolvedValue(null);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      
      const result = await service.createChooseOrganizationTask(
        mockSessionId,
        mockUserId,
        mockRealmId,
        organizations
      );
      
      expect(result.type).toBe('choose_organization');
      expect(mockCreateSessionTask).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'choose_organization',
          metadata: expect.objectContaining({
            available_organizations: organizations
          })
        })
      );
    });
    
    it('should throw error when no organizations provided', async () => {
      try {
        await service.createChooseOrganizationTask(mockSessionId, mockUserId, mockRealmId, []);
        fail('Expected error to be thrown');
      } catch (error) {
        expect((error as SessionTasksError).code).toBe('NO_ORGANIZATIONS');
      }
    });
  });

  describe('createAcceptTermsTask', () => {
    it('should create terms acceptance task', async () => {
      const mockTask = createMockTask({ type: 'accept_terms' });
      mockGetSessionTaskByType.mockResolvedValue(null);
      mockCreateSessionTask.mockResolvedValue(mockTask);
      
      const result = await service.createAcceptTermsTask(
        mockSessionId,
        mockUserId,
        mockRealmId,
        '2.0',
        'https://example.com/terms'
      );
      
      expect(result.type).toBe('accept_terms');
      expect(mockCreateSessionTask).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'accept_terms',
          metadata: expect.objectContaining({
            terms_version: '2.0',
            terms_url: 'https://example.com/terms'
          })
        })
      );
    });
  });

  describe('createCustomTask', () => {
    it('should create custom task with metadata', async () => {
      const mockTask = createMockTask({ type: 'custom', blocking: false });
      mockCreateSessionTask.mockResolvedValue(mockTask);
      
      const result = await service.createCustomTask(
        mockSessionId,
        mockUserId,
        mockRealmId,
        'survey',
        { surveyId: 'survey_123' },
        false
      );
      
      expect(result.type).toBe('custom');
      expect(mockCreateSessionTask).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'custom',
          blocking: false,
          metadata: expect.objectContaining({
            custom_type: 'survey',
            custom_data: { surveyId: 'survey_123' }
          })
        })
      );
    });
    
    it('should create blocking custom task when specified', async () => {
      const mockTask = createMockTask({ type: 'custom', blocking: true });
      mockCreateSessionTask.mockResolvedValue(mockTask);
      
      await service.createCustomTask(
        mockSessionId,
        mockUserId,
        mockRealmId,
        'verification',
        {},
        true
      );
      
      expect(mockCreateSessionTask).toHaveBeenCalledWith(
        expect.objectContaining({
          blocking: true
        })
      );
    });
  });


  describe('getTask', () => {
    it('should return task when found', async () => {
      const mockTask = createMockTask();
      mockGetSessionTaskById.mockResolvedValue(mockTask);
      
      const result = await service.getTask(mockSessionId, mockTaskId);
      
      expect(result).toEqual(mockTask);
    });
    
    it('should return null when task not found', async () => {
      mockGetSessionTaskById.mockResolvedValue(null);
      
      const result = await service.getTask(mockSessionId, 'nonexistent');
      
      expect(result).toBeNull();
    });
    
    it('should return null for empty session ID', async () => {
      const result = await service.getTask('', mockTaskId);
      
      expect(result).toBeNull();
    });
    
    it('should return null for empty task ID', async () => {
      const result = await service.getTask(mockSessionId, '');
      
      expect(result).toBeNull();
    });
  });

  describe('getAllTasks', () => {
    it('should return all tasks for a session', async () => {
      const tasks = [
        createMockTask({ id: 'task_1', status: 'pending' }),
        createMockTask({ id: 'task_2', status: 'completed' }),
        createMockTask({ id: 'task_3', status: 'skipped' })
      ];
      mockGetSessionTasks.mockResolvedValue(tasks);
      
      const result = await service.getAllTasks(mockSessionId);
      
      expect(result).toHaveLength(3);
    });
    
    it('should throw error for empty session ID', async () => {
      await expect(service.getAllTasks('')).rejects.toThrow('Session ID is required');
    });
  });

  describe('deleteAllTasks', () => {
    it('should delete all tasks for a session', async () => {
      mockDeleteAllSessionTasks.mockResolvedValue(3);
      
      const result = await service.deleteAllTasks(mockSessionId);
      
      expect(result).toBe(3);
      expect(mockDeleteAllSessionTasks).toHaveBeenCalledWith(mockSessionId);
    });
    
    it('should throw error for empty session ID', async () => {
      await expect(service.deleteAllTasks('')).rejects.toThrow('Session ID is required');
    });
  });

  describe('getPendingTaskCount', () => {
    it('should return count of pending tasks', async () => {
      mockCountPendingTasks.mockResolvedValue(5);
      
      const result = await service.getPendingTaskCount(mockSessionId);
      
      expect(result).toBe(5);
    });
    
    it('should return 0 for empty session ID', async () => {
      const result = await service.getPendingTaskCount('');
      
      expect(result).toBe(0);
    });
  });

  describe('getBlockingTaskCount', () => {
    it('should return count of blocking tasks', async () => {
      mockCountPendingBlockingTasks.mockResolvedValue(2);
      
      const result = await service.getBlockingTaskCount(mockSessionId);
      
      expect(result).toBe(2);
    });
    
    it('should return 0 for empty session ID', async () => {
      const result = await service.getBlockingTaskCount('');
      
      expect(result).toBe(0);
    });
  });

  describe('getBlockingTasks', () => {
    it('should return blocking tasks sorted by priority', async () => {
      const tasks = [
        createMockTask({ id: 'task_1', type: 'setup_mfa', priority: 2, blocking: true }),
        createMockTask({ id: 'task_2', type: 'reset_password', priority: 1, blocking: true })
      ];
      mockGetPendingBlockingTasks.mockResolvedValue(tasks);
      
      const result = await service.getBlockingTasks(mockSessionId);
      
      expect(result).toHaveLength(2);
      expect(result[0].priority).toBe(1);
      expect(result[1].priority).toBe(2);
    });
    
    it('should throw error for empty session ID', async () => {
      await expect(service.getBlockingTasks('')).rejects.toThrow('Session ID is required');
    });
  });

  describe('getPendingTasksResponse', () => {
    it('should return tasks in API response format', async () => {
      const tasks = [
        createMockTask({ id: 'task_1', type: 'reset_password', priority: 1 })
      ];
      mockGetPendingSessionTasks.mockResolvedValue(tasks);
      
      const result = await service.getPendingTasksResponse(mockSessionId);
      
      expect(result).toHaveLength(1);
      expect(result[0]).toHaveProperty('id');
      expect(result[0]).toHaveProperty('session_id');
      expect(result[0]).toHaveProperty('type');
      expect(result[0]).toHaveProperty('status');
      expect(result[0]).toHaveProperty('priority');
      expect(result[0]).toHaveProperty('blocking');
      // Should not include internal fields
      expect(result[0]).not.toHaveProperty('user_id');
      expect(result[0]).not.toHaveProperty('realm_id');
    });
  });
});

describe('SessionTasksError', () => {
  it('should create error with code and message', () => {
    const error = new SessionTasksError('TEST_ERROR', 'Test message');
    
    expect(error.code).toBe('TEST_ERROR');
    expect(error.message).toBe('Test message');
    expect(error.statusCode).toBe(400);
    expect(error.name).toBe('SessionTasksError');
  });
  
  it('should create error with custom status code', () => {
    const error = new SessionTasksError('NOT_FOUND', 'Not found', 404);
    
    expect(error.statusCode).toBe(404);
  });
});
