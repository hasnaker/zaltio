/**
 * Session Task Repository Tests
 * Tests for session task CRUD operations
 * 
 * Validates: Requirements 4.1 (Session Tasks)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (DynamoDB mocked for unit tests)
 */

// Mock DynamoDB
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  },
  TableNames: {
    SESSIONS: 'zalt-sessions'
  }
}));

// Import after mocks
import {
  createSessionTask,
  getSessionTaskById,
  getSessionTasks,
  getPendingSessionTasks,
  getPendingBlockingTasks,
  hasBlockingTasks,
  getUserTasks,
  completeSessionTask,
  skipSessionTask,
  updateSessionTaskMetadata,
  deleteSessionTask,
  deleteAllSessionTasks,
  createSessionTasks,
  getSessionTaskByType,
  countPendingTasks,
  countPendingBlockingTasks
} from './session-task.repository';
import { SessionTask, SessionTaskType, SessionTaskStatus } from '../models/session-task.model';

describe('Session Task Repository', () => {
  const mockSessionId = 'session_test123';
  const mockUserId = 'user_abc123';
  const mockRealmId = 'realm_test';
  const mockTaskId = 'task_def456789012';
  
  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('createSessionTask', () => {
    it('should create a new session task with generated ID', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        session_id: mockSessionId,
        user_id: mockUserId,
        realm_id: mockRealmId,
        type: 'reset_password' as SessionTaskType,
        metadata: {
          reason: 'compromised' as const,
          message: 'Your password was found in a data breach'
        }
      };
      
      const result = await createSessionTask(input);
      
      // Verify task was created
      expect(result).toBeDefined();
      expect(result.id).toMatch(/^task_[a-f0-9]{24}$/);
      expect(result.session_id).toBe(mockSessionId);
      expect(result.user_id).toBe(mockUserId);
      expect(result.realm_id).toBe(mockRealmId);
      expect(result.type).toBe('reset_password');
      expect(result.status).toBe('pending');
      expect(result.metadata?.reason).toBe('compromised');
      expect(result.blocking).toBe(true); // reset_password is blocking by default
      expect(result.priority).toBe(1); // reset_password has highest priority
      
      // Verify DynamoDB put was called
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should use default priority and blocking for task type', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        session_id: mockSessionId,
        user_id: mockUserId,
        realm_id: mockRealmId,
        type: 'choose_organization' as SessionTaskType
      };
      
      const result = await createSessionTask(input);
      
      expect(result.priority).toBe(4); // choose_organization default priority
      expect(result.blocking).toBe(true); // choose_organization is blocking
    });
    
    it('should allow custom priority and blocking override', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        session_id: mockSessionId,
        user_id: mockUserId,
        realm_id: mockRealmId,
        type: 'custom' as SessionTaskType,
        priority: 10,
        blocking: true
      };
      
      const result = await createSessionTask(input);
      
      expect(result.priority).toBe(10);
      expect(result.blocking).toBe(true);
    });
    
    it('should set expiration if provided', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const expiresAt = new Date(Date.now() + 3600000).toISOString();
      const input = {
        session_id: mockSessionId,
        user_id: mockUserId,
        realm_id: mockRealmId,
        type: 'accept_terms' as SessionTaskType,
        expires_at: expiresAt
      };
      
      const result = await createSessionTask(input);
      
      expect(result.expires_at).toBe(expiresAt);
    });
  });

  describe('getSessionTaskById', () => {
    it('should return task when found', async () => {
      const mockTask = {
        id: mockTaskId,
        session_id: mockSessionId,
        user_id: mockUserId,
        realm_id: mockRealmId,
        type: 'setup_mfa',
        status: 'pending',
        created_at: '2026-01-01T00:00:00Z',
        priority: 2,
        blocking: true
      };
      
      mockSend.mockResolvedValueOnce({
        Item: mockTask
      });
      
      const result = await getSessionTaskById(mockSessionId, mockTaskId);
      
      expect(result).toBeDefined();
      expect(result?.id).toBe(mockTaskId);
      expect(result?.type).toBe('setup_mfa');
      expect(result?.status).toBe('pending');
    });
    
    it('should return null when task not found', async () => {
      mockSend.mockResolvedValueOnce({
        Item: undefined
      });
      
      const result = await getSessionTaskById(mockSessionId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });

  describe('getSessionTasks', () => {
    it('should return all tasks for a session', async () => {
      const mockTasks = [
        {
          id: 'task_1',
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'reset_password',
          status: 'pending',
          created_at: '2026-01-01T00:00:00Z',
          priority: 1,
          blocking: true
        },
        {
          id: 'task_2',
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'setup_mfa',
          status: 'pending',
          created_at: '2026-01-01T00:00:00Z',
          priority: 2,
          blocking: true
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockTasks
      });
      
      const result = await getSessionTasks(mockSessionId);
      
      expect(result).toHaveLength(2);
      expect(result[0].type).toBe('reset_password');
      expect(result[1].type).toBe('setup_mfa');
    });
    
    it('should return empty array when no tasks', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getSessionTasks(mockSessionId);
      
      expect(result).toEqual([]);
    });
  });

  describe('getPendingSessionTasks', () => {
    it('should return only pending tasks', async () => {
      const mockTasks = [
        {
          id: 'task_1',
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'reset_password',
          status: 'pending',
          created_at: '2026-01-01T00:00:00Z',
          priority: 1,
          blocking: true
        },
        {
          id: 'task_2',
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'setup_mfa',
          status: 'completed',
          created_at: '2026-01-01T00:00:00Z',
          completed_at: '2026-01-01T01:00:00Z',
          priority: 2,
          blocking: true
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockTasks
      });
      
      const result = await getPendingSessionTasks(mockSessionId);
      
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('reset_password');
      expect(result[0].status).toBe('pending');
    });
  });

  describe('getPendingBlockingTasks', () => {
    it('should return only pending blocking tasks', async () => {
      const mockTasks = [
        {
          id: 'task_1',
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'reset_password',
          status: 'pending',
          created_at: '2026-01-01T00:00:00Z',
          priority: 1,
          blocking: true
        },
        {
          id: 'task_2',
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'custom',
          status: 'pending',
          created_at: '2026-01-01T00:00:00Z',
          priority: 5,
          blocking: false
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockTasks
      });
      
      const result = await getPendingBlockingTasks(mockSessionId);
      
      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('reset_password');
      expect(result[0].blocking).toBe(true);
    });
  });

  describe('hasBlockingTasks', () => {
    it('should return true when blocking tasks exist', async () => {
      const mockTasks = [
        {
          id: 'task_1',
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'reset_password',
          status: 'pending',
          created_at: '2026-01-01T00:00:00Z',
          priority: 1,
          blocking: true
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockTasks
      });
      
      const result = await hasBlockingTasks(mockSessionId);
      
      expect(result).toBe(true);
    });
    
    it('should return false when no blocking tasks', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await hasBlockingTasks(mockSessionId);
      
      expect(result).toBe(false);
    });
  });

  describe('completeSessionTask', () => {
    it('should complete a pending task', async () => {
      const completedTask = {
        id: mockTaskId,
        session_id: mockSessionId,
        user_id: mockUserId,
        realm_id: mockRealmId,
        type: 'reset_password',
        status: 'completed',
        created_at: '2026-01-01T00:00:00Z',
        completed_at: '2026-01-01T01:00:00Z',
        priority: 1,
        blocking: true
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: completedTask
      });
      
      const result = await completeSessionTask(mockSessionId, mockTaskId);
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('completed');
      expect(result?.completed_at).toBeDefined();
    });
    
    it('should return null when task not found', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await completeSessionTask(mockSessionId, 'nonexistent');
      
      expect(result).toBeNull();
    });
    
    it('should return null when task already completed', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await completeSessionTask(mockSessionId, mockTaskId);
      
      expect(result).toBeNull();
    });
  });

  describe('skipSessionTask', () => {
    it('should skip a non-blocking pending task', async () => {
      const skippedTask = {
        id: mockTaskId,
        session_id: mockSessionId,
        user_id: mockUserId,
        realm_id: mockRealmId,
        type: 'custom',
        status: 'skipped',
        created_at: '2026-01-01T00:00:00Z',
        completed_at: '2026-01-01T01:00:00Z',
        priority: 5,
        blocking: false
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: skippedTask
      });
      
      const result = await skipSessionTask(mockSessionId, mockTaskId);
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('skipped');
    });
    
    it('should return null when trying to skip blocking task', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await skipSessionTask(mockSessionId, mockTaskId);
      
      expect(result).toBeNull();
    });
  });

  describe('updateSessionTaskMetadata', () => {
    it('should update task metadata', async () => {
      const updatedTask = {
        id: mockTaskId,
        session_id: mockSessionId,
        user_id: mockUserId,
        realm_id: mockRealmId,
        type: 'choose_organization',
        status: 'pending',
        metadata: {
          available_organizations: [
            { id: 'org_1', name: 'Org 1', role: 'admin' },
            { id: 'org_2', name: 'Org 2', role: 'member' }
          ]
        },
        created_at: '2026-01-01T00:00:00Z',
        priority: 4,
        blocking: true
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedTask
      });
      
      const result = await updateSessionTaskMetadata(mockSessionId, mockTaskId, {
        available_organizations: [
          { id: 'org_1', name: 'Org 1', role: 'admin' },
          { id: 'org_2', name: 'Org 2', role: 'member' }
        ]
      });
      
      expect(result).toBeDefined();
      expect(result?.metadata?.available_organizations).toHaveLength(2);
    });
    
    it('should return null when task not found', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await updateSessionTaskMetadata(mockSessionId, 'nonexistent', {});
      
      expect(result).toBeNull();
    });
  });

  describe('deleteSessionTask', () => {
    it('should delete a task', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const result = await deleteSessionTask(mockSessionId, mockTaskId);
      
      expect(result).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should return false on error', async () => {
      mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));
      
      const result = await deleteSessionTask(mockSessionId, 'nonexistent');
      
      expect(result).toBe(false);
    });
  });

  describe('deleteAllSessionTasks', () => {
    it('should delete all tasks for a session', async () => {
      const mockTasks = [
        { id: 'task_1', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'reset_password', status: 'pending', created_at: '2026-01-01T00:00:00Z', priority: 1, blocking: true },
        { id: 'task_2', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'setup_mfa', status: 'pending', created_at: '2026-01-01T00:00:00Z', priority: 2, blocking: true }
      ];
      
      mockSend
        .mockResolvedValueOnce({ Items: mockTasks }) // getSessionTasks
        .mockResolvedValueOnce({}); // BatchWriteCommand
      
      const result = await deleteAllSessionTasks(mockSessionId);
      
      expect(result).toBe(2);
    });
    
    it('should return 0 when no tasks', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await deleteAllSessionTasks(mockSessionId);
      
      expect(result).toBe(0);
    });
  });

  describe('createSessionTasks', () => {
    it('should create multiple tasks in batch', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const inputs = [
        {
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'reset_password' as SessionTaskType
        },
        {
          session_id: mockSessionId,
          user_id: mockUserId,
          realm_id: mockRealmId,
          type: 'setup_mfa' as SessionTaskType
        }
      ];
      
      const result = await createSessionTasks(inputs);
      
      expect(result).toHaveLength(2);
      expect(result[0].type).toBe('reset_password');
      expect(result[1].type).toBe('setup_mfa');
      expect(result[0].id).not.toBe(result[1].id);
    });
  });

  describe('getSessionTaskByType', () => {
    it('should return pending task of specific type', async () => {
      const mockTasks = [
        { id: 'task_1', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'reset_password', status: 'pending', created_at: '2026-01-01T00:00:00Z', priority: 1, blocking: true },
        { id: 'task_2', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'setup_mfa', status: 'completed', created_at: '2026-01-01T00:00:00Z', priority: 2, blocking: true }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockTasks });
      
      const result = await getSessionTaskByType(mockSessionId, 'reset_password');
      
      expect(result).toBeDefined();
      expect(result?.type).toBe('reset_password');
      expect(result?.status).toBe('pending');
    });
    
    it('should return null when no pending task of type exists', async () => {
      const mockTasks = [
        { id: 'task_1', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'reset_password', status: 'completed', created_at: '2026-01-01T00:00:00Z', priority: 1, blocking: true }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockTasks });
      
      const result = await getSessionTaskByType(mockSessionId, 'reset_password');
      
      expect(result).toBeNull();
    });
  });

  describe('countPendingTasks', () => {
    it('should return count of pending tasks', async () => {
      const mockTasks = [
        { id: 'task_1', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'reset_password', status: 'pending', created_at: '2026-01-01T00:00:00Z', priority: 1, blocking: true },
        { id: 'task_2', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'setup_mfa', status: 'pending', created_at: '2026-01-01T00:00:00Z', priority: 2, blocking: true },
        { id: 'task_3', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'accept_terms', status: 'completed', created_at: '2026-01-01T00:00:00Z', priority: 3, blocking: true }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockTasks });
      
      const result = await countPendingTasks(mockSessionId);
      
      expect(result).toBe(2);
    });
  });

  describe('countPendingBlockingTasks', () => {
    it('should return count of pending blocking tasks', async () => {
      const mockTasks = [
        { id: 'task_1', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'reset_password', status: 'pending', created_at: '2026-01-01T00:00:00Z', priority: 1, blocking: true },
        { id: 'task_2', session_id: mockSessionId, user_id: mockUserId, realm_id: mockRealmId, type: 'custom', status: 'pending', created_at: '2026-01-01T00:00:00Z', priority: 5, blocking: false }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockTasks });
      
      const result = await countPendingBlockingTasks(mockSessionId);
      
      expect(result).toBe(1);
    });
  });

  describe('getUserTasks', () => {
    it('should return all tasks for a user', async () => {
      const mockTasks = [
        { id: 'task_1', session_id: 'session_1', user_id: mockUserId, realm_id: mockRealmId, type: 'reset_password', status: 'pending', created_at: '2026-01-01T00:00:00Z', priority: 1, blocking: true },
        { id: 'task_2', session_id: 'session_2', user_id: mockUserId, realm_id: mockRealmId, type: 'setup_mfa', status: 'completed', created_at: '2026-01-01T00:00:00Z', priority: 2, blocking: true }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockTasks });
      
      const result = await getUserTasks(mockRealmId, mockUserId);
      
      expect(result).toHaveLength(2);
    });
    
    it('should filter by status when provided', async () => {
      const mockTasks = [
        { id: 'task_1', session_id: 'session_1', user_id: mockUserId, realm_id: mockRealmId, type: 'reset_password', status: 'pending', created_at: '2026-01-01T00:00:00Z', priority: 1, blocking: true }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockTasks });
      
      const result = await getUserTasks(mockRealmId, mockUserId, 'pending');
      
      expect(result).toHaveLength(1);
      expect(result[0].status).toBe('pending');
    });
  });
});


describe('Session Task Model Utilities', () => {
  // Import model utilities
  const {
    isValidTaskType,
    isValidTaskStatus,
    getDefaultPriority,
    getDefaultBlocking,
    isTaskExpired,
    isTaskBlocking,
    sortTasksByPriority,
    getPendingBlockingTasks: modelGetPendingBlockingTasks,
    toSessionTaskResponse,
    DEFAULT_TASK_PRIORITIES,
    DEFAULT_TASK_BLOCKING
  } = require('../models/session-task.model');
  
  describe('isValidTaskType', () => {
    it('should return true for valid task types', () => {
      expect(isValidTaskType('choose_organization')).toBe(true);
      expect(isValidTaskType('setup_mfa')).toBe(true);
      expect(isValidTaskType('reset_password')).toBe(true);
      expect(isValidTaskType('accept_terms')).toBe(true);
      expect(isValidTaskType('custom')).toBe(true);
    });
    
    it('should return false for invalid task types', () => {
      expect(isValidTaskType('invalid')).toBe(false);
      expect(isValidTaskType('')).toBe(false);
      expect(isValidTaskType('RESET_PASSWORD')).toBe(false);
    });
  });
  
  describe('isValidTaskStatus', () => {
    it('should return true for valid statuses', () => {
      expect(isValidTaskStatus('pending')).toBe(true);
      expect(isValidTaskStatus('completed')).toBe(true);
      expect(isValidTaskStatus('skipped')).toBe(true);
    });
    
    it('should return false for invalid statuses', () => {
      expect(isValidTaskStatus('invalid')).toBe(false);
      expect(isValidTaskStatus('PENDING')).toBe(false);
    });
  });
  
  describe('getDefaultPriority', () => {
    it('should return correct priorities for each type', () => {
      expect(getDefaultPriority('reset_password')).toBe(1);
      expect(getDefaultPriority('setup_mfa')).toBe(2);
      expect(getDefaultPriority('accept_terms')).toBe(3);
      expect(getDefaultPriority('choose_organization')).toBe(4);
      expect(getDefaultPriority('custom')).toBe(5);
    });
  });
  
  describe('getDefaultBlocking', () => {
    it('should return correct blocking for each type', () => {
      expect(getDefaultBlocking('reset_password')).toBe(true);
      expect(getDefaultBlocking('setup_mfa')).toBe(true);
      expect(getDefaultBlocking('accept_terms')).toBe(true);
      expect(getDefaultBlocking('choose_organization')).toBe(true);
      expect(getDefaultBlocking('custom')).toBe(false);
    });
  });
  
  describe('isTaskExpired', () => {
    it('should return false when no expiration', () => {
      const task = {
        id: 'task_1',
        session_id: 'session_1',
        user_id: 'user_1',
        realm_id: 'realm_1',
        type: 'reset_password',
        status: 'pending',
        created_at: '2026-01-01T00:00:00Z',
        priority: 1,
        blocking: true
      };
      
      expect(isTaskExpired(task)).toBe(false);
    });
    
    it('should return true when expired', () => {
      const task = {
        id: 'task_1',
        session_id: 'session_1',
        user_id: 'user_1',
        realm_id: 'realm_1',
        type: 'reset_password',
        status: 'pending',
        created_at: '2026-01-01T00:00:00Z',
        expires_at: '2020-01-01T00:00:00Z', // Past date
        priority: 1,
        blocking: true
      };
      
      expect(isTaskExpired(task)).toBe(true);
    });
    
    it('should return false when not expired', () => {
      const futureDate = new Date(Date.now() + 3600000).toISOString();
      const task = {
        id: 'task_1',
        session_id: 'session_1',
        user_id: 'user_1',
        realm_id: 'realm_1',
        type: 'reset_password',
        status: 'pending',
        created_at: '2026-01-01T00:00:00Z',
        expires_at: futureDate,
        priority: 1,
        blocking: true
      };
      
      expect(isTaskExpired(task)).toBe(false);
    });
  });
  
  describe('isTaskBlocking', () => {
    it('should return true for pending blocking task', () => {
      const task = {
        id: 'task_1',
        session_id: 'session_1',
        user_id: 'user_1',
        realm_id: 'realm_1',
        type: 'reset_password',
        status: 'pending',
        created_at: '2026-01-01T00:00:00Z',
        priority: 1,
        blocking: true
      };
      
      expect(isTaskBlocking(task)).toBe(true);
    });
    
    it('should return false for completed task', () => {
      const task = {
        id: 'task_1',
        session_id: 'session_1',
        user_id: 'user_1',
        realm_id: 'realm_1',
        type: 'reset_password',
        status: 'completed',
        created_at: '2026-01-01T00:00:00Z',
        priority: 1,
        blocking: true
      };
      
      expect(isTaskBlocking(task)).toBe(false);
    });
    
    it('should return false for non-blocking task', () => {
      const task = {
        id: 'task_1',
        session_id: 'session_1',
        user_id: 'user_1',
        realm_id: 'realm_1',
        type: 'custom',
        status: 'pending',
        created_at: '2026-01-01T00:00:00Z',
        priority: 5,
        blocking: false
      };
      
      expect(isTaskBlocking(task)).toBe(false);
    });
    
    it('should return false for expired task', () => {
      const task = {
        id: 'task_1',
        session_id: 'session_1',
        user_id: 'user_1',
        realm_id: 'realm_1',
        type: 'reset_password',
        status: 'pending',
        created_at: '2026-01-01T00:00:00Z',
        expires_at: '2020-01-01T00:00:00Z',
        priority: 1,
        blocking: true
      };
      
      expect(isTaskBlocking(task)).toBe(false);
    });
  });
  
  describe('sortTasksByPriority', () => {
    it('should sort tasks by priority (lower first)', () => {
      const tasks = [
        { id: 'task_3', priority: 4, type: 'choose_organization', status: 'pending', session_id: 's1', user_id: 'u1', realm_id: 'r1', created_at: '2026-01-01T00:00:00Z', blocking: true },
        { id: 'task_1', priority: 1, type: 'reset_password', status: 'pending', session_id: 's1', user_id: 'u1', realm_id: 'r1', created_at: '2026-01-01T00:00:00Z', blocking: true },
        { id: 'task_2', priority: 2, type: 'setup_mfa', status: 'pending', session_id: 's1', user_id: 'u1', realm_id: 'r1', created_at: '2026-01-01T00:00:00Z', blocking: true }
      ];
      
      const sorted = sortTasksByPriority(tasks);
      
      expect(sorted[0].id).toBe('task_1');
      expect(sorted[1].id).toBe('task_2');
      expect(sorted[2].id).toBe('task_3');
    });
  });
  
  describe('toSessionTaskResponse', () => {
    it('should convert task to response format', () => {
      const task = {
        id: 'task_1',
        session_id: 'session_1',
        user_id: 'user_1',
        realm_id: 'realm_1',
        type: 'reset_password' as const,
        status: 'pending' as const,
        metadata: { reason: 'compromised' },
        created_at: '2026-01-01T00:00:00Z',
        priority: 1,
        blocking: true
      };
      
      const response = toSessionTaskResponse(task);
      
      expect(response.id).toBe('task_1');
      expect(response.session_id).toBe('session_1');
      expect(response.type).toBe('reset_password');
      expect(response.status).toBe('pending');
      expect(response.metadata?.reason).toBe('compromised');
      expect(response.priority).toBe(1);
      expect(response.blocking).toBe(true);
      // Should not include user_id and realm_id in response
      expect((response as Record<string, unknown>).user_id).toBeUndefined();
      expect((response as Record<string, unknown>).realm_id).toBeUndefined();
    });
  });
});
