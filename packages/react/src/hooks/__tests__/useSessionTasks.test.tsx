/**
 * useSessionTasks Hook Tests
 * 
 * Validates: Requirements 4.6 (Session Task Handling UI)
 * 
 * Tests:
 * - Detect pending session tasks
 * - Complete tasks with validation
 * - Skip non-blocking tasks
 * - Handle task completion callbacks
 * - Error handling
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import React, { ReactNode } from 'react';
import { useSessionTasks, SessionTask, SessionTaskType } from '../useSessionTasks';
import { ZaltContext, ZaltContextValue } from '../../context';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Create mock client
const createMockClient = () => ({
  getAuthState: vi.fn().mockReturnValue({
    user: { id: 'user_123', email: 'test@example.com' },
    isAuthenticated: true,
    isLoading: false,
    error: null,
  }),
  login: vi.fn(),
  logout: vi.fn(),
  register: vi.fn(),
  onAuthStateChange: vi.fn().mockReturnValue(() => {}),
  mfa: { setup: vi.fn(), verify: vi.fn(), disable: vi.fn(), getStatus: vi.fn() },
  webauthn: {
    getRegistrationOptions: vi.fn(),
    register: vi.fn(),
    getAuthenticationOptions: vi.fn(),
    authenticate: vi.fn(),
    listCredentials: vi.fn(),
    removeCredential: vi.fn(),
  },
});

// Create wrapper with mock context
const createWrapper = (mockClient: ReturnType<typeof createMockClient>) => {
  const contextValue: ZaltContextValue = {
    client: mockClient as any,
    state: {
      user: { id: 'user_123', email: 'test@example.com' } as any,
      isAuthenticated: true,
      isLoading: false,
      error: null,
    },
    signIn: vi.fn(),
    signUp: vi.fn(),
    signOut: vi.fn(),
  };

  return ({ children }: { children: ReactNode }) => (
    <ZaltContext.Provider value={contextValue}>
      {children}
    </ZaltContext.Provider>
  );
};

// Sample tasks for testing
const createMockTask = (overrides: Partial<SessionTask> = {}): SessionTask => ({
  id: 'task_123',
  session_id: 'session_456',
  type: 'reset_password',
  status: 'pending',
  metadata: { reason: 'compromised', message: 'Password must be reset' },
  created_at: '2026-01-25T10:00:00Z',
  priority: 1,
  blocking: true,
  ...overrides,
});

describe('useSessionTasks', () => {
  let mockClient: ReturnType<typeof createMockClient>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
    mockClient = createMockClient();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Initial State', () => {
    it('should initialize with empty tasks', () => {
      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false 
      }));

      expect(result.current.tasks).toEqual([]);
      expect(result.current.currentTask).toBeNull();
      expect(result.current.hasBlockingTasks).toBe(false);
      expect(result.current.pendingTaskCount).toBe(0);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should have all required methods', () => {
      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false 
      }));

      expect(typeof result.current.fetchTasks).toBe('function');
      expect(typeof result.current.completeTask).toBe('function');
      expect(typeof result.current.skipTask).toBe('function');
      expect(typeof result.current.getTask).toBe('function');
      expect(typeof result.current.getTaskByType).toBe('function');
      expect(typeof result.current.clearError).toBe('function');
    });
  });

  describe('Fetch Tasks', () => {
    it('should fetch tasks successfully', async () => {
      const mockTasks = [
        createMockTask({ id: 'task_1', type: 'reset_password', priority: 1 }),
        createMockTask({ id: 'task_2', type: 'setup_mfa', priority: 2 }),
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: mockTasks, has_blocking_tasks: true, count: 2 }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false 
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(result.current.tasks).toHaveLength(2);
      expect(result.current.pendingTaskCount).toBe(2);
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/session/tasks',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Authorization': 'Bearer test_token',
          }),
        })
      );
    });

    it('should handle fetch error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({ error: { message: 'Server error' } }),
      });

      const onError = vi.fn();
      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
        onError,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(result.current.error).toBe('Server error');
      expect(onError).toHaveBeenCalled();
    });

    it('should set error when no access token', async () => {
      const { result } = renderHook(() => useSessionTasks({ 
        autoFetch: false 
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(result.current.error).toBe('Access token is required');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should auto-fetch on mount when autoFetch is true', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: [], has_blocking_tasks: false, count: 0 }),
      });

      renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: true 
      }));

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalled();
      });
    });
  });

  describe('Current Task', () => {
    it('should return highest priority task as current', async () => {
      const mockTasks = [
        createMockTask({ id: 'task_1', type: 'setup_mfa', priority: 2 }),
        createMockTask({ id: 'task_2', type: 'reset_password', priority: 1 }),
        createMockTask({ id: 'task_3', type: 'choose_organization', priority: 4 }),
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: mockTasks }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false 
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(result.current.currentTask?.id).toBe('task_2');
      expect(result.current.currentTask?.type).toBe('reset_password');
    });

    it('should return null when no tasks', () => {
      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false 
      }));

      expect(result.current.currentTask).toBeNull();
    });
  });

  describe('Complete Task', () => {
    it('should complete task successfully', async () => {
      const mockTasks = [createMockTask({ id: 'task_1' })];

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ tasks: mockTasks }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ 
            message: 'Task completed',
            task: { id: 'task_1', status: 'completed', completed_at: '2026-01-25T10:05:00Z' },
            remaining_tasks: 0,
          }),
        });

      const onTaskCompleted = vi.fn();
      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
        onTaskCompleted,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      let success: boolean;
      await act(async () => {
        success = await result.current.completeTask('task_1', { new_password: 'NewSecure123!' });
      });

      expect(success!).toBe(true);
      expect(result.current.tasks).toHaveLength(0);
      expect(onTaskCompleted).toHaveBeenCalledWith(expect.objectContaining({
        id: 'task_1',
        status: 'completed',
      }));
    });

    it('should handle complete task error', async () => {
      const mockTasks = [createMockTask({ id: 'task_1' })];

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ tasks: mockTasks }),
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 400,
          json: async () => ({ error: { message: 'Weak password' } }),
        });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      let success: boolean;
      await act(async () => {
        success = await result.current.completeTask('task_1', { new_password: 'weak' });
      });

      expect(success!).toBe(false);
      expect(result.current.error).toBe('Weak password');
      expect(result.current.tasks).toHaveLength(1); // Task not removed
    });

    it('should call onAllTasksCompleted when last task completed', async () => {
      const mockTasks = [createMockTask({ id: 'task_1' })];

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ tasks: mockTasks }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ message: 'Task completed', remaining_tasks: 0 }),
        });

      const onAllTasksCompleted = vi.fn();
      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
        onAllTasksCompleted,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      await act(async () => {
        await result.current.completeTask('task_1');
      });

      expect(onAllTasksCompleted).toHaveBeenCalled();
    });
  });

  describe('Skip Task', () => {
    it('should skip non-blocking task successfully', async () => {
      const mockTasks = [
        createMockTask({ id: 'task_1', blocking: false, type: 'custom' }),
      ];

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ tasks: mockTasks }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ message: 'Task skipped' }),
        });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      let success: boolean;
      await act(async () => {
        success = await result.current.skipTask('task_1');
      });

      expect(success!).toBe(true);
      expect(result.current.tasks).toHaveLength(0);
    });

    it('should not skip blocking task', async () => {
      const mockTasks = [
        createMockTask({ id: 'task_1', blocking: true }),
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: mockTasks }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      let success: boolean;
      await act(async () => {
        success = await result.current.skipTask('task_1');
      });

      expect(success!).toBe(false);
      expect(result.current.error).toBe('Cannot skip a blocking task');
      expect(result.current.tasks).toHaveLength(1);
    });
  });

  describe('Has Blocking Tasks', () => {
    it('should return true when blocking tasks exist', async () => {
      const mockTasks = [
        createMockTask({ id: 'task_1', blocking: true }),
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: mockTasks }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(result.current.hasBlockingTasks).toBe(true);
    });

    it('should return false when no blocking tasks', async () => {
      const mockTasks = [
        createMockTask({ id: 'task_1', blocking: false }),
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: mockTasks }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(result.current.hasBlockingTasks).toBe(false);
    });
  });

  describe('Get Task Methods', () => {
    it('should get task by ID', async () => {
      const mockTasks = [
        createMockTask({ id: 'task_1', type: 'reset_password' }),
        createMockTask({ id: 'task_2', type: 'setup_mfa' }),
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: mockTasks }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      const task = result.current.getTask('task_2');
      expect(task?.type).toBe('setup_mfa');
    });

    it('should get task by type', async () => {
      const mockTasks = [
        createMockTask({ id: 'task_1', type: 'reset_password' }),
        createMockTask({ id: 'task_2', type: 'setup_mfa' }),
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: mockTasks }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      const task = result.current.getTaskByType('setup_mfa');
      expect(task?.id).toBe('task_2');
    });

    it('should return undefined for non-existent task', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: [] }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(result.current.getTask('non_existent')).toBeUndefined();
      expect(result.current.getTaskByType('reset_password')).toBeUndefined();
    });
  });

  describe('Clear Error', () => {
    it('should clear error state', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({ error: { message: 'Server error' } }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(result.current.error).toBe('Server error');

      act(() => {
        result.current.clearError();
      });

      expect(result.current.error).toBeNull();
    });
  });

  describe('Polling', () => {
    it('should poll for tasks at specified interval', async () => {
      vi.useFakeTimers();

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [] }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
        pollingInterval: 5000,
      }));

      // Manual first fetch
      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);

      vi.useRealTimers();
    });
  });

  describe('Task Types', () => {
    const taskTypes: SessionTaskType[] = [
      'reset_password',
      'setup_mfa',
      'choose_organization',
      'verify_email',
      'accept_terms',
      'custom',
    ];

    taskTypes.forEach((type) => {
      it(`should handle ${type} task type`, async () => {
        const mockTasks = [createMockTask({ id: 'task_1', type })];

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ tasks: mockTasks }),
        });

        const { result } = renderHook(() => useSessionTasks({ 
          accessToken: 'test_token',
          autoFetch: false,
        }));

        await act(async () => {
          await result.current.fetchTasks();
        });

        expect(result.current.currentTask?.type).toBe(type);
      });
    });
  });

  describe('Task Metadata', () => {
    it('should preserve task metadata', async () => {
      const mockTasks = [
        createMockTask({
          id: 'task_1',
          type: 'choose_organization',
          metadata: {
            available_organizations: [
              { id: 'org_1', name: 'Org 1', role: 'admin' },
              { id: 'org_2', name: 'Org 2', role: 'member' },
            ],
            message: 'Select your organization',
          },
        }),
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ tasks: mockTasks }),
      });

      const { result } = renderHook(() => useSessionTasks({ 
        accessToken: 'test_token',
        autoFetch: false,
      }));

      await act(async () => {
        await result.current.fetchTasks();
      });

      expect(result.current.currentTask?.metadata?.available_organizations).toHaveLength(2);
      expect(result.current.currentTask?.metadata?.message).toBe('Select your organization');
    });
  });
});
