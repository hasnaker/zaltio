/**
 * useSessionTasks Hook - Session Task Management
 * Task 23.3: SDK <SessionTaskHandler /> component support hook
 * 
 * Provides:
 * - Detect pending session tasks
 * - Get task details and metadata
 * - Complete tasks with validation
 * - Skip non-blocking tasks
 * - Auto-refresh task status
 * 
 * Validates: Requirements 4.6 (Session Task Handling UI)
 */

'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useZaltContext } from '../context';

/**
 * Session task types supported by Zalt
 */
export type SessionTaskType = 
  | 'choose_organization'
  | 'setup_mfa'
  | 'reset_password'
  | 'accept_terms'
  | 'verify_email'
  | 'custom';

/**
 * Session task status
 */
export type SessionTaskStatus = 'pending' | 'completed' | 'skipped';

/**
 * Organization option for choose_organization task
 */
export interface OrganizationOption {
  id: string;
  name: string;
  role?: string;
}

/**
 * Session task metadata
 */
export interface SessionTaskMetadata {
  // For choose_organization
  available_organizations?: OrganizationOption[];
  
  // For setup_mfa
  required_mfa_methods?: string[];
  mfa_policy_id?: string;
  
  // For reset_password
  reason?: 'compromised' | 'expired' | 'admin_forced' | 'policy';
  compromised_at?: string;
  
  // For accept_terms
  terms_version?: string;
  terms_url?: string;
  
  // For verify_email
  email?: string;
  
  // For custom tasks
  custom_type?: string;
  webhook_url?: string;
  custom_data?: Record<string, unknown>;
  
  // Common fields
  message?: string;
  instructions?: string;
}

/**
 * Session task from API
 */
export interface SessionTask {
  id: string;
  session_id: string;
  type: SessionTaskType;
  status: SessionTaskStatus;
  metadata?: SessionTaskMetadata;
  created_at: string;
  completed_at?: string;
  priority: number;
  blocking: boolean;
}

/**
 * Task completion data for different task types
 */
export interface TaskCompletionData {
  // For reset_password
  new_password?: string;
  
  // For setup_mfa
  mfa_method?: 'totp' | 'webauthn';
  verification_code?: string;
  
  // For choose_organization
  organization_id?: string;
  
  // For accept_terms
  accepted?: boolean;
  terms_version?: string;
  
  // For verify_email
  verification_code?: string;
  
  // For custom tasks
  custom_data?: Record<string, unknown>;
}

/**
 * Hook options
 */
export interface UseSessionTasksOptions {
  /** API base URL */
  apiUrl?: string;
  /** Access token for API calls */
  accessToken?: string;
  /** Auto-fetch tasks on mount */
  autoFetch?: boolean;
  /** Polling interval in milliseconds (0 to disable) */
  pollingInterval?: number;
  /** Callback when task is completed */
  onTaskCompleted?: (task: SessionTask) => void;
  /** Callback when all tasks are completed */
  onAllTasksCompleted?: () => void;
  /** Callback on error */
  onError?: (error: Error) => void;
}

/**
 * Hook return type
 */
export interface UseSessionTasksReturn {
  /** List of pending tasks */
  tasks: SessionTask[];
  /** Current highest priority task */
  currentTask: SessionTask | null;
  /** Whether there are blocking tasks */
  hasBlockingTasks: boolean;
  /** Count of pending tasks */
  pendingTaskCount: number;
  /** Loading state */
  isLoading: boolean;
  /** Completing task state */
  isCompleting: boolean;
  /** Error state */
  error: string | null;
  /** Fetch/refresh tasks */
  fetchTasks: () => Promise<void>;
  /** Complete a task */
  completeTask: (taskId: string, data?: TaskCompletionData) => Promise<boolean>;
  /** Skip a non-blocking task */
  skipTask: (taskId: string) => Promise<boolean>;
  /** Get task by ID */
  getTask: (taskId: string) => SessionTask | undefined;
  /** Get task by type */
  getTaskByType: (type: SessionTaskType) => SessionTask | undefined;
  /** Clear error */
  clearError: () => void;
}

/**
 * useSessionTasks Hook
 * 
 * Manages session tasks (post-login requirements) with support for
 * detecting, completing, and skipping tasks.
 * 
 * @example
 * ```tsx
 * import { useSessionTasks } from '@zalt/react';
 * 
 * function SessionTaskManager() {
 *   const { 
 *     tasks, 
 *     currentTask, 
 *     hasBlockingTasks,
 *     completeTask,
 *     skipTask 
 *   } = useSessionTasks({ accessToken });
 * 
 *   if (!currentTask) {
 *     return <div>No pending tasks</div>;
 *   }
 * 
 *   return (
 *     <div>
 *       <h2>Complete Required Action</h2>
 *       {currentTask.type === 'reset_password' && (
 *         <PasswordResetForm 
 *           onSubmit={(password) => completeTask(currentTask.id, { new_password: password })}
 *         />
 *       )}
 *     </div>
 *   );
 * }
 * ```
 */
export function useSessionTasks(options: UseSessionTasksOptions = {}): UseSessionTasksReturn {
  const {
    apiUrl = '/api',
    accessToken,
    autoFetch = true,
    pollingInterval = 0,
    onTaskCompleted,
    onAllTasksCompleted,
    onError
  } = options;

  // Try to get context, but don't fail if not available
  let contextAccessToken: string | undefined;
  try {
    const context = useZaltContext();
    // In a real implementation, we'd get the token from the client
    contextAccessToken = undefined;
  } catch {
    // Context not available, use provided accessToken
  }

  const effectiveAccessToken = accessToken || contextAccessToken;

  // State
  const [tasks, setTasks] = useState<SessionTask[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isCompleting, setIsCompleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Clear error state
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  /**
   * Fetch tasks from API
   */
  const fetchTasks = useCallback(async () => {
    if (!effectiveAccessToken) {
      setError('Access token is required');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/session/tasks`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${effectiveAccessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `Failed to fetch tasks (${response.status})`;
        throw new Error(errorMessage);
      }

      const data = await response.json();
      const fetchedTasks = data.tasks || [];
      
      setTasks(fetchedTasks);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch tasks';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, effectiveAccessToken, onError]);

  /**
   * Complete a task
   */
  const completeTask = useCallback(async (
    taskId: string, 
    data?: TaskCompletionData
  ): Promise<boolean> => {
    if (!effectiveAccessToken) {
      setError('Access token is required');
      return false;
    }

    setIsCompleting(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/session/tasks/${taskId}/complete`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${effectiveAccessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data || {})
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `Failed to complete task (${response.status})`;
        throw new Error(errorMessage);
      }

      const responseData = await response.json();
      
      // Find the completed task for callback
      const completedTask = tasks.find(t => t.id === taskId);
      
      // Remove the task from local state
      setTasks(prev => prev.filter(t => t.id !== taskId));
      
      // Trigger callback
      if (completedTask) {
        onTaskCompleted?.({
          ...completedTask,
          status: 'completed',
          completed_at: responseData.task?.completed_at || new Date().toISOString()
        });
      }

      // Check if all tasks completed
      const remainingTasks = tasks.filter(t => t.id !== taskId);
      if (remainingTasks.length === 0) {
        onAllTasksCompleted?.();
      }

      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to complete task';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
      return false;
    } finally {
      setIsCompleting(false);
    }
  }, [apiUrl, effectiveAccessToken, tasks, onTaskCompleted, onAllTasksCompleted, onError]);

  /**
   * Skip a non-blocking task
   */
  const skipTask = useCallback(async (taskId: string): Promise<boolean> => {
    if (!effectiveAccessToken) {
      setError('Access token is required');
      return false;
    }

    // Check if task is blocking
    const task = tasks.find(t => t.id === taskId);
    if (task?.blocking) {
      setError('Cannot skip a blocking task');
      return false;
    }

    setIsCompleting(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/session/tasks/${taskId}/skip`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${effectiveAccessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.error?.message || `Failed to skip task (${response.status})`;
        throw new Error(errorMessage);
      }

      // Remove the task from local state
      setTasks(prev => prev.filter(t => t.id !== taskId));

      return true;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to skip task';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
      return false;
    } finally {
      setIsCompleting(false);
    }
  }, [apiUrl, effectiveAccessToken, tasks, onError]);

  /**
   * Get task by ID
   */
  const getTask = useCallback((taskId: string): SessionTask | undefined => {
    return tasks.find(t => t.id === taskId);
  }, [tasks]);

  /**
   * Get task by type
   */
  const getTaskByType = useCallback((type: SessionTaskType): SessionTask | undefined => {
    return tasks.find(t => t.type === type);
  }, [tasks]);

  /**
   * Computed: Current highest priority task
   */
  const currentTask = useMemo(() => {
    if (tasks.length === 0) return null;
    // Tasks should already be sorted by priority from API
    // Lower priority number = higher priority
    return [...tasks].sort((a, b) => a.priority - b.priority)[0];
  }, [tasks]);

  /**
   * Computed: Whether there are blocking tasks
   */
  const hasBlockingTasks = useMemo(() => {
    return tasks.some(t => t.blocking && t.status === 'pending');
  }, [tasks]);

  /**
   * Computed: Count of pending tasks
   */
  const pendingTaskCount = useMemo(() => {
    return tasks.filter(t => t.status === 'pending').length;
  }, [tasks]);

  /**
   * Auto-fetch on mount
   */
  useEffect(() => {
    if (autoFetch && effectiveAccessToken) {
      fetchTasks();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoFetch, effectiveAccessToken]);

  /**
   * Polling for task updates
   */
  useEffect(() => {
    if (pollingInterval <= 0 || !effectiveAccessToken) {
      return;
    }

    const interval = setInterval(() => {
      fetchTasks();
    }, pollingInterval);

    return () => clearInterval(interval);
  }, [pollingInterval, effectiveAccessToken, fetchTasks]);

  return {
    tasks,
    currentTask,
    hasBlockingTasks,
    pendingTaskCount,
    isLoading,
    isCompleting,
    error,
    fetchTasks,
    completeTask,
    skipTask,
    getTask,
    getTaskByType,
    clearError
  };
}

export default useSessionTasks;
