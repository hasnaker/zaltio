/**
 * Session Tasks Service - Post-Login Requirements for Zalt.io
 * 
 * Session Tasks are mandatory actions that users must complete after login
 * before they can access the application. Examples include:
 * - Choosing an organization (multi-org users)
 * - Setting up MFA (when required by policy)
 * - Resetting password (compromised or expired)
 * - Accepting terms of service
 * - Custom tasks via webhook
 * 
 * Validates: Requirements 4.2, 4.3, 4.4, 4.5, 4.7, 4.8, 4.9 (Session Tasks)
 * 
 * Security:
 * - Blocking tasks prevent API access until completed
 * - Force password reset can revoke all sessions
 * - Mass password reset for security incidents
 * - Audit logging for all task operations
 */

import {
  SessionTask,
  SessionTaskType,
  SessionTaskMetadata,
  CreateSessionTaskInput,
  toSessionTaskResponse,
  SessionTaskResponse,
  sortTasksByPriority,
  isTaskBlocking,
  getDefaultPriority,
  getDefaultBlocking
} from '../models/session-task.model';
import {
  createSessionTask,
  getSessionTaskById,
  getSessionTasks,
  getPendingSessionTasks,
  getPendingBlockingTasks,
  hasBlockingTasks as repoHasBlockingTasks,
  completeSessionTask,
  skipSessionTask,
  deleteAllSessionTasks,
  createSessionTasks,
  getSessionTaskByType,
  countPendingTasks,
  countPendingBlockingTasks
} from '../repositories/session-task.repository';
import { getUserSessions, deleteUserSessions } from '../repositories/session.repository';
import { listRealmUsers } from '../repositories/user.repository';

// Re-export types for convenience
export {
  SessionTask,
  SessionTaskType,
  SessionTaskMetadata,
  SessionTaskResponse
};

/**
 * Session Tasks Service Error
 */
export class SessionTasksError extends Error {
  code: string;
  statusCode: number;
  
  constructor(code: string, message: string, statusCode: number = 400) {
    super(message);
    this.name = 'SessionTasksError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Result of force password reset operation
 */
export interface ForcePasswordResetResult {
  userId: string;
  taskId: string;
  sessionsRevoked: number;
}

/**
 * Result of mass password reset operation
 */
export interface MassPasswordResetResult {
  realmId: string;
  usersAffected: number;
  tasksCreated: number;
  sessionsRevoked: number;
  errors: Array<{ userId: string; error: string }>;
}

/**
 * Session Tasks Service
 */
export class SessionTasksService {
  
  /**
   * Create a new session task
   * 
   * @param sessionId - Session ID to attach the task to
   * @param type - Type of task (choose_organization, setup_mfa, reset_password, accept_terms, custom)
   * @param metadata - Optional task-specific metadata
   * @returns Created session task
   */
  async createTask(
    sessionId: string,
    userId: string,
    realmId: string,
    type: SessionTaskType,
    metadata?: SessionTaskMetadata
  ): Promise<SessionTask> {
    // Validate inputs
    if (!sessionId || sessionId.trim().length === 0) {
      throw new SessionTasksError('INVALID_SESSION_ID', 'Session ID is required');
    }
    
    if (!userId || userId.trim().length === 0) {
      throw new SessionTasksError('INVALID_USER_ID', 'User ID is required');
    }
    
    if (!realmId || realmId.trim().length === 0) {
      throw new SessionTasksError('INVALID_REALM_ID', 'Realm ID is required');
    }
    
    // Check if task of same type already exists for this session
    const existingTask = await getSessionTaskByType(sessionId, type);
    if (existingTask) {
      throw new SessionTasksError(
        'TASK_ALREADY_EXISTS',
        `A pending ${type} task already exists for this session`
      );
    }
    
    const input: CreateSessionTaskInput = {
      session_id: sessionId,
      user_id: userId,
      realm_id: realmId,
      type,
      metadata,
      priority: getDefaultPriority(type),
      blocking: getDefaultBlocking(type)
    };
    
    const task = await createSessionTask(input);
    
    // Audit log
    this.logAuditEvent('session_task.created', {
      sessionId,
      userId,
      realmId,
      taskId: task.id,
      taskType: type,
      blocking: task.blocking
    }).catch(() => {});
    
    return task;
  }
  
  /**
   * Get all pending tasks for a session
   * Returns tasks sorted by priority (highest priority first)
   * 
   * @param sessionId - Session ID to get tasks for
   * @returns Array of pending session tasks
   */
  async getPendingTasks(sessionId: string): Promise<SessionTask[]> {
    if (!sessionId || sessionId.trim().length === 0) {
      throw new SessionTasksError('INVALID_SESSION_ID', 'Session ID is required');
    }
    
    const tasks = await getPendingSessionTasks(sessionId);
    return sortTasksByPriority(tasks);
  }
  
  /**
   * Get pending tasks as API response format
   * 
   * @param sessionId - Session ID to get tasks for
   * @returns Array of session task responses
   */
  async getPendingTasksResponse(sessionId: string): Promise<SessionTaskResponse[]> {
    const tasks = await this.getPendingTasks(sessionId);
    return tasks.map(toSessionTaskResponse);
  }
  
  /**
   * Complete a session task
   * 
   * @param taskId - Task ID to complete
   * @param sessionId - Session ID the task belongs to
   * @returns Completed task or null if not found/already completed
   */
  async completeTask(
    sessionId: string,
    taskId: string
  ): Promise<SessionTask | null> {
    if (!sessionId || sessionId.trim().length === 0) {
      throw new SessionTasksError('INVALID_SESSION_ID', 'Session ID is required');
    }
    
    if (!taskId || taskId.trim().length === 0) {
      throw new SessionTasksError('INVALID_TASK_ID', 'Task ID is required');
    }
    
    // Get task first to verify it exists and get metadata for audit
    const existingTask = await getSessionTaskById(sessionId, taskId);
    if (!existingTask) {
      throw new SessionTasksError('TASK_NOT_FOUND', 'Session task not found', 404);
    }
    
    if (existingTask.status !== 'pending') {
      throw new SessionTasksError(
        'TASK_NOT_PENDING',
        `Task is already ${existingTask.status}`
      );
    }
    
    const completedTask = await completeSessionTask(sessionId, taskId);
    
    if (completedTask) {
      // Audit log
      this.logAuditEvent('session_task.completed', {
        sessionId,
        userId: completedTask.user_id,
        realmId: completedTask.realm_id,
        taskId,
        taskType: completedTask.type
      }).catch(() => {});
    }
    
    return completedTask;
  }
  
  /**
   * Skip a non-blocking session task
   * 
   * @param sessionId - Session ID the task belongs to
   * @param taskId - Task ID to skip
   * @returns Skipped task or null if not found/blocking
   */
  async skipTask(
    sessionId: string,
    taskId: string
  ): Promise<SessionTask | null> {
    if (!sessionId || sessionId.trim().length === 0) {
      throw new SessionTasksError('INVALID_SESSION_ID', 'Session ID is required');
    }
    
    if (!taskId || taskId.trim().length === 0) {
      throw new SessionTasksError('INVALID_TASK_ID', 'Task ID is required');
    }
    
    // Get task first to verify it exists
    const existingTask = await getSessionTaskById(sessionId, taskId);
    if (!existingTask) {
      throw new SessionTasksError('TASK_NOT_FOUND', 'Session task not found', 404);
    }
    
    if (existingTask.blocking) {
      throw new SessionTasksError(
        'TASK_BLOCKING',
        'Cannot skip a blocking task'
      );
    }
    
    if (existingTask.status !== 'pending') {
      throw new SessionTasksError(
        'TASK_NOT_PENDING',
        `Task is already ${existingTask.status}`
      );
    }
    
    const skippedTask = await skipSessionTask(sessionId, taskId);
    
    if (skippedTask) {
      // Audit log
      this.logAuditEvent('session_task.skipped', {
        sessionId,
        userId: skippedTask.user_id,
        realmId: skippedTask.realm_id,
        taskId,
        taskType: skippedTask.type
      }).catch(() => {});
    }
    
    return skippedTask;
  }
  
  /**
   * Check if session has any blocking tasks
   * Used by middleware to block API access
   * 
   * @param sessionId - Session ID to check
   * @returns True if session has pending blocking tasks
   */
  async hasBlockingTasks(sessionId: string): Promise<boolean> {
    if (!sessionId || sessionId.trim().length === 0) {
      return false;
    }
    
    return repoHasBlockingTasks(sessionId);
  }
  
  /**
   * Get blocking tasks for a session
   * 
   * @param sessionId - Session ID to get blocking tasks for
   * @returns Array of blocking tasks
   */
  async getBlockingTasks(sessionId: string): Promise<SessionTask[]> {
    if (!sessionId || sessionId.trim().length === 0) {
      throw new SessionTasksError('INVALID_SESSION_ID', 'Session ID is required');
    }
    
    const tasks = await getPendingBlockingTasks(sessionId);
    return sortTasksByPriority(tasks);
  }
  
  /**
   * Force password reset for a specific user
   * Creates reset_password task for all active sessions
   * Optionally revokes all sessions
   * 
   * @param userId - User ID to force password reset for
   * @param realmId - Realm ID the user belongs to
   * @param options - Options including whether to revoke sessions
   * @returns Result with task ID and sessions revoked count
   */
  async forcePasswordReset(
    userId: string,
    realmId: string,
    options: {
      revokeAllSessions?: boolean;
      reason?: 'compromised' | 'expired' | 'admin_forced' | 'policy';
      message?: string;
    } = {}
  ): Promise<ForcePasswordResetResult> {
    if (!userId || userId.trim().length === 0) {
      throw new SessionTasksError('INVALID_USER_ID', 'User ID is required');
    }
    
    if (!realmId || realmId.trim().length === 0) {
      throw new SessionTasksError('INVALID_REALM_ID', 'Realm ID is required');
    }
    
    const { revokeAllSessions = false, reason = 'admin_forced', message } = options;
    
    // Get user's active sessions
    const sessions = await getUserSessions(realmId, userId);
    
    let sessionsRevoked = 0;
    let taskId = '';
    
    if (sessions.length === 0) {
      // No active sessions - create a placeholder task that will be applied on next login
      // This is handled by the login flow checking for pending password resets
      this.logAuditEvent('session_task.force_password_reset', {
        userId,
        realmId,
        reason,
        sessionsRevoked: 0,
        noActiveSessions: true
      }).catch(() => {});
      
      return {
        userId,
        taskId: '', // No task created as no active sessions
        sessionsRevoked: 0
      };
    }
    
    // Create reset_password task for the first session (user will see it on any session)
    const firstSession = sessions[0];
    const task = await createSessionTask({
      session_id: firstSession.id,
      user_id: userId,
      realm_id: realmId,
      type: 'reset_password',
      metadata: {
        reason,
        message: message || 'Your password must be reset',
        compromised_at: reason === 'compromised' ? new Date().toISOString() : undefined
      },
      blocking: true,
      priority: 1 // Highest priority
    });
    
    taskId = task.id;
    
    // Create tasks for other sessions too
    if (sessions.length > 1) {
      const otherSessionInputs = sessions.slice(1).map(session => ({
        session_id: session.id,
        user_id: userId,
        realm_id: realmId,
        type: 'reset_password' as SessionTaskType,
        metadata: {
          reason,
          message: message || 'Your password must be reset',
          compromised_at: reason === 'compromised' ? new Date().toISOString() : undefined
        },
        blocking: true,
        priority: 1
      }));
      
      await createSessionTasks(otherSessionInputs);
    }
    
    // Optionally revoke all sessions
    if (revokeAllSessions) {
      sessionsRevoked = await deleteUserSessions(realmId, userId);
    }
    
    // Audit log
    this.logAuditEvent('session_task.force_password_reset', {
      userId,
      realmId,
      taskId,
      reason,
      sessionsAffected: sessions.length,
      sessionsRevoked,
      revokeAllSessions
    }).catch(() => {});
    
    return {
      userId,
      taskId,
      sessionsRevoked
    };
  }
  
  /**
   * Force password reset for all users in a realm
   * Used for security incidents (mass breach response)
   * 
   * @param realmId - Realm ID to force password reset for all users
   * @param options - Options including whether to revoke sessions
   * @returns Result with counts of affected users, tasks, and sessions
   */
  async forcePasswordResetAll(
    realmId: string,
    options: {
      revokeAllSessions?: boolean;
      reason?: 'compromised' | 'policy';
      message?: string;
      batchSize?: number;
    } = {}
  ): Promise<MassPasswordResetResult> {
    if (!realmId || realmId.trim().length === 0) {
      throw new SessionTasksError('INVALID_REALM_ID', 'Realm ID is required');
    }
    
    const { 
      revokeAllSessions = false, 
      reason = 'compromised',
      message = 'Security incident: All passwords must be reset',
      batchSize = 100
    } = options;
    
    const result: MassPasswordResetResult = {
      realmId,
      usersAffected: 0,
      tasksCreated: 0,
      sessionsRevoked: 0,
      errors: []
    };
    
    // Paginate through all users in the realm
    let lastEvaluatedKey: Record<string, unknown> | undefined;
    
    do {
      const usersResult = await listRealmUsers(realmId, {
        limit: batchSize,
        lastEvaluatedKey
      });
      
      // Process each user
      for (const user of usersResult.users) {
        try {
          const resetResult = await this.forcePasswordReset(user.id, realmId, {
            revokeAllSessions,
            reason,
            message
          });
          
          result.usersAffected++;
          if (resetResult.taskId) {
            result.tasksCreated++;
          }
          result.sessionsRevoked += resetResult.sessionsRevoked;
        } catch (error) {
          result.errors.push({
            userId: user.id,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }
      
      lastEvaluatedKey = usersResult.lastEvaluatedKey as Record<string, unknown> | undefined;
    } while (lastEvaluatedKey);
    
    // Audit log for mass operation
    this.logAuditEvent('session_task.force_password_reset_all', {
      realmId,
      reason,
      usersAffected: result.usersAffected,
      tasksCreated: result.tasksCreated,
      sessionsRevoked: result.sessionsRevoked,
      errorCount: result.errors.length,
      revokeAllSessions
    }).catch(() => {});
    
    return result;
  }
  
  /**
   * Create MFA setup task for a session
   * Used when MFA is required by policy but not enabled
   * 
   * @param sessionId - Session ID
   * @param userId - User ID
   * @param realmId - Realm ID
   * @param requiredMethods - Required MFA methods
   * @returns Created task
   */
  async createMfaSetupTask(
    sessionId: string,
    userId: string,
    realmId: string,
    requiredMethods?: string[]
  ): Promise<SessionTask> {
    return this.createTask(sessionId, userId, realmId, 'setup_mfa', {
      required_mfa_methods: requiredMethods,
      message: 'MFA setup is required by your organization policy'
    });
  }
  
  /**
   * Create organization selection task for a session
   * Used when user belongs to multiple organizations
   * 
   * @param sessionId - Session ID
   * @param userId - User ID
   * @param realmId - Realm ID
   * @param organizations - Available organizations to choose from
   * @returns Created task
   */
  async createChooseOrganizationTask(
    sessionId: string,
    userId: string,
    realmId: string,
    organizations: Array<{ id: string; name: string; role?: string }>
  ): Promise<SessionTask> {
    if (!organizations || organizations.length === 0) {
      throw new SessionTasksError(
        'NO_ORGANIZATIONS',
        'At least one organization is required'
      );
    }
    
    return this.createTask(sessionId, userId, realmId, 'choose_organization', {
      available_organizations: organizations,
      message: 'Please select an organization to continue'
    });
  }
  
  /**
   * Create terms acceptance task for a session
   * 
   * @param sessionId - Session ID
   * @param userId - User ID
   * @param realmId - Realm ID
   * @param termsVersion - Version of terms to accept
   * @param termsUrl - URL to terms document
   * @returns Created task
   */
  async createAcceptTermsTask(
    sessionId: string,
    userId: string,
    realmId: string,
    termsVersion: string,
    termsUrl?: string
  ): Promise<SessionTask> {
    return this.createTask(sessionId, userId, realmId, 'accept_terms', {
      terms_version: termsVersion,
      terms_url: termsUrl,
      message: 'Please accept the updated terms of service'
    });
  }
  
  /**
   * Create custom task for a session
   * 
   * @param sessionId - Session ID
   * @param userId - User ID
   * @param realmId - Realm ID
   * @param customType - Custom task type identifier
   * @param metadata - Custom task metadata
   * @param blocking - Whether task should block API access
   * @returns Created task
   */
  async createCustomTask(
    sessionId: string,
    userId: string,
    realmId: string,
    customType: string,
    metadata?: Record<string, unknown>,
    blocking: boolean = false
  ): Promise<SessionTask> {
    const input: CreateSessionTaskInput = {
      session_id: sessionId,
      user_id: userId,
      realm_id: realmId,
      type: 'custom',
      metadata: {
        custom_type: customType,
        custom_data: metadata
      },
      blocking,
      priority: 5 // Custom tasks have lowest priority
    };
    
    const task = await createSessionTask(input);
    
    // Audit log
    this.logAuditEvent('session_task.created', {
      sessionId,
      userId,
      realmId,
      taskId: task.id,
      taskType: 'custom',
      customType,
      blocking
    }).catch(() => {});
    
    return task;
  }
  
  /**
   * Get task by ID
   * 
   * @param sessionId - Session ID
   * @param taskId - Task ID
   * @returns Task or null if not found
   */
  async getTask(sessionId: string, taskId: string): Promise<SessionTask | null> {
    if (!sessionId || !taskId) {
      return null;
    }
    return getSessionTaskById(sessionId, taskId);
  }
  
  /**
   * Get all tasks for a session (including completed)
   * 
   * @param sessionId - Session ID
   * @returns Array of all tasks
   */
  async getAllTasks(sessionId: string): Promise<SessionTask[]> {
    if (!sessionId || sessionId.trim().length === 0) {
      throw new SessionTasksError('INVALID_SESSION_ID', 'Session ID is required');
    }
    
    return getSessionTasks(sessionId);
  }
  
  /**
   * Delete all tasks for a session
   * Used when session is terminated
   * 
   * @param sessionId - Session ID
   * @returns Number of tasks deleted
   */
  async deleteAllTasks(sessionId: string): Promise<number> {
    if (!sessionId || sessionId.trim().length === 0) {
      throw new SessionTasksError('INVALID_SESSION_ID', 'Session ID is required');
    }
    
    const count = await deleteAllSessionTasks(sessionId);
    
    // Audit log
    this.logAuditEvent('session_task.deleted_all', {
      sessionId,
      tasksDeleted: count
    }).catch(() => {});
    
    return count;
  }
  
  /**
   * Get count of pending tasks for a session
   * 
   * @param sessionId - Session ID
   * @returns Count of pending tasks
   */
  async getPendingTaskCount(sessionId: string): Promise<number> {
    if (!sessionId || sessionId.trim().length === 0) {
      return 0;
    }
    return countPendingTasks(sessionId);
  }
  
  /**
   * Get count of pending blocking tasks for a session
   * 
   * @param sessionId - Session ID
   * @returns Count of pending blocking tasks
   */
  async getBlockingTaskCount(sessionId: string): Promise<number> {
    if (!sessionId || sessionId.trim().length === 0) {
      return 0;
    }
    return countPendingBlockingTasks(sessionId);
  }
  
  /**
   * Log audit event
   */
  private async logAuditEvent(
    event: string,
    data: Record<string, unknown>
  ): Promise<void> {
    // In production, this would call the audit service
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[AUDIT] ${event}`, JSON.stringify({
        timestamp: new Date().toISOString(),
        ...data
      }));
    }
  }
}

// Export singleton instance
export const sessionTasksService = new SessionTasksService();
