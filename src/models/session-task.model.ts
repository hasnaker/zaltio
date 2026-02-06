/**
 * Session Task Model - Post-Login Requirements for Zalt.io
 * 
 * Session Tasks are mandatory actions that users must complete after login
 * before they can access the application. Examples include:
 * - Choosing an organization (multi-org users)
 * - Setting up MFA (when required by policy)
 * - Resetting password (compromised or expired)
 * - Accepting terms of service
 * - Custom tasks via webhook
 * 
 * DynamoDB Schema:
 * - Table: zalt-sessions
 * - pk: SESSION#{sessionId}#TASK#{taskId}
 * - sk: TASK
 * 
 * Validates: Requirements 4.1 (Session Tasks)
 */

/**
 * Session task types
 */
export type SessionTaskType = 
  | 'choose_organization'  // User must select an organization
  | 'setup_mfa'            // User must set up MFA
  | 'reset_password'       // User must reset their password
  | 'accept_terms'         // User must accept terms of service
  | 'custom';              // Custom task type via webhook

/**
 * Session task status
 */
export type SessionTaskStatus = 'pending' | 'completed' | 'skipped';

/**
 * Session Task entity
 */
export interface SessionTask {
  id: string;                    // task_xxx format
  session_id: string;            // Associated session ID
  user_id: string;               // User who must complete the task
  realm_id: string;              // Realm context
  type: SessionTaskType;         // Type of task
  status: SessionTaskStatus;     // Current status
  metadata?: SessionTaskMetadata; // Task-specific metadata
  created_at: string;            // When task was created
  completed_at?: string;         // When task was completed
  expires_at?: string;           // Optional expiration
  priority: number;              // Task priority (lower = higher priority)
  blocking: boolean;             // Whether task blocks API access
}

/**
 * Task-specific metadata types
 */
export interface SessionTaskMetadata {
  // For choose_organization
  available_organizations?: Array<{
    id: string;
    name: string;
    role?: string;
  }>;
  
  // For setup_mfa
  required_mfa_methods?: string[];
  mfa_policy_id?: string;
  
  // For reset_password
  reason?: 'compromised' | 'expired' | 'admin_forced' | 'policy';
  compromised_at?: string;
  
  // For accept_terms
  terms_version?: string;
  terms_url?: string;
  
  // For custom tasks
  custom_type?: string;
  webhook_url?: string;
  custom_data?: Record<string, unknown>;
  
  // Common fields
  message?: string;
  instructions?: string;
}

/**
 * Input for creating a session task
 */
export interface CreateSessionTaskInput {
  session_id: string;
  user_id: string;
  realm_id: string;
  type: SessionTaskType;
  metadata?: SessionTaskMetadata;
  priority?: number;
  blocking?: boolean;
  expires_at?: string;
}

/**
 * Session task response (API response format)
 */
export interface SessionTaskResponse {
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
 * Default task priorities (lower = higher priority)
 */
export const DEFAULT_TASK_PRIORITIES: Record<SessionTaskType, number> = {
  reset_password: 1,      // Highest priority - security critical
  setup_mfa: 2,           // High priority - security requirement
  accept_terms: 3,        // Medium priority - legal requirement
  choose_organization: 4, // Lower priority - user preference
  custom: 5               // Lowest priority - custom tasks
};

/**
 * Default blocking behavior per task type
 */
export const DEFAULT_TASK_BLOCKING: Record<SessionTaskType, boolean> = {
  reset_password: true,      // Must reset password before continuing
  setup_mfa: true,           // Must setup MFA before continuing
  accept_terms: true,        // Must accept terms before continuing
  choose_organization: true, // Must choose org before continuing
  custom: false              // Custom tasks are non-blocking by default
};

/**
 * Validate session task type
 */
export function isValidTaskType(type: string): type is SessionTaskType {
  return ['choose_organization', 'setup_mfa', 'reset_password', 'accept_terms', 'custom'].includes(type);
}

/**
 * Validate session task status
 */
export function isValidTaskStatus(status: string): status is SessionTaskStatus {
  return ['pending', 'completed', 'skipped'].includes(status);
}

/**
 * Get default priority for a task type
 */
export function getDefaultPriority(type: SessionTaskType): number {
  return DEFAULT_TASK_PRIORITIES[type] ?? 5;
}

/**
 * Get default blocking behavior for a task type
 */
export function getDefaultBlocking(type: SessionTaskType): boolean {
  return DEFAULT_TASK_BLOCKING[type] ?? false;
}

/**
 * Check if a task is expired
 */
export function isTaskExpired(task: SessionTask): boolean {
  if (!task.expires_at) {
    return false;
  }
  return new Date(task.expires_at) < new Date();
}

/**
 * Check if a task is blocking
 */
export function isTaskBlocking(task: SessionTask): boolean {
  // Completed or skipped tasks don't block
  if (task.status !== 'pending') {
    return false;
  }
  
  // Expired tasks don't block
  if (isTaskExpired(task)) {
    return false;
  }
  
  return task.blocking;
}

/**
 * Sort tasks by priority (lower priority number = higher priority)
 */
export function sortTasksByPriority(tasks: SessionTask[]): SessionTask[] {
  return [...tasks].sort((a, b) => a.priority - b.priority);
}

/**
 * Filter pending blocking tasks
 */
export function getPendingBlockingTasks(tasks: SessionTask[]): SessionTask[] {
  return tasks.filter(task => isTaskBlocking(task));
}

/**
 * Convert SessionTask to API response format
 */
export function toSessionTaskResponse(task: SessionTask): SessionTaskResponse {
  return {
    id: task.id,
    session_id: task.session_id,
    type: task.type,
    status: task.status,
    metadata: task.metadata,
    created_at: task.created_at,
    completed_at: task.completed_at,
    priority: task.priority,
    blocking: task.blocking
  };
}
