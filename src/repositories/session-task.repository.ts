/**
 * Session Task Repository - DynamoDB operations for session tasks
 * 
 * Table: zalt-sessions (shared with sessions)
 * PK: SESSION#{sessionId}#TASK#{taskId}
 * SK: TASK
 * GSI: session-task-index (session_id → tasks)
 * GSI: user-task-index (user_id → tasks)
 * 
 * Validates: Requirements 4.1 (Session Tasks)
 */

import {
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
  DeleteCommand,
  BatchWriteCommand,
  ScanCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from '../services/dynamodb.service';
import {
  SessionTask,
  CreateSessionTaskInput,
  SessionTaskStatus,
  getDefaultPriority,
  getDefaultBlocking
} from '../models/session-task.model';
import { randomBytes } from 'crypto';

// GSI names for session tasks
const SESSION_TASK_INDEX = 'session-task-index';
const USER_TASK_INDEX = 'user-task-index';

/**
 * Generate unique task ID
 */
function generateTaskId(): string {
  return `task_${randomBytes(12).toString('hex')}`;
}

/**
 * Create composite primary key for session task
 */
function createPK(sessionId: string, taskId: string): string {
  return `SESSION#${sessionId}#TASK#${taskId}`;
}

/**
 * Create a new session task
 */
export async function createSessionTask(input: CreateSessionTaskInput): Promise<SessionTask> {
  const taskId = generateTaskId();
  const now = new Date().toISOString();
  
  const task: SessionTask = {
    id: taskId,
    session_id: input.session_id,
    user_id: input.user_id,
    realm_id: input.realm_id,
    type: input.type,
    status: 'pending',
    metadata: input.metadata,
    created_at: now,
    priority: input.priority ?? getDefaultPriority(input.type),
    blocking: input.blocking ?? getDefaultBlocking(input.type),
    expires_at: input.expires_at
  };
  
  await dynamoDb.send(new PutCommand({
    TableName: TableNames.SESSIONS,
    Item: {
      pk: createPK(input.session_id, taskId),
      sk: 'TASK',
      ...task
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  }));
  
  return task;
}

/**
 * Get session task by ID
 */
export async function getSessionTaskById(
  sessionId: string,
  taskId: string
): Promise<SessionTask | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TableNames.SESSIONS,
    Key: {
      pk: createPK(sessionId, taskId),
      sk: 'TASK'
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  return itemToSessionTask(result.Item);
}

/**
 * Get all tasks for a session
 */
export async function getSessionTasks(sessionId: string): Promise<SessionTask[]> {
  // Use Scan with filter since pk contains composite key (sessionId + taskId)
  // The pk format is SESSION#{sessionId}#TASK#{taskId}
  // In production, consider adding a GSI on session_id for better performance
  const result = await dynamoDb.send(new ScanCommand({
    TableName: TableNames.SESSIONS,
    FilterExpression: 'session_id = :sessionId AND sk = :sk',
    ExpressionAttributeValues: {
      ':sessionId': sessionId,
      ':sk': 'TASK'
    }
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return [];
  }
  
  return result.Items.map(item => itemToSessionTask(item));
}

/**
 * Get pending tasks for a session
 */
export async function getPendingSessionTasks(sessionId: string): Promise<SessionTask[]> {
  const tasks = await getSessionTasks(sessionId);
  return tasks.filter(task => task.status === 'pending');
}

/**
 * Get pending blocking tasks for a session
 */
export async function getPendingBlockingTasks(sessionId: string): Promise<SessionTask[]> {
  const tasks = await getPendingSessionTasks(sessionId);
  return tasks.filter(task => task.blocking);
}

/**
 * Check if session has any blocking tasks
 */
export async function hasBlockingTasks(sessionId: string): Promise<boolean> {
  const blockingTasks = await getPendingBlockingTasks(sessionId);
  return blockingTasks.length > 0;
}

/**
 * Get all tasks for a user across all sessions
 */
export async function getUserTasks(
  realmId: string,
  userId: string,
  status?: SessionTaskStatus
): Promise<SessionTask[]> {
  // Use Scan with filter for user_id
  // In production, consider adding a GSI on user_id for better performance
  const filterExpression = status 
    ? 'user_id = :userId AND realm_id = :realmId AND #status = :status AND sk = :sk'
    : 'user_id = :userId AND realm_id = :realmId AND sk = :sk';
  
  const expressionAttributeValues: Record<string, unknown> = {
    ':userId': userId,
    ':realmId': realmId,
    ':sk': 'TASK'
  };
  
  if (status) {
    expressionAttributeValues[':status'] = status;
  }
  
  const result = await dynamoDb.send(new ScanCommand({
    TableName: TableNames.SESSIONS,
    FilterExpression: filterExpression,
    ExpressionAttributeNames: status ? { '#status': 'status' } : undefined,
    ExpressionAttributeValues: expressionAttributeValues
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return [];
  }
  
  return result.Items.map(item => itemToSessionTask(item));
}

/**
 * Complete a session task
 */
export async function completeSessionTask(
  sessionId: string,
  taskId: string
): Promise<SessionTask | null> {
  const now = new Date().toISOString();
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: createPK(sessionId, taskId),
        sk: 'TASK'
      },
      UpdateExpression: 'SET #status = :status, completed_at = :completedAt',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':status': 'completed' as SessionTaskStatus,
        ':completedAt': now,
        ':pending': 'pending'
      },
      ConditionExpression: 'attribute_exists(pk) AND #status = :pending',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToSessionTask(result.Attributes);
  } catch (error: unknown) {
    // Task doesn't exist or is not pending
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Skip a session task (for non-blocking tasks)
 */
export async function skipSessionTask(
  sessionId: string,
  taskId: string
): Promise<SessionTask | null> {
  const now = new Date().toISOString();
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: createPK(sessionId, taskId),
        sk: 'TASK'
      },
      UpdateExpression: 'SET #status = :status, completed_at = :completedAt',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':status': 'skipped' as SessionTaskStatus,
        ':completedAt': now,
        ':pending': 'pending',
        ':blocking': false
      },
      // Can only skip non-blocking pending tasks
      ConditionExpression: 'attribute_exists(pk) AND #status = :pending AND blocking = :blocking',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToSessionTask(result.Attributes);
  } catch (error: unknown) {
    // Task doesn't exist, is not pending, or is blocking
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Update task metadata
 */
export async function updateSessionTaskMetadata(
  sessionId: string,
  taskId: string,
  metadata: Record<string, unknown>
): Promise<SessionTask | null> {
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: createPK(sessionId, taskId),
        sk: 'TASK'
      },
      UpdateExpression: 'SET metadata = :metadata',
      ExpressionAttributeValues: {
        ':metadata': metadata
      },
      ConditionExpression: 'attribute_exists(pk)',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToSessionTask(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Delete a session task
 */
export async function deleteSessionTask(
  sessionId: string,
  taskId: string
): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: createPK(sessionId, taskId),
        sk: 'TASK'
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Delete all tasks for a session
 */
export async function deleteAllSessionTasks(sessionId: string): Promise<number> {
  const tasks = await getSessionTasks(sessionId);
  
  if (tasks.length === 0) {
    return 0;
  }
  
  // Batch delete (max 25 items per batch)
  const batches: SessionTask[][] = [];
  for (let i = 0; i < tasks.length; i += 25) {
    batches.push(tasks.slice(i, i + 25));
  }
  
  let deletedCount = 0;
  
  for (const batch of batches) {
    try {
      await dynamoDb.send(new BatchWriteCommand({
        RequestItems: {
          [TableNames.SESSIONS]: batch.map(task => ({
            DeleteRequest: {
              Key: {
                pk: createPK(sessionId, task.id),
                sk: 'TASK'
              }
            }
          }))
        }
      }));
      deletedCount += batch.length;
    } catch (error) {
      console.error('Failed to delete session tasks batch:', error);
    }
  }
  
  return deletedCount;
}

/**
 * Create multiple tasks for a session (batch create)
 */
export async function createSessionTasks(
  inputs: CreateSessionTaskInput[]
): Promise<SessionTask[]> {
  const tasks: SessionTask[] = [];
  const now = new Date().toISOString();
  
  for (const input of inputs) {
    const taskId = generateTaskId();
    const task: SessionTask = {
      id: taskId,
      session_id: input.session_id,
      user_id: input.user_id,
      realm_id: input.realm_id,
      type: input.type,
      status: 'pending',
      metadata: input.metadata,
      created_at: now,
      priority: input.priority ?? getDefaultPriority(input.type),
      blocking: input.blocking ?? getDefaultBlocking(input.type),
      expires_at: input.expires_at
    };
    tasks.push(task);
  }
  
  // Batch write (max 25 items per batch)
  const batches: SessionTask[][] = [];
  for (let i = 0; i < tasks.length; i += 25) {
    batches.push(tasks.slice(i, i + 25));
  }
  
  for (const batch of batches) {
    await dynamoDb.send(new BatchWriteCommand({
      RequestItems: {
        [TableNames.SESSIONS]: batch.map(task => ({
          PutRequest: {
            Item: {
              pk: createPK(task.session_id, task.id),
              sk: 'TASK',
              ...task
            }
          }
        }))
      }
    }));
  }
  
  return tasks;
}

/**
 * Get task by type for a session (useful for checking if task already exists)
 */
export async function getSessionTaskByType(
  sessionId: string,
  type: string
): Promise<SessionTask | null> {
  const tasks = await getSessionTasks(sessionId);
  return tasks.find(task => task.type === type && task.status === 'pending') || null;
}

/**
 * Count pending tasks for a session
 */
export async function countPendingTasks(sessionId: string): Promise<number> {
  const tasks = await getPendingSessionTasks(sessionId);
  return tasks.length;
}

/**
 * Count pending blocking tasks for a session
 */
export async function countPendingBlockingTasks(sessionId: string): Promise<number> {
  const tasks = await getPendingBlockingTasks(sessionId);
  return tasks.length;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert DynamoDB item to SessionTask
 */
function itemToSessionTask(item: Record<string, unknown>): SessionTask {
  return {
    id: item.id as string,
    session_id: item.session_id as string,
    user_id: item.user_id as string,
    realm_id: item.realm_id as string,
    type: item.type as SessionTask['type'],
    status: item.status as SessionTask['status'],
    metadata: item.metadata as SessionTask['metadata'],
    created_at: item.created_at as string,
    completed_at: item.completed_at as string | undefined,
    expires_at: item.expires_at as string | undefined,
    priority: item.priority as number,
    blocking: item.blocking as boolean
  };
}
