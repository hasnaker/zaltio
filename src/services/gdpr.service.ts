/**
 * GDPR Compliance Service for HSD Auth Platform
 * Validates: Requirements 8.5
 * 
 * Implements GDPR requirements for data retention and deletion:
 * - User data deletion functionality
 * - Data retention policies
 * - Audit trail for data operations
 */

import * as crypto from 'crypto';

// Use crypto.randomUUID() instead of uuid package for ESM compatibility
const uuidv4 = () => crypto.randomUUID();
import {
  PutCommand,
  QueryCommand,
  DeleteCommand,
  GetCommand,
  ScanCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from './dynamodb.service';

/**
 * Data deletion request status
 */
export type DeletionRequestStatus = 
  | 'pending'
  | 'in_progress'
  | 'completed'
  | 'failed'
  | 'cancelled';

/**
 * Data operation types for audit trail
 */
export type DataOperationType =
  | 'CREATE'
  | 'READ'
  | 'UPDATE'
  | 'DELETE'
  | 'EXPORT'
  | 'DELETION_REQUEST'
  | 'DELETION_COMPLETED'
  | 'RETENTION_CLEANUP';

/**
 * Data deletion request
 */
export interface DeletionRequest {
  id: string;
  user_id: string;
  realm_id: string;
  email: string;
  status: DeletionRequestStatus;
  requested_at: string;
  completed_at?: string;
  deleted_data: DeletedDataSummary;
  error_message?: string;
}

/**
 * Summary of deleted data
 */
export interface DeletedDataSummary {
  user_record: boolean;
  sessions_count: number;
  audit_logs_count: number;
  total_records: number;
}

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  id: string;
  timestamp: string;
  operation: DataOperationType;
  realm_id: string;
  user_id?: string;
  actor_id?: string;
  resource_type: string;
  resource_id: string;
  details: Record<string, unknown>;
  ip_address?: string;
  user_agent?: string;
}

/**
 * Data retention policy
 */
export interface RetentionPolicy {
  realm_id: string;
  user_data_retention_days: number;
  session_retention_days: number;
  audit_log_retention_days: number;
  inactive_account_retention_days: number;
  deletion_request_retention_days: number;
}

/**
 * Default retention policy (GDPR compliant)
 */
export const DEFAULT_RETENTION_POLICY: Omit<RetentionPolicy, 'realm_id'> = {
  user_data_retention_days: 365 * 3, // 3 years
  session_retention_days: 30,
  audit_log_retention_days: 365 * 7, // 7 years for compliance
  inactive_account_retention_days: 365 * 2, // 2 years
  deletion_request_retention_days: 365 * 3 // 3 years for proof of deletion
};

/**
 * Create an audit log entry
 * Validates: Requirements 8.5 (audit trail for data operations)
 */
export async function createAuditLog(
  entry: Omit<AuditLogEntry, 'id' | 'timestamp'>
): Promise<AuditLogEntry> {
  const auditEntry: AuditLogEntry = {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    ...entry
  };

  const command = new PutCommand({
    TableName: TableNames.SESSIONS, // Using sessions table with different SK pattern
    Item: {
      pk: `AUDIT#${entry.realm_id}`,
      sk: `LOG#${auditEntry.timestamp}#${auditEntry.id}`,
      ...auditEntry,
      ttl: calculateTTL(DEFAULT_RETENTION_POLICY.audit_log_retention_days)
    }
  });

  await dynamoDb.send(command);
  return auditEntry;
}

/**
 * Get audit logs for a user
 */
export async function getAuditLogsForUser(
  realmId: string,
  userId: string,
  limit: number = 100
): Promise<AuditLogEntry[]> {
  const command = new QueryCommand({
    TableName: TableNames.SESSIONS,
    KeyConditionExpression: 'pk = :pk',
    FilterExpression: 'user_id = :userId',
    ExpressionAttributeValues: {
      ':pk': `AUDIT#${realmId}`,
      ':userId': userId
    },
    Limit: limit,
    ScanIndexForward: false // Most recent first
  });

  const result = await dynamoDb.send(command);
  return (result.Items || []) as AuditLogEntry[];
}

/**
 * Create a data deletion request
 * Validates: Requirements 8.5 (user data deletion functionality)
 */
export async function createDeletionRequest(
  realmId: string,
  userId: string,
  email: string,
  actorId?: string,
  ipAddress?: string
): Promise<DeletionRequest> {
  const request: DeletionRequest = {
    id: uuidv4(),
    user_id: userId,
    realm_id: realmId,
    email,
    status: 'pending',
    requested_at: new Date().toISOString(),
    deleted_data: {
      user_record: false,
      sessions_count: 0,
      audit_logs_count: 0,
      total_records: 0
    }
  };

  const command = new PutCommand({
    TableName: TableNames.USERS,
    Item: {
      pk: `DELETION#${realmId}`,
      sk: `REQUEST#${request.id}`,
      ...request,
      ttl: calculateTTL(DEFAULT_RETENTION_POLICY.deletion_request_retention_days)
    }
  });

  await dynamoDb.send(command);

  // Create audit log for deletion request
  await createAuditLog({
    operation: 'DELETION_REQUEST',
    realm_id: realmId,
    user_id: userId,
    actor_id: actorId || userId,
    resource_type: 'user',
    resource_id: userId,
    details: {
      email,
      request_id: request.id
    },
    ip_address: ipAddress
  });

  return request;
}

/**
 * Get deletion request by ID
 */
export async function getDeletionRequest(
  realmId: string,
  requestId: string
): Promise<DeletionRequest | null> {
  const command = new GetCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: `DELETION#${realmId}`,
      sk: `REQUEST#${requestId}`
    }
  });

  const result = await dynamoDb.send(command);
  return result.Item as DeletionRequest | null;
}

/**
 * Update deletion request status
 */
export async function updateDeletionRequestStatus(
  realmId: string,
  requestId: string,
  status: DeletionRequestStatus,
  deletedData?: Partial<DeletedDataSummary>,
  errorMessage?: string
): Promise<void> {
  const existingRequest = await getDeletionRequest(realmId, requestId);
  if (!existingRequest) {
    throw new Error(`Deletion request ${requestId} not found`);
  }

  const updatedRequest: DeletionRequest = {
    ...existingRequest,
    status,
    deleted_data: {
      ...existingRequest.deleted_data,
      ...deletedData
    },
    ...(status === 'completed' || status === 'failed' 
      ? { completed_at: new Date().toISOString() } 
      : {}),
    ...(errorMessage ? { error_message: errorMessage } : {})
  };

  const command = new PutCommand({
    TableName: TableNames.USERS,
    Item: {
      pk: `DELETION#${realmId}`,
      sk: `REQUEST#${requestId}`,
      ...updatedRequest,
      ttl: calculateTTL(DEFAULT_RETENTION_POLICY.deletion_request_retention_days)
    }
  });

  await dynamoDb.send(command);
}

/**
 * Execute user data deletion
 * Validates: Requirements 8.5 (permanent removal of personal information)
 */
export async function executeUserDeletion(
  realmId: string,
  userId: string,
  requestId: string
): Promise<DeletedDataSummary> {
  const summary: DeletedDataSummary = {
    user_record: false,
    sessions_count: 0,
    audit_logs_count: 0,
    total_records: 0
  };

  try {
    // Update status to in_progress
    await updateDeletionRequestStatus(realmId, requestId, 'in_progress');

    // 1. Delete all user sessions
    const sessionsDeleted = await deleteUserSessions(realmId, userId);
    summary.sessions_count = sessionsDeleted;
    summary.total_records += sessionsDeleted;

    // 2. Delete user record
    const userDeleted = await deleteUserRecord(realmId, userId);
    summary.user_record = userDeleted;
    if (userDeleted) {
      summary.total_records += 1;
    }

    // 3. Anonymize audit logs (keep for compliance but remove PII)
    const logsAnonymized = await anonymizeUserAuditLogs(realmId, userId);
    summary.audit_logs_count = logsAnonymized;

    // Update status to completed
    await updateDeletionRequestStatus(realmId, requestId, 'completed', summary);

    // Create completion audit log
    await createAuditLog({
      operation: 'DELETION_COMPLETED',
      realm_id: realmId,
      user_id: '[DELETED]',
      resource_type: 'user',
      resource_id: userId,
      details: {
        request_id: requestId,
        deleted_summary: summary
      }
    });

    return summary;
  } catch (error) {
    await updateDeletionRequestStatus(
      realmId,
      requestId,
      'failed',
      summary,
      (error as Error).message
    );
    throw error;
  }
}

/**
 * Delete all sessions for a user
 */
async function deleteUserSessions(
  realmId: string,
  userId: string
): Promise<number> {
  const queryCommand = new QueryCommand({
    TableName: TableNames.SESSIONS,
    IndexName: 'user-index',
    KeyConditionExpression: 'user_id = :userId',
    FilterExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':userId': userId,
      ':realmId': realmId
    }
  });

  const result = await dynamoDb.send(queryCommand);
  let deletedCount = 0;

  if (result.Items) {
    for (const item of result.Items) {
      const deleteCommand = new DeleteCommand({
        TableName: TableNames.SESSIONS,
        Key: {
          pk: item.pk,
          sk: item.sk
        }
      });

      try {
        await dynamoDb.send(deleteCommand);
        deletedCount++;
      } catch {
        console.error(`Failed to delete session ${item.pk}`);
      }
    }
  }

  return deletedCount;
}

/**
 * Delete user record
 */
async function deleteUserRecord(
  realmId: string,
  userId: string
): Promise<boolean> {
  const deleteCommand = new DeleteCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: `${realmId}#${userId}`,
      sk: `USER#${userId}`
    }
  });

  try {
    await dynamoDb.send(deleteCommand);
    return true;
  } catch {
    return false;
  }
}

/**
 * Anonymize user audit logs (keep structure but remove PII)
 */
async function anonymizeUserAuditLogs(
  realmId: string,
  userId: string
): Promise<number> {
  const logs = await getAuditLogsForUser(realmId, userId, 1000);
  let anonymizedCount = 0;

  for (const log of logs) {
    const anonymizedLog = {
      ...log,
      user_id: '[DELETED]',
      details: {
        ...log.details,
        email: '[DELETED]',
        ip_address: '[DELETED]'
      }
    };

    const command = new PutCommand({
      TableName: TableNames.SESSIONS,
      Item: {
        pk: `AUDIT#${realmId}`,
        sk: `LOG#${log.timestamp}#${log.id}`,
        ...anonymizedLog
      }
    });

    try {
      await dynamoDb.send(command);
      anonymizedCount++;
    } catch {
      console.error(`Failed to anonymize audit log ${log.id}`);
    }
  }

  return anonymizedCount;
}

/**
 * Get retention policy for a realm
 */
export async function getRetentionPolicy(
  realmId: string
): Promise<RetentionPolicy> {
  const command = new GetCommand({
    TableName: TableNames.REALMS,
    Key: {
      pk: realmId,
      sk: 'RETENTION_POLICY'
    }
  });

  const result = await dynamoDb.send(command);
  
  if (result.Item) {
    return result.Item as RetentionPolicy;
  }

  return {
    realm_id: realmId,
    ...DEFAULT_RETENTION_POLICY
  };
}

/**
 * Set retention policy for a realm
 */
export async function setRetentionPolicy(
  policy: RetentionPolicy
): Promise<void> {
  const command = new PutCommand({
    TableName: TableNames.REALMS,
    Item: {
      pk: policy.realm_id,
      sk: 'RETENTION_POLICY',
      ...policy
    }
  });

  await dynamoDb.send(command);

  await createAuditLog({
    operation: 'UPDATE',
    realm_id: policy.realm_id,
    resource_type: 'retention_policy',
    resource_id: policy.realm_id,
    details: { policy }
  });
}

/**
 * Execute retention cleanup for expired data
 * Validates: Requirements 8.5 (data retention policies)
 */
export async function executeRetentionCleanup(
  realmId: string
): Promise<{ sessionsDeleted: number; inactiveAccountsDeleted: number }> {
  const policy = await getRetentionPolicy(realmId);
  const now = new Date();
  
  let sessionsDeleted = 0;
  let inactiveAccountsDeleted = 0;

  // Clean up expired sessions
  const sessionCutoff = new Date(
    now.getTime() - policy.session_retention_days * 24 * 60 * 60 * 1000
  ).toISOString();

  const sessionQuery = new QueryCommand({
    TableName: TableNames.SESSIONS,
    IndexName: 'realm-index',
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: 'created_at < :cutoff',
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':cutoff': sessionCutoff
    }
  });

  const sessionResult = await dynamoDb.send(sessionQuery);
  
  if (sessionResult.Items) {
    for (const item of sessionResult.Items) {
      const deleteCommand = new DeleteCommand({
        TableName: TableNames.SESSIONS,
        Key: {
          pk: item.pk,
          sk: item.sk
        }
      });

      try {
        await dynamoDb.send(deleteCommand);
        sessionsDeleted++;
      } catch {
        // Continue with other deletions
      }
    }
  }

  // Clean up inactive accounts
  const inactiveCutoff = new Date(
    now.getTime() - policy.inactive_account_retention_days * 24 * 60 * 60 * 1000
  ).toISOString();

  const userQuery = new QueryCommand({
    TableName: TableNames.USERS,
    IndexName: 'realm-index',
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: 'last_login < :cutoff',
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':cutoff': inactiveCutoff
    }
  });

  const userResult = await dynamoDb.send(userQuery);

  if (userResult.Items) {
    for (const item of userResult.Items) {
      // Create deletion request for inactive account
      await createDeletionRequest(
        realmId,
        item.id as string,
        item.email as string,
        'SYSTEM',
        'retention-cleanup'
      );
      inactiveAccountsDeleted++;
    }
  }

  // Create audit log for cleanup
  await createAuditLog({
    operation: 'RETENTION_CLEANUP',
    realm_id: realmId,
    resource_type: 'realm',
    resource_id: realmId,
    details: {
      sessions_deleted: sessionsDeleted,
      inactive_accounts_flagged: inactiveAccountsDeleted,
      policy
    }
  });

  return { sessionsDeleted, inactiveAccountsDeleted };
}

/**
 * Export user data (GDPR data portability)
 */
export async function exportUserData(
  realmId: string,
  userId: string
): Promise<Record<string, unknown>> {
  // Get user record
  const userCommand = new GetCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: `${realmId}#${userId}`,
      sk: `USER#${userId}`
    }
  });

  const userResult = await dynamoDb.send(userCommand);
  const userData = userResult.Item;

  // Get user sessions
  const sessionQuery = new QueryCommand({
    TableName: TableNames.SESSIONS,
    IndexName: 'user-index',
    KeyConditionExpression: 'user_id = :userId',
    FilterExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':userId': userId,
      ':realmId': realmId
    }
  });

  const sessionResult = await dynamoDb.send(sessionQuery);

  // Get audit logs
  const auditLogs = await getAuditLogsForUser(realmId, userId, 1000);

  // Create audit log for export
  await createAuditLog({
    operation: 'EXPORT',
    realm_id: realmId,
    user_id: userId,
    resource_type: 'user',
    resource_id: userId,
    details: {
      exported_at: new Date().toISOString()
    }
  });

  // Remove sensitive fields from export
  const sanitizedUser = userData ? {
    id: userData.id,
    email: userData.email,
    email_verified: userData.email_verified,
    profile: userData.profile,
    created_at: userData.created_at,
    updated_at: userData.updated_at,
    last_login: userData.last_login,
    status: userData.status
  } : null;

  return {
    user: sanitizedUser,
    sessions: (sessionResult.Items || []).map(s => ({
      id: s.id,
      created_at: s.created_at,
      expires_at: s.expires_at,
      ip_address: s.ip_address,
      user_agent: s.user_agent
    })),
    audit_logs: auditLogs.map(l => ({
      timestamp: l.timestamp,
      operation: l.operation,
      resource_type: l.resource_type,
      details: l.details
    })),
    exported_at: new Date().toISOString()
  };
}

/**
 * Calculate TTL timestamp for DynamoDB
 */
function calculateTTL(retentionDays: number): number {
  return Math.floor(Date.now() / 1000) + (retentionDays * 24 * 60 * 60);
}

/**
 * Verify deletion completeness
 * Validates: Requirements 8.5 (verification of complete removal)
 */
export async function verifyDeletionCompleteness(
  realmId: string,
  userId: string
): Promise<{ complete: boolean; remainingData: string[] }> {
  const remainingData: string[] = [];

  // Check for user record
  const userCommand = new GetCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: `${realmId}#${userId}`,
      sk: `USER#${userId}`
    }
  });

  const userResult = await dynamoDb.send(userCommand);
  if (userResult.Item) {
    remainingData.push('user_record');
  }

  // Check for sessions
  const sessionQuery = new QueryCommand({
    TableName: TableNames.SESSIONS,
    IndexName: 'user-index',
    KeyConditionExpression: 'user_id = :userId',
    FilterExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':userId': userId,
      ':realmId': realmId
    },
    Limit: 1
  });

  const sessionResult = await dynamoDb.send(sessionQuery);
  if (sessionResult.Items && sessionResult.Items.length > 0) {
    remainingData.push('sessions');
  }

  // Check for non-anonymized audit logs
  const auditLogs = await getAuditLogsForUser(realmId, userId, 1);
  const nonAnonymizedLogs = auditLogs.filter(l => l.user_id !== '[DELETED]');
  if (nonAnonymizedLogs.length > 0) {
    remainingData.push('audit_logs');
  }

  return {
    complete: remainingData.length === 0,
    remainingData
  };
}
