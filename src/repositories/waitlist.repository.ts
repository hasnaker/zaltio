/**
 * Waitlist Repository - DynamoDB operations for waitlist entries
 * 
 * Table: zalt-waitlist
 * PK: REALM#{realmId}#WAITLIST#{entryId}
 * SK: WAITLIST
 * GSI: email-index (email -> entryId)
 * GSI: realm-index (realmId -> entries)
 * GSI: referral-index (referralCode -> entries)
 * 
 * Security Requirements:
 * - Email must be normalized (lowercase, trimmed)
 * - No email enumeration (same response for existing/new)
 * - Audit logging for all operations
 * - Rate limiting on join endpoint
 * 
 * Validates: Requirements 5.1, 5.2 (Waitlist Mode)
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
import { dynamoDb } from '../services/dynamodb.service';
import {
  WaitlistEntry,
  WaitlistStatus,
  WaitlistResponse,
  WaitlistJoinResult,
  WaitlistStats,
  BulkApprovalResult,
  JoinWaitlistInput,
  generateWaitlistId,
  generateReferralCode,
  normalizeEmail,
  toWaitlistResponse,
  canApproveEntry,
  canApproveEntryDetailed,
  canRejectEntry,
  canRejectEntryDetailed,
  calculateTTL,
  MAX_BULK_ENTRIES
} from '../models/waitlist.model';

// Table and index names
const TABLE_NAME = process.env.WAITLIST_TABLE || 'zalt-waitlist';
const EMAIL_INDEX = 'email-index';
const REALM_INDEX = 'realm-index';
const REFERRAL_INDEX = 'referral-index';

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Create composite primary key for waitlist entry
 */
function createPK(realmId: string, entryId: string): string {
  return `REALM#${realmId}#WAITLIST#${entryId}`;
}

/**
 * Create sort key for waitlist entry
 */
function createSK(): string {
  return 'WAITLIST';
}

// ============================================================================
// Create Operations
// ============================================================================

/**
 * Join the waitlist
 * Returns existing entry if email already exists (no enumeration)
 */
export async function joinWaitlist(input: JoinWaitlistInput): Promise<WaitlistJoinResult> {
  const normalizedEmail = normalizeEmail(input.email);
  
  // Check if email already exists
  const existing = await getEntryByEmail(input.realm_id, normalizedEmail);
  if (existing) {
    return {
      entry: toWaitlistResponse(existing),
      already_exists: true,
      position: existing.position,
      referral_code: existing.referral_code
    };
  }
  
  // Get current position (count of entries + 1)
  const position = await getNextPosition(input.realm_id);
  
  const entryId = generateWaitlistId();
  const referralCode = generateReferralCode();
  const now = new Date().toISOString();
  const ttl = calculateTTL(now);
  
  // Check if referral code is valid
  let referredBy: string | undefined;
  if (input.referral_code) {
    const referrer = await getEntryByReferralCode(input.realm_id, input.referral_code);
    if (referrer && referrer.status !== 'rejected') {
      referredBy = input.referral_code;
      // Increment referrer's referral count
      await incrementReferralCount(input.realm_id, referrer.id);
    }
  }
  
  const entry: WaitlistEntry = {
    id: entryId,
    realm_id: input.realm_id,
    email: normalizedEmail,
    status: 'pending',
    position,
    referral_code: referralCode,
    referred_by: referredBy,
    referral_count: 0,
    metadata: input.metadata,
    created_at: now,
    updated_at: now
  };
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: createPK(input.realm_id, entryId),
      sk: createSK(),
      ttl,
      ...entry
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  }));
  
  return {
    entry: toWaitlistResponse(entry),
    already_exists: false,
    position,
    referral_code: referralCode
  };
}

// ============================================================================
// Read Operations
// ============================================================================

/**
 * Get waitlist entry by ID
 */
export async function getEntryById(
  realmId: string,
  entryId: string
): Promise<WaitlistEntry | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(realmId, entryId),
      sk: createSK()
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  return itemToWaitlistEntry(result.Item);
}

/**
 * Get waitlist entry by email
 */
export async function getEntryByEmail(
  realmId: string,
  email: string
): Promise<WaitlistEntry | null> {
  const normalizedEmail = normalizeEmail(email);
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: EMAIL_INDEX,
    KeyConditionExpression: 'email = :email',
    FilterExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':email': normalizedEmail,
      ':realmId': realmId
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  return itemToWaitlistEntry(result.Items[0]);
}

/**
 * Get waitlist entry by referral code
 */
export async function getEntryByReferralCode(
  realmId: string,
  referralCode: string
): Promise<WaitlistEntry | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REFERRAL_INDEX,
    KeyConditionExpression: 'referral_code = :code',
    FilterExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':code': referralCode.toUpperCase(),
      ':realmId': realmId
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  return itemToWaitlistEntry(result.Items[0]);
}

/**
 * List waitlist entries for a realm
 */
export async function listEntries(
  realmId: string,
  options?: {
    status?: WaitlistStatus;
    limit?: number;
    cursor?: string;
    sortBy?: 'position' | 'created_at';
    sortOrder?: 'asc' | 'desc';
  }
): Promise<{ entries: WaitlistResponse[]; nextCursor?: string }> {
  const limit = options?.limit || 50;
  
  let filterExpression: string | undefined;
  const expressionAttributeValues: Record<string, unknown> = {
    ':realmId': realmId
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  if (options?.status) {
    filterExpression = '#status = :status';
    expressionAttributeValues[':status'] = options.status;
    expressionAttributeNames['#status'] = 'status';
  }
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: filterExpression,
    ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0 
      ? expressionAttributeNames 
      : undefined,
    ExpressionAttributeValues: expressionAttributeValues,
    Limit: limit,
    ExclusiveStartKey: options?.cursor 
      ? JSON.parse(Buffer.from(options.cursor, 'base64').toString())
      : undefined,
    ScanIndexForward: options?.sortOrder !== 'desc'
  }));
  
  const entries = (result.Items || []).map(item => 
    toWaitlistResponse(itemToWaitlistEntry(item))
  );
  
  // Sort by position if requested
  if (options?.sortBy === 'position') {
    entries.sort((a, b) => {
      const diff = a.position - b.position;
      return options.sortOrder === 'desc' ? -diff : diff;
    });
  }
  
  return {
    entries,
    nextCursor: result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined
  };
}

/**
 * Get waitlist position for an entry
 */
export async function getPosition(
  realmId: string,
  entryId: string
): Promise<{ position: number; total: number } | null> {
  const entry = await getEntryById(realmId, entryId);
  if (!entry) {
    return null;
  }
  
  // Count total pending entries
  const stats = await getWaitlistStats(realmId);
  
  return {
    position: entry.position,
    total: stats.pending
  };
}

/**
 * Get next position number for new entry
 */
async function getNextPosition(realmId: string): Promise<number> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':realmId': realmId
    },
    Select: 'COUNT'
  }));
  
  return (result.Count || 0) + 1;
}

/**
 * Get waitlist statistics for a realm
 */
export async function getWaitlistStats(realmId: string): Promise<WaitlistStats> {
  const stats: WaitlistStats = {
    total: 0,
    pending: 0,
    approved: 0,
    rejected: 0,
    invited: 0,
    referral_signups: 0
  };
  
  let lastKey: Record<string, unknown> | undefined;
  
  do {
    const result = await dynamoDb.send(new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: REALM_INDEX,
      KeyConditionExpression: 'realm_id = :realmId',
      ExpressionAttributeValues: {
        ':realmId': realmId
      },
      ExclusiveStartKey: lastKey
    }));
    
    for (const item of result.Items || []) {
      stats.total++;
      const status = item.status as WaitlistStatus;
      stats[status]++;
      
      if (item.referred_by) {
        stats.referral_signups++;
      }
    }
    
    lastKey = result.LastEvaluatedKey;
  } while (lastKey);
  
  return stats;
}

// ============================================================================
// Update Operations
// ============================================================================

/**
 * Approve a waitlist entry
 */
export async function approveEntry(
  realmId: string,
  entryId: string,
  approvedBy: string
): Promise<WaitlistEntry | null> {
  const entry = await getEntryById(realmId, entryId);
  if (!entry) {
    return null;
  }
  
  const validation = canApproveEntryDetailed(entry);
  if (!validation.valid) {
    throw new Error(validation.error);
  }
  
  const now = new Date().toISOString();
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, entryId),
        sk: createSK()
      },
      UpdateExpression: `
        SET #status = :approved, 
            approved_at = :now, 
            approved_by = :approvedBy,
            updated_at = :now
      `,
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':approved': 'approved' as WaitlistStatus,
        ':now': now,
        ':approvedBy': approvedBy,
        ':pending': 'pending'
      },
      ConditionExpression: 'attribute_exists(pk) AND #status = :pending',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToWaitlistEntry(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Reject a waitlist entry
 */
export async function rejectEntry(
  realmId: string,
  entryId: string,
  rejectedBy: string,
  reason?: string
): Promise<WaitlistEntry | null> {
  const entry = await getEntryById(realmId, entryId);
  if (!entry) {
    return null;
  }
  
  const validation = canRejectEntryDetailed(entry);
  if (!validation.valid) {
    throw new Error(validation.error);
  }
  
  const now = new Date().toISOString();
  
  let updateExpression = `
    SET #status = :rejected, 
        rejected_at = :now, 
        rejected_by = :rejectedBy,
        updated_at = :now
  `;
  
  const expressionAttributeValues: Record<string, unknown> = {
    ':rejected': 'rejected' as WaitlistStatus,
    ':now': now,
    ':rejectedBy': rejectedBy,
    ':pending': 'pending',
    ':approved': 'approved'
  };
  
  if (reason) {
    updateExpression += ', rejection_reason = :reason';
    expressionAttributeValues[':reason'] = reason;
  }
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, entryId),
        sk: createSK()
      },
      UpdateExpression: updateExpression,
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: expressionAttributeValues,
      ConditionExpression: 'attribute_exists(pk) AND (#status = :pending OR #status = :approved)',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToWaitlistEntry(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Mark entry as invited (after sending invitation)
 */
export async function markAsInvited(
  realmId: string,
  entryId: string
): Promise<WaitlistEntry | null> {
  const now = new Date().toISOString();
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, entryId),
        sk: createSK()
      },
      UpdateExpression: `
        SET #status = :invited, 
            invitation_sent_at = :now,
            updated_at = :now
      `,
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':invited': 'invited' as WaitlistStatus,
        ':now': now,
        ':approved': 'approved'
      },
      ConditionExpression: 'attribute_exists(pk) AND #status = :approved',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToWaitlistEntry(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Increment referral count for an entry
 */
async function incrementReferralCount(
  realmId: string,
  entryId: string
): Promise<void> {
  try {
    await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, entryId),
        sk: createSK()
      },
      UpdateExpression: 'SET referral_count = referral_count + :one, updated_at = :now',
      ExpressionAttributeValues: {
        ':one': 1,
        ':now': new Date().toISOString()
      },
      ConditionExpression: 'attribute_exists(pk)'
    }));
  } catch {
    // Ignore errors - referral count is not critical
  }
}

/**
 * Bulk approve entries
 */
export async function bulkApprove(
  realmId: string,
  entryIds: string[],
  approvedBy: string
): Promise<BulkApprovalResult> {
  const result: BulkApprovalResult = {
    approved: [],
    failed: []
  };
  
  // Limit bulk operations
  const idsToProcess = entryIds.slice(0, MAX_BULK_ENTRIES);
  
  for (const entryId of idsToProcess) {
    try {
      const entry = await approveEntry(realmId, entryId, approvedBy);
      if (entry) {
        result.approved.push(entryId);
      } else {
        result.failed.push({ id: entryId, error: 'Entry not found or not pending' });
      }
    } catch (error) {
      result.failed.push({ 
        id: entryId, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      });
    }
  }
  
  return result;
}

// ============================================================================
// Delete Operations
// ============================================================================

/**
 * Delete a waitlist entry
 */
export async function deleteEntry(
  realmId: string,
  entryId: string
): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, entryId),
        sk: createSK()
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Delete all waitlist entries for a realm
 */
export async function deleteAllRealmEntries(realmId: string): Promise<number> {
  const { entries } = await listEntries(realmId, { limit: 1000 });
  
  if (entries.length === 0) {
    return 0;
  }
  
  // Batch delete (max 25 items per batch)
  const batches: WaitlistResponse[][] = [];
  for (let i = 0; i < entries.length; i += 25) {
    batches.push(entries.slice(i, i + 25));
  }
  
  let deletedCount = 0;
  
  for (const batch of batches) {
    try {
      await dynamoDb.send(new BatchWriteCommand({
        RequestItems: {
          [TABLE_NAME]: batch.map(entry => ({
            DeleteRequest: {
              Key: {
                pk: createPK(realmId, entry.id),
                sk: createSK()
              }
            }
          }))
        }
      }));
      deletedCount += batch.length;
    } catch (error) {
      console.error('Failed to delete waitlist batch:', error);
    }
  }
  
  return deletedCount;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert DynamoDB item to WaitlistEntry
 */
function itemToWaitlistEntry(item: Record<string, unknown>): WaitlistEntry {
  return {
    id: item.id as string,
    realm_id: item.realm_id as string,
    email: item.email as string,
    status: item.status as WaitlistStatus,
    position: item.position as number,
    referral_code: item.referral_code as string,
    referred_by: item.referred_by as string | undefined,
    referral_count: (item.referral_count as number) || 0,
    metadata: item.metadata as WaitlistEntry['metadata'],
    created_at: item.created_at as string,
    updated_at: item.updated_at as string,
    approved_at: item.approved_at as string | undefined,
    approved_by: item.approved_by as string | undefined,
    rejected_at: item.rejected_at as string | undefined,
    rejected_by: item.rejected_by as string | undefined,
    rejection_reason: item.rejection_reason as string | undefined,
    invitation_sent_at: item.invitation_sent_at as string | undefined
  };
}
