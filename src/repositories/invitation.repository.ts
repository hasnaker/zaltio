/**
 * Invitation Repository - DynamoDB operations for team member invitations
 * 
 * Table: zalt-invitations
 * PK: TENANT#{tenantId}#INVITATION#{invitationId}
 * SK: INVITATION
 * GSI: token-index (tokenHash -> invitationId)
 * GSI: email-index (email -> invitations)
 * 
 * Security Requirements:
 * - Token must be cryptographically secure (32 bytes, hex encoded)
 * - Token must be hashed before storage (SHA-256)
 * - Audit logging for all operations
 * - No email enumeration
 * 
 * Validates: Requirements 11.1 (Invitation System)
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
  Invitation,
  CreateInvitationInput,
  InvitationStatus,
  InvitationResponse,
  InvitationWithToken,
  InvitationValidationResult,
  generateInvitationId,
  generateInvitationToken,
  hashInvitationToken,
  calculateExpiryDate,
  calculateTTL,
  normalizeEmail,
  toInvitationResponse,
  canAcceptInvitation,
  isInvitationExpired
} from '../models/invitation.model';

// Table and index names
const TABLE_NAME = process.env.INVITATIONS_TABLE || 'zalt-invitations';
const TOKEN_INDEX = 'token-index';
const EMAIL_INDEX = 'email-index';
const TENANT_INDEX = 'tenant-index';

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Create composite primary key for invitation
 */
function createPK(tenantId: string, invitationId: string): string {
  return `TENANT#${tenantId}#INVITATION#${invitationId}`;
}

/**
 * Create sort key for invitation
 */
function createSK(): string {
  return 'INVITATION';
}

// ============================================================================
// Create Operations
// ============================================================================

/**
 * Create a new invitation
 * Returns the invitation with the raw token (only time token is available)
 * 
 * Security: Token is hashed with SHA-256 before storage
 */
export async function createInvitation(input: CreateInvitationInput): Promise<InvitationWithToken> {
  const invitationId = generateInvitationId();
  const rawToken = generateInvitationToken();
  const tokenHash = hashInvitationToken(rawToken);
  const now = new Date().toISOString();
  const expiresAt = calculateExpiryDate(input.expires_in_days);
  const ttl = calculateTTL(expiresAt);
  const normalizedEmail = normalizeEmail(input.email);
  
  const invitation: Invitation = {
    id: invitationId,
    tenant_id: input.tenant_id,
    email: normalizedEmail,
    role: input.role,
    permissions: input.permissions,
    invited_by: input.invited_by,
    token_hash: tokenHash,
    status: 'pending',
    expires_at: expiresAt,
    created_at: now,
    metadata: {
      ...input.metadata,
      resend_count: 0
    }
  };
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: createPK(input.tenant_id, invitationId),
      sk: createSK(),
      // TTL for automatic cleanup
      ttl,
      // Entity data (includes token_hash, email, tenant_id for GSI)
      ...invitation
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  }));
  
  return {
    invitation: toInvitationResponse(invitation),
    token: rawToken
  };
}

// ============================================================================
// Read Operations
// ============================================================================

/**
 * Get invitation by ID
 */
export async function getInvitationById(
  tenantId: string,
  invitationId: string
): Promise<Invitation | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(tenantId, invitationId),
      sk: createSK()
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  return itemToInvitation(result.Item);
}

/**
 * Get invitation by token hash
 * Used for accepting invitations
 * 
 * Security: Caller must hash the raw token before calling this
 */
export async function getInvitationByTokenHash(tokenHash: string): Promise<Invitation | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: TOKEN_INDEX,
    KeyConditionExpression: 'token_hash = :tokenHash',
    ExpressionAttributeValues: {
      ':tokenHash': tokenHash
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  return itemToInvitation(result.Items[0]);
}

/**
 * Validate invitation token and return invitation if valid
 * This is the main entry point for accepting invitations
 * 
 * Security: Token is hashed before lookup
 */
export async function validateInvitationToken(rawToken: string): Promise<InvitationValidationResult> {
  const tokenHash = hashInvitationToken(rawToken);
  const invitation = await getInvitationByTokenHash(tokenHash);
  
  if (!invitation) {
    return {
      valid: false,
      error: 'Invalid invitation token',
      error_code: 'INVITATION_NOT_FOUND'
    };
  }
  
  return canAcceptInvitation(invitation);
}

/**
 * List invitations for a tenant
 */
export async function listInvitationsByTenant(
  tenantId: string,
  options?: {
    status?: InvitationStatus;
    limit?: number;
    cursor?: string;
  }
): Promise<{ invitations: InvitationResponse[]; nextCursor?: string }> {
  const limit = options?.limit || 50;
  
  let filterExpression: string | undefined;
  const expressionAttributeValues: Record<string, unknown> = {
    ':tenantId': tenantId
  };
  
  if (options?.status) {
    filterExpression = '#status = :status';
    expressionAttributeValues[':status'] = options.status;
  }
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: TENANT_INDEX,
    KeyConditionExpression: 'tenant_id = :tenantId',
    FilterExpression: filterExpression,
    ExpressionAttributeNames: filterExpression ? { '#status': 'status' } : undefined,
    ExpressionAttributeValues: expressionAttributeValues,
    Limit: limit,
    ExclusiveStartKey: options?.cursor 
      ? JSON.parse(Buffer.from(options.cursor, 'base64').toString())
      : undefined,
    ScanIndexForward: false // Newest first
  }));
  
  const invitations = (result.Items || []).map(item => 
    toInvitationResponse(itemToInvitation(item))
  );
  
  return {
    invitations,
    nextCursor: result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined
  };
}

/**
 * List invitations by email
 * Used to check if user already has pending invitations
 * 
 * Security: Email is normalized before lookup
 */
export async function listInvitationsByEmail(
  email: string,
  options?: {
    status?: InvitationStatus;
    limit?: number;
  }
): Promise<InvitationResponse[]> {
  const normalizedEmail = normalizeEmail(email);
  const limit = options?.limit || 50;
  
  let filterExpression: string | undefined;
  const expressionAttributeValues: Record<string, unknown> = {
    ':email': normalizedEmail
  };
  
  if (options?.status) {
    filterExpression = '#status = :status';
    expressionAttributeValues[':status'] = options.status;
  }
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: EMAIL_INDEX,
    KeyConditionExpression: 'email = :email',
    FilterExpression: filterExpression,
    ExpressionAttributeNames: filterExpression ? { '#status': 'status' } : undefined,
    ExpressionAttributeValues: expressionAttributeValues,
    Limit: limit
  }));
  
  return (result.Items || []).map(item => 
    toInvitationResponse(itemToInvitation(item))
  );
}

/**
 * Check if email has pending invitation to tenant
 * Used to prevent duplicate invitations
 */
export async function hasPendingInvitation(
  tenantId: string,
  email: string
): Promise<boolean> {
  const normalizedEmail = normalizeEmail(email);
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: EMAIL_INDEX,
    KeyConditionExpression: 'email = :email',
    FilterExpression: 'tenant_id = :tenantId AND #status = :pending',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':email': normalizedEmail,
      ':tenantId': tenantId,
      ':pending': 'pending'
    },
    Limit: 1
  }));
  
  return (result.Items?.length || 0) > 0;
}

// ============================================================================
// Update Operations
// ============================================================================

/**
 * Accept an invitation
 * Marks the invitation as accepted and records who accepted it
 */
export async function acceptInvitation(
  tenantId: string,
  invitationId: string,
  acceptedByUserId: string
): Promise<Invitation | null> {
  const now = new Date().toISOString();
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId, invitationId),
        sk: createSK()
      },
      UpdateExpression: 'SET #status = :accepted, accepted_at = :now, accepted_by_user_id = :userId',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':accepted': 'accepted' as InvitationStatus,
        ':now': now,
        ':userId': acceptedByUserId,
        ':pending': 'pending'
      },
      // Can only accept pending invitations
      ConditionExpression: 'attribute_exists(pk) AND #status = :pending',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToInvitation(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Revoke an invitation
 * Marks the invitation as revoked so it can no longer be accepted
 */
export async function revokeInvitation(
  tenantId: string,
  invitationId: string,
  revokedBy: string
): Promise<Invitation | null> {
  const now = new Date().toISOString();
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId, invitationId),
        sk: createSK()
      },
      UpdateExpression: 'SET #status = :revoked, revoked_at = :now, revoked_by = :revokedBy',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':revoked': 'revoked' as InvitationStatus,
        ':now': now,
        ':revokedBy': revokedBy,
        ':pending': 'pending'
      },
      // Can only revoke pending invitations
      ConditionExpression: 'attribute_exists(pk) AND #status = :pending',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToInvitation(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Mark invitation as expired
 * Used by background job to expire old invitations
 */
export async function expireInvitation(
  tenantId: string,
  invitationId: string
): Promise<Invitation | null> {
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId, invitationId),
        sk: createSK()
      },
      UpdateExpression: 'SET #status = :expired',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':expired': 'expired' as InvitationStatus,
        ':pending': 'pending'
      },
      // Can only expire pending invitations
      ConditionExpression: 'attribute_exists(pk) AND #status = :pending',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToInvitation(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Update invitation for resend
 * Generates new token and extends expiry
 */
export async function resendInvitation(
  tenantId: string,
  invitationId: string,
  newExpiryDays?: number
): Promise<InvitationWithToken | null> {
  // First get the existing invitation
  const existing = await getInvitationById(tenantId, invitationId);
  if (!existing || existing.status !== 'pending') {
    return null;
  }
  
  const rawToken = generateInvitationToken();
  const tokenHash = hashInvitationToken(rawToken);
  const now = new Date().toISOString();
  const expiresAt = calculateExpiryDate(newExpiryDays);
  const ttl = calculateTTL(expiresAt);
  const resendCount = (existing.metadata?.resend_count || 0) + 1;
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId, invitationId),
        sk: createSK()
      },
      UpdateExpression: `
        SET token_hash = :tokenHash, 
            expires_at = :expiresAt, 
            #ttl = :ttl,
            metadata.resend_count = :resendCount,
            metadata.last_resent_at = :now
      `,
      ExpressionAttributeNames: {
        '#ttl': 'ttl',
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':tokenHash': tokenHash,
        ':expiresAt': expiresAt,
        ':ttl': ttl,
        ':resendCount': resendCount,
        ':now': now,
        ':pending': 'pending'
      },
      ConditionExpression: 'attribute_exists(pk) AND #status = :pending',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    const invitation = itemToInvitation(result.Attributes);
    return {
      invitation: toInvitationResponse(invitation),
      token: rawToken
    };
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

// ============================================================================
// Delete Operations
// ============================================================================

/**
 * Delete an invitation permanently
 * Use revokeInvitation for soft delete
 */
export async function deleteInvitation(
  tenantId: string,
  invitationId: string
): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId, invitationId),
        sk: createSK()
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Delete all invitations for a tenant
 * Used when deleting a tenant
 */
export async function deleteAllTenantInvitations(tenantId: string): Promise<number> {
  const { invitations } = await listInvitationsByTenant(tenantId, { limit: 1000 });
  
  if (invitations.length === 0) {
    return 0;
  }
  
  // Batch delete (max 25 items per batch)
  const batches: InvitationResponse[][] = [];
  for (let i = 0; i < invitations.length; i += 25) {
    batches.push(invitations.slice(i, i + 25));
  }
  
  let deletedCount = 0;
  
  for (const batch of batches) {
    try {
      await dynamoDb.send(new BatchWriteCommand({
        RequestItems: {
          [TABLE_NAME]: batch.map(inv => ({
            DeleteRequest: {
              Key: {
                pk: createPK(tenantId, inv.id),
                sk: createSK()
              }
            }
          }))
        }
      }));
      deletedCount += batch.length;
    } catch (error) {
      console.error('Failed to delete invitation batch:', error);
    }
  }
  
  return deletedCount;
}

// ============================================================================
// Statistics
// ============================================================================

/**
 * Count invitations by status for a tenant
 */
export async function countInvitationsByStatus(
  tenantId: string
): Promise<Record<InvitationStatus, number>> {
  const counts: Record<InvitationStatus, number> = {
    pending: 0,
    accepted: 0,
    expired: 0,
    revoked: 0
  };
  
  const { invitations } = await listInvitationsByTenant(tenantId, { limit: 1000 });
  
  for (const inv of invitations) {
    // Check if pending invitation is actually expired
    if (inv.status === 'pending' && new Date(inv.expires_at) < new Date()) {
      counts.expired++;
    } else {
      counts[inv.status]++;
    }
  }
  
  return counts;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert DynamoDB item to Invitation
 */
function itemToInvitation(item: Record<string, unknown>): Invitation {
  return {
    id: item.id as string,
    tenant_id: item.tenant_id as string,
    email: item.email as string,
    role: item.role as string,
    permissions: item.permissions as string[] | undefined,
    invited_by: item.invited_by as string,
    token_hash: item.token_hash as string,
    status: item.status as InvitationStatus,
    expires_at: item.expires_at as string,
    created_at: item.created_at as string,
    accepted_at: item.accepted_at as string | undefined,
    accepted_by_user_id: item.accepted_by_user_id as string | undefined,
    revoked_at: item.revoked_at as string | undefined,
    revoked_by: item.revoked_by as string | undefined,
    metadata: item.metadata as Invitation['metadata']
  };
}
