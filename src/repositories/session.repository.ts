/**
 * Session Repository - DynamoDB operations for sessions
 * Validates: Requirements 2.3, 9.5 (session management)
 * 
 * DynamoDB Table Schema:
 * - Primary Key: sessionId (HASH)
 * - GSI: user-index (userId)
 */

import {
  PutCommand,
  GetCommand,
  DeleteCommand,
  QueryCommand,
  UpdateCommand,
  ScanCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from '../services/dynamodb.service';
import { Session, CreateSessionInput } from '../models/session.model';
import * as crypto from 'crypto';

// Use crypto.randomUUID() instead of uuid package for ESM compatibility
const uuidv4 = () => crypto.randomUUID();

const DEFAULT_SESSION_TTL = 7 * 24 * 60 * 60; // 7 days in seconds

/**
 * Hash refresh token for storage and lookup
 */
function hashRefreshToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Create a new session with TTL for automatic cleanup
 * Uses pk/sk format: pk = "SESSION#{realmId}#{userId}", sk = "SESSION#{sessionId}"
 */
export async function createSession(
  input: CreateSessionInput,
  accessToken: string,
  refreshToken: string,
  expiresInSeconds: number = DEFAULT_SESSION_TTL
): Promise<Session> {
  const sessionId = uuidv4();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiresInSeconds * 1000);
  const ttl = Math.floor(expiresAt.getTime() / 1000);
  const refreshTokenHash = hashRefreshToken(refreshToken);

  const session = {
    pk: `SESSION#${input.realm_id}#${input.user_id}`,
    sk: `SESSION#${sessionId}`,
    sessionId: sessionId,
    id: sessionId,
    userId: input.user_id,
    user_id: input.user_id,
    realmId: input.realm_id,
    realm_id: input.realm_id,
    access_token: accessToken,
    refresh_token: refreshToken,
    refresh_token_hash: refreshTokenHash,
    expires_at: expiresAt.toISOString(),
    created_at: now.toISOString(),
    last_used_at: now.toISOString(),
    ip_address: input.ip_address,
    user_agent: input.user_agent,
    device_fingerprint: input.device_fingerprint,
    revoked: false,
    ttl
  };

  const command = new PutCommand({
    TableName: TableNames.SESSIONS,
    Item: session
  });

  await dynamoDb.send(command);

  return session as Session;
}


/**
 * Find session by ID - requires realmId and userId for pk/sk lookup
 * For lookup by sessionId only, use findSessionByRefreshToken or scan
 */
export async function findSessionById(sessionId: string, realmId?: string, userId?: string): Promise<Session | null> {
  // If we have realmId and userId, do direct lookup
  if (realmId && userId) {
    const command = new GetCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `SESSION#${realmId}#${userId}`,
        sk: `SESSION#${sessionId}`
      }
    });

    const result = await dynamoDb.send(command);
    return result.Item ? result.Item as Session : null;
  }

  // Otherwise scan for the session (less efficient but works)
  const command = new ScanCommand({
    TableName: TableNames.SESSIONS,
    FilterExpression: 'sessionId = :sessionId',
    ExpressionAttributeValues: {
      ':sessionId': sessionId
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  return result.Items[0] as Session;
}

/**
 * Find session by refresh token
 * Since we don't have a GSI on refresh_token, we scan with filter
 * In production, consider adding a GSI or using refresh_token_hash as secondary key
 */
export async function findSessionByRefreshToken(
  refreshToken: string
): Promise<Session | null> {
  const refreshTokenHash = hashRefreshToken(refreshToken);
  
  // Scan with filter - not ideal but works for now
  // TODO: Add GSI on refresh_token_hash for better performance
  const command = new ScanCommand({
    TableName: TableNames.SESSIONS,
    FilterExpression: 'refresh_token_hash = :hash OR refresh_token = :token',
    ExpressionAttributeValues: {
      ':hash': refreshTokenHash,
      ':token': refreshToken
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  return result.Items[0] as Session;
}

/**
 * Update session tokens after refresh with grace period support
 * Stores old token hash for 30-second grace period (Siberci recommendation)
 */
export async function updateSessionTokens(
  sessionId: string,
  realmId: string,
  userId: string,
  newAccessToken: string,
  newRefreshToken: string,
  oldRefreshTokenHash?: string,
  expiresInSeconds: number = DEFAULT_SESSION_TTL
): Promise<Session | null> {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiresInSeconds * 1000);
  const ttl = Math.floor(expiresAt.getTime() / 1000);
  const newRefreshTokenHash = hashRefreshToken(newRefreshToken);

  const command = new UpdateCommand({
    TableName: TableNames.SESSIONS,
    Key: {
      pk: `SESSION#${realmId}#${userId}`,
      sk: `SESSION#${sessionId}`
    },
    UpdateExpression: 'SET access_token = :accessToken, refresh_token = :refreshToken, refresh_token_hash = :newHash, expires_at = :expiresAt, #ttl = :ttl, old_refresh_token_hash = :oldHash, rotated_at = :rotatedAt, last_used_at = :lastUsed',
    ExpressionAttributeNames: {
      '#ttl': 'ttl'
    },
    ExpressionAttributeValues: {
      ':accessToken': newAccessToken,
      ':refreshToken': newRefreshToken,
      ':newHash': newRefreshTokenHash,
      ':expiresAt': expiresAt.toISOString(),
      ':ttl': ttl,
      ':oldHash': oldRefreshTokenHash || null,
      ':rotatedAt': now.toISOString(),
      ':lastUsed': now.toISOString()
    },
    ReturnValues: 'ALL_NEW'
  });

  try {
    const result = await dynamoDb.send(command);
    return result.Attributes as Session;
  } catch (error) {
    console.error('Failed to update session tokens:', error);
    return null;
  }
}

/**
 * Find session by old refresh token (grace period lookup)
 * Used when client retries with old token within 30-second window
 */
export async function findSessionByOldRefreshToken(
  oldRefreshTokenHash: string
): Promise<Session | null> {
  // Scan with filter for old_refresh_token_hash
  const command = new ScanCommand({
    TableName: TableNames.SESSIONS,
    FilterExpression: 'old_refresh_token_hash = :hash',
    ExpressionAttributeValues: {
      ':hash': oldRefreshTokenHash
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  return result.Items[0] as Session;
}

/**
 * Clear old refresh token hash after grace period expires
 */
export async function clearOldRefreshToken(
  sessionId: string,
  realmId: string,
  userId: string
): Promise<void> {
  const command = new UpdateCommand({
    TableName: TableNames.SESSIONS,
    Key: {
      pk: `SESSION#${realmId}#${userId}`,
      sk: `SESSION#${sessionId}`
    },
    UpdateExpression: 'REMOVE old_refresh_token_hash',
    ReturnValues: 'NONE'
  });

  try {
    await dynamoDb.send(command);
  } catch (error) {
    console.error('Failed to clear old refresh token:', error);
  }
}

/**
 * Delete session (for logout)
 */
export async function deleteSession(
  sessionId: string,
  realmId?: string,
  userId?: string
): Promise<boolean> {
  // If we have realmId and userId, do direct delete
  if (realmId && userId) {
    const command = new DeleteCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `SESSION#${realmId}#${userId}`,
        sk: `SESSION#${sessionId}`
      }
    });

    try {
      await dynamoDb.send(command);
      return true;
    } catch (error) {
      console.error('Failed to delete session:', error);
      return false;
    }
  }

  // Otherwise find the session first then delete
  const session = await findSessionById(sessionId);
  if (!session) {
    return false;
  }

  const command = new DeleteCommand({
    TableName: TableNames.SESSIONS,
    Key: {
      pk: `SESSION#${session.realm_id}#${session.user_id}`,
      sk: `SESSION#${sessionId}`
    }
  });

  try {
    await dynamoDb.send(command);
    return true;
  } catch (error) {
    console.error('Failed to delete session:', error);
    return false;
  }
}

/**
 * Delete all sessions for a user (for security events)
 */
export async function deleteUserSessions(
  realmId: string,
  userId: string
): Promise<number> {
  // Query all sessions for this user using pk prefix
  const command = new QueryCommand({
    TableName: TableNames.SESSIONS,
    KeyConditionExpression: 'pk = :pk AND begins_with(sk, :skPrefix)',
    ExpressionAttributeValues: {
      ':pk': `SESSION#${realmId}#${userId}`,
      ':skPrefix': 'SESSION#'
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return 0;
  }

  // Delete each session
  let deletedCount = 0;
  for (const item of result.Items) {
    const session = item as { pk: string; sk: string };
    const deleteCommand = new DeleteCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: session.pk,
        sk: session.sk
      }
    });
    
    try {
      await dynamoDb.send(deleteCommand);
      deletedCount++;
    } catch {
      // Continue with other deletions
    }
  }

  return deletedCount;
}

/**
 * Count active sessions for a user (for concurrent session limits)
 */
export async function countUserSessions(
  realmId: string,
  userId: string
): Promise<number> {
  const command = new QueryCommand({
    TableName: TableNames.SESSIONS,
    KeyConditionExpression: 'pk = :pk AND begins_with(sk, :skPrefix)',
    ExpressionAttributeValues: {
      ':pk': `SESSION#${realmId}#${userId}`,
      ':skPrefix': 'SESSION#'
    },
    Select: 'COUNT'
  });

  const result = await dynamoDb.send(command);
  return result.Count || 0;
}

/**
 * Delete all sessions in a realm (for realm cleanup)
 * Validates: Requirements 1.5 (cascading deletion)
 */
export async function deleteAllRealmSessions(realmId: string): Promise<number> {
  // Scan for all sessions in this realm (pk starts with SESSION#{realmId}#)
  const scanCommand = new ScanCommand({
    TableName: TableNames.SESSIONS,
    FilterExpression: 'begins_with(pk, :pkPrefix)',
    ExpressionAttributeValues: {
      ':pkPrefix': `SESSION#${realmId}#`
    }
  });

  const result = await dynamoDb.send(scanCommand);
  
  if (!result.Items || result.Items.length === 0) {
    return 0;
  }

  // Delete each session
  let deletedCount = 0;
  for (const item of result.Items) {
    const session = item as { pk: string; sk: string };
    const deleteCommand = new DeleteCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: session.pk,
        sk: session.sk
      }
    });
    
    try {
      await dynamoDb.send(deleteCommand);
      deletedCount++;
    } catch {
      console.error(`Failed to delete session in realm ${realmId}`);
    }
  }

  return deletedCount;
}

/**
 * Count sessions in a realm
 */
export async function countRealmSessions(realmId: string): Promise<number> {
  const command = new ScanCommand({
    TableName: TableNames.SESSIONS,
    FilterExpression: 'begins_with(pk, :pkPrefix)',
    ExpressionAttributeValues: {
      ':pkPrefix': `SESSION#${realmId}#`
    },
    Select: 'COUNT'
  });

  const result = await dynamoDb.send(command);
  return result.Count || 0;
}

/**
 * Revoke all sessions for a user (security event - password reset, account compromise)
 * This is an alias for deleteUserSessions with additional logging
 */
export async function revokeAllUserSessions(
  realmId: string,
  userId: string
): Promise<number> {
  console.log(`[SECURITY] Revoking all sessions for user ${userId} in realm ${realmId}`);
  const count = await deleteUserSessions(realmId, userId);
  console.log(`[SECURITY] Revoked ${count} sessions for user ${userId}`);
  return count;
}

/**
 * Get all active sessions for a user (for session management UI)
 */
export async function getUserSessions(
  realmId: string,
  userId: string
): Promise<Session[]> {
  const command = new QueryCommand({
    TableName: TableNames.SESSIONS,
    KeyConditionExpression: 'pk = :pk AND begins_with(sk, :skPrefix)',
    ExpressionAttributeValues: {
      ':pk': `SESSION#${realmId}#${userId}`,
      ':skPrefix': 'SESSION#'
    }
  });

  const result = await dynamoDb.send(command);
  return (result.Items || []) as Session[];
}

/**
 * Update session last activity timestamp
 * Validates: Requirement 13.2 - Last activity tracking
 */
export async function updateSessionLastActivity(
  sessionId: string,
  realmId: string,
  userId: string
): Promise<boolean> {
  const now = new Date().toISOString();

  const command = new UpdateCommand({
    TableName: TableNames.SESSIONS,
    Key: {
      pk: `SESSION#${realmId}#${userId}`,
      sk: `SESSION#${sessionId}`
    },
    UpdateExpression: 'SET last_used_at = :lastUsed',
    ExpressionAttributeValues: {
      ':lastUsed': now
    },
    ConditionExpression: 'attribute_exists(pk)',
    ReturnValues: 'NONE'
  });

  try {
    await dynamoDb.send(command);
    return true;
  } catch (error) {
    // ConditionalCheckFailedException means session doesn't exist
    if ((error as Error).name === 'ConditionalCheckFailedException') {
      return false;
    }
    console.error('Failed to update session last activity:', error);
    return false;
  }
}


/**
 * Alias for deleteUserSessions - used by password reset handler
 */
export const deleteAllUserSessions = deleteUserSessions;


// ============================================
// MFA Session Functions (DynamoDB-backed)
// ============================================

/**
 * MFA Session data structure
 */
export interface MfaSessionData {
  sessionId: string;
  userId: string;
  realmId: string;
  email: string;
  expiresAt: number;
  deviceFingerprint?: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  ttl: number;
}

/**
 * Create MFA session in DynamoDB
 * Used during login when MFA is required
 */
export async function createMfaSession(
  sessionId: string,
  data: {
    userId: string;
    realmId: string;
    email: string;
    expiresAt: number;
    deviceFingerprint?: string;
    ipAddress: string;
    userAgent: string;
  }
): Promise<void> {
  const now = new Date().toISOString();
  const ttl = Math.floor(data.expiresAt / 1000); // DynamoDB TTL in seconds

  const mfaSession = {
    pk: `MFA#${data.realmId}#${data.userId}`,
    sk: `MFA#${sessionId}`,
    sessionId: sessionId,
    userId: data.userId,
    realmId: data.realmId,
    email: data.email,
    expiresAt: data.expiresAt,
    deviceFingerprint: data.deviceFingerprint,
    ipAddress: data.ipAddress,
    userAgent: data.userAgent,
    createdAt: now,
    ttl
  };

  const command = new PutCommand({
    TableName: TableNames.SESSIONS,
    Item: mfaSession
  });

  await dynamoDb.send(command);
}

/**
 * Get MFA session from DynamoDB
 */
export async function getMfaSessionFromDb(sessionId: string, realmId?: string, userId?: string): Promise<MfaSessionData | null> {
  // If we have realmId and userId, do direct lookup
  if (realmId && userId) {
    const command = new GetCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `MFA#${realmId}#${userId}`,
        sk: `MFA#${sessionId}`
      }
    });

    const result = await dynamoDb.send(command);
    
    if (!result.Item) {
      return null;
    }

    const session = result.Item as MfaSessionData;

    // Check if expired
    if (Date.now() > session.expiresAt) {
      await deleteMfaSessionFromDb(sessionId, realmId, userId);
      return null;
    }

    return session;
  }

  // Otherwise scan for the MFA session
  const command = new ScanCommand({
    TableName: TableNames.SESSIONS,
    FilterExpression: 'sessionId = :sessionId AND begins_with(pk, :pkPrefix)',
    ExpressionAttributeValues: {
      ':sessionId': sessionId,
      ':pkPrefix': 'MFA#'
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  const session = result.Items[0] as MfaSessionData;

  // Check if expired
  if (Date.now() > session.expiresAt) {
    await deleteMfaSessionFromDb(sessionId, session.realmId, session.userId);
    return null;
  }

  return session;
}

/**
 * Delete MFA session from DynamoDB
 */
export async function deleteMfaSessionFromDb(sessionId: string, realmId?: string, userId?: string): Promise<void> {
  if (realmId && userId) {
    const command = new DeleteCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `MFA#${realmId}#${userId}`,
        sk: `MFA#${sessionId}`
      }
    });

    try {
      await dynamoDb.send(command);
    } catch (error) {
      console.error('Failed to delete MFA session:', error);
    }
    return;
  }

  // Find and delete
  const session = await getMfaSessionFromDb(sessionId);
  if (session) {
    const command = new DeleteCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `MFA#${session.realmId}#${session.userId}`,
        sk: `MFA#${sessionId}`
      }
    });

    try {
      await dynamoDb.send(command);
    } catch (error) {
      console.error('Failed to delete MFA session:', error);
    }
  }
}
