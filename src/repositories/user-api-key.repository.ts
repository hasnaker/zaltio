/**
 * User API Key Repository - DynamoDB operations for user-generated API keys
 * Table: zalt-user-api-keys
 * PK: USER#{userId}#KEY#{keyId}
 * SK: KEY
 * GSI: key-hash-index (keyHash -> key details)
 * GSI: realm-index (realmId -> keys)
 * 
 * Validates: Requirements 2.1, 2.2 (User-Generated API Keys)
 */

import { 
  GetCommand, 
  PutCommand, 
  UpdateCommand, 
  QueryCommand,
  DeleteCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from '../services/dynamodb.service';
import { 
  UserAPIKey, 
  CreateUserAPIKeyInput, 
  UserAPIKeyWithSecret,
  UserAPIKeyResponse,
  UserAPIKeyStatus,
  UserAPIKeyContext,
  USER_API_KEY_PREFIX,
  USER_API_KEY_LENGTH,
  isValidUserAPIKeyFormat,
  getKeyDisplayPrefix
} from '../models/user-api-key.model';
import { createHash, randomBytes } from 'crypto';

const TABLE_NAME = process.env.USER_API_KEYS_TABLE || 'zalt-user-api-keys';
const KEY_HASH_INDEX = 'key-hash-index';
const REALM_INDEX = 'realm-index';
const USER_INDEX = 'user-index';

/**
 * Generate unique key ID
 */
function generateKeyId(): string {
  return `key_${randomBytes(12).toString('hex')}`;
}

/**
 * Generate random API key
 * Format: zalt_key_{32 random alphanumeric chars}
 */
function generateUserAPIKey(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = USER_API_KEY_PREFIX;
  for (let i = 0; i < 32; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

/**
 * Hash API key for storage (SHA-256)
 */
function hashAPIKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

/**
 * Convert UserAPIKey to UserAPIKeyResponse (exclude sensitive data)
 */
function toResponse(key: UserAPIKey): UserAPIKeyResponse {
  return {
    id: key.id,
    user_id: key.user_id,
    realm_id: key.realm_id,
    tenant_id: key.tenant_id,
    name: key.name,
    description: key.description,
    key_prefix: key.key_prefix,
    scopes: key.scopes,
    status: key.status,
    created_at: key.created_at,
    updated_at: key.updated_at,
    expires_at: key.expires_at,
    last_used_at: key.last_used_at,
    usage_count: key.usage_count,
    ip_restrictions: key.ip_restrictions
  };
}

/**
 * Create a new user API key
 * Returns the full key only once - it cannot be retrieved later
 */
export async function createUserAPIKey(input: CreateUserAPIKeyInput): Promise<UserAPIKeyWithSecret> {
  const keyId = generateKeyId();
  const now = new Date().toISOString();
  const fullKey = generateUserAPIKey();
  const keyHash = hashAPIKey(fullKey);
  const keyPrefix = getKeyDisplayPrefix(fullKey);
  
  // Default scopes if not provided
  const scopes = input.scopes && input.scopes.length > 0 
    ? input.scopes 
    : ['full:access'];
  
  const apiKey: UserAPIKey = {
    id: keyId,
    user_id: input.user_id,
    realm_id: input.realm_id,
    tenant_id: input.tenant_id,
    name: input.name,
    description: input.description,
    key_prefix: keyPrefix,
    key_hash: keyHash,
    scopes,
    status: 'active',
    created_at: now,
    updated_at: now,
    expires_at: input.expires_at,
    usage_count: 0,
    ip_restrictions: input.ip_restrictions
  };
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: `USER#${input.user_id}#KEY#${keyId}`,
      sk: 'KEY',
      ...apiKey,
      key_hash: keyHash
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  }));
  
  // Return with full key (only time it's available)
  return {
    key: toResponse(apiKey),
    full_key: fullKey
  };
}

/**
 * Get user API key by ID
 */
export async function getUserAPIKeyById(userId: string, keyId: string): Promise<UserAPIKey | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: `USER#${userId}#KEY#${keyId}`,
      sk: 'KEY'
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  const { pk, sk, ...apiKey } = result.Item;
  return apiKey as UserAPIKey;
}

/**
 * Validate user API key and return key context
 * Used for authenticating API requests
 */
export async function validateUserAPIKey(fullKey: string): Promise<UserAPIKeyContext | null> {
  // Validate format first
  if (!isValidUserAPIKeyFormat(fullKey)) {
    return null;
  }
  
  const keyHash = hashAPIKey(fullKey);
  
  // Query by key hash using GSI
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: KEY_HASH_INDEX,
    KeyConditionExpression: 'key_hash = :keyHash',
    ExpressionAttributeValues: {
      ':keyHash': keyHash
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  const { pk, sk, ...apiKey } = result.Items[0];
  const key = apiKey as UserAPIKey;
  
  // Check if key is active
  if (key.status !== 'active') {
    return null;
  }
  
  // Check expiration
  if (key.expires_at && new Date(key.expires_at) < new Date()) {
    return null;
  }
  
  // Update last used timestamp and usage count (fire and forget)
  recordUserAPIKeyUsage(key.user_id, key.id).catch(() => {});
  
  return {
    key,
    user_id: key.user_id,
    realm_id: key.realm_id,
    tenant_id: key.tenant_id,
    scopes: key.scopes
  };
}

/**
 * List all API keys for a user
 */
export async function listUserAPIKeysByUser(userId: string): Promise<UserAPIKeyResponse[]> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: USER_INDEX,
    KeyConditionExpression: 'user_id = :userId',
    ExpressionAttributeValues: {
      ':userId': userId
    }
  }));
  
  if (!result.Items) {
    return [];
  }
  
  return result.Items.map(item => {
    const { pk, sk, key_hash, ...apiKey } = item;
    return toResponse(apiKey as UserAPIKey);
  });
}

/**
 * List API keys for a specific realm
 */
export async function listUserAPIKeysByRealm(realmId: string): Promise<UserAPIKeyResponse[]> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':realmId': realmId
    }
  }));
  
  if (!result.Items) {
    return [];
  }
  
  return result.Items.map(item => {
    const { pk, sk, key_hash, ...apiKey } = item;
    return toResponse(apiKey as UserAPIKey);
  });
}

/**
 * Revoke a user API key
 */
export async function revokeUserAPIKey(
  userId: string,
  keyId: string,
  revokedBy?: string
): Promise<UserAPIKey | null> {
  const now = new Date().toISOString();
  
  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: `USER#${userId}#KEY#${keyId}`,
      sk: 'KEY'
    },
    UpdateExpression: 'SET #status = :status, revoked_at = :revokedAt, revoked_by = :revokedBy, updated_at = :now',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':status': 'revoked' as UserAPIKeyStatus,
      ':revokedAt': now,
      ':revokedBy': revokedBy || userId,
      ':now': now
    },
    ConditionExpression: 'attribute_exists(pk)',
    ReturnValues: 'ALL_NEW'
  }));
  
  if (!result.Attributes) {
    return null;
  }
  
  const { pk, sk, ...apiKey } = result.Attributes;
  return apiKey as UserAPIKey;
}

/**
 * Record API key usage
 */
export async function recordUserAPIKeyUsage(userId: string, keyId: string): Promise<void> {
  const now = new Date().toISOString();
  
  await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: `USER#${userId}#KEY#${keyId}`,
      sk: 'KEY'
    },
    UpdateExpression: 'SET last_used_at = :now, usage_count = if_not_exists(usage_count, :zero) + :one',
    ExpressionAttributeValues: {
      ':now': now,
      ':zero': 0,
      ':one': 1
    }
  }));
}

/**
 * Update user API key
 */
export async function updateUserAPIKey(
  userId: string,
  keyId: string,
  updates: Partial<Pick<UserAPIKey, 'name' | 'description' | 'scopes' | 'expires_at' | 'ip_restrictions'>>
): Promise<UserAPIKey | null> {
  const now = new Date().toISOString();
  
  // Build update expression dynamically
  const updateParts: string[] = ['updated_at = :now'];
  const expressionValues: Record<string, any> = { ':now': now };
  const expressionNames: Record<string, string> = {};
  
  if (updates.name !== undefined) {
    updateParts.push('#name = :name');
    expressionNames['#name'] = 'name';
    expressionValues[':name'] = updates.name;
  }
  
  if (updates.description !== undefined) {
    updateParts.push('description = :description');
    expressionValues[':description'] = updates.description;
  }
  
  if (updates.scopes !== undefined) {
    updateParts.push('scopes = :scopes');
    expressionValues[':scopes'] = updates.scopes;
  }
  
  if (updates.expires_at !== undefined) {
    updateParts.push('expires_at = :expiresAt');
    expressionValues[':expiresAt'] = updates.expires_at;
  }
  
  if (updates.ip_restrictions !== undefined) {
    updateParts.push('ip_restrictions = :ipRestrictions');
    expressionValues[':ipRestrictions'] = updates.ip_restrictions;
  }
  
  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: `USER#${userId}#KEY#${keyId}`,
      sk: 'KEY'
    },
    UpdateExpression: `SET ${updateParts.join(', ')}`,
    ExpressionAttributeNames: Object.keys(expressionNames).length > 0 ? expressionNames : undefined,
    ExpressionAttributeValues: expressionValues,
    ConditionExpression: 'attribute_exists(pk)',
    ReturnValues: 'ALL_NEW'
  }));
  
  if (!result.Attributes) {
    return null;
  }
  
  const { pk, sk, ...apiKey } = result.Attributes;
  return apiKey as UserAPIKey;
}

/**
 * Delete user API key permanently (use revokeUserAPIKey for soft delete)
 */
export async function deleteUserAPIKey(userId: string, keyId: string): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: `USER#${userId}#KEY#${keyId}`,
        sk: 'KEY'
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Revoke all API keys for a user
 */
export async function revokeAllUserAPIKeys(userId: string, revokedBy?: string): Promise<number> {
  const keys = await listUserAPIKeysByUser(userId);
  let revokedCount = 0;
  
  for (const key of keys) {
    if (key.status === 'active') {
      await revokeUserAPIKey(userId, key.id, revokedBy);
      revokedCount++;
    }
  }
  
  return revokedCount;
}

/**
 * Check if user has any active API keys
 */
export async function hasActiveUserAPIKeys(userId: string): Promise<boolean> {
  const keys = await listUserAPIKeysByUser(userId);
  return keys.some(key => key.status === 'active');
}
